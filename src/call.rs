use con::Con;
use mio::{Token,Poll,Event,Ready};
use std::io::ErrorKind as IoErrorKind;
use tls_api::{TlsConnector};
use httparse::{self, Response as ParseResp};
use http::response::Builder as RespBuilder;
use http::{self,Request,Version};
use http::header::*;
use ::Httpc;
use std::str::FromStr;
use std::time::{Duration,Instant};
use dns_cache::DnsCache;
use std::io::{Read,Write};
use ::httpc::{SendState,RecvState};

pub(crate) struct CallParam<'a> {
    pub poll: &'a Poll,
    pub ev: &'a Event,
    pub dns: &'a mut DnsCache,
}

/// Start configure call.
pub struct CallBuilder {
    pub(crate) tk: Token,
    pub(crate) req: Request<Vec<u8>>,
    dur: Duration,
    max_response: usize,
    // stream_response: bool,
    // TODO: Enum with None, StreamedPlain, StreamChunked
    // stream_req_body: bool,
}

impl CallBuilder {
    /// mio token is identifier for call in Httpc
    /// If req contains body it will be used.
    /// If req contains no body, but has content-length set,
    /// it will wait for send body to be provided
    /// through Httpc::event calls. 
    pub fn new(tk: Token, req: Request<Vec<u8>>) -> CallBuilder {
        CallBuilder {
            tk,
            // stream_response: false,
            // stream_req_body: false,
            max_response: 1024*1024*10,
            dur: Duration::from_millis(30000),
            req,
        }
    }

    /// Consume and execute
    pub fn call<C:TlsConnector>(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<()> {
        httpc.call::<C>(self, poll)
    }

    //// If post/put and no body in supplied http::Request
    //// it will assume body will be received client side.
    //// Content-length header must be set manually.
    // pub fn stream_req_body(&mut self, b: bool) -> &mut Self {
    //     self.stream_req_body = b;
    //     self
    // }

    // /// http::Response will be returned as soon as it is received
    // /// and body will be streamed to client as it is received.
    // /// max_body is ignored in this case.
    // pub fn stream_response(&mut self, b: bool) -> &mut Self {
    //     self.stream_response = b;
    //     self
    // }

    /// Default 10MB
    /// This will limit how big the internal Vec<u8> can grow.
    /// HTTP response headers are always stored in internal buffer.
    /// HTTP response body is stored in internal buffer if no external
    /// buffer is provided.
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.max_response = m;
        self
    }

    /// Default 30s
    pub fn timeout(&mut self, d: Duration) -> &mut Self {
        self.dur = d;
        self
    }
}

#[derive(PartialEq)]
enum Dir {
    SendingHdr(usize),
    SendingBody(usize),
    Receiving(usize),
    Done,
}

pub(crate) struct Call {
    b: CallBuilder,
    _start: Instant,
    con: Con,
    buf: Vec<u8>,
    hdr_sz: usize,
    body_sz: usize,
    // resp: Option<Response<Vec<u8>>>,
    dir: Dir,
}

impl Call {
    pub(crate) fn new(b: CallBuilder, con: Con, buf: Vec<u8>) -> Call {
        Call {
            dir: Dir::SendingHdr(0),
            _start: Instant::now(),
            b,
            con,
            buf,
            hdr_sz: 0,
            body_sz: 0,
            // resp: None,
        }
    }

    // pub fn is_done(&self) -> bool {
    //     self.dir == Dir::Done
    // }

    pub(crate) fn stop(self) -> (Con, Vec<u8>) {
        (self.con, self.buf)
    }

    fn make_space(&mut self, internal: bool, buf: &mut Vec<u8>) -> ::Result<usize> {
        let orig_len = buf.len();
        let spare_capacity = orig_len - buf.capacity();
        let bytes_needed = if self.body_sz == 0 { //|| self.b.stream_response {
            4096 * 2
        } else {
            self.hdr_sz + self.body_sz
        };
        if internal && orig_len + bytes_needed > self.b.max_response {
            return Err(::Error::ResponseTooBig);
        }
        if spare_capacity < bytes_needed {
            buf.reserve_exact(bytes_needed - spare_capacity);
        }
        unsafe {
            buf.set_len(orig_len + bytes_needed);
        }
        Ok(orig_len)
    }
    
    fn fill_send_req(&mut self, buf: &mut Vec<u8>) {
        buf.extend(self.b.req.method().as_str().as_bytes());
        buf.extend(b" ");
        buf.extend(self.b.req.uri().path().as_bytes());
        if let Some(q) = self.b.req.uri().query() {
            buf.extend(b"?");
            buf.extend(q.as_bytes());
        }
        buf.extend(b" HTTP/1.1\r\n");
        for (k,v) in self.b.req.headers().iter() {
            buf.extend(k.as_str().as_bytes());
            buf.extend(b": ");
            buf.extend(v.as_bytes());
            buf.extend(b"\r\n");
        }
        let cl = self.b.req.headers().get(CONTENT_LENGTH);
        if None == cl {
            let mut ar = [0u8;15];
            self.body_sz = self.b.req.body().len();
            if let Ok(_) = ::itoa::write(&mut ar[..], self.body_sz) {
                buf.extend(CONTENT_LENGTH.as_str().as_bytes());
                buf.extend(b": ");
                buf.extend(&ar[..]);
                buf.extend(b"\r\n");
            }
        } else if let Some(cl) = cl {
            if let Ok(cl1) = cl.to_str() {
                self.body_sz = usize::from_str(cl1).unwrap();
            }
        }
        if None == self.b.req.headers().get(USER_AGENT) {
            buf.extend(USER_AGENT.as_str().as_bytes());
            buf.extend(b": ");
            buf.extend((env!("CARGO_PKG_NAME")).as_bytes());
            buf.extend(b" ");
            buf.extend((env!("CARGO_PKG_VERSION")).as_bytes());
            buf.extend(b"\r\n");
        }
        if None == self.b.req.headers().get(CONNECTION) {
            buf.extend(CONNECTION.as_str().as_bytes());
            buf.extend(b": keep-alive\r\n");
        }
        if None == self.b.req.headers().get(HOST) {
            if let Some(h) = self.b.req.uri().host() {
                buf.extend(HOST.as_str().as_bytes());
                buf.extend(b": ");
                buf.extend(h.as_bytes());
            }
        }
        buf.extend(b"\r\n");
    }

    pub fn event_send<C:TlsConnector>(&mut self, 
            cp: &mut CallParam, 
            b: Option<&[u8]>) -> ::Result<SendState> {
        match self.dir {
            Dir::Done => {
                return Ok(SendState::Done);
            }
            Dir::Receiving(_) => {
                return Ok(SendState::Receiving)
            }
            Dir::SendingHdr(pos) => {
                let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                if self.hdr_sz == 0 {
                    self.make_space(false, &mut buf)?;
                    self.fill_send_req(&mut buf);
                }
                let hdr_sz = self.hdr_sz;
                let ret = self.event_send1::<C>(cp, 0, &buf[pos..hdr_sz]);
                self.buf = buf;
                if let Dir::SendingBody(_) = self.dir {
                    // go again
                    return self.event_send::<C>(cp, b);
                }
                ret
            }
            Dir::SendingBody(pos) if self.b.req.body().len() > 0 => {
                self.event_send1::<C>(cp, pos, &[])
            }
            Dir::SendingBody(_pos) if b.is_some() => {
                let b = b.unwrap();
                self.event_send1::<C>(cp, 0, &b[..])
            }
            _ => {
                Ok(SendState::WaitReqBody)
            }
        }
    }

    pub fn event_recv<C:TlsConnector>(&mut self, 
            cp: &mut CallParam, 
            b: Option<&mut Vec<u8>>) -> ::Result<RecvState> {
        match self.dir {
            Dir::Done => {
                return Ok(RecvState::Done);
            }
            Dir::Receiving(rec_pos) => {
                if self.hdr_sz == 0 || b.is_none() {
                    let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                    // Have we already received everything?
                    // Move body data to beginning of buffer
                    // and return with body.
                    if rec_pos >= self.body_sz {
                        unsafe {
                            let src:*const u8 = buf.as_ptr().offset(self.hdr_sz as isize);
                            let dst:*mut u8 = buf.as_mut_ptr();
                            ::std::ptr::copy(src, dst, self.body_sz);
                        }
                        return Ok(RecvState::DoneWithBody(buf));
                    }
                    let ret = self.event_rec1::<C>(cp, true, &mut buf);
                    self.buf = buf;
                    ret
                } else {
                    let mut b = b.unwrap();
                    // Can we copy anything from internal buffer to 
                    // a client provided one?
                    if self.buf.len() > self.hdr_sz {
                        (&mut b).extend(&self.buf[self.hdr_sz..]);
                        if rec_pos >= self.body_sz {
                            self.dir = Dir::Done;
                            return Ok(RecvState::ReceivedBody(self.buf.len() - self.hdr_sz));
                        }
                        self.buf.truncate(self.hdr_sz);
                    }
                    self.event_rec1::<C>(cp, false, b)
                }
            }
            _ => {
                Ok(RecvState::Sending)
            }
        }
    }

    fn event_send1<C:TlsConnector>(&mut self, 
            cp: &mut CallParam, 
            in_pos: usize, 
            b: &[u8]) -> ::Result<SendState> {
        self.con.signalled::<C,Vec<u8>>(cp, &self.b.req)?;
        // if !self.con.ready.is_writable() {
        //     return Ok(SendState::Nothing);
        // }
        let mut io_ret;
        loop {
            if b.len() > 0 {
                io_ret = self.con.write(&b[in_pos..]);
            } else {
                io_ret = self.con.write(&self.b.req.body()[in_pos..]);
            }
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        self.con.ready.remove(Ready::writable());
                        return Ok(SendState::Nothing);
                    }
                }
                &Ok(sz) if sz > 0 => {
                    if let Dir::SendingHdr(pos) = self.dir {
                        if self.hdr_sz == pos+sz {
                            if self.body_sz > 0 {
                                self.dir = Dir::SendingBody(0);
                            } else {
                                self.hdr_sz = 0;
                                self.body_sz = 0;
                                self.dir = Dir::Receiving(0);
                            }
                        } else {
                            self.dir = Dir::SendingHdr(pos+sz);
                        }
                        return Ok(SendState::Nothing);
                    } else if let Dir::SendingBody(pos) = self.dir {
                        if self.body_sz == pos+sz {
                            self.hdr_sz = 0;
                            self.body_sz = 0;
                            self.dir = Dir::Receiving(0);
                            return Ok(SendState::Receiving);
                        }
                        self.dir = Dir::SendingBody(pos+sz);
                        return Ok(SendState::SentBody(pos+sz));
                    }
                }
                _ => {
                    return Err(::Error::Closed);
                }
            }
        }
    }

    fn event_rec1<C:TlsConnector>(&mut self, 
            cp: &mut CallParam, 
            internal: bool, 
            buf: &mut Vec<u8>) -> ::Result<RecvState> {
        let mut orig_len = self.make_space(internal, buf)?;
        let mut io_ret;
        let mut entire_sz = 0;
        self.con.signalled::<C,Vec<u8>>(cp, &self.b.req)?;
        // if !self.con.ready.is_readable() {
        //     return Ok(RecvState::Nothing);
        // }
        loop {
            io_ret = self.con.read(&mut buf[orig_len..]);
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        self.con.ready.remove(Ready::readable());
                        if entire_sz == 0 {
                            return Ok(RecvState::Nothing);
                        }
                        break;
                    }
                }
                &Ok(sz) if sz > 0 => {
                    entire_sz += sz;
                    if buf.len() == orig_len+sz {
                        orig_len = self.make_space(internal, buf)?;
                        continue;
                    }
                    buf.truncate(orig_len+sz);
                }
                _ => {}
            }
            break;
        }
        if entire_sz > 0 {
            io_ret = Ok(entire_sz);
        }
        match io_ret {
            Ok(0) => {
                return Err(::Error::Closed);
            }
            Ok(bytes_rec) => {
                if self.hdr_sz == 0 {
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut presp = ParseResp::new(&mut headers);
                    let buflen = buf.len();
                    match presp.parse(buf) {
                        Ok(httparse::Status::Complete(hdr_sz)) => {
                            self.hdr_sz = hdr_sz;
                            let mut b = RespBuilder::new();
                            for h in presp.headers.iter() {
                                b.header(h.name, h.value);
                            }
                            if let Some(status) = presp.code {
                                b.status(status);
                            }
                            if let Some(v) = presp.version {
                                if v == 0 {
                                    b.version(Version::HTTP_10);
                                } else if v == 1 {
                                    b.version(Version::HTTP_11);
                                }
                            }
                            let resp = b.body(Vec::new())?;
                            if let Some(ref clh) = resp.headers().get(http::header::CONTENT_LENGTH) {
                                if let Ok(clhs) = clh.to_str() {
                                    if let Ok(bsz) = usize::from_str(clhs) {
                                        self.body_sz = bsz;
                                    }
                                }
                            }
                            if self.body_sz == 0 {
                                self.dir == Dir::Done;
                            } else {
                                self.dir = Dir::Receiving(buflen - self.hdr_sz);
                            }
                            return Ok(RecvState::Response(resp));
                        }
                        Ok(httparse::Status::Partial) => {
                            return Ok(RecvState::Nothing);
                        }
                        Err(e) => {
                            return Err(From::from(e));
                        }
                    }
                } else {
                    let pos = if let Dir::Receiving(pos) = self.dir {
                        pos
                    } else { 0 };
                    
                    if pos + bytes_rec >= self.body_sz {
                        self.dir = Dir::Done;
                    } else {
                        self.dir = Dir::Receiving(pos + bytes_rec);
                    }
                    return Ok(RecvState::ReceivedBody(pos + bytes_rec));
                }
            }
            Err(e) => {
                return Err(From::from(e));
            }
        }
    }
}