use con::Con;
use mio::{Token,Poll,Event,Ready};
use std::io::ErrorKind as IoErrorKind;
use tls_api::{TlsConnector};
use httparse::{self, Response as ParseResp};
use http::response::Builder as RespBuilder;
use http::{self,Request,Version,Response};
use http::header::*;
use ::Httpc;
use std::str::FromStr;
use std::time::{Duration,Instant};
use dns_cache::DnsCache;
use std::io::{Read,Write};
use ::httpc::EventResult;

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
    max_body: Option<usize>,
    stream_response: bool,
    // TODO: Enum with None, StreamedPlain, StreamChunked
    // stream_req_body: bool,
}

impl CallBuilder {
    /// mio token is identifier for call in Httpc
    pub fn new(tk: Token, req: Request<Vec<u8>>) -> CallBuilder {
        // if req.body().len() > 0 {
        //     if None == req.headers().get(CONTENT_LENGTH) {
        //         let mut ar = [0u8;15];
        //         if let Ok(_) = ::itoa::write(&mut ar[..], req.body().len()) {
        //             req.headers_mut().insert(CONTENT_LENGTH,
        //                 HeaderValue::from_bytes(&ar).unwrap());
        //         }
        //     }
        // }
        // if None == req.headers().get(USER_AGENT) {
        //     req.headers_mut().insert(CONTENT_LENGTH,HeaderValue::from_static(""));
        // }
        CallBuilder {
            tk,
            stream_response: false,
            // stream_req_body: false,
            max_body: Some(1024*1024*10),
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

    /// http::Response will be returned as soon as it is received
    /// and body will be streamed to client as it is received.
    /// max_body is ignored in this case.
    pub fn stream_response(&mut self, b: bool) -> &mut Self {
        self.stream_response = b;
        self
    }

    /// Default 10MB
    pub fn max_body(&mut self, m: Option<usize>) -> &mut Self {
        self.max_body = m;
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
    Receiving,
}

pub(crate) struct Call {
    b: CallBuilder,
    _start: Instant,
    con: Con,
    buf: Vec<u8>,
    hdr_sz: usize,
    body_sz: usize,
    resp: Option<Response<Vec<u8>>>,
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
            resp: None,
        }
    }

    pub(crate) fn stop(self) -> (Con, Vec<u8>) {
        (self.con, self.buf)
    }

    fn make_space(&mut self, buf: &mut Vec<u8>) -> usize {
        let orig_len = buf.len();
        let spare_capacity = orig_len - buf.capacity();
        let bytes_needed = if self.body_sz == 0 || self.b.stream_response {
            4096 * 2
        } else {
            self.hdr_sz + self.body_sz
        };
        if spare_capacity >= bytes_needed {
            unsafe {
                buf.set_len(orig_len + spare_capacity);
            }
        } else {
            buf.reserve_exact(bytes_needed - spare_capacity);
            unsafe {
                buf.set_len(bytes_needed - spare_capacity);
            }
        }
        orig_len
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

    pub fn event<C:TlsConnector>(&mut self, cp: &mut CallParam, b: Option<&mut Vec<u8>>) -> ::Result<EventResult> {
        match self.dir {
            Dir::Receiving => {
                if self.hdr_sz == 0 || !self.b.stream_response || b.is_none() {
                    let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                    let ret = self.event_rec::<C>(cp, &mut buf);
                    self.buf = buf;
                    ret
                } else {
                    let mut b = b.unwrap();
                    if self.buf.len() > self.hdr_sz {
                        (&mut b).extend(&self.buf[self.hdr_sz..]);
                        self.buf.truncate(self.hdr_sz);
                    }
                    self.event_rec::<C>(cp, b)
                }
            }
            Dir::SendingHdr(pos) => {
                let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                if self.hdr_sz == 0 {
                    self.make_space(&mut buf);
                    self.fill_send_req(&mut buf);
                }
                let hdr_sz = self.hdr_sz;
                let ret = self.event_send::<C>(cp, 0, &buf[pos..hdr_sz]);
                self.buf = buf;
                if let Dir::SendingBody(_) = self.dir {
                    // go again
                    return self.event::<C>(cp, b);
                }
                ret
            }
            Dir::SendingBody(_pos) if b.is_some() => {
                let b = b.unwrap();
                self.event_send::<C>(cp, 0, &b[..])
            }
            Dir::SendingBody(pos) if self.b.req.body().len() > 0 => {
                self.event_send::<C>(cp, pos, &[])
            }
            _ => {
                Ok(EventResult::WaitReqBody)
            }
        }
    }

    fn event_send<C:TlsConnector>(&mut self, cp: &mut CallParam, in_pos: usize, b: &[u8]) -> ::Result<EventResult> {
        self.con.signalled::<C,Vec<u8>>(cp, &self.b.req)?;
        if !self.con.ready.is_writable() {
            return Ok(EventResult::Nothing);
        }
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
                        return Ok(EventResult::Nothing);
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
                                self.dir = Dir::Receiving;
                            }
                        } else {
                            self.dir = Dir::SendingHdr(pos+sz);
                        }
                        return Ok(EventResult::Nothing);
                    } else if let Dir::SendingBody(pos) = self.dir {
                        if self.body_sz == pos+sz {
                            self.hdr_sz = 0;
                            self.body_sz = 0;
                            self.dir = Dir::Receiving;
                            return Ok(EventResult::Nothing);
                        }
                        self.dir = Dir::SendingBody(pos+sz);
                        return Ok(EventResult::SentBody(pos+sz));
                    }
                }
                _ => {
                    return Err(::Error::Closed);
                }
            }
        }
    }

    fn event_rec<C:TlsConnector>(&mut self, cp: &mut CallParam, b: &mut Vec<u8>) -> ::Result<EventResult> {
        let mut orig_len = self.make_space(b);
        let mut io_ret;
        let mut entire_sz = 0;
        self.con.signalled::<C,Vec<u8>>(cp, &self.b.req)?;
        if !self.con.ready.is_readable() {
            return Ok(EventResult::Nothing);
        }
        loop {
            io_ret = self.con.read(b);
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        self.con.ready.remove(Ready::readable());
                        if entire_sz == 0 {
                            return Ok(EventResult::Nothing);
                        }
                        break;
                    }
                }
                &Ok(sz) if sz > 0 => {
                    entire_sz += sz;
                    if b.len() == orig_len+sz {
                        orig_len = self.make_space(b);
                        continue;
                    }
                    b.truncate(orig_len+sz);
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
            Ok(_) => {
                if self.hdr_sz == 0 {
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut presp = ParseResp::new(&mut headers);
                    match presp.parse(b) {
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
                            self.resp = Some(resp);
                        }
                        Ok(httparse::Status::Partial) => {
                        }
                        Err(e) => {
                            return Err(From::from(e));
                        }
                    }
                } else if b.len() >= self.body_sz + self.hdr_sz && self.body_sz > 0 {
                    return Ok(true);
                } else {
                    return Ok(false);
                }
            }
            Err(e) => {
                return Err(From::from(e));
            }
        }

        Ok(false)
    }
}