use con::Con;
use mio::{Token,Poll,Event,Ready};
use std::io::ErrorKind as IoErrorKind;
use tls_api::{TlsConnector};
use httparse::{self, Response as ParseResp};
use http::response::Builder as RespBuilder;
use http::{self,Request,Version,Response,Method};
use http::header::*;
use ::Httpc;
use std::str::FromStr;
use std::time::{Duration,Instant};
use dns_cache::DnsCache;
use std::io::Read;

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
    stream_req_body: bool,
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
            stream_req_body: false,
            max_body: Some(1024*1024*10),
            dur: Duration::from_millis(30000),
            req,
        }
    }

    /// Consume and execute
    pub fn call<C:TlsConnector>(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<()> {
        httpc.call::<C>(self, poll)
    }

    /// If post/put and no body in supplied http::Request
    /// it will assume body will be received client side.
    /// Content-length header must be set manually.
    pub fn stream_req_body(&mut self, b: bool) -> &mut Self {
        self.stream_req_body = b;
        self
    }

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

enum Dir {
    Sending,
    Receiving,
}

pub(crate) struct Call {
    b: CallBuilder,
    start: Instant,
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
            dir: Dir::Sending,
            start: Instant::now(),
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

    pub fn event<C:TlsConnector>(&mut self, cp: &mut CallParam, b: Option<&mut Vec<u8>>) -> ::Result<bool> {
        if self.hdr_sz == 0 || !self.b.stream_response || b.is_none() {
            let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
            let ret = self.event1::<C>(cp, &mut buf);
            self.buf = buf;
            // ::std::mem::replace(&mut self.buf, Vec::new());
            ret
        } else {
            let mut b = b.unwrap();
            if self.buf.len() > self.hdr_sz {
                (&mut b).extend(&self.buf[self.hdr_sz..]);
                self.buf.truncate(self.hdr_sz);
            }
            self.event1::<C>(cp, b)
        }
    }

    fn event1<C:TlsConnector>(&mut self, cp: &mut CallParam, b: &mut Vec<u8>) -> ::Result<bool> {
        let mut orig_len = self.make_space(b);
        // let mut resp:Option<Response<Vec<u8>>> = None;
        let mut read_ret;
        let mut entire_sz = 0;
        loop {
            self.con.signalled::<C,Vec<u8>>(cp, &self.b.req)?;
            read_ret = self.con.read(b);

            match &read_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        self.con.ready.remove(Ready::writable());
                        if entire_sz == 0 {
                            return Ok(false);
                        }
                        break;
                    }
                }
                &Ok(sz) if sz > 0 => {
                    if b.len() == orig_len+sz {
                        entire_sz += sz;
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
            read_ret = Ok(entire_sz);
        }
        match read_ret {
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