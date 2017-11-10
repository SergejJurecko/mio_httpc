use con::Con;
use mio::{Token,Poll};
use std::io::ErrorKind as IoErrorKind;
use tls_api::{TlsConnector};
use httparse::{self, Response as ParseResp};
use http::response::Builder as RespBuilder;
use http::{self,Request,Version,Response};
use ::Httpc;
use std::str::FromStr;
use std::time::{Duration,Instant};

/// Start configure call.
pub struct CallBuilder {
    pub(crate) tk: Token,
    pub(crate) req: Option<Request<Vec<u8>>>,
    dur: Duration,
    max_body: Option<usize>,
    stream_response: bool,
}

impl CallBuilder {
    /// mio token is identifier for call in Httpc
    pub fn new(tk: Token, req: Request<Vec<u8>>) -> CallBuilder {
        CallBuilder {
            tk,
            stream_response: false,
            max_body: Some(1024*1024*10),
            dur: Duration::from_millis(30000),
            req: Some(req),
        }
    }

    /// Consume and execute
    pub fn call<C:TlsConnector>(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<()> {
        httpc.call::<C>(self, poll)
    }

    /// http::Response and Body will be streamed to client as it is received.
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

pub struct Call {
    b: CallBuilder,
    start: Instant,
    con: Con<Vec<u8>>,
    buf: Vec<u8>,
    hdr_sz: usize,
    body_sz: usize,
    on_body: bool,
    resp: Option<Response<Vec<u8>>>,
}

impl Call {
    pub(crate) fn new(b: CallBuilder, con: Con<Vec<u8>>, buf: Vec<u8>) -> Call {
        Call {
            start: Instant::now(),
            b,
            con,
            buf,
            on_body: false,
            hdr_sz: 0,
            body_sz: 0,
            resp: None,
        }
    }

    pub(crate) fn stop(self) -> (Con<Vec<u8>>, Vec<u8>) {
        (self.con, self.buf)
    }

    fn make_space(&mut self) -> usize {
        let orig_len = self.buf.len();
        let spare_capacity = orig_len - self.buf.capacity();
        let bytes_needed = if self.body_sz == 0 {
            4096 * 2
        } else {
            self.hdr_sz + self.body_sz
        };
        if spare_capacity >= bytes_needed {
            unsafe {
                self.buf.set_len(orig_len + spare_capacity);
            }
        } else {
            self.buf.reserve_exact(bytes_needed - spare_capacity);
            unsafe {
                self.buf.set_len(bytes_needed - spare_capacity);
            }
        }
        orig_len
    }

    pub fn event<C:TlsConnector>(&mut self, poll: &Poll) -> ::Result<bool> {
        let mut orig_len = self.make_space();
        // let mut resp:Option<Response<Vec<u8>>> = None;
        let mut read_ret;
        let mut entire_sz = 0;
        loop {
            read_ret = self.con.signalled::<C>(poll, &mut self.buf[orig_len..]);
            match &read_ret {
                &Err(ref e) => {
                    match e {
                        &::Error::Io(ref ie) => {
                            if ie.kind() == IoErrorKind::Interrupted {
                                continue;
                            } else if ie.kind() == IoErrorKind::WouldBlock {
                                if entire_sz == 0 {
                                    return Ok(false);
                                }
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                &Ok(sz) if sz > 0 => {
                    if self.buf.len() == orig_len+sz {
                        entire_sz += sz;
                        orig_len = self.make_space();
                        continue;
                    }
                    self.buf.truncate(orig_len+sz);
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
                if !self.on_body {
                    let mut headers = [httparse::EMPTY_HEADER; 16];
                    let mut presp = ParseResp::new(&mut headers);
                    match presp.parse(&self.buf) {
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
                } else if self.buf.len() >= self.body_sz + self.hdr_sz {
                    return Ok(true);
                }
            }
            Err(e) => {
                return Err(e);
            }
        }

        Ok(false)
    }
}