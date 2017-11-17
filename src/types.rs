use dns_cache::DnsCache;
use mio::{Poll,Event};
use http::{Request};
use std::time::Duration;
use httpc::PrivHttpc;
use tls_api::{TlsConnector};
use btoi::btou_radix;

pub struct ChunkIndex {
    // (offset,len)
    chunks: Vec<(usize,usize)>,
    remain: usize,
}

impl ChunkIndex {
    pub fn new() -> ChunkIndex {
        ChunkIndex {
            chunks: Vec::new(),
            remain: 0,
        }
    }

    pub fn enable(&mut self) {
        self.chunks = Vec::with_capacity(16);
        self.remain = 0;
    }

    pub fn enabled(&self) -> bool {
        self.chunks.len() > 0 || self.chunks.capacity() > 0
    }

    pub fn push(&mut self, offset: usize, b: &[u8]) -> ::Result<()> {
        let blen = b.len();
        if self.remain < blen && blen - self.remain > 2 {
            let mut len = 0;
            for i in self.remain..blen {
                if i+1 < blen && b[i] == b'\r' && b[i+1] == b'\n' {
                    len = i - self.remain;
                    break;
                }
            }
            if len == 0 {
                return Err(::Error::ChunkedParse)
            }
            if let Ok(n) = btou_radix(&b[self.remain..self.remain+len], 16) {
                self.chunks.push((offset+self.remain+len+2, n));
            } else {
                return Err(::Error::ChunkedParse);
            }
        }
        Ok(())
    }
}

pub struct CallParam<'a> {
    pub poll: &'a Poll,
    pub dns: &'a mut DnsCache,
    // pub con: &'a mut Con,
    pub ev: &'a Event,
}

/// Start configure call.
pub struct PrivCallBuilder {
    pub req: Request<Vec<u8>>,
    pub chunked_parse: bool,
    pub dur: Duration,
    pub max_response: usize,
}

#[allow(dead_code)]
impl PrivCallBuilder {
    pub fn new(req: Request<Vec<u8>>) -> PrivCallBuilder {
        PrivCallBuilder {
            max_response: 1024*1024*10,
            dur: Duration::from_millis(30000),
            req,
            chunked_parse: true,
        }
    }
    pub fn call<C:TlsConnector>(self, httpc: &mut PrivHttpc, poll: &Poll) -> ::Result<::CallId> {
        httpc.call::<C>(self, poll)
    }
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.max_response = m;
        self
    }
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.chunked_parse = b;
        self
    }
    pub fn timeout(&mut self, d: Duration) -> &mut Self {
        self.dur = d;
        self
    }
}

