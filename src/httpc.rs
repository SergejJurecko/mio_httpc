use mio::{Token,Poll,Event};
// use httparse::{self, Response as ParseResp};
use http::{Response};
// use http::response::Builder as RespBuilder;
use dns_cache::DnsCache;
use con::Con;
use ::Result;
use tls_api::{TlsConnector};
use std::collections::VecDeque;
use call::{Call,CallBuilder};
use fnv::FnvHashMap as HashMap;

pub enum EventResult {
    /// HTTP Response. BodyChunk will be empty if ubuf is present
    /// and large enough. Otherwise ubuf is filled with any possible data is
    /// in chunk.
    Response(Response<Vec<u8>>),
    /// All errors except HeadersOverlimit are terminal and connection is closed.
    Error(::Error),
    /// How many bytes of body have been sent.
    SentBody(usize),
    /// How many bytes were received.
    ReceivedBody(usize),
    /// Request is done body has been returned in user provided buffer or
    /// there is no response body.
    Done,
    /// Request is done with body.
    DoneWithBody(Vec<u8>),
    /// Waiting for body to be provided for sending.
    WaitReqBody,
    // Nothing yet to return.
    Nothing,
}

pub struct Httpc {
    cache: DnsCache,
    calls: HashMap<usize,Call>,
    // tk_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    max_hdrs: usize,
}

impl Httpc {
    pub fn new() -> Httpc {
        // let mut calls = Vec::with_capacity(tk_count);
        // for _ in 0..tk_count {
        //     calls.push(None);
        // }
        Httpc {
            cache: DnsCache::new(),
            calls: HashMap::default(),
            // tk_offset,
            free_bufs: VecDeque::new(),
            max_hdrs: 4096*2,
        }
    }

    /// Max size of all response headers.
    /// Default is 8K.
    pub fn max_hdrs_len(&self) -> usize {
        self.max_hdrs
    }

    /// Will only set if sz >= 4096
    pub fn set_max_hdrs_len(&mut self, sz: usize) {
        if sz >= 4096 {
            self.max_hdrs = sz;
        }
    }

    /// Reuse a response buffer for subsequent calls.
    pub fn reuse(&mut self, mut buf: Vec<u8>) {
        buf.truncate(0);
        self.free_bufs.push_front(buf);
    }

    pub(crate) fn call<C:TlsConnector>(&mut self, b: CallBuilder, poll: &Poll) -> Result<()> {
        let id = b.tk.0;
        // let req = b.req.take().unwrap();
        let con = Con::new::<C,Vec<u8>>(b.tk, &b.req, &mut self.cache, poll)?;
        let call = Call::new(b, con, self.get_buf());
        self.calls.insert(id, call);
        Ok(())
    }

    pub fn call_close(&mut self, tk: Token) {
        if let Some(call) = self.calls.remove(&tk.0) {
            let (_, buf) = call.stop();
            self.free_bufs.push_front(buf);
        }
    }

    fn get_buf(&mut self) -> Vec<u8> {
        if let Some(buf)  = self.free_bufs.pop_front() {
            buf
        } else {
            let b = Vec::with_capacity(self.max_hdrs);
            // unsafe { b.set_len(self.max_hdrs); }
            b
        }
    }

    /// If stream_response=true for call, body will be written to b
    /// if it is set. b will be increased in size if required.
    pub fn event<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, b: Option<&mut Vec<u8>>) -> EventResult {
        let cret = if let Some(c) = self.calls.get_mut(&ev.token().0) {
            let mut cp = ::call::CallParam {
                poll,
                ev,
                dns: &mut self.cache,
            };
            c.event::<C>(&mut cp, b)
        } else {
            return EventResult::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(EventResult::Done) => {
                self.call_over(ev);
                return EventResult::Done;
            }
            Ok(EventResult::DoneWithBody(body)) => {
                self.call_over(ev);
                return EventResult::DoneWithBody(body);
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_over(ev);
                return EventResult::Error(e); 
            }
        }
    }

    fn call_over(&mut self, ev: &Event) {
        if let Some(call) = self.calls.remove(&ev.token().0) {
            let (_con,cb) = call.stop();
            if cb.capacity() > 0 {
                self.reuse(cb);
            }
        }
    }
}

