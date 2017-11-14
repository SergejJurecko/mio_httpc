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

pub enum SendState {
    /// Unrecoverable error has occured and call is finished.
    Error(::Error),
    /// How many bytes of body have been sent.
    SentBody(usize),
    /// Waiting for body to be provided for sending.
    WaitReqBody,
    /// Call has switched to receiving state.
    Receiving,
    /// Request is done body has been returned in user provided buffer or
    /// there is no response body.
    Done,
    // Nothing yet to return.
    Nothing,
}

pub enum RecvState {
    /// Unrecoverable error has occured and call is finished.
    Error(::Error),
    /// HTTP Response. If there is a body it will follow, otherwise call is done.
    Response(Response<Vec<u8>>),
    /// How many bytes were received.
    ReceivedBody(usize),
    /// Request is done with body.
    DoneWithBody(Vec<u8>),
    /// We are not done sending request yet.
    Sending,
    /// Request is done body has been returned in user provided buffer or
    /// there is no response body.
    Done,
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
    pub fn event<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event) -> Option<u32> {
        Some(1)
    }

    /// If POST/PUT it will be either taken from buf, from Request provided to CallBuilder
    /// or will return SendState::WaitReqBody.
    /// buf slice is assumed to have taken previous SendState::SentBody(usize) into account
    /// and starts from part of buffer that has not been sent yet.
    pub fn call_send<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, buf: Option<&[u8]>) -> SendState {
        let id = ev.token().0;
        let cret = if let Some(c) = self.calls.get_mut(&ev.token().0) {
            let mut cp = ::call::CallParam {
                poll,
                ev,
                dns: &mut self.cache,
            };
            c.event_send::<C>(&mut cp, buf)
        } else {
            return SendState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(SendState::Done) => {
                self.call_over(id);
                return SendState::Done;
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_over(id);
                return SendState::Error(e); 
            }
        }
    }

    /// If no buf provided, response body (if any) is stored in an internal buffer.
    /// If buf provided after some body has been received, it will be copied to it.
    /// Buf will be expanded if required.
    /// If body is only stored in internal buffer it will be limited to CallBuilder::max_response.
    pub fn call_recv<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, buf: Option<&mut Vec<u8>>) -> RecvState {
        let id = ev.token().0;
        let cret = if let Some(c) = self.calls.get_mut(&ev.token().0) {
            let mut cp = ::call::CallParam {
                poll,
                ev,
                dns: &mut self.cache,
            };
            c.event_recv::<C>(&mut cp, buf)
        } else {
            return RecvState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(RecvState::Done) => {
                self.call_over(id);
                return RecvState::Done;
            }
            Ok(RecvState::DoneWithBody(body)) => {
                self.call_over(id);
                return RecvState::DoneWithBody(body);
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_over(id);
                return RecvState::Error(e); 
            }
        }
    }

    fn call_over(&mut self, id: usize) {
        if let Some(call) = self.calls.remove(&id) {
            let (_con,cb) = call.stop();
            if cb.capacity() > 0 {
                self.reuse(cb);
            }
        }
    }
}

