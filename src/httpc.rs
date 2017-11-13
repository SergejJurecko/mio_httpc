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
    /// How many bytes of body has been sent.
    SentBody(usize),
    /// Waiting for body to be provided for sending.
    WaitReqBody,
    // No call exists for token.
    InvalidToken,
    // Nothing yet to return.
    Nothing,
}

impl EventResult {
    fn is_terminal(&self) -> bool {
        match *self {
            EventResult::Error(::Error::HeadersOverlimit(_)) => false,
            EventResult::Error(_) => true,
            _ => false,
        }
    }
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
    // pub fn reuse(&mut self, mut buf: Vec<u8>) {
    //     let mut cap = buf.capacity();
    //     if cap < self.max_hdrs {
    //         buf.reserve(self.max_hdrs - cap);
    //         cap = buf.capacity();
    //     }
    //     if cap < buf.len() {
    //         unsafe {
    //             buf.set_len(cap);
    //         }
    //     }
    //     self.free_bufs.push_front(buf);
    // }

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
            let mut b = Vec::with_capacity(self.max_hdrs);
            // unsafe { b.set_len(self.max_hdrs); }
            b
        }
    }

    /// If stream_response=true for call, body will be written to b
    /// if it is set. b will be increased in size if required.
    pub fn event<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, b: Option<&mut Vec<u8>>) -> EventResult {
        if let Some(c) = self.calls.get_mut(&ev.token().0) {
            let mut cp = ::call::CallParam {
                poll,
                ev,
                dns: &mut self.cache,
            };
            match c.event::<C>(&mut cp, b) {
                Ok(er) => {
                    return er;
                }
                Err(e) => {
                   return EventResult::Error(e); 
                }
            }
        }
        EventResult::InvalidToken
    }

    // pub fn read_body(&mut self, tk: Token, ubuf: Option<&mut [u8]>) -> ConReturn {
    //     if !(tk.0 >= self.tk_offset && tk.0 <= self.tk_offset + self.cons.len()) {
    //         return ConReturn::InvalidToken;
    //     }
    //     let mut ret = ConReturn::Nothing;
    //     let id = tk.0 - self.tk_offset;
    //     let con = self.cons[id].take();
    //     if con.is_none() {
    //         ret = ConReturn::Error(::Error::InvalidToken);
    //     }
    //     let mut con = con.unwrap();
    //     if !con.resp_returned {
    //         ret = ConReturn::Error(::Error::NoBody);
    //     }
    //     let buf = con.buf.take();
    //     if buf.is_none() {
    //         ret = ConReturn::Error(::Error::NoBody);
    //     }

    //     match ret {
    //         ConReturn::Nothing if ubuf.is_some() => {
    //             let ubuf = ubuf.unwrap();
    //             let mut buf = buf.unwrap();
    //             if ubuf.len() < con.buf_used {
    //                 ret = ConReturn::Error(::Error::TooSmall);
    //             } else {
    //                 let again = ubuf.len() == con.buf_used;
    //                 (&mut ubuf[..con.buf_used]).copy_from_slice(&buf[..con.buf_used]);
    //                 ret = ConReturn::Body(buf.len(), true);
    //                 self.free_bufs.push_front(buf);
    //                 con.buf_used = 0;
    //             }
    //         }
    //         ConReturn::Nothing => {
    //             let mut buf = buf.unwrap();
    //             // let mut again = con.buf_used == buf.len();
    //             unsafe {
    //                 buf.set_len(con.buf_used);
    //             }
    //             con.buf_used = 0;
    //             ret = ConReturn::BodyChunk(buf,false);
    //         }
    //         _ => {}
    //     }
    //     self.cons[id] = Some(con);
    //     ret
    // }


    // pub fn event<C:TlsConnector>(&mut self, poll: &Poll, tk: Token, ubuf: Option<&mut [u8]>) -> ConReturn {
    //     if !(tk.0 >= self.tk_offset && tk.0 <= self.tk_offset + self.cons.len()) {
    //         return ConReturn::InvalidToken;
    //     }
    //     let id = tk.0 - self.tk_offset;
    //     let con = self.cons[id].take();
    //     if con.is_none() {
    //         return ConReturn::InvalidToken;
    //     }
    //     let mut con = con.unwrap();
    //     let mut buf = con.hdr_buf.take();
    //     if buf.is_none() {
    //         let mut buf = self.get_buf();
    //         // con.hdr_buf_used = 0;
    //     }
    //     let mut ret = ConReturn::Nothing;
    //     let mut hdr_sz = 0;
    //     let mut ubuf_used = false;
    //     let mut ubuf_len = 0;
    //     let mut empty = [];
    //     let ubuf = if ubuf.is_some() {
    //         ubuf.unwrap()
    //     } else {
    //         &mut empty
    //     };
    //     let mut res;
    //     loop {
    //         res = if !con.on_body || ubuf.len() == 0 {
    //             con.con.signalled::<C>(poll, &mut buf[con.buf_used..])
    //         } else {
    //             ubuf_len = ubuf.len();
    //             ubuf_used = true;
    //             con.con.signalled::<C>(poll, ubuf)
    //         };
    //         match &res {
    //             &Err(ref e) => {
    //                 match e {
    //                     &::Error::Io(ref ie) => {
    //                         if ie.kind() == IoErrorKind::Interrupted {
    //                             continue;
    //                         }
    //                     }
    //                     _ => {}
    //                 }
    //             }
    //             _ => {}
    //         }
    //         break;
    //     }
    //     match res {
    //         Ok(0) => {
    //             ret = ConReturn::Error(::Error::Closed);
    //         }
    //         Ok(rec_sz) => {
    //             if !con.resp_returned {
    //                 let mut headers = [httparse::EMPTY_HEADER; 16];
    //                 let mut presp = ParseResp::new(&mut headers);
    //                 let used = presp.parse(&buf);
    //                 match used {
    //                     Ok(httparse::Status::Complete(hdr_sz1)) => {
    //                         con.buf_used += rec_sz;
    //                         hdr_sz = hdr_sz1;
    //                         con.resp_returned = true;
    //                         let mut b = RespBuilder::new();
    //                         for h in presp.headers.iter() {
    //                             b.header(h.name, h.value);
    //                         }
    //                         if let Some(status) = presp.code {
    //                             b.status(status);
    //                         }
    //                         if let Some(v) = presp.version {
    //                             if v == 0 {
    //                                 b.version(Version::HTTP_10);
    //                             } else if v == 1 {
    //                                 b.version(Version::HTTP_11);
    //                             }
    //                         }
    //                         let be = b.body(Vec::new());
    //                         if let Ok(r) = be {
    //                             ret = ConReturn::Response(r, con.buf_used - hdr_sz)
    //                         } else if let Err(e) = be {
    //                             ret = ConReturn::Error(From::from(e));
    //                         }
    //                     }
    //                     Ok(httparse::Status::Partial) => {
    //                         con.buf_used += rec_sz;
    //                     }
    //                     Err(e) => {
    //                         ret = ConReturn::Error(From::from(e));
    //                         con.buf_used = 0;
    //                     }
    //                 }
    //             } else {
    //                 con.buf_used = rec_sz;
    //                 // ret = ConReturn::Body(buf);
    //             }
    //         }
    //         Err(e) => {
    //             let is_wblock = match &e {
    //                 &::Error::Io(ref ie) => {
    //                     if ie.kind() == IoErrorKind::WouldBlock {
    //                         true
    //                     } else {
    //                         false
    //                     }
    //                 }
    //                 _ => false,
    //             };
    //             if is_wblock {
    //                 ret = ConReturn::Nothing;
    //             } else {
    //                 ret = ConReturn::Error(e);
    //                 con.buf_used = 0;
    //             }
    //         }
    //     }
    //     if ret.is_terminal() {
    //         self.free_bufs.push_front(buf);
    //         self.cons[id] = None;
    //     } else {
    //         if con.buf_used > 0 && con.resp_returned {
    //             if ubuf_used {
    //                 self.free_bufs.push_front(buf);
    //                 let used = con.buf_used;
    //                 con.buf_used = 0;
    //                 ret = ConReturn::Body(used, used == ubuf_len);
    //             } else {
    //                 unsafe { buf.set_len(con.buf_used); }
    //                 con.buf_used = 0;
    //                 let more = buf.len() == buf.capacity();
    //                 ret = ConReturn::BodyChunk(buf, more);
    //             }
    //         } else if con.buf_used == 0 {
    //             // con.buf = None;
    //             self.free_bufs.push_front(buf);
    //         } else if !con.resp_returned && con.buf_used == buf.len() {
    //             // incomplete headers
    //             if con.buf_used < self.max_hdrs {
    //                 // we can expand buffer
    //                 buf.reserve(self.max_hdrs - con.buf_used);
    //                 // We must go again because sockets are edge triggered
    //                 con.buf = Some(buf);
    //                 self.cons[id] = Some(con);
    //                 if ubuf.len() > 0 {
    //                     return self.event::<C>(poll, tk, Some(ubuf));
    //                 } else {
    //                     return self.event::<C>(poll, tk, None);
    //                 }
    //             } else {
    //                 // User must decide.
    //                 ret = ConReturn::Error(::Error::HeadersOverlimit(self.max_hdrs));
    //                 con.buf = Some(buf);
    //             }
    //         } else if hdr_sz > 0 && hdr_sz < con.buf_used {
    //             unsafe {
    //                 let src:*const u8 = buf.as_ptr().offset(hdr_sz as isize);
    //                 let dst:*mut u8 = //if ubuf.len() == 0 {
    //                     buf.as_mut_ptr();
    //                 // } else {
    //                 //     ubuf.as_mut_ptr()
    //                 // };
    //                 ::std::ptr::copy_nonoverlapping(src, dst, con.buf_used-hdr_sz);
    //                 // buf.set_len(con.buf_used - hdr_sz);
    //                 con.buf_used -= hdr_sz;
    //             }
    //         } else if hdr_sz > 0 {
    //             // Got headers but no body
    //             con.buf_used = 0;
    //             self.free_bufs.push_front(buf);
    //         } else {
    //             con.buf = Some(buf);
    //         }
    //         self.cons[id] = Some(con);
    //     }
    //     ret
    // }
}

