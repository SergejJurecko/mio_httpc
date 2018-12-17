use call::CallImpl;
use connection::{Con, ConTable};
use mio::{Event, Poll, Token};
use resolve::DnsCache;
use std::collections::VecDeque;
use tls_api::TlsConnector;
use types::*;
// use fnv::FnvHashMap as HashMap;
use std::time::Instant;
use {Call, CallRef, RecvState, Response, Result, SendState};

pub struct HttpcImpl {
    cache: DnsCache,
    // timed_out_calls: HashMap<CallRef,CallImpl>,
    // con_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    cons: ConTable,
    last_timeout: Instant,
    cfg: ::HttpcCfg,
    call_idgen: u64,
}

const BUF_SZ: usize = 4096 * 2;

impl HttpcImpl {
    pub fn new(con_offset: usize, cfg: Option<::HttpcCfg>) -> HttpcImpl {
        let mut cfg = cfg.unwrap_or_default();
        cfg.con_offset = con_offset;
        let mut r = HttpcImpl {
            cfg,
            // timed_out_calls: HashMap::default(),
            last_timeout: Instant::now(),
            cache: DnsCache::new(),
            // con_offset,
            free_bufs: VecDeque::new(),
            cons: ConTable::new(),
            call_idgen: 10,
        };
        r.free_bufs.push_back(Vec::with_capacity(BUF_SZ));
        r.free_bufs.push_back(Vec::with_capacity(BUF_SZ));
        r
    }

    pub fn recfg(&mut self, mut cfg: ::HttpcCfg) {
        cfg.con_offset = self.cfg.con_offset;
        self.cfg = cfg;
    }

    pub fn open_connections(&self) -> usize {
        self.cons.open_cons()
    }

    pub fn reuse(&mut self, mut buf: Vec<u8>) {
        if buf.len() + buf.capacity() == 0 {
            return;
        }
        if self.free_bufs.len() >= self.cfg.cache_buffers {
            return;
        }
        let cap = buf.capacity();
        if cap > BUF_SZ {
            unsafe {
                buf.set_len(BUF_SZ);
            }
            buf.shrink_to_fit();
        } else if cap < BUF_SZ {
            buf.reserve_exact(BUF_SZ - cap);
        }
        buf.truncate(0);
        self.free_bufs.push_front(buf);
    }

    pub fn call<C: TlsConnector>(&mut self, b: CallBuilderImpl, poll: &Poll) -> Result<Call> {
        let con_id = if b.bytes.host.len() > 0 {
            if let Some(con_id) = self.cons.try_keepalive(&b.bytes.host, poll) {
                Some(con_id)
            } else {
                None
            }
        } else {
            None
        };
        let call_id = self.call_idgen;
        self.call_idgen += 1;
        if let Some(con_id) = con_id {
            let call = CallImpl::new(call_id, b, self.get_buf(), self.get_buf());
            self.cons.push_ka_con(con_id, call)?;
            let id = Call::new(call_id, con_id as _, usize::max_value());
            return Ok(id);
        }
        // cons.push_con will set actual mio token
        let con1 = Con::new::<C, Vec<u8>>(
            call_id,
            Token::from(self.cfg.con_offset),
            &b,
            &mut self.cache,
            // poll,
            b.dns_timeout,
            b.insecure,
            &self.cfg,
        )?;

        let call = CallImpl::new(call_id, b, self.get_buf(), self.get_buf());
        if let Some((con_id1, con_id2)) = self.cons.push_con(con1, call, poll, &self.cfg)? {
            let mut call = Call::new(call_id, con_id1, con_id2);
            // if con1.resolved().len() > 0 {
            //     // if let Some(con_id) = self.cons.push_other_con(mut c: Con, first: usize, poll: &Poll)
            // }
            Ok(call)
        } else {
            Err(::Error::NoSpace)
        }
    }

    pub fn call_close(&mut self, id: Call) {
        if id.is_empty() {
            return;
        }
        self.call_close_int(id);
    }

    fn call_close_int(&mut self, id: Call) -> CallBuilderImpl {
        let (builder, b1, b2) = self.cons.close_call(id);
        if b1.capacity() > 0 || b1.len() > 0 {
            self.reuse(b1);
        }
        if b2.capacity() > 0 || b2.len() > 0 {
            self.reuse(b2);
        }
        builder
    }

    pub fn get_buf(&mut self) -> Vec<u8> {
        if let Some(buf) = self.free_bufs.pop_front() {
            buf
        } else {
            let b = Vec::with_capacity(BUF_SZ);
            b
        }
    }

    pub fn timeout(&mut self) -> Vec<CallRef> {
        let mut out = Vec::new();
        self.timeout_extend(&mut out);
        out
    }

    pub fn timeout_extend(&mut self, out: &mut Vec<CallRef>) {
        let now = Instant::now();
        if now.duration_since(self.last_timeout).subsec_nanos() < 50_000_000 {
            return;
        }
        self.last_timeout = now;
        self.cons.timeout_extend(now, out);
    }

    pub fn event<C: TlsConnector>(&mut self, ev: &Event) -> Option<CallRef> {
        let mut id = ev.token().0;
        if id >= self.cfg.con_offset && id <= self.cfg.con_offset + (u16::max_value() as usize) {
            id -= self.cfg.con_offset;
            if let Some(call_id) = self.cons.signalled_con(id, ev.readiness()) {
                return Some(CallRef::new(call_id));
            }
        }
        None
    }

    pub fn peek_body(&mut self, call: &Call, off: &mut usize) -> &[u8] {
        if call.is_empty() {
            return &[];
        }
        self.cons.peek_body(call, off)
    }
    pub fn try_truncate(&mut self, call: &::Call, off: &mut usize) {
        if call.is_empty() {
            return;
        }
        self.cons.try_truncate(call, off);
    }

    pub fn call_send<C: TlsConnector>(
        &mut self,
        poll: &Poll,
        call: &mut Call,
        buf: Option<&[u8]>,
    ) -> SendState {
        if call.is_empty() {
            return SendState::Done;
        }
        let cret = {
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
                cfg: &self.cfg,
            };
            self.cons.event_send::<C>(call, &mut cp, buf)
        };
        match cret {
            Ok(SendStateInt::Done) => {
                self.call_close(call.clone());
                call.invalidate();
                return SendState::Done;
            }
            // Ok(SendStateInt::Error(e)) => {
            //     return SendState::Error(e);
            // }
            Ok(SendStateInt::Receiving) => {
                return SendState::Receiving;
            }
            Ok(SendStateInt::SentBody(sz)) => {
                return SendState::SentBody(sz);
            }
            Ok(SendStateInt::Wait) => {
                return SendState::Wait;
            }
            Ok(SendStateInt::WaitReqBody) => {
                return SendState::WaitReqBody;
            }
            Ok(SendStateInt::Retry(_err)) => {
                let mut b = self.call_close_int(call.clone());
                call.invalidate();
                b.reused = true;
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        *call = nc;
                        return SendState::Wait;
                    }
                    Err(e) => {
                        return SendState::Error(e);
                    }
                }
            }
            Err(e) => {
                self.call_close(call.clone());
                call.invalidate();
                return SendState::Error(e);
            }
        }
    }

    pub fn call_recv<C: TlsConnector>(
        &mut self,
        poll: &Poll,
        call: &mut Call,
        buf: Option<&mut Vec<u8>>,
    ) -> RecvState {
        if call.is_empty() {
            return RecvState::Done;
        }
        let cret = {
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
                cfg: &self.cfg,
            };
            self.cons.event_recv::<C>(call, &mut cp, buf)
        };
        match cret {
            Ok(RecvStateInt::Response(r, ::ResponseBody::Sized(0))) => {
                self.call_close(call.clone());
                call.invalidate();
                return RecvState::Response(r, ::ResponseBody::Sized(0));
            }
            Ok(RecvStateInt::Done) => {
                self.call_close(call.clone());
                call.invalidate();
                return RecvState::Done;
            }
            Ok(RecvStateInt::DoneWithBody(body)) => {
                self.call_close(call.clone());
                call.invalidate();
                return RecvState::DoneWithBody(body);
            }
            Ok(RecvStateInt::Retry(_err)) => {
                let mut b = self.call_close_int(call.clone());
                call.invalidate();
                b.reused = true;
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        *call = nc;
                        return RecvState::Sending;
                    }
                    Err(e) => {
                        return RecvState::Error(e);
                    }
                }
            }
            Ok(RecvStateInt::Redirect(r)) => {
                let mut b = self.call_close_int(call.clone());
                call.invalidate();
                if b.max_redirects > 0 {
                    b.max_redirects -= 1;
                }
                b.reused = true;
                if Self::fix_location(&r, &mut b) {
                    match self.call::<C>(b, poll) {
                        Ok(nc) => {
                            *call = nc;
                            return RecvState::Sending;
                        }
                        Err(e) => {
                            return RecvState::Error(e);
                        }
                    }
                }
                return RecvState::Response(r, ::ResponseBody::Sized(0));
            }
            Ok(RecvStateInt::DigestAuth(r, d)) => {
                let mut b = self.call_close_int(call.clone());
                call.invalidate();
                if b.auth.hdr.len() > 0 {
                    // If an attempt was already made once, return response.
                    return RecvState::Response(r, ::ResponseBody::Sized(0));
                }
                b.auth_recv(d);
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        *call = nc;
                        return RecvState::Sending;
                    }
                    Err(e) => {
                        return RecvState::Error(e);
                    }
                }
            }
            Ok(RecvStateInt::BasicAuth) => {
                let mut b = self.call_close_int(call.clone());
                call.invalidate();
                b.digest_auth(false);
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        *call = nc;
                        return RecvState::Sending;
                    }
                    Err(e) => {
                        return RecvState::Error(e);
                    }
                }
            }
            Ok(RecvStateInt::Sending) => {
                return RecvState::Sending;
            }
            Ok(RecvStateInt::ReceivedBody(b)) => {
                return RecvState::ReceivedBody(b);
            }
            Ok(RecvStateInt::Wait) => {
                return RecvState::Wait;
            }
            Ok(RecvStateInt::Response(a, b)) => {
                return RecvState::Response(a, b);
            }
            // Ok(RecvStateInt::Error(e)) => {
            //     return RecvState::Error(e);
            // }
            Err(e) => {
                self.call_close(call.clone());
                call.invalidate();
                return RecvState::Error(e);
            }
        }
    }

    fn fix_location(r: &Response, b: &mut CallBuilderImpl) -> bool {
        let hdrs = r.headers();
        for h in hdrs {
            if h.is("location") {
                if h.value.starts_with("https://") || h.value.starts_with("http://") {
                    if let Ok(_) = b.url(h.value) {
                        return true;
                    }
                } else if h.value.len() > 0 {
                    b.bytes.path.truncate(0);
                    b.bytes.query.truncate(0);
                    if h.value.as_bytes()[0] != b'/' {
                        b.bytes.path.push(b'/');
                    }
                    let mut path_split = h.value.split("?");
                    if let Some(path) = path_split.next() {
                        b.bytes.path.extend_from_slice(path.as_bytes());
                    }
                    if let Some(query) = path_split.next() {
                        if query.len() > 0 {
                            b.bytes.query.push(b'?');
                            b.bytes.query.extend_from_slice(query.as_bytes());
                        }
                    }
                    return true;
                }
                break;
            }
        }
        false
    }
}
