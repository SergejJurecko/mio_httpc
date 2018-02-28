use mio::{Event, Poll, Token};
use dns_cache::DnsCache;
use connection::{Con, ConTable};
use tls_api::TlsConnector;
use std::collections::VecDeque;
use call::CallImpl;
use types::*;
// use fnv::FnvHashMap as HashMap;
use {Call, CallRef, RecvState, Response, Result, SendState};
use std::time::Instant;
use std::str::FromStr;

pub struct HttpcImpl {
    cache: DnsCache,
    // timed_out_calls: HashMap<CallRef,CallImpl>,
    con_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    cons: ConTable,
    last_timeout: Instant,
    cfg: ::HttpcCfg,
}

const BUF_SZ: usize = 4096 * 2;

impl HttpcImpl {
    pub fn new(con_offset: usize, cfg: Option<::HttpcCfg>) -> HttpcImpl {
        HttpcImpl {
            cfg: cfg.unwrap_or_default(),
            // timed_out_calls: HashMap::default(),
            last_timeout: Instant::now(),
            cache: DnsCache::new(),
            con_offset,
            free_bufs: VecDeque::new(),
            cons: ConTable::new(),
        }
    }

    pub fn open_connections(&self) -> usize {
        self.cons.open_cons()
    }

    pub fn reuse(&mut self, mut buf: Vec<u8>) {
        if self.free_bufs.len() > 5 {
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
        let con_id = if let Some(host) = b.req.uri().host() {
            if let Some(con_id) = self.cons.try_keepalive(host, poll) {
                Some(con_id)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(con_id) = con_id {
            let call = CallImpl::new(b, self.get_buf());
            self.cons.push_ka_con(con_id, call, poll)?;
            let id = Call::new(con_id, 0);
            return Ok(id);
        }
        // cons.push_con will set actual mio token
        let con = Con::new::<C, Vec<u8>>(
            Token::from(self.con_offset),
            &b.req,
            &mut self.cache,
            poll,
            b.dns_timeout,
            b.insecure,
        )?;
        let call = CallImpl::new(b, self.get_buf());
        if let Some(con_id) = self.cons.push_con(con, call, poll)? {
            let id = Call::new(con_id, 0);
            Ok(id)
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
        let (builder, b1) = self.cons.close_call(id.con_id(), id.call_id());
        if b1.capacity() > 0 || b1.len() > 0 {
            self.reuse(b1);
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
        if id >= self.con_offset && id <= (u16::max_value() as usize) {
            id -= self.con_offset;
            if let Some(_) = self.cons.get_signalled_con(id) {
                // println!("Signalled {:?}", ev);
                return Some(CallRef::new(id as u16, 0));
            }
        }
        None
    }

    pub fn peek_body(&mut self, call: &Call, off: &mut usize) -> &[u8] {
        if call.is_empty() {
            return &[];
        }
        self.cons.peek_body(call.con_id(), call.call_id(), off)
    }
    pub fn try_truncate(&mut self, call: &::Call, off: &mut usize) {
        if call.is_empty() {
            return;
        }
        self.cons.try_truncate(call.con_id(), call.call_id(), off);
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
            self.cons
                .event_send::<C>(call.con_id(), call.call_id(), &mut cp, buf)
        };
        match cret {
            Ok(SendStateInt::Done) => {
                self.call_close(Call(call.0));
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
            Ok(SendStateInt::Retry(err)) => {
                let mut b = self.call_close_int(Call(call.0));
                call.invalidate();
                b.reused = true;
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        call.0 = nc.0;
                        return SendState::Wait;
                    }
                    Err(e) => {
                        return SendState::Error(e);
                    }
                }
            }
            Err(e) => {
                self.call_close(Call(call.0));
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
            self.cons
                .event_recv::<C>(call.con_id(), call.call_id(), &mut cp, buf)
        };
        match cret {
            Ok(RecvStateInt::Response(r, ::ResponseBody::Sized(0))) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Response(r, ::ResponseBody::Sized(0));
            }
            Ok(RecvStateInt::Done) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Done;
            }
            Ok(RecvStateInt::DoneWithBody(body)) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::DoneWithBody(body);
            }
            Ok(RecvStateInt::Retry(err)) => {
                let mut b = self.call_close_int(Call(call.0));
                call.invalidate();
                b.reused = true;
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        call.0 = nc.0;
                        return RecvState::Sending;
                    }
                    Err(e) => {
                        return RecvState::Error(e);
                    }
                }
            }
            Ok(RecvStateInt::Redirect(r)) => {
                let mut b = self.call_close_int(Call(call.0));
                call.invalidate();
                if b.max_redirects > 0 {
                    b.max_redirects -= 1;
                }
                b.reused = true;
                if Self::fix_location(&r, &mut b) {
                    match self.call::<C>(b, poll) {
                        Ok(nc) => {
                            call.0 = nc.0;
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
                let mut b = self.call_close_int(Call(call.0));
                call.invalidate();
                if b.auth.hdr.len() > 0 {
                    // If an attempt was already made once, return response.
                    return RecvState::Response(r, ::ResponseBody::Sized(0));
                }
                b.auth(d);
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        call.0 = nc.0;
                        return RecvState::Sending;
                    }
                    Err(e) => {
                        return RecvState::Error(e);
                    }
                }
            }
            Ok(RecvStateInt::BasicAuth) => {
                let mut b = self.call_close_int(Call(call.0));
                call.invalidate();
                b.digest_auth(false);
                match self.call::<C>(b, poll) {
                    Ok(nc) => {
                        call.0 = nc.0;
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
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Error(e);
            }
        }
    }

    fn fix_location(r: &Response<Vec<u8>>, b: &mut CallBuilderImpl) -> bool {
        if let Some(ref clh) = r.headers().get(::http::header::LOCATION) {
            if let Ok(s) = clh.to_str() {
                if let Ok(nuri) = ::http::Uri::from_str(s) {
                    let mut s128 = [0u8; 128];
                    let mut svec = Vec::new();
                    let uri_len = if nuri.scheme_part().is_some() {
                        *b.req.uri_mut() = nuri;
                        return true;
                    } else {
                        let old_uri = b.req.uri();
                        let scheme = old_uri.scheme_part().unwrap();
                        let auth = old_uri.authority_part().unwrap();
                        let path = nuri.path();
                        let (quer, quer_len) = if let Some(q) = old_uri.query() {
                            (q, q.len() + 1)
                        } else {
                            ("", 0)
                        };
                        let uri_len = scheme.as_str().len() + "://".len() + auth.as_str().len()
                            + path.len() + quer_len;
                        if uri_len <= 128 {
                            let mut pos = 0;
                            s128[pos..pos + scheme.as_str().len()]
                                .copy_from_slice(scheme.as_str().as_bytes());
                            pos += scheme.as_str().len();
                            s128[pos..pos + 3].copy_from_slice(b"://");
                            pos += 3;
                            s128[pos..pos + auth.as_str().len()]
                                .copy_from_slice(auth.as_str().as_bytes());
                            pos += auth.as_str().len();
                            s128[pos..pos + path.len()].copy_from_slice(&path.as_bytes());
                            pos += path.len();
                            if quer_len > 0 {
                                s128[pos..pos + 1].copy_from_slice(b"?");
                                pos += 1;
                                s128[pos..pos + quer_len].copy_from_slice(&quer.as_bytes());
                            }
                        } else {
                            svec.extend(scheme.as_str().as_bytes());
                            svec.extend(b"://");
                            svec.extend(auth.as_str().as_bytes());
                            svec.extend(path.as_bytes());
                            if quer_len > 0 {
                                svec.extend(b"?");
                                svec.extend(quer.as_bytes());
                            }
                        }
                        uri_len
                    };
                    let slice: &[u8] = if uri_len <= 128 {
                        &s128[..uri_len]
                    } else {
                        &svec
                    };
                    if let Ok(s) = ::std::str::from_utf8(slice) {
                        if let Ok(nuri) = ::http::Uri::from_str(s) {
                            *b.req.uri_mut() = nuri;
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}
