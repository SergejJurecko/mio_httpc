use mio::{Token,Poll,Event};
use dns_cache::DnsCache;
use con::{Con,ConTable};
use ::Result;
use tls_api::{TlsConnector};
use std::collections::VecDeque;
use call::{CallImpl};
use types::*;
use fnv::FnvHashMap as HashMap;
use ::{SendState,RecvState,CallRef,Call};
use std::time::{Instant};

pub struct HttpcImpl {
    cache: DnsCache,
    calls: HashMap<CallRef,CallImpl>,
    timed_out_calls: HashMap<CallRef,CallImpl>,
    con_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    cons: ConTable,
    last_timeout: Instant,
}

const BUF_SZ:usize = 4096*2;

impl HttpcImpl {
    pub fn new(con_offset: usize) -> HttpcImpl {
        HttpcImpl {
            timed_out_calls: HashMap::default(),
            last_timeout: Instant::now(),
            cache: DnsCache::new(),
            calls: HashMap::default(),
            con_offset,
            free_bufs: VecDeque::new(),
            cons: ConTable::new(),
        }
    }

    pub fn reuse(&mut self, mut buf: Vec<u8>) {
        let cap = buf.capacity();
        if cap > BUF_SZ {
            unsafe {
                buf.set_len(BUF_SZ);
            }
            buf.shrink_to_fit();
        } else if cap < BUF_SZ {
            buf.reserve_exact(BUF_SZ-cap);
        }
        buf.truncate(0);
        self.free_bufs.push_front(buf);
    }

    pub fn call<C:TlsConnector>(&mut self, mut b: CallBuilderImpl, poll: &Poll) -> Result<Call> {
        // cons.push_con will set actual mio token
        let root_ca = ::std::mem::replace(&mut b.root_ca, Vec::new());
        let con = Con::new::<C,Vec<u8>>(Token::from(self.con_offset), 
            &b.req, 
            &mut self.cache, 
            poll, 
            root_ca,
            b.dns_timeout)?;
        let call = CallImpl::new(b, self.get_buf());
        if let Some(con_id) = self.cons.push_con(con) {
            let id = Call::new(con_id, 0);
            self.calls.insert(id.get_ref(), call);
            Ok(id)
        } else {
            Err(::Error::NoSpace)
        }
    }

    pub fn call_close(&mut self, id: Call) {
        if let Some(call) = self.calls.remove(&id.get_ref()) {
            self.call_close_detached(id, call);
        }
    }

    fn call_close_detached(&mut self, id: Call, call: CallImpl) {
        let buf = call.stop();
        if buf.capacity() > 0 {
            self.reuse(buf);
        }
        self.cons.close_con(id.get_ref().con_id());
    }

    pub fn get_buf(&mut self) -> Vec<u8> {
        if let Some(buf)  = self.free_bufs.pop_front() {
            buf
        } else {
            let b = Vec::with_capacity(BUF_SZ);
            b
        }
    }

    pub fn timeout<C:TlsConnector>(&mut self) -> Vec<CallRef> {
        let mut out = Vec::new();
        self.timeout_extend::<C>(&mut out);
        out
    }

    pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<CallRef>) {
        let now = Instant::now();
        if now.duration_since(self.last_timeout).subsec_nanos() < 50_000_000 {
            return;
        }
        self.last_timeout = now;
        for (k,v) in self.calls.iter() {
            if v.is_done() {
                continue;
            }
            if now - v.start_time() >= v.settings().dur {
                out.push(CallRef(k.0));
            } else {
                if let Some(con) = self.cons.get_con(k.con_id() as usize) {
                    if let Some(host) = v.settings().req.uri().host() {
                        con.timeout(host);
                    }
                }
            }
        }
        // let calls = ::std::mem::replace(&mut self.calls, HashMap::default());
        // let (keepers,gonners) = 
        //     calls.into_iter().partition(|&(ref k, ref v)| {
        //         now - v.start_time() >= v.settings().dur
        //     } );
        // self.calls = keepers;
        // if gonners.len() > 0 {
        //     for (k,v) in gonners.into_iter() {
        //         out.push(k);
        //         self.call_close_detached(k,v);
        //     }
        // }
    }

    pub fn event<C:TlsConnector>(&mut self, ev: &Event) -> Option<CallRef> {
        let mut id = ev.token().0;
        if id >= self.con_offset && id <= (u16::max_value() as usize) {
            id -= self.con_offset;
            if let Some(con) = self.cons.get_con(id) {
                con.unreg_for(ev.readiness());
                return Some(CallRef::new(id as u16, 0));
            }
        }
        None
    }

    pub fn peek_body(&mut self, call: &Call, off: &mut usize) -> &[u8] {
        if call.is_empty() {
            return &[];
        }
        if let Some(c) = self.calls.get_mut(&call.get_ref()) {
            return c.peek_body(off);
        }
        &[]
    }
    pub fn try_truncate(&mut self, call: &::Call, off: &mut usize) {
        if call.is_empty() {
            return;
        }
        if let Some(c) = self.calls.get_mut(&call.get_ref()) {
            return c.try_truncate(off);
        }
    }

    pub fn call_send<C:TlsConnector>(&mut self, poll: &Poll, call: &mut Call, buf: Option<&[u8]>) -> SendState {
        if call.is_empty() {
            return SendState::Done;
        }
        let cret = if let Some(c) = self.calls.get_mut(&call.get_ref()) {
            let con = if let Some(con) = self.cons.get_con(call.get_ref().con_id() as usize) {
                con
            } else {
                return SendState::Error(::Error::InvalidToken);
            };
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
                // ev,
            };
            c.event_send::<C>(con, &mut cp, buf)
        } else {
            return SendState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(SendState::Done) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return SendState::Done;
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return SendState::Error(e); 
            }
        }
    }

    pub fn call_recv<C:TlsConnector>(&mut self, poll: &Poll, call: &mut Call, buf: Option<&mut Vec<u8>>) -> RecvState {
        if call.is_empty() {
            return RecvState::Done;
        }
        let cret = if let Some(c) = self.calls.get_mut(&call.get_ref()) {
            let con = if let Some(con) = self.cons.get_con(call.get_ref().con_id() as usize) {
                con
            } else {
                return RecvState::Error(::Error::InvalidToken);
            };
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
            };
            c.event_recv::<C>(con, &mut cp, buf)
        } else {
            return RecvState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(RecvState::Response(r,::ResponseBody::Sized(0))) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Response(r,::ResponseBody::Sized(0));
            }
            Ok(RecvState::Done) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Done;
            }
            Ok(RecvState::DoneWithBody(body)) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::DoneWithBody(body);
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_close(Call(call.0));
                call.invalidate();
                return RecvState::Error(e); 
            }
        }
    }
}

