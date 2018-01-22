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
    timed_out_calls: HashMap<CallRef,CallImpl>,
    con_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    cons: ConTable,
    last_timeout: Instant,
}

const BUF_SZ:usize = 4096*2;

impl HttpcImpl {
    pub fn new(con_offset: usize) -> HttpcImpl {
        ::types::tp();
        panic!("ok");
        HttpcImpl {
            timed_out_calls: HashMap::default(),
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
        let con_id = if let Some(host) = b.req.uri().host() {
            if let Some(con_id) = self.cons.try_keepalive(host, poll) {
                Some(con_id)
            } else {
                None
            }
        } else { None };
        if let Some(con_id) = con_id {
            let call = CallImpl::new(b, self.get_buf());
            let id = Call::new(con_id, 0);
            return Ok(id);
        }
        // cons.push_con will set actual mio token
        let root_ca = ::std::mem::replace(&mut b.root_ca, Vec::new());
        let con = Con::new::<C,Vec<u8>>(Token::from(self.con_offset), 
            &b.req, 
            &mut self.cache, 
            poll, 
            root_ca,
            b.dns_timeout)?;
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
        let (b1, b2) = self.cons.close_call(id.con_id(), id.call_id());
        if b1.capacity() > 0 || b1.len() > 0 {
            self.reuse(b1);
        }
        if b2.capacity() > 0 || b2.len() > 0 {
            self.reuse(b2);
        }
    }

    pub fn get_buf(&mut self) -> Vec<u8> {
        if let Some(buf)  = self.free_bufs.pop_front() {
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

    pub fn event<C:TlsConnector>(&mut self, ev: &Event) -> Option<CallRef> {
        let mut id = ev.token().0;
        if id >= self.con_offset && id <= (u16::max_value() as usize) {
            id -= self.con_offset;
            if let Some(con) = self.cons.get_signalled_con(id) {
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

    pub fn call_send<C:TlsConnector>(&mut self, poll: &Poll, call: &mut Call, buf: Option<&[u8]>) -> SendState {
        if call.is_empty() {
            return SendState::Done;
        }
        let cret = {
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
            };
            self.cons.event_send::<C>(call.con_id(), call.call_id(), &mut cp, buf)
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
        let cret = {
            let mut cp = ::types::CallParam {
                poll,
                dns: &mut self.cache,
            };
            self.cons.event_recv::<C>(call.con_id(), call.call_id(), &mut cp, buf)
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

