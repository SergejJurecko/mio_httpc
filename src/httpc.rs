use mio::{Token,Poll,Event};
use dns_cache::DnsCache;
use con::Con;
use ::Result;
use tls_api::{TlsConnector};
use std::collections::VecDeque;
use call::{Call,PrivCallBuilder};
use fnv::FnvHashMap as HashMap;
use con_table::ConTable;
use ::{SendState,RecvState,CallId};

pub struct PrivHttpc {
    cache: DnsCache,
    calls: HashMap<::CallId,Call>,
    con_offset: usize,
    free_bufs: VecDeque<Vec<u8>>,
    cons: ConTable,
}

const BUF_SZ:usize = 4096*2;

impl PrivHttpc {
    pub fn new(con_offset: usize) -> PrivHttpc {
        PrivHttpc {
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

    pub fn call<C:TlsConnector>(&mut self, b: PrivCallBuilder, poll: &Poll) -> Result<::CallId> {
        // cons.push_con will set actual mio token
        let con = Con::new::<C,Vec<u8>>(Token::from(self.con_offset), &b.req, &mut self.cache, poll)?;
        let call = Call::new(b, self.get_buf());
        if let Some(con_id) = self.cons.push_con(con) {
            let id = CallId::new(con_id, 0);
            self.calls.insert(id, call);
            Ok(id)
        } else {
            Err(::Error::NoSpace)
        }
    }

    pub fn call_close(&mut self, id: ::CallId) {
        if let Some(call) = self.calls.remove(&id) {
            let buf = call.stop();
            if buf.capacity() > 0 {
                self.reuse(buf);
            }
        }
        self.cons.close_con(id.con_id());
    }

    fn get_buf(&mut self) -> Vec<u8> {
        if let Some(buf)  = self.free_bufs.pop_front() {
            buf
        } else {
            let b = Vec::with_capacity(BUF_SZ);
            b
        }
    }
    pub fn event<C:TlsConnector>(&mut self, ev: &Event) -> Option<::CallId> {
        let mut id = ev.token().0;
        if id >= self.con_offset && id <= (u16::max_value() as usize) {
            id -= self.con_offset;
            if self.cons.get_con(id).is_some() {
                return Some(::CallId::new(id as u16, 0));
            }
        }
        None
    }

    pub fn call_send<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&[u8]>) -> SendState {
        let cret = if let Some(c) = self.calls.get_mut(&id) {
            let con = if let Some(con) = self.cons.get_con(id.con_id() as usize) {
                con
            } else {
                return SendState::Error(::Error::InvalidToken);
            };
            let mut cp = ::call::CallParam {
                poll,
                dns: &mut self.cache,
                ev,
            };
            c.event_send::<C>(con, &mut cp, buf)
        } else {
            return SendState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(SendState::Done) => {
                self.call_close(id);
                return SendState::Done;
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_close(id);
                return SendState::Error(e); 
            }
        }
    }

    pub fn call_recv<C:TlsConnector>(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&mut Vec<u8>>) -> RecvState {
        let cret = if let Some(c) = self.calls.get_mut(&id) {
            let con = if let Some(con) = self.cons.get_con(id.con_id() as usize) {
                con
            } else {
                return RecvState::Error(::Error::InvalidToken);
            };
            let mut cp = ::call::CallParam {
                poll,
                ev,
                dns: &mut self.cache,
            };
            c.event_recv::<C>(con, &mut cp, buf)
        } else {
            return RecvState::Error(::Error::InvalidToken);
        };
        match cret {
            Ok(RecvState::Response(r,0)) => {
                self.call_close(id);
                return RecvState::Response(r,0);
            }
            Ok(RecvState::Done) => {
                self.call_close(id);
                return RecvState::Done;
            }
            Ok(RecvState::DoneWithBody(body)) => {
                self.call_close(id);
                return RecvState::DoneWithBody(body);
            }
            Ok(er) => {
                return er;
            }
            Err(e) => {
                self.call_close(id);
                return RecvState::Error(e); 
            }
        }
    }
}

