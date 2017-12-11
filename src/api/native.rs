extern crate tls_api_native_tls;
use http::{Request};
use ::types::CallBuilderImpl;
use mio::{Poll,Event};
use tls_api::{TlsConnector};
use ::Result;

pub struct CallBuilder {
    cb: CallBuilderImpl,
}

impl CallBuilder {
    pub fn new(req: Request<Vec<u8>>) -> CallBuilder {
        CallBuilder {
            cb: CallBuilderImpl::new(req),
        }
    }
    pub fn call(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<::Call> {
        httpc.call::<tls_api_native_tls::TlsConnector>(self.cb, poll)
    }
    pub fn websocket(mut self, httpc: &mut Httpc, poll: &Poll) -> ::Result<::WebSocket> {
        self.cb.websocket();
        let cid = self.call(httpc, poll)?;
        Ok(::WebSocket::new(cid, httpc.h.get_buf()))
    }
    pub fn add_root_ca_der(mut self, v: Vec<u8>) -> Self {
        self.cb.add_root_ca(v);
        self
    }
    pub fn max_response(mut self, m: usize) -> Self {
        self.cb.max_response(m);
        self
    }
    pub fn dns_retry_ms(mut self, n: u64) -> Self {
        self.cb.dns_retry_ms(n);
        self
    }
    pub fn chunked_parse(mut self, b: bool) -> Self {
        self.cb.chunked_parse(b);
        self
    }
    pub fn chunked_max_chunk(mut self, v: usize) -> Self {
        self.cb.chunked_max_chunk(v);
        self
    }
    pub fn timeout_ms(mut self, d: u64) -> Self {
        self.cb.timeout_ms(d);
        self
    }
}

pub struct Httpc {
    h: ::httpc::HttpcImpl,
}

impl Httpc {
    pub fn new(con_offset: usize) -> Httpc {
        Httpc {
            h: ::httpc::HttpcImpl::new(con_offset),
        }
    }
    pub(crate) fn call<C:TlsConnector>(&mut self, b: CallBuilderImpl, poll: &Poll) -> Result<::Call> {
        self.h.call::<C>(b, poll)
    }
    pub(crate) fn peek_body(&mut self, id: &::Call, off: &mut usize) -> &[u8] {
        self.h.peek_body(id, off)
    }
    pub(crate) fn try_truncate(&mut self, id: &::Call, off: &mut usize) {
        self.h.try_truncate(id, off);
    }
    pub fn open_connections(&self) -> usize {
        self.h.open_connections()
    }
    pub fn reuse(&mut self, buf: Vec<u8>) {
        self.h.reuse(buf);
    }
    pub fn call_close(&mut self, id: ::Call) {
        self.h.call_close(id);
    }
    pub fn timeout(&mut self) -> Vec<::CallRef> {
        self.h.timeout()
    }
    pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<::CallRef>) {
        self.h.timeout_extend(out)
    }
    pub fn event(&mut self, ev: &Event) -> Option<::CallRef> {
        self.h.event::<tls_api_native_tls::TlsConnector>(ev)
    }
    pub fn call_send(&mut self, poll: &Poll, id: &mut ::Call, buf: Option<&[u8]>) -> ::SendState {
        self.h.call_send::<tls_api_native_tls::TlsConnector>(poll, id, buf)
    }
    pub fn call_recv(&mut self, poll: &Poll, id: &mut ::Call, buf: Option<&mut Vec<u8>>) -> ::RecvState {
        self.h.call_recv::<tls_api_native_tls::TlsConnector>(poll, id, buf)
    }
}