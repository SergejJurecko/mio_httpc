extern crate tls_api_rustls;
use http::{Request};
use ::types::PrivCallBuilder;
use mio::{Poll,Event};
use tls_api::{TlsConnector};
use ::Result;

pub struct CallBuilder {
    cb: PrivCallBuilder,
}

impl CallBuilder {
    pub fn new(req: Request<Vec<u8>>) -> CallBuilder {
        CallBuilder {
            cb: PrivCallBuilder::new(req),
        }
    }
    pub fn call(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<::CallId> {
        httpc.call::<tls_api_rustls::TlsConnector>(self.cb, poll)
    }
    pub fn websocket(mut self, httpc: &mut Httpc, poll: &Poll) -> ::Result<::WebSocket> {
        self.cb.websocket();
        let cid = self.call(httpc, poll)?;
        Ok(::WebSocket::new(cid))
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
    h: ::httpc::PrivHttpc,
}

impl Httpc {
    pub fn new(con_offset: usize) -> Httpc {
        Httpc {
            h: ::httpc::PrivHttpc::new(con_offset),
        }
    }
    pub(crate) fn call<C:TlsConnector>(&mut self, b: PrivCallBuilder, poll: &Poll) -> Result<::CallId> {
        self.h.call::<C>(b, poll)
    }
    pub fn reuse(&mut self, buf: Vec<u8>) {
        self.h.reuse(buf);
    }
    pub fn call_close(&mut self, id: ::CallId) {
        self.h.call_close(id);
    }
    pub fn timeout(&mut self) -> Vec<::CallId> {
        self.h.timeout::<tls_api_rustls::TlsConnector>()
    }
    pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<::CallId>) {
        self.h.timeout_extend::<tls_api_rustls::TlsConnector>(out)
    }
    pub fn event(&mut self, ev: &Event) -> Option<::CallId> {
        self.h.event::<tls_api_rustls::TlsConnector>(ev)
    }
    pub fn call_send(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&[u8]>) -> ::SendState {
        self.h.call_send::<tls_api_rustls::TlsConnector>(poll, ev, id, buf)
    }
    pub fn call_recv(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&mut Vec<u8>>) -> ::RecvState {
        self.h.call_recv::<tls_api_rustls::TlsConnector>(poll, ev, id, buf)
    }
}
