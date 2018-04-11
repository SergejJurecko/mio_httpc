use tls_api;
use http::{Method, Request, Uri};
use http::header::{HeaderName, HeaderValue};
use types::CallBuilderImpl;
use mio::{Event, Poll};
use tls_api::TlsConnector;
use {Call, CallRef, Result};
use http::request::Builder;
use http::HttpTryFrom;
use SimpleCall;

#[derive(Debug, Default)]
pub struct CallBuilder {
    cb: Option<CallBuilderImpl>,
    builder: Builder,
    body: Vec<u8>,
}

#[cfg(feature = "rustls")]
type CONNECTOR = tls_api::rustls::TlsConnector;
#[cfg(feature = "native")]
type CONNECTOR = tls_api::native::TlsConnector;
#[cfg(feature = "openssl")]
type CONNECTOR = tls_api::openssl::TlsConnector;

impl CallBuilder {
    pub fn new() -> CallBuilder {
        CallBuilder {
            builder: Builder::new(),
            cb: Some(CallBuilderImpl::new(Request::new(Vec::new()))),
            body: Vec::new(),
        }
    }

    pub fn get<T>(uri: T) -> CallBuilder
    where
        Uri: HttpTryFrom<T>,
    {
        let mut b = CallBuilder::new();
        b.method(Method::GET).uri(uri);
        b
    }

    pub fn post<T>(uri: T, body: Vec<u8>) -> CallBuilder
    where
        Uri: HttpTryFrom<T>,
    {
        let mut b = CallBuilder::new();
        b.body = body;
        b.method(Method::POST).uri(uri);
        b
    }

    pub fn put<T>(uri: T, body: Vec<u8>) -> CallBuilder
    where
        Uri: HttpTryFrom<T>,
    {
        let mut b = CallBuilder::new();
        b.body = body;
        b.method(Method::PUT).uri(uri);
        b
    }

    pub fn delete<T>(uri: T) -> CallBuilder
    where
        Uri: HttpTryFrom<T>,
    {
        let mut b = CallBuilder::new();
        b.method(Method::DELETE).uri(uri);
        b
    }

    pub fn method<T>(&mut self, method: T) -> &mut Self
    where
        Method: HttpTryFrom<T>,
    {
        self.builder.method(method);
        self
    }

    pub fn body(&mut self, body: Vec<u8>) -> &mut Self {
        self.body = body;
        self
    }

    pub fn uri<T>(&mut self, uri: T) -> &mut Self
    where
        Uri: HttpTryFrom<T>,
    {
        self.builder.uri(uri);
        self
    }

    pub fn header<K, V>(&mut self, key: K, value: V) -> &mut CallBuilder
    where
        HeaderName: HttpTryFrom<K>,
        HeaderValue: HttpTryFrom<V>,
    {
        self.builder.header(key, value);
        self
    }

    fn finish(&mut self) -> ::Result<()> {
        let mut body = Vec::new();
        ::std::mem::swap(&mut self.body, &mut body);
        let mut builder = Builder::new();
        ::std::mem::swap(&mut self.builder, &mut builder);
        self.cb.as_mut().unwrap().req = builder.body(body)?;
        Ok(())
    }

    pub fn simple_call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<SimpleCall> {
        self.finish()?;
        let cb = self.cb.take().unwrap();
        Ok(httpc.call::<CONNECTOR>(cb, poll)?.simple())
    }
    pub fn call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<Call> {
        self.finish()?;
        let cb = self.cb.take().unwrap();
        httpc.call::<CONNECTOR>(cb, poll)
    }
    pub fn websocket(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<::WebSocket> {
        self.finish()?;
        let mut cb = self.cb.take().unwrap();
        cb.websocket();
        let cid = httpc.call::<CONNECTOR>(cb, poll)?;
        Ok(::WebSocket::new(cid, httpc.h.get_buf()))
    }
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.cb.as_mut().unwrap().max_response(m);
        self
    }
    pub fn dns_retry_ms(&mut self, n: u64) -> &mut Self {
        self.cb.as_mut().unwrap().dns_retry_ms(n);
        self
    }
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.cb.as_mut().unwrap().chunked_parse(b);
        self
    }
    pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
        self.cb.as_mut().unwrap().chunked_max_chunk(v);
        self
    }
    pub fn timeout_ms(&mut self, d: u64) -> &mut Self {
        self.cb.as_mut().unwrap().timeout_ms(d);
        self
    }
    pub fn max_redirects(&mut self, v: u8) -> &mut Self {
        self.cb.as_mut().unwrap().max_redirects(v);
        self
    }
    pub fn gzip(&mut self, b: bool) -> &mut Self {
        self.cb.as_mut().unwrap().gzip(b);
        self
    }
    pub fn insecure_do_not_verify_domain(&mut self) -> &mut Self {
        self.cb.as_mut().unwrap().insecure();
        self
    }
    // pub fn auth(&mut self, v: ::AuthenticateInfo) -> &mut Self {
    //     self.cb.auth(v);
    //     self
    // }
    pub fn digest_auth(&mut self, v: bool) -> &mut Self {
        self.cb.as_mut().unwrap().digest_auth(v);
        self
    }
}

pub struct Httpc {
    h: ::httpc::HttpcImpl,
}

impl Httpc {
    pub fn new(con_offset: usize, cfg: Option<::HttpcCfg>) -> Httpc {
        Httpc {
            h: ::httpc::HttpcImpl::new(con_offset, cfg),
        }
    }
    pub(crate) fn call<C: TlsConnector>(
        &mut self,
        b: CallBuilderImpl,
        poll: &Poll,
    ) -> Result<Call> {
        self.h.call::<C>(b, poll)
    }
    pub(crate) fn peek_body(&mut self, id: &::Call, off: &mut usize) -> &[u8] {
        self.h.peek_body(id, off)
    }
    pub(crate) fn try_truncate(&mut self, id: &::Call, off: &mut usize) {
        self.h.try_truncate(id, off);
    }
    pub fn recfg(&mut self, cfg: ::HttpcCfg) {
        self.h.recfg(cfg);
    }
    pub fn open_connections(&self) -> usize {
        self.h.open_connections()
    }
    pub fn reuse(&mut self, buf: Vec<u8>) {
        self.h.reuse(buf);
    }
    pub fn call_close(&mut self, id: Call) {
        self.h.call_close(id);
    }
    pub fn timeout(&mut self) -> Vec<CallRef> {
        self.h.timeout()
    }
    pub fn timeout_extend<C: TlsConnector>(&mut self, out: &mut Vec<CallRef>) {
        self.h.timeout_extend(out)
    }
    pub fn event(&mut self, ev: &Event) -> Option<CallRef> {
        self.h.event::<CONNECTOR>(ev)
    }
    pub fn call_send(&mut self, poll: &Poll, id: &mut Call, buf: Option<&[u8]>) -> ::SendState {
        self.h.call_send::<CONNECTOR>(poll, id, buf)
    }
    pub fn call_recv(
        &mut self,
        poll: &Poll,
        id: &mut Call,
        buf: Option<&mut Vec<u8>>,
    ) -> ::RecvState {
        self.h.call_recv::<CONNECTOR>(poll, id, buf)
    }
}
