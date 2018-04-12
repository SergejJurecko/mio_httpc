use tls_api;
use http::{Method, Request};
use http::header::{HeaderName, HeaderValue};
use types::CallBuilderImpl;
use mio::{Event, Poll};
use tls_api::TlsConnector;
use {Call, CallRef, Result};
use http::request::Builder;
use percent_encoding::{utf8_percent_encode, DEFAULT_ENCODE_SET};
use http::HttpTryFrom;
use SimpleCall;
use smallvec::SmallVec;

// type UriBuf = SmallVec<[u8; 1024]>;
type AuthBuf = SmallVec<[u8; 64]>;
type HostBuf = SmallVec<[u8; 64]>;
type PathBuf = SmallVec<[u8; 256]>;
type QueryBuf = SmallVec<[u8; 256]>;

/// Used to start a call and get a Call for it.
#[derive(Debug, Default)]
pub struct CallBuilder {
    cb: Option<CallBuilderImpl>,
    builder: Builder,
    body: Vec<u8>,
    tls: bool,
    auth: AuthBuf,
    host: HostBuf,
    path: PathBuf,
    query: QueryBuf,
}

#[cfg(feature = "rustls")]
type CONNECTOR = tls_api::rustls::TlsConnector;
#[cfg(feature = "native")]
type CONNECTOR = tls_api::native::TlsConnector;
#[cfg(feature = "openssl")]
type CONNECTOR = tls_api::openssl::TlsConnector;
#[cfg(not(any(feature = "rustls", feature = "native", feature = "openssl")))]
type CONNECTOR = tls_api::dummy::TlsConnector;

/// If you're only executing a one-off call you should set connection: close as default
/// is keep-alive.
///
/// If you do not set body, but do set content-length,
/// it will wait for send body to be provided through Httpc::call_send.
/// You must use a streaming interface in this case and can not use SimpleCall.
///
/// mio_httpc will set headers (if they are not already):
/// user-agent, connection, host, auth, content-length
impl CallBuilder {
    /// Start an empty CallBuilder
    pub fn new() -> CallBuilder {
        CallBuilder {
            builder: Builder::new(),
            tls: false,
            cb: Some(CallBuilderImpl::new(Request::new(Vec::new()))),
            body: Vec::new(),
            auth: SmallVec::new(),
            host: SmallVec::new(),
            path: SmallVec::new(),
            query: SmallVec::new(),
        }
    }

    // fn uri_encoded(orig: &str, uri_buf: &mut UriBuffer) -> bool {
    //     let mut must_encode = false;
    //     for c in orig.as_bytes() {
    //         if ::types::URI_CHARS[(*c) as usize] == 0 {
    //             must_encode = true;
    //             break;
    //         }
    //     }
    //     if !must_encode {
    //         return false;
    //     }
    //     let enc = utf8_percent_encode(orig, DEFAULT_ENCODE_SET);
    //     for v in enc {
    //         uri_buf.extend_from_slice(v.as_bytes());
    //     }
    //     true
    // }

    /// Start a GET request.
    pub fn get() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.method(Method::GET);
        b
    }

    /// Start a POST request.
    pub fn post(body: Vec<u8>) -> CallBuilder {
        let mut b = CallBuilder::new();
        b.body = body;
        b.method(Method::POST);
        b
    }

    /// Start a PUT request.
    pub fn put(body: Vec<u8>) -> CallBuilder {
        let mut b = CallBuilder::new();
        b.body = body;
        b.method(Method::PUT);
        b
    }

    /// Start a DELETE request.
    pub fn delete() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.method(Method::DELETE);
        b
    }

    /// Default: http
    /// Use https for call.
    pub fn https(&mut self) -> &mut Self {
        self.tls = true;
        self
    }

    /// Set host where to connect to. It can be a domain or IP address.
    pub fn host(&mut self, s: &str) -> &mut Self {
        self.host.extend_from_slice(s.as_bytes());
        self
    }

    /// Use http authentication with username and password.
    pub fn auth(&mut self, us: &str, pw: &str) -> &mut Self {
        // self.auth
        self
    }

    /// Set full path. No procent encoding is done. Will fail later if it contains invalid characters.
    pub fn path(&mut self, path: &str) -> &mut Self {
        // self.auth
        self
    }

    /// Add a single part of path. Parts are delimited by / which are added automatically.
    /// Procent encoding will be done on any uri invalid characters.
    /// If part contains /, it will be procent encoded!
    pub fn path_part(&mut self, part: &str) -> &mut Self {
        self
    }

    /// Add multiple parts in one go.
    pub fn path_parts(&mut self, parts: &[&str]) -> &mut Self {
        self
    }

    /// Add a key-value pair to query.
    pub fn query(&mut self, k: &str, v: &str) -> &mut Self {
        self
    }

    /// Set method for call. Like: Method::GET or "GET"
    pub fn method<T>(&mut self, method: T) -> &mut Self
    where
        Method: HttpTryFrom<T>,
    {
        self.builder.method(method);
        self
    }

    /// Set body.
    pub fn body(&mut self, body: Vec<u8>) -> &mut Self {
        self.body = body;
        self
    }

    /// Set full URI for call. It must be properly procent encoded for any non-uri characters.
    /// It is safer to construct uri using: https/host/auth/path_part/query
    /// and not use this.
    pub fn uri(&mut self, uri: &str) -> &mut Self {
        // let mut uri_buf: UriBuffer = SmallVec::new();
        // if Self::uri_encoded(uri, &mut uri_buf) {
        //     let enc = unsafe { ::std::str::from_utf8_unchecked(&uri_buf) };
        //     println!("Encoded: {}", enc);
        //     self.builder.uri(enc);
        // } else {
        self.builder.uri(uri);
        // }
        self
    }

    /// Set HTTP header.
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

    /// Consume and execute HTTP call. Returns SimpleCall interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn simple_call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<SimpleCall> {
        self.finish()?;
        let cb = self.cb.take().unwrap();
        Ok(httpc.call::<CONNECTOR>(cb, poll)?.simple())
    }

    /// Consume and execute HTTP call. Return low level streaming call interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<Call> {
        self.finish()?;
        let cb = self.cb.take().unwrap();
        httpc.call::<CONNECTOR>(cb, poll)
    }

    /// Consume and start a WebSocket
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn websocket(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<::WebSocket> {
        self.finish()?;
        let mut cb = self.cb.take().unwrap();
        cb.websocket();
        let cid = httpc.call::<CONNECTOR>(cb, poll)?;
        Ok(::WebSocket::new(cid, httpc.h.get_buf()))
    }

    /// Default 10MB.
    ///
    /// This will limit how big the internal Vec<u8> can grow.
    /// HTTP response headers are always stored in internal buffer.
    /// HTTP response body is stored in internal buffer if no external
    /// buffer is provided.
    ///
    /// For WebSockets this will also be a received fragment size limit!
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.cb.as_mut().unwrap().max_response(m);
        self
    }

    /// Default: 100ms
    ///
    /// Starting point of dns packet resends if nothing received.
    /// Every next resend timeout is 2x the previous one but stops at 1s.
    /// Make sure to call Httpc::timeout!
    /// So for 100ms: 100ms, 200ms, 400ms, 800ms, 1000ms, 1000ms...
    pub fn dns_retry_ms(&mut self, n: u64) -> &mut Self {
        self.cb.as_mut().unwrap().dns_retry_ms(n);
        self
    }

    /// Default true.
    ///
    /// Configurable because it entails copying the data stream.
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.cb.as_mut().unwrap().chunked_parse(b);
        self
    }

    /// Default 32K
    ///
    /// Max size of chunk in a chunked transfer.
    pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
        self.cb.as_mut().unwrap().chunked_max_chunk(v);
        self
    }

    /// Default 60s
    ///
    /// Maximum amount of time a call should last.
    /// Make sure to call Httpc::timeout!
    pub fn timeout_ms(&mut self, d: u64) -> &mut Self {
        self.cb.as_mut().unwrap().timeout_ms(d);
        self
    }

    /// Default 4.
    ///
    /// How many redirects to follow. 0 to disable following redirects.
    pub fn max_redirects(&mut self, v: u8) -> &mut Self {
        self.cb.as_mut().unwrap().max_redirects(v);
        self
    }

    /// Tell server to gzip response and unzip transparently before returning body to client.
    /// Default is true.
    pub fn gzip(&mut self, b: bool) -> &mut Self {
        self.cb.as_mut().unwrap().gzip(b);
        self
    }

    /// Default secure.
    ///
    /// Turn off domain verification over ssl. This should only be used when testing as you are throwing away
    /// a big part of ssl security.
    pub fn insecure_do_not_verify_domain(&mut self) -> &mut Self {
        self.cb.as_mut().unwrap().insecure();
        self
    }

    /// Use digest authentication. If you know server is using digest auth you REALLY should set it to true.
    /// If server is using basic authentication and you set digest_auth to true, mio_httpc will retry with basic.
    /// If not set, basic auth is assumed which is very insecure.
    pub fn digest_auth(&mut self, v: bool) -> &mut Self {
        self.cb.as_mut().unwrap().digest_auth(v);
        self
    }
}

pub struct Httpc {
    h: ::httpc::HttpcImpl,
}

impl Httpc {
    /// Httpc will create connections with mio token in range [con_offset..con_offset+0xFFFF]
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
    /// Reconfigure httpc.
    pub fn recfg(&mut self, cfg: ::HttpcCfg) {
        self.h.recfg(cfg);
    }
    /// Number of currently open connections (in active and idle keep-alive state)
    pub fn open_connections(&self) -> usize {
        self.h.open_connections()
    }
    /// Reuse a response buffer for subsequent calls.
    pub fn reuse(&mut self, buf: Vec<u8>) {
        self.h.reuse(buf);
    }
    /// Prematurely finish call.
    pub fn call_close(&mut self, id: Call) {
        self.h.call_close(id);
    }
    /// Call periodically to check for call timeouts and DNS retries.
    /// Returns list of calls that have timed out.
    /// You must execute call_close yourself (or SimpleCall::abort) and timeout will return them
    /// every time until you do.
    /// (every 100ms for example)
    pub fn timeout(&mut self) -> Vec<CallRef> {
        self.h.timeout()
    }
    /// Same as timeout except that timed out calls get appended.
    /// This way you can reuse old allocations (if you truncated to 0).
    pub fn timeout_extend<C: TlsConnector>(&mut self, out: &mut Vec<CallRef>) {
        self.h.timeout_extend(out)
    }
    /// Get CallRef for ev if token in configured range for Httpc.
    /// Compare CallRef external call.
    ///
    /// First you must call call_send until you get a SendState::Receiving
    /// after that call is in receive state and you must call call_recv.
    pub fn event(&mut self, ev: &Event) -> Option<CallRef> {
        self.h.event::<CONNECTOR>(ev)
    }
    /// If request has body it will be either taken from buf, from Request provided to CallBuilder
    /// or will return SendState::WaitReqBody.
    ///
    /// buf slice is assumed to have taken previous SendState::SentBody(usize) into account
    /// and starts from part of buffer that has not been sent yet.
    pub fn call_send(&mut self, poll: &Poll, id: &mut Call, buf: Option<&[u8]>) -> ::SendState {
        self.h.call_send::<CONNECTOR>(poll, id, buf)
    }

    /// If no buf provided, response body (if any) is stored in an internal buffer.
    /// If buf provided after some body has been received, it will be copied to it.
    ///
    /// Buf will be expanded if required. Bytes are always appended. If you want to receive
    /// response entirely in buf, you should reserve capacity for entire body before calling call_recv.
    ///
    /// If body is only stored in internal buffer it will be limited to CallBuilder::max_response.
    pub fn call_recv(
        &mut self,
        poll: &Poll,
        id: &mut Call,
        buf: Option<&mut Vec<u8>>,
    ) -> ::RecvState {
        self.h.call_recv::<CONNECTOR>(poll, id, buf)
    }
}
