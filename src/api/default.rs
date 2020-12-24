use http::header::{HeaderName, HeaderValue};
use http::HttpTryFrom;
use http::{Method, Uri};
use mio::{Event, Registry};
use tls_api::TlsConnector;
use types::CallBuilderImpl;
use SimpleCall;
use {Call, CallRef, RecvState, Result, SendState, WebSocket};

/// Used to start a call and get a Call for it.
#[derive(Debug, Default)]
pub struct CallBuilder {
    // pub(crate) builder: Builder,
}

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
        CallBuilder {}
    }

    /// Start a GET request.
    pub fn get(uri: &str) -> CallBuilder {
        CallBuilder::new()
    }

    /// Start a POST request.
    pub fn post(uri: &str, body: Vec<u8>) -> CallBuilder {
        CallBuilder::new()
    }

    /// Start a PUT request.
    pub fn put(uri: &str, body: Vec<u8>) -> CallBuilder {
        CallBuilder::new()
    }

    /// Start a DELETE request.
    pub fn delete(uri: &str) -> CallBuilder {
        CallBuilder::new()
    }

    /// Set method for call. Like: Method::GET.
    pub fn method<T>(&mut self, method: T) -> &mut Self
    where
        Method: HttpTryFrom<T>,
    {
        self
    }

    pub fn body(&mut self, body: Vec<u8>) -> &mut Self {
        self
    }

    /// Set URI for call.
    pub fn uri(&mut self, uri: &str) -> &mut Self {
        self
    }

    /// Set HTTP header.
    pub fn header<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        HeaderName: HttpTryFrom<K>,
        HeaderValue: HttpTryFrom<V>,
    {
        self
    }

    /// Consume and execute HTTP call. Returns SimpleCall interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn simple_call(&mut self, httpc: &mut Httpc, poll: &Registry) -> ::Result<SimpleCall> {
        Err(::Error::NoTls)
    }

    /// Consume and execute HTTP call. Return low level streaming call interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn call(&mut self, httpc: &mut Httpc, poll: &Registry) -> ::Result<Call> {
        Err(::Error::NoTls)
    }

    /// Consume and start a WebSocket
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn websocket(&mut self, httpc: &mut Httpc, poll: &Registry) -> ::Result<WebSocket> {
        Err(::Error::NoTls)
    }

    /// Default 10MB.
    ///
    /// This will limit how big the internal Vec<u8> can grow.
    /// HTTP response headers are always stored in internal buffer.
    /// HTTP response body is stored in internal buffer if no external
    /// buffer is provided.
    ///
    /// For WebSockets this will also be a received fragment size limit!
    pub fn max_response(&mut self, _m: usize) -> &mut Self {
        self
    }

    /// Default: 100ms
    ///
    /// Starting point of dns packet resends if nothing received.
    /// Every next resend timeout is 2x the previous one but stops at 1s.
    /// So for 100ms: 100ms, 200ms, 400ms, 800ms, 1000ms, 1000ms...
    pub fn dns_retry_ms(&mut self, _n: u64) -> &mut Self {
        self
    }

    /// Default true.
    ///
    /// Configurable because it entails copying the data stream.
    pub fn chunked_parse(&mut self, _b: bool) -> &mut Self {
        self
    }

    /// Default 32K
    ///
    /// Max size of chunk in a chunked transfer.
    pub fn chunked_max_chunk(&mut self, _v: usize) -> &mut Self {
        self
    }

    /// Default 60s
    ///
    /// Maximum amount of time a call should last.
    pub fn timeout_ms(&mut self, _d: u64) -> &mut Self {
        self
    }

    // /// If server using digest authentication, you will get AuthenticateInfo on first call.
    // /// You must supply it to second call.
    // pub fn auth(&mut self, _v: ::AuthenticateInfo) -> &mut Self {
    //     self
    // }

    /// Use digest authentication. If you know server is using digest auth you REALLY should set it to true.
    /// If server is using basic authentication and you set digest_auth to true, mio_httpc will retry with basic.
    /// If not set, basic auth is assumed which is very insecure.
    pub fn digest_auth(&mut self, _v: bool) -> &mut Self {
        self
    }

    /// Tell server to gzip response and unzip transparently before returning body to client.
    /// Default is true.
    pub fn gzip(&mut self, _b: bool) -> &mut Self {
        self
    }

    /// Default 4.
    ///
    /// How many redirects to follow. 0 to disable.
    pub fn max_redirects(&mut self, _v: u8) -> &mut Self {
        self
    }

    /// Default secure.
    ///
    /// Turn off domain verification over ssl. This should only be used when testing as you are throwing away
    /// a big part of ssl security.
    pub fn insecure_do_not_verify_domain(&mut self) -> &mut Self {
        self
    }
}

/// Send requests, receive responses.
pub struct Httpc {}

impl Httpc {
    /// Httpc will create connections with mio token in range [con_offset..con_offset+0xFFFF]
    pub fn new(con_offset: usize, cfg: Option<::HttpcCfg>) -> Httpc {
        Httpc {}
    }
    pub(crate) fn call<C: TlsConnector>(
        &mut self,
        b: CallBuilderImpl,
        poll: &Registry,
    ) -> Result<Call> {
        Err(::Error::NoTls)
    }
    pub(crate) fn peek_body(&mut self, id: &::Call, off: &mut usize) -> &[u8] {
        &[]
    }
    pub(crate) fn try_truncate(&mut self, id: &::Call, off: &mut usize) {}

    /// Number of currently open connections (in active and idle keep-alive state)
    pub fn open_connections(&self) -> usize {
        0
    }

    /// Reconfigure client
    pub fn recfg(&mut self, _cfg: ::HttpcCfg) {}

    /// Reuse a response buffer for subsequent calls.
    pub fn reuse(&mut self, buf: Vec<u8>) {}

    /// Prematurely finish call.
    pub fn call_close(&mut self, id: Call) {}

    /// Call periodically to check for call timeouts and DNS retries.
    /// Returns list of calls that have timed out.
    /// You must execute call_close yourself (or SimpleCall::abort) and timeout will return them
    /// every time until you do.
    /// (every 100ms for example)
    pub fn timeout(&mut self) -> Vec<CallRef> {
        Vec::new()
    }

    /// Same as timeout except that timed out calls get appended.
    /// This way you can reuse old allocations (if you truncated to 0).
    pub fn timeout_extend<C: TlsConnector>(&mut self, out: &mut Vec<CallRef>) {}

    /// Get CallRef for ev if token in configured range for Httpc.
    /// Compare CallRef external call.
    ///
    /// First you must call call_send until you get a SendState::Receiving
    /// after that call is in receive state and you must call call_recv.
    pub fn event(&mut self, ev: &Event) -> Option<CallRef> {
        None
    }

    /// If request has body it will be either taken from buf, from Request provided to CallBuilder
    /// or will return SendState::WaitReqBody.
    ///
    /// buf slice is assumed to have taken previous SendState::SentBody(usize) into account
    /// and starts from part of buffer that has not been sent yet.
    pub fn call_send(&mut self, poll: &Registry, id: &mut Call, buf: Option<&[u8]>) -> SendState {
        ::SendState::Error(::Error::NoTls)
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
        poll: &Registry,
        id: &mut Call,
        buf: Option<&mut Vec<u8>>,
    ) -> RecvState {
        ::RecvState::Error(::Error::NoTls)
    }
}
