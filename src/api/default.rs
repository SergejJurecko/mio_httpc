use http::{Request,Response};
use ::types::CallBuilderImpl;
use mio::{Poll,Event};
use tls_api::{TlsConnector};
use ::{Result,WebSocket,Call, CallRef, SendState, RecvState};

/// Used to start a call and get a Call for it.
pub struct CallBuilder {
}

impl CallBuilder {
    /// If req contains body it will be used.
    /// 
    /// If req contains no body, but has content-length set,
    /// it will wait for send body to be provided through Httpc::call_send. 
    /// mio_httpc will set headers (if they are not already): 
    /// user-agent, connection, host, auth, content-length
    /// If you're only executing a one-off call you should set connection: close as default
    /// is keep-alive.
    pub fn new(req: Request<Vec<u8>>) -> CallBuilder {
        CallBuilder{}
    }

    /// Consume and execute HTTP call
    pub fn call(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<Call> {
        Err(::Error::NoTls)
    }

    /// Consume and start a WebSocket
    pub fn websocket(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<WebSocket> {
        Err(::Error::NoTls)
    }

    /// Add custom root ca in DER format
    pub fn add_root_ca_der(self, v: Vec<u8>) -> Self {
        self
    }

    /// Default 10MB.
    /// 
    /// This will limit how big the internal Vec<u8> can grow.
    /// HTTP response headers are always stored in internal buffer.
    /// HTTP response body is stored in internal buffer if no external
    /// buffer is provided.
    /// 
    /// For WebSockets this will also be a received fragment size limit!
    pub fn max_response(self, m: usize) -> Self {
        self
    }

    /// Default: 100ms
    /// 
    /// Starting point of dns packet resends if nothing received.
    /// Every next resend timeout is 2x the previous one but stops at 1s.
    /// So for 100ms: 100ms, 200ms, 400ms, 800ms, 1000ms, 1000ms...
    pub fn dns_retry_ms(self, n: u64) -> Self {
        self
    }

    /// Default true.
    /// 
    /// Configurable because it entails copying the data stream.
    pub fn chunked_parse(self, b: bool) -> Self {
        self
    }

    /// Default 32K
    /// 
    /// Max size of chunk in a chunked transfer.
    pub fn chunked_max_chunk(self, v: usize) -> Self {
        self
    }

    /// Default 60s
    /// 
    /// Maximum amount of time a call should last.
    pub fn timeout_ms(self, d: u64) -> Self {
        self
    }

    /// Use a previous response to create request. This is useful for 
    /// redirects or http digest authorization responses.
    pub fn prev_resp(self, v: Response<Vec<u8>>) -> Self {
        self
    }
}

/// Send requests, receive responses.
pub struct Httpc {
}

impl Httpc {
    /// Httpc will create connections with mio token in range [con_offset..con_offset+0xFFFF]
    pub fn new(con_offset: usize) -> Httpc {
        Httpc {
        }
    }
    pub(crate) fn call<C:TlsConnector>(&mut self, b: CallBuilderImpl, poll: &Poll) -> Result<Call> {
        Err(::Error::NoTls)
    }
    pub(crate) fn peek_body(&mut self, id: &::Call, off: &mut usize) -> &[u8] {
        &[]
    }
    pub(crate) fn try_truncate(&mut self, id: &::Call, off: &mut usize) {
    }

    /// Number of currently open connections (in active and idle keep-alive state)
    pub fn open_connections(&self) -> usize {
        0
    }

    /// Reuse a response buffer for subsequent calls.
    pub fn reuse(&mut self, buf: Vec<u8>) {
    }

    /// Prematurely finish call. 
    pub fn call_close(&mut self, id: Call) {
    }

    /// Call periodically to check for call timeouts and DNS retries.
    /// Returns list of calls that have timed out.
    /// You must execute call_close yourself and timeout will return them
    /// every time until you do.
    /// (every 100ms for example)
    pub fn timeout(&mut self) -> Vec<CallRef> {
        Vec::new()
    }

    /// Same as timeout except that timed out calls get appended.
    /// This way you can reuse old allocations (if you truncated to 0).
    pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<CallRef>) {
    }

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
    pub fn call_send(&mut self, poll: &Poll, id: &mut Call, buf: Option<&[u8]>) -> SendState {
        ::SendState::Error(::Error::NoTls)
    }

    /// If no buf provided, response body (if any) is stored in an internal buffer.
    /// If buf provided after some body has been received, it will be copied to it.
    /// 
    /// Buf will be expanded if required. Bytes are always appended. If you want to receive
    /// response entirely in buf, you should reserve capacity for entire body before calling call_recv.
    /// 
    /// If body is only stored in internal buffer it will be limited to CallBuilder::max_response.
    pub fn call_recv(&mut self, poll: &Poll, id: &mut Call, buf: Option<&mut Vec<u8>>) -> RecvState {
        ::RecvState::Error(::Error::NoTls)
    }
}
