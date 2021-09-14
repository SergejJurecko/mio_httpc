use crate::tls_api;
use crate::tls_api::TlsConnector;
use crate::types::{CallBuilderImpl, Method};
use crate::SimpleCall;
use crate::{Call, CallRef, Result};
use mio::{Event, Poll};

/// Used to start a call and get a Call for it.
#[derive(Debug, Default)]
pub struct CallBuilder {
    cb: Option<CallBuilderImpl>,
}

#[cfg(feature = "rustls")]
type CONNECTOR = tls_api::rustls::TlsConnector;
#[cfg(feature = "native")]
type CONNECTOR = tls_api::native::TlsConnector;
#[cfg(feature = "openssl")]
type CONNECTOR = tls_api::openssl::TlsConnector;
#[cfg(not(any(feature = "rustls", feature = "native", feature = "openssl")))]
type CONNECTOR = tls_api::dummy::TlsConnector;

/// CallBuilder constructs a call. It is finished after calling: exec, simple_call, call or websocket.
///
/// Some headers are set automatically unless set explicitly:
/// user-agent, connection, host, auth, content-length
///
/// If you're only executing a one-off call you should set connection header to close as default
/// is keep-alive.
///
/// If you do not set body, but do set content-length,
/// it will wait for send body to be provided through Httpc::call_send.
/// You must use a streaming interface in this case and can not use SimpleCall.
impl CallBuilder {
    pub fn new() -> CallBuilder {
        CallBuilder {
            // builder: Builder::new(),
            cb: Some(CallBuilderImpl::new()),
            ..Default::default()
        }
    }

    /// Start a GET request.
    pub fn get() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().method = Method::GET;
        b
    }

    /// Start a POST request.
    pub fn post(body: Vec<u8>) -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().body = body;
        b.cb.as_mut().unwrap().method = Method::POST;
        b
    }

    /// Start a PUT request.
    pub fn put(body: Vec<u8>) -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().body = body;
        b.cb.as_mut().unwrap().method = Method::PUT;
        b
    }

    /// Start a DELETE request.
    pub fn delete() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().method = Method::DELETE;
        b
    }

    /// Start an OPTIONS request.
    pub fn options() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().method = Method::OPTIONS;
        b
    }

    /// Start a HEAD request.
    pub fn head() -> CallBuilder {
        let mut b = CallBuilder::new();
        b.cb.as_mut().unwrap().method = Method::HEAD;
        b
    }

    /// Set method: "GET", "POST", "PUT", "OPTIONS", "DELETE" or "HEAD"
    pub fn method(&mut self, m: &str) -> &mut Self {
        self.cb.as_mut().unwrap().method(m);
        self
    }

    /// Default: http
    ///
    /// Use https for call.
    /// Shorthand for set_https(true)
    pub fn https(&mut self) -> &mut Self {
        self.cb.as_mut().unwrap().https();
        self
    }

    /// Default: false
    ///
    /// Use https for call.
    pub fn set_https(&mut self, v: bool) -> &mut Self {
        self.cb.as_mut().unwrap().set_https(v);
        self
    }

    /// Set host where to connect to. It can be a domain or IP address.
    pub fn host(&mut self, s: &str) -> &mut Self {
        self.cb.as_mut().unwrap().host(s);
        self
    }

    /// Set connection port.
    pub fn port(&mut self, p: u16) -> &mut Self {
        self.cb.as_mut().unwrap().port = p;
        self
    }

    /// Specifically set mio token IDs for call. Must be outside of token range specified im Httpc::new
    /// Two tokens are required becase when initiating connection both ipv4 and ipv6 connections
    /// are attempted. First one to connect wins and the other one is closed.
    pub fn event_token(&mut self, p: [usize; 2]) -> &mut Self {
        self.cb.as_mut().unwrap().evids = p;
        self
    }

    /// Use http authentication with username and password.
    pub fn auth(&mut self, us: &str, pw: &str) -> &mut Self {
        self.cb.as_mut().unwrap().auth(us, pw);
        self
    }

    /// Set full path. No percent encoding is done. Will fail later if it contains invalid characters.
    pub fn path(&mut self, inpath: &str) -> &mut Self {
        self.cb.as_mut().unwrap().path(inpath);
        self
    }

    /// Add a single segment of path. Parts are delimited by / which are added automatically.
    /// Any path unsafe characters are percent encoded.
    /// If part contains /, it will be percent encoded!
    pub fn path_segm(&mut self, segm: &str) -> &mut Self {
        self.cb.as_mut().unwrap().path_segm(segm);
        self
    }

    /// Add multiple segments in one go.
    pub fn path_segms(&mut self, parts: &[&str]) -> &mut Self {
        for p in parts {
            self.path_segm(p);
        }
        self
    }

    /// Add a key-value pair to query. Any url unsafe characters are percent encoded.
    pub fn query(&mut self, k: &str, v: &str) -> &mut Self {
        self.cb.as_mut().unwrap().query(k, v);
        self
    }

    /// Add multiple key-value pars in one go.
    pub fn query_list(&mut self, kvl: &[(&str, &str)]) -> &mut Self
// where
    //     I: Deref<Target = str>,
    {
        for &(ref k, ref v) in kvl {
            self.query(k, v);
        }
        self
    }

    /// Set full URL. If not valid it will return error. Be mindful of characters
    /// that need to be percent encoded. Using https, path_segm, query and auth functions
    /// to construct URL is much safer as those encode data automatically.
    pub fn url(&mut self, url: &str) -> crate::Result<&mut Self> {
        self.cb.as_mut().unwrap().url(url)?;
        Ok(self)
    }

    /// Set body.
    pub fn body(&mut self, body: Vec<u8>) -> &mut Self {
        self.cb.as_mut().unwrap().body = body;
        self
    }

    /// Set HTTP header.
    pub fn header(&mut self, key: &str, value: &str) -> &mut CallBuilder {
        self.cb.as_mut().unwrap().header(key, value);
        self
    }

    /// Execute directly. This will block until completion!
    pub fn exec(&mut self) -> crate::Result<(crate::Response, Vec<u8>)> {
        let poll = ::mio::Poll::new()?;
        let mut htp = Httpc::new(0, None);
        let mut events = ::mio::Events::with_capacity(2);
        let mut call = self.simple_call(&mut htp, &poll)?;
        loop {
            poll.poll(&mut events, Some(::std::time::Duration::from_millis(100)))?;
            for cref in htp.timeout().into_iter() {
                if call.is_ref(cref) {
                    return Err(crate::Error::TimeOut);
                }
            }

            for ev in events.iter() {
                let cref = htp.event(&ev);

                if call.is_call(&cref) {
                    if call.perform(&mut htp, &poll)? {
                        if let Some((resp, v)) = call.finish() {
                            return Ok((resp, v));
                        }
                        return Ok((crate::Response::new(), Vec::new()));
                    }
                }
            }
        }
    }

    /// Consume and execute HTTP call. Returns SimpleCall interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn simple_call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<SimpleCall> {
        // self.finish()?;
        let cb = self.cb.take().unwrap();
        Ok(httpc.call::<CONNECTOR>(cb, poll)?.simple())
    }

    /// Consume and execute HTTP call. Return low level streaming call interface.
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn call(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<Call> {
        // self.finish()?;
        let mut cb = self.cb.take().unwrap();
        // cant stream response with gzip on
        cb.gzip(false);
        httpc.call::<CONNECTOR>(cb, poll)
    }

    /// Consume and start a WebSocket
    /// CallBuilder is invalid after this call and will panic if used again.
    pub fn websocket(&mut self, httpc: &mut Httpc, poll: &Poll) -> Result<crate::WebSocket> {
        // self.finish()?;
        let mut cb = self.cb.take().unwrap();
        cb.websocket();
        let cid = httpc.call::<CONNECTOR>(cb, poll)?;
        Ok(crate::WebSocket::new(cid, httpc.h.get_buf()))
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

    /// Default 128K
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

    /// Default true.
    ///
    /// Tell server to gzip response and unzip transparently before returning body to client.
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

    /// Return constructed URL.
    pub fn get_url(&mut self) -> String {
        self.cb.as_mut().unwrap().get_url()
    }
}

pub struct Httpc {
    h: crate::httpc::HttpcImpl,
}

impl Httpc {
    /// Httpc will create connections with mio token in range [con_offset..con_offset+0xFFFF]
    pub fn new(con_offset: usize, cfg: Option<crate::HttpcCfg>) -> Httpc {
        Httpc {
            h: crate::httpc::HttpcImpl::new(con_offset, cfg),
        }
    }
    pub(crate) fn call<C: TlsConnector>(
        &mut self,
        b: CallBuilderImpl,
        poll: &Poll,
    ) -> Result<Call> {
        self.h.call::<C>(b, poll)
    }
    pub(crate) fn peek_body(&mut self, id: &crate::Call, off: &mut usize) -> &[u8] {
        self.h.peek_body(id, off)
    }
    pub(crate) fn try_truncate(&mut self, id: &crate::Call, off: &mut usize) {
        self.h.try_truncate(id, off);
    }
    /// Reconfigure httpc.
    pub fn cfg_mut(&mut self) -> &mut crate::HttpcCfg {
        self.h.cfg_mut()
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
    /// Compare CallRef with external Call to find out which call this
    /// event belongs to if any.
    ///
    /// This call is mandatory as it sets up internal data structures for when something
    /// is signalled! Even if you know which call is being signalled, you must call event
    /// to let mio_httpc know what state socket is in.
    ///
    /// For streaming API first you must call call_send until you get a SendState::Receiving
    /// after that call is in receive state and you must call call_recv.
    pub fn event(&mut self, ev: &Event) -> Option<CallRef> {
        self.h.event::<CONNECTOR>(ev)
    }
    /// If request has body it will be either taken from buf, from Request provided to CallBuilder
    /// or will return SendState::WaitReqBody.
    ///
    /// buf slice is assumed to have taken previous SendState::SentBody(usize) into account
    /// and starts from part of buffer that has not been sent yet.
    pub fn call_send(
        &mut self,
        poll: &Poll,
        id: &mut Call,
        buf: Option<&[u8]>,
    ) -> crate::SendState {
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
    ) -> crate::RecvState {
        self.h.call_recv::<CONNECTOR>(poll, id, buf)
    }
}
