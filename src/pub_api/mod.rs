
/// Used when call is in send request state.
#[derive(Debug)]
pub enum SendState {
    /// Unrecoverable error has occured and call is finished.
    Error(::Error),
    /// How many bytes of body have been sent.
    SentBody(usize),
    /// Waiting for body to be provided for sending.
    WaitReqBody,
    /// Call has switched to receiving state.
    Receiving,
    /// Request is done, body has been returned or
    /// there is no response body.
    Done,
    /// Nothing yet to return.
    Wait,
}

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
pub enum ResponseBody {
    Sized(usize),
    Streamed,
}
impl ::std::fmt::Display for ResponseBody {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            ResponseBody::Sized(sz) => {
                write!(f, "ResponseBody::Sized({})", sz)
            }
            ResponseBody::Streamed => {
                write!(f, "ResponseBody::Streamed")
            }
        }
    }
}

impl ResponseBody {
    pub fn is_empty(&self) -> bool {
        match *self {
            ResponseBody::Sized(n) if n == 0 => true,
            _ => false,
        }
    }
}

/// Used when call is in receive response state.
#[derive(Debug)]
pub enum RecvState {
    /// Unrecoverable error has occured and call is finished.
    Error(::Error),
    /// HTTP Response and response body size. 
    /// If there is a body it will follow, otherwise call is done.
    Response(::http::Response<Vec<u8>>,ResponseBody),
    /// How many bytes were received.
    ReceivedBody(usize),
    /// Request is done with body.
    DoneWithBody(Vec<u8>),
    /// We are not done sending request yet.
    Sending,
    /// Request is done, body has been returned or
    /// there is no response body.
    Done,
    /// Nothing yet to return.
    Wait,
}

/// Id for calls. Directly tied to mio token but not equal to it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallId(u32);

impl CallId {
    // (Call:16, Con:16)
    pub(crate) fn new(con_id: u16, call_id: u16) -> CallId {
        let con_id = con_id as u32;
        let call_id = call_id as u32;
        CallId((call_id << 16) | con_id)
    }

    pub(crate) fn con_id(&self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// Extract body from http::Response
pub fn extract_body(r: &mut ::http::Response<Vec<u8>>) -> Vec<u8> {
    ::std::mem::replace(r.body_mut(), Vec::new())
}

#[derive(Clone,Copy,PartialEq,Eq)]
enum State {
    Sending,
    Receiving,
    Done,
}

/// Simplified API for non-streaming requests and responses.
/// If body exists it needs to be provided to Request. If response has a body
/// it is returned in Response.
pub struct SimpleCall {
    state: State,
    id: CallId,
    resp: Option<::http::Response<Vec<u8>>>,
    resp_body: Option<Vec<u8>>,
}

impl SimpleCall {
    /// Replaces self with an empty SimpleCall and returns result if any.
    pub fn take(&mut self) -> Option<::http::Response<Vec<u8>>> {
        let out = ::std::mem::replace(self, SimpleCall::empty());
        out.close()
    }

    pub fn id(&self) -> &CallId {
        &self.id
    }

    /// Consume and return response with body.
    pub fn close(mut self) -> Option<::http::Response<Vec<u8>>> {
        let r = self.resp.take();
        let b = self.resp_body.take();
        if let Some(mut rs) = r {
            if let Some(rb) = b {
                ::std::mem::replace(rs.body_mut(), rb);
                return Some(rs);
            }
        }
        None
    }

    /// For quick comparison with httpc::event response.
    /// If cid is none will return false.
    pub fn is_callid(&self, cid: &Option<CallId>) -> bool {
        if let &Some(ref b) = cid {
            return self.id == *b;
        }
        false
    }

    /// If using Option<SimpleCall> in a struct, you can quickly compare 
    /// callid from httpc::event. If either is none will return false.
    pub fn is_opt_callid(a: &Option<SimpleCall>, b: &Option<CallId>) -> bool {
        if let &Some(ref a) = a {
            if let &Some(ref b) = b {
                return a.id == *b;
            }
        }
        false
    }

    /// Is request finished.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Perform operation. Returns true if request is finished.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &::mio::Poll, ev: &::mio::Event) -> ::Result<bool> {
        if self.is_done() {
            return Ok(true);
        }
        if self.state == State::Sending {
            match htp.call_send(poll, ev, self.id, None) {
                SendState::Wait => {}
                SendState::Receiving => {
                    self.state = State::Receiving;
                }
                SendState::SentBody(_) => {}
                SendState::Error(e) => {
                    self.state = State::Done;
                    return Err(From::from(e));
                }
                SendState::WaitReqBody => {
                    self.state = State::Done;
                    return Err(::Error::MissingBody);
                }
                SendState::Done => {
                    self.state = State::Done;
                    return Ok(true);
                }
            }
        }
        if self.state == State::Receiving {
            loop {
                match htp.call_recv(poll, ev, self.id, None) {
                    RecvState::DoneWithBody(b) => {
                        self.resp_body = Some(b);
                        self.state = State::Done;
                        return Ok(true);
                    }
                    RecvState::Done => {
                        self.state = State::Done;
                        return Ok(true);
                    }
                    RecvState::Error(e) => {
                        self.state = State::Done;
                        return Err(From::from(e));
                    }
                    RecvState::Response(r,body) => {
                        self.resp = Some(r);
                        match body {
                            ResponseBody::Sized(0) => {
                                self.state = State::Done;
                                return Ok(true);
                            }
                            _ => {}
                        }
                    }
                    RecvState::Wait => {}
                    RecvState::Sending => {}
                    RecvState::ReceivedBody(_) => {}
                }
            }
        }
        Ok(false)
    }

    /// An empty SimpleCall not associated with a valid mio::Token/CallId.
    /// Exists to be overwritten with an actual valid request.
    /// Always returns is_done true.
    pub fn empty() -> SimpleCall {
        SimpleCall {
            state: State::Done,
            id: CallId(0xFFFF_FFFF),
            resp: None,
            resp_body: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.id.0 == 0xFFFF_FFFF
    }
}
impl From<CallId> for SimpleCall {
    fn from(v: CallId) -> SimpleCall {
        SimpleCall {
            state: State::Sending,
            id: v,
            resp: None,
            resp_body: None,
        }
    }
}

pub use self::pub_httpc::*;

#[cfg(not(any(feature="rustls", feature="native", feature="openssl")))]
mod pub_httpc {
    use http::{Request};
    use ::types::PrivCallBuilder;
    use mio::{Poll,Event};
    use tls_api::{TlsConnector};
    use ::Result;

    /// Used to start a call and get a CallId for it.
    pub struct CallBuilder {
    }

    impl CallBuilder {
        /// If req contains body it will be used.
        /// 
        /// If req contains no body, but has content-length set,
        /// it will wait for send body to be provided through Httpc::call_send. 
        pub fn new(req: Request<Vec<u8>>) -> CallBuilder {
            CallBuilder{}
        }
        /// Consume and execute
        pub fn call(self, httpc: &mut Httpc, poll: &Poll) -> ::Result<::CallId> {
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
    }

    /// Send request data, receive response data for CallId.
    pub struct Httpc {
    }

    impl Httpc {
        /// Httpc will create connections with mio token in range [con_offset..con_offset+0xFFFF]
        pub fn new(con_offset: usize) -> Httpc {
            Httpc {
            }
        }
        pub(crate) fn call<C:TlsConnector>(&mut self, b: PrivCallBuilder, poll: &Poll) -> Result<::CallId> {
            Err(::Error::NoTls)
        }

        /// Reuse a response buffer for subsequent calls.
        pub fn reuse(&mut self, buf: Vec<u8>) {
        }

        /// Prematurely finish call. 
        pub fn call_close(&mut self, id: ::CallId) {
        }

        /// Call periodically to check for call timeouts and DNS retries.
        /// Returns list of calls that have timed out.
        /// You must execute call_close yourself and timeout will return them
        /// every time until you do.
        /// (every 100ms for example)
        pub fn timeout(&mut self) -> Vec<::CallId> {
            Vec::new()
        }

        /// Same as timeout except that timed out calls get appended.
        /// This way you can reuse old allocations (if you truncated to 0).
        pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<::CallId>) {
        }

        /// Get CallId for ev if token in configured range for Httpc.
        /// 
        /// First you must call call_send until you get a SendState::Receiving
        /// after that call is in receive state and you must call call_recv.
        pub fn event(&mut self, ev: &Event) -> Option<::CallId> {
            None
        }

        /// If request has body it will be either taken from buf, from Request provided to CallBuilder
        /// or will return SendState::WaitReqBody.
        /// 
        /// buf slice is assumed to have taken previous SendState::SentBody(usize) into account
        /// and starts from part of buffer that has not been sent yet.
        pub fn call_send(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&[u8]>) -> ::SendState {
            ::SendState::Error(::Error::NoTls)
        }

        /// If no buf provided, response body (if any) is stored in an internal buffer.
        /// If buf provided after some body has been received, it will be copied to it.
        /// 
        /// Buf will be expanded if required. Bytes are always appended. If you want to receive
        /// response entirely in buf, you should reserve capacity for entire body before calling call_recv.
        /// 
        /// If body is only stored in internal buffer it will be limited to CallBuilder::max_response.
        pub fn call_recv(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&mut Vec<u8>>) -> ::RecvState {
            ::RecvState::Error(::Error::NoTls)
        }
    }
}

#[cfg(feature = "rustls")]
mod pub_httpc {
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
}

#[cfg(feature = "native")]
mod pub_httpc {
    extern crate tls_api_native_tls;
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
            httpc.call::<tls_api_native_tls::TlsConnector>(self.cb, poll)
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
            self.h.timeout::<tls_api_native_tls::TlsConnector>()
        }
        pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<::CallId>) {
            self.h.timeout_extend::<tls_api_native_tls::TlsConnector>(out)
        }
        pub fn event(&mut self, ev: &Event) -> Option<::CallId> {
            self.h.event::<tls_api_native_tls::TlsConnector>(ev)
        }
        pub fn call_send(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&[u8]>) -> ::SendState {
            self.h.call_send::<tls_api_native_tls::TlsConnector>(poll, ev, id, buf)
        }
        pub fn call_recv(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&mut Vec<u8>>) -> ::RecvState {
            self.h.call_recv::<tls_api_native_tls::TlsConnector>(poll, ev, id, buf)
        }
    }
}

#[cfg(feature = "openssl")]
mod pub_httpc {
    extern crate tls_api_openssl;
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
            httpc.call::<tls_api_openssl::TlsConnector>(self.cb, poll)
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
            self.h.timeout::<tls_api_openssl::TlsConnector>()
        }
        pub fn timeout_extend<C:TlsConnector>(&mut self, out: &mut Vec<::CallId>) {
            self.h.timeout_extend::<tls_api_openssl::TlsConnector>(out)
        }
        pub fn event(&mut self, ev: &Event) -> Option<::CallId> {
            self.h.event::<tls_api_openssl::TlsConnector>(ev)
        }
        pub fn call_send(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&[u8]>) -> ::SendState {
            self.h.call_send::<tls_api_openssl::TlsConnector>(poll, ev, id, buf)
        }
        pub fn call_recv(&mut self, poll: &Poll, ev: &Event, id: ::CallId, buf: Option<&mut Vec<u8>>) -> ::RecvState {
            self.h.call_recv::<tls_api_openssl::TlsConnector>(poll, ev, id, buf)
        }
    }
}