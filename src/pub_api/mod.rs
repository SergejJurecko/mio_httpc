
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

pub use self::pub_httpc::*;

#[cfg(not(any(feature="rustls", feature="native", feature="openssl")))]
mod pub_httpc {
    use std::time::Duration;
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
        pub fn add_root_ca_der(&mut self, v: Vec<u8>) -> &mut Self {
            self
        }

        /// Default 10MB.
        /// 
        /// This will limit how big the internal Vec<u8> can grow.
        /// HTTP response headers are always stored in internal buffer.
        /// HTTP response body is stored in internal buffer if no external
        /// buffer is provided.
        pub fn max_response(&mut self, m: usize) -> &mut Self {
            self
        }

        /// Default true.
        /// 
        /// Configurable because it entails copying the data stream.
        pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
            self
        }

        /// Default 32K
        /// 
        /// Max size of chunk in a chunked transfer.
        pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
            self
        }

        /// Default 60s
        /// 
        /// Maximum amount of time a call should last.
        pub fn timeout(&mut self, d: Duration) -> &mut Self {
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

        /// If calls executing, timeout should be called at least every ~200ms.
        pub fn timeout(&mut self) {
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
    use std::time::Duration;
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
        pub fn add_root_ca_der(&mut self, v: Vec<u8>) -> &mut Self {
            self.cb.add_root_ca(v);
            self
        }
        pub fn max_response(&mut self, m: usize) -> &mut Self {
            self.cb.max_response(m);
            self
        }
        pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
            self.cb.chunked_parse(b);
            self
        }
        pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
            self.cb.chunked_max_chunk(v);
            self
        }
        pub fn timeout(&mut self, d: Duration) -> &mut Self {
            self.cb.timeout(d);
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
        pub fn timeout(&mut self) {
            self.h.timeout::<tls_api_rustls::TlsConnector>()
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
    use std::time::Duration;
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
        pub fn add_root_ca_der(&mut self, v: Vec<u8>) -> &mut Self {
            self.cb.add_root_ca(v);
            self
        }
        pub fn max_response(&mut self, m: usize) -> &mut Self {
            self.cb.max_response(m);
            self
        }
        pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
            self.cb.chunked_parse(b);
            self
        }
        pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
            self.cb.chunked_max_chunk(v);
            self
        }
        pub fn timeout(&mut self, d: Duration) -> &mut Self {
            self.cb.timeout(d);
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
        pub fn timeout(&mut self) {
            self.h.timeout::<tls_api_native_tls::TlsConnector>()
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
    use std::time::Duration;
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
        pub fn add_root_ca_der(&mut self, v: Vec<u8>) -> &mut Self {
            self.cb.add_root_ca(v);
            self
        }
        pub fn max_response(&mut self, m: usize) -> &mut Self {
            self.cb.max_response(m);
            self
        }
        pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
            self.cb.chunked_parse(b);
            self
        }
        pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
            self.cb.chunked_max_chunk(v);
            self
        }
        pub fn timeout(&mut self, d: Duration) -> &mut Self {
            self.cb.timeout(d);
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
        pub fn timeout(&mut self) {
            self.h.timeout::<tls_api_openssl::TlsConnector>()
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