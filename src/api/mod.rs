
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
pub struct CallId(pub(crate) u32);

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

mod websocket;
pub use self::websocket::*;

mod simple_call;
pub use self::simple_call::*;

#[cfg(not(any(feature="rustls", feature="native", feature="openssl")))]
mod default;
#[cfg(not(any(feature="rustls", feature="native", feature="openssl")))]
pub use self::default::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use self::rustls::*;

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use self::native::*;

#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use self::openssl::*;

