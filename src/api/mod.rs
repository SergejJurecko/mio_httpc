
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

/// Call structure.
#[derive(Debug, PartialEq)] // much fewer derives then ref on purpose. We want a single instance.
pub struct Call(pub(crate) u32);

impl Call {
    /// Get a CallRef that matches this call.
    pub fn get_ref(&self) -> CallRef {
        CallRef(self.0)
    }

    /// Is CallRef for this call.
    pub fn is_ref(&self, r: CallRef) -> bool {
        self.0 == r.0
    }
    // (Call:16, Con:16)
    pub(crate) fn new(con_id: u16, call_id: u16) -> Call {
        let con_id = con_id as u32;
        let call_id = call_id as u32;
        Call((call_id << 16) | con_id)
    }

    pub(crate) fn empty() -> Call {
        Call(0xffff_ffff)
    }

    pub(crate) fn is_empty(&self) -> bool {
        *self == Call::empty()
    }
    pub(crate) fn call_id(&self) -> u16 {
        ((self.0 >> 16) & 0xFFFF) as u16
    }
    pub(crate) fn con_id(&self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
    // Once call finished it gets invalidated.
    // This is a fail-safe so we can destroy Call structure
    // from Httpc on error or request finished.
    pub(crate) fn invalidate(&mut self) {
        *self = Call::empty();
    }
}

// I wish...Need httpc.
// impl Drop for Call {
//     fn drop(&mut self) {
//         if !self.is_empty() {
//         }
//     }
// }

/// Reference to call. Used for matching mio Token with call.
/// If you have lots of calls, you can use this as a key in a HashMap 
/// (you probably want fnv HashMap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallRef(pub(crate) u32);
impl CallRef {
    // (Call:16, Con:16)
    pub(crate) fn new(con_id: u16, call_id: u16) -> CallRef {
        let con_id = con_id as u32;
        let call_id = call_id as u32;
        CallRef((call_id << 16) | con_id)
    }

    pub(crate) fn con_id(&self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

/// Extract body from http::Response
pub fn extract_body(r: &mut ::http::Response<Vec<u8>>) -> Vec<u8> {
    ::std::mem::replace(r.body_mut(), Vec::new())
}
#[allow(unused_imports)]
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

