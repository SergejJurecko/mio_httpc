//! mio_httpc is an async http client that runs on top of mio only.
//!
//! For convenience it also provides CallBuilder::exec for a simple one-line blocking HTTP call.
//!
//! Except CallBuilder::exec no call will block, not even for DNS resolution as it is implemented internally to avoid blocking.
//!
//! For https to work you must specify one of the TLS implementations using features: rtls (rustls), native, openssl.
//! Default build will fail on any https URI.
//!
//! CallBuilder also has URL construction functions (host/path_segm/query/set_https/auth/https) which will take care of url-safe encoding.
//!
//! mio_httpc does a minimal amount of allocation and in general works with buffers you provide and an internal pool
//! of buffers that get reused on new calls.
//!
//! # Examples
//!
//! ```no_run
//! extern crate mio_httpc;
//! extern crate mio;
//!
//! use mio_httpc::{CallBuilder,Httpc};
//! use mio::{Poll,Events};
//!
//! let poll = Poll::new().unwrap();
//! let mut htp = Httpc::new(10,None);
//! let mut call = CallBuilder::get()
//!     .url("https://www.reddit.com").expect("Invalid url")
//!     .timeout_ms(500)
//!     .simple_call(&mut htp, &poll)?;
//!
//! let to = ::std::time::Duration::from_millis(100);
//! let mut events = Events::with_capacity(8);
//! 'outer: loop {
//!     poll.poll(&mut events, Some(to)).unwrap();
//!     for cref in htp.timeout().into_iter() {
//!        if call.is_ref(cref) {
//!            println!("Request timed out");
//!            call.abort(&mut htp);
//!            break 'outer;
//!        }
//!    }
//!
//!    for ev in events.iter() {
//!        let cref = htp.event(&ev);
//!
//!        if call.is_call(&cref) {
//!            if call.perform(&mut htp, &poll)? {
//!                let (resp,body) = call.finish()?;
//!                if let Ok(s) = String::from_utf8(body) {
//!                    println!("Body: {}",s);
//!                }
//!                break 'outer;
//!            }
//!        }
//!    }
//! }
//! ```
//!
//! ```no_run
//! extern crate mio_httpc;
//! use mio_httpc::CallBuilder;
//!
//! // One line blocking call.
//!
//! let (response_meta, body) = CallBuilder::get().timeout_ms(5000).url("http://www.example.com")?.exec()?;
//!
//! ```
#![doc(html_root_url = "https://docs.rs/mio_httpc")]
#![crate_name = "mio_httpc"]

extern crate httparse;
extern crate rand;
// extern crate tls_api;
extern crate byteorder;
extern crate data_encoding;
extern crate fxhash;
// extern crate http;
extern crate itoa;
extern crate libc;
extern crate libflate;
extern crate md5;
extern crate mio;
#[cfg(feature = "native")]
extern crate native_tls;
#[cfg(feature = "openssl")]
extern crate openssl;
extern crate pest;
#[macro_use]
extern crate pest_derive;
extern crate percent_encoding;
#[cfg(feature = "rustls")]
extern crate rustls;
extern crate slab;
extern crate smallvec;
extern crate url;

// #[macro_use]
// extern crate failure;
#[cfg(test)]
#[macro_use]
extern crate matches;

mod api;
mod call;
mod connection;
#[allow(dead_code, unused_imports)]
mod dns_parser;
mod httpc;
mod resolve;
mod tls_api;
#[allow(dead_code, unused_variables)]
mod types;

pub use crate::api::*;
#[cfg(feature = "native")]
pub use native_tls::Error as TLSError;
#[cfg(feature = "openssl")]
pub use openssl::error::Error as OpenSSLError;
#[cfg(feature = "openssl")]
pub use openssl::error::ErrorStack as OpenSSLErrorStack;
#[cfg(feature = "openssl")]
pub use openssl::ssl::Error as TLSError;
#[cfg(feature = "rustls")]
pub use rustls::TLSError;

#[cfg(not(any(feature = "rustls", feature = "native", feature = "openssl")))]
pub use crate::tls_api::{dummy::hash, HashType};
#[cfg(feature = "native")]
pub use crate::tls_api::{native::hash, HashType};
#[cfg(feature = "openssl")]
pub use crate::tls_api::{openssl::hash, HashType};
#[cfg(feature = "rustls")]
pub use crate::tls_api::{rustls::hash, HashType};

pub type Result<T> = ::std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Io(::std::io::Error),
    Utf8(std::str::Utf8Error),
    FromUtf8(std::string::FromUtf8Error),
    Addr(std::net::AddrParseError),
    Httparse(httparse::Error),
    WebSocketFail(Response),
    TimeOut,
    /// Request structure did not contain body and CallSimple was used for POST/PUT.
    MissingBody,
    /// Response over max_response limit
    ResponseTooBig,
    /// Connection closed.
    Closed,
    /// No host found in request
    NoHost,
    /// Invalid scheme
    InvalidScheme,
    #[cfg(any(feature = "rustls", feature = "native", feature = "openssl"))]
    Tls(TLSError),
    #[cfg(feature = "openssl")]
    OpenSSLErrorStack(OpenSSLErrorStack),
    #[cfg(feature = "openssl")]
    OpenSSLError(OpenSSLError),
    /// All 0xFFFF slots for connections are full.
    NoSpace,
    Url(url::ParseError),
    Other(&'static str),
    /// You must pick one of the features: native, rustls, openssl
    NoTls,
    /// Eror while parsing chunked stream
    ChunkedParse,
    /// Eror while parsing chunked stream
    WebSocketParse,
    /// Eror while parsing chunked stream
    AuthenticateParse,
    InvalidPin,
    /// Chunk was larger than configured CallBuilder::chunked_max_chunk.
    ChunkOverlimit(usize),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::Url(e)
    }
}
#[cfg(any(feature = "rustls", feature = "native", feature = "openssl"))]
impl From<TLSError> for Error {
    fn from(e: TLSError) -> Self {
        Error::Tls(e)
    }
}
#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSSLErrorStack(e)
    }
}
#[cfg(feature = "openssl")]
impl From<OpenSSLError> for Error {
    fn from(e: OpenSSLError) -> Self {
        Error::OpenSSLError(e)
    }
}
impl From<httparse::Error> for Error {
    fn from(e: httparse::Error) -> Self {
        Error::Httparse(e)
    }
}
impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::FromUtf8(e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_headers() {
        let v = b"HTTP/1.1 200 OK\r\nContent-length: 100\r\nUpgrade: websocket\r\n".to_vec();
        let mut r = crate::Response::new();
        r.hdrs = v;

        {
            let hdrs = r.headers();
            for h in hdrs {
                println!("{}: {}", h.name, h.value);
            }
        }
    }
}
