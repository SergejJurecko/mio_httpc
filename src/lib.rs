//! mio_httpc is an async http client that runs on top of mio only.
//!
//! For convenience it also provides a SyncCall interface. This is a simple one-line HTTP client operation.
//!
//! No call will block (except SyncCall), not even for DNS resolution as it is implemented internally to avoid blocking.
//!
//! For https to work you must specify one of the TLS implementations using features: rtls (rustls), native, openssl.
//! Default build will fail on any https URI.
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
//! let mut call = CallBuilder::get("https://www.reddit.com")
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
//!                let mut resp = call.close()?;
//!                let v = mio_httpc::extract_body(&mut resp);
//!                if let Ok(s) = String::from_utf8(v) {
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
//! use mio_httpc::SyncCall;
//!
//! // One line blocking call.
//!
//! let (status, hdrs, body) = SyncCall::new().timeout_ms(5000).get(uri).expect("Request failed");
//!
//! ```
#![doc(html_root_url = "https://docs.rs/mio_httpc")]
#![crate_name = "mio_httpc"]

extern crate httparse;
extern crate rand;
// extern crate tls_api;
extern crate byteorder;
extern crate data_encoding;
extern crate fnv;
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

#[macro_use]
extern crate failure;
#[cfg(test)]
#[macro_use]
extern crate matches;

// #[allow(dead_code, unused_variables)]
mod dns_cache;
// #[allow(dead_code, unused_variables)]
mod dns;
#[allow(dead_code, unused_imports)]
mod dns_parser;
// #[allow(dead_code, unused_variables)]
mod connection;
// #[allow(dead_code, unused_variables)]
mod httpc;
// #[allow(dead_code, unused_variables, unused_imports)]
mod call;
// #[allow(dead_code, unused_variables)]
mod api;
#[allow(dead_code, unused_variables)]
mod types;
mod tls_api;

pub use api::*;
// pub use http::Error as HttpError;
// pub use http::header::*;
// pub use http::method::*;
// // pub use http::request::*;
// pub use http::response::*;
// pub use http::status::*;
// pub use http::uri::*;
// pub use http::version::*;
#[cfg(feature = "rustls")]
pub use rustls::TLSError;
#[cfg(feature = "native")]
pub use native_tls::Error as TLSError;
#[cfg(feature = "openssl")]
pub use openssl::error::Error as OpenSSLError;
#[cfg(feature = "openssl")]
pub use openssl::error::ErrorStack as OpenSSLErrorStack;
#[cfg(feature = "openssl")]
pub use openssl::ssl::Error as TLSError;
// #[cfg(feature = "openssl")]
// pub use rustls::TLSError;
// pub use http::Extensions;
// use failure::Error;

pub type Result<T> = ::std::result::Result<T, Error>;
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "IO error: {}", _0)]
    Io(#[cause] ::std::io::Error),

    #[fail(display = "Utf8 error: {}", _0)]
    Utf8(#[cause] std::str::Utf8Error),

    #[fail(display = "FromUtf8 error: {}", _0)]
    FromUtf8(#[cause] std::string::FromUtf8Error),

    #[fail(display = "AddrParseError: {}", _0)]
    Addr(#[cause] std::net::AddrParseError),

    // #[fail(display = "TlsError: {}", _0)]
    // Tls (#[cause] tls_api::Error),
    #[fail(display = "Httparse error: {}", _0)]
    Httparse(#[cause] httparse::Error),

    // #[fail(display = "Http error: {}", _0)]
    // Http(#[cause] http::Error),

    #[fail(display = "WebSocket setup failed")]
    WebSocketFail(Response),

    #[fail(display = "Sync call timed out")]
    TimeOut,
    /// Request structure did not contain body and CallSimple was used for POST/PUT.
    #[fail(display = "Request structure did not contain body and CallSimple was used for POST/PUT.")]
    MissingBody,
    // /// No call for mio::Token
    // #[fail(display = "No call for token")]
    // InvalidToken,
    /// Response over max_response limit
    #[fail(display = "Response over max_response limit")]
    ResponseTooBig,
    /// Connection closed.
    #[fail(display = "Connection closed")]
    Closed,
    /// No host found in request
    #[fail(display = "No host found in request")]
    NoHost,
    /// Invalid scheme
    #[fail(display = "Invalid scheme")]
    InvalidScheme,

    #[cfg(any(feature = "rustls", feature = "native", feature = "openssl"))]
    #[fail(display = "TLS error {}", _0)]
    Tls(#[cause] TLSError),

    #[cfg(feature = "openssl")]
    #[fail(display = "OpenSSL stack error {}", _0)]
    OpenSSLErrorStack(#[cause] OpenSSLErrorStack),

    #[cfg(feature = "openssl")]
    #[fail(display = "OpenSSL error {}", _0)]
    OpenSSLError(#[cause] OpenSSLError),

    // /// TLS handshake failed.
    // #[fail(display = "Handshake failed {}",_0)]
    // TlsHandshake(#[cause] tls_api::Error),
    /// All 0xFFFF slots for connections are full.
    #[fail(display = "Concurrent connection limit")]
    NoSpace,

    #[fail(display = "URL parse error {}",_0)]
    Url(#[cause] url::ParseError),

    #[fail(display = "{}", _0)]
    Other(&'static str),
    /// You must pick one of the features: native, rustls, openssl
    #[fail(display = "You must pick one of the features: native, rustls, openssl")]
    NoTls,
    /// Eror while parsing chunked stream
    #[fail(display = "Error parsing chunked transfer")]
    ChunkedParse,
    /// Eror while parsing chunked stream
    #[fail(display = "Error parsing WebSocket transfer")]
    WebSocketParse,
    /// Eror while parsing chunked stream
    #[fail(display = "Error parsing WWW-Authenticate header")]
    AuthenticateParse,
    /// Chunk was larger than configured CallBuilder::cunked_max_chunk.
    #[fail(display = "Chunk was larger than configured CallBuilder::cunked_max_chunk. {}", _0)]
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
// impl From<tls_api::Error> for Error {
//     fn from(e: tls_api::Error) -> Self {
//         Error::Tls(e)
//     }
// }
impl From<httparse::Error> for Error {
    fn from(e: httparse::Error) -> Self {
        Error::Httparse(e)
    }
}
// impl From<http::Error> for Error {
//     fn from(e: http::Error) -> Self {
//         Error::Http(e)
//     }
// }
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
        let mut r = ::Response::new();
        r.hdrs = v;

        {
            let hdrs = r.headers();
            for h in hdrs {
                println!("{}: {}",h.name, h.value);
            }
        }
    }
}