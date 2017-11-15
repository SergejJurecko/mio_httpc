extern crate rand;
extern crate httparse;
// extern crate url;
extern crate tls_api;
extern crate mio;
extern crate byteorder;
extern crate libc;
extern crate fnv;
// extern crate time;
extern crate http;
extern crate itoa;
#[macro_use(quick_error)]
extern crate quick_error;
#[cfg(test)]
#[macro_use]
extern crate matches;
#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate core_foundation_sys;

mod con_table;
mod dns_cache;
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(unused_variables)]
#[allow(non_snake_case)]
mod dns;
#[allow(dead_code)]
mod dns_parser;
mod con;
mod httpc;
mod call;
pub use httpc::*;
pub use call::CallBuilder;

// TODO:
// - con pool. tk must not be client side provided...client id and token are different
// - hide tls-api, configure through compile options
// - dns retries
// - timeouts
// - websockets
// - chunked response
// - http2

// use std::str::FromStr;
// pub fn content_length<T>(resp: &http::Response<T>) -> usize {
//     if let Some(ref clh) = resp.headers().get(http::header::CONTENT_LENGTH) {
//         if let Ok(clhs) = clh.to_str() {
//             if let Ok(bsz) = usize::from_str(clhs) {
//                 return bsz;
//             }
//         }
//     }
//     0
// }

// use url::ParseError as UrlParseError;

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

    // pub(crate) fn call_id(&self) -> u32 {
    //     // self.0 & 0xFFFF_FFFF
    //     self.0
    // }
}

pub type Result<T> = ::std::result::Result<T,Error>;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: std::io::Error) {
            description(err.description())
            from()
        }
        Utf8(err: std::str::Utf8Error) {
            description(err.description())
            from()
        }
        FromUtf8(err: std::string::FromUtf8Error) {
            description(err.description())
            from()
        }
        Addr(err: std::net::AddrParseError) {
            description(err.description())
            from()
        }
        Tls(err: tls_api::Error) {
            description(err.description())
            from()
        }
        Httparse(err: httparse::Error) {
            description(err.description())
            from()
        }
        Http(err: http::Error) {
            description(err.description())
            from()
        }
        InvalidToken {
            display("No call for token")
        }
        ResponseTooBig {
            display("Response over max_response limit")
        }
        Closed {
            display("Connection closed")
        }
        NoHost {
            display("No host found in request")
        }
        InvalidScheme {
            display("Invalid scheme")
        }
        TlsHandshake {
            display("Handshake failed")
        }
        NoSpace {
            display("Concurrent connection limit")
        }
        // #[cfg(unix)]
        // Nix(err: nix::Error) {
        //     description(err.description())
        //     from()
        // }
        Empty {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        // assert_eq!(2 + 2, 4);
        let mut v:Vec<u8> = vec![1,2,3,4,5];
    }
}
