extern crate rand;
extern crate httparse;
// extern crate url;
extern crate tls_api;
extern crate mio;
extern crate byteorder;
extern crate libc;
extern crate fnv;
extern crate time;
extern crate http;
#[macro_use(quick_error)]
extern crate quick_error;
#[cfg(test)]
#[macro_use]
extern crate matches;
#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate core_foundation_sys;

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
// pub use dns_cache::*;


// use url::ParseError as UrlParseError;

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

        /// Returned headers are larger then Httpc::max_hdrs_len. You can increase it
        /// and call Httpc::event again or abandon with Httpc::call_close. 
        HeadersOverlimit(sz: usize) {
            display("Response headers are oversized max={}", sz)
        }
        Closed {
            display("Connection closed")
        }
        InvalidToken {
            display("MIO token is invalid")
        }
        TooSmall {
            display("Supplied buffer not big enough")
        }
        NoBody {
            display("Can not read body when body not received yet")
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
        assert_eq!(2 + 2, 4);
    }
}
