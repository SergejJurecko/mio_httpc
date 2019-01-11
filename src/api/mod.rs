use std::ffi::OsStr;
use std::fmt::{Display, Error as FmtError, Formatter};
use std::fs;
use std::io::Read;
use std::str::from_utf8;

/// Used when call is in send request state.
#[derive(Debug)]
pub enum SendState {
    /// Unrecoverable error has occured and call is finished.
    Error(crate::Error),
    /// How many bytes of body have just been sent.
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

#[derive(Default, Debug)]
pub struct Response {
    pub(crate) hdrs: Vec<u8>,
    pub status: u16,
    pub(crate) ws: bool,
}
impl Response {
    pub(crate) fn new() -> Response {
        Response {
            ..Default::default()
        }
    }

    pub fn headers(&self) -> Headers {
        let mut raw = [::httparse::EMPTY_HEADER; 32];
        let mut out = Headers::new();
        {
            let mut presp = ::httparse::Response::new(&mut raw);
            let _ = presp.parse(&self.hdrs);
        }
        let mut pos = 0;
        for i in 0..raw.len() {
            if raw[i].name.len() == 0 {
                break;
            }
            if let Ok(v) = from_utf8(raw[i].value) {
                out.headers[pos] = Header::new(raw[i].name, v);
                pos += 1;
                out.len = pos;
            }
        }
        out
    }
}

/// A single header
#[derive(Default, Copy, Clone)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}
impl<'a> Header<'a> {
    fn new(n: &'a str, v: &'a str) -> Header<'a> {
        Header { name: n, value: v }
    }

    /// Case insensitive header name comparison
    pub fn is(&self, v: &str) -> bool {
        self.name.eq_ignore_ascii_case(v)
    }
}
impl<'a> Display for Header<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "[ {}: {} ]", self.name, self.value)
    }
}

/// Iterator over headers in response
#[derive(Default, Copy, Clone)]
pub struct Headers<'a> {
    headers: [Header<'a>; 32],
    len: usize,
    next: usize,
}
impl<'a> Headers<'a> {
    fn new() -> Headers<'a> {
        Default::default()
    }
}

impl<'a> Display for Headers<'a> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        for h in 0..self.len {
            self.headers[h].fmt(f)?;
        }
        Ok(())
    }
}

impl<'a> Iterator for Headers<'a> {
    type Item = Header<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.len {
            return None;
        }
        self.next += 1;
        Some(self.headers[self.next - 1])
    }
}

/// Top level configuration for mio_http.
#[derive(Default, Clone)]
pub struct HttpcCfg {
    /// Extra root certificates in der format.
    pub der_ca: Vec<Vec<u8>>,
    /// Extra root certificates in pem format.
    pub pem_ca: Vec<Vec<u8>>,
    /// Default: 8
    ///
    /// Max 8K buffers to keep cached for subsequent requests.
    /// Every request requires 2.
    pub cache_buffers: usize,
    /// Set DNS servers if library can not easily get them from system (like Android).
    /// macOS, iOS and unix with /etc/resolv.conf are supported ATM.
    /// If none provided and library can't get them, google DNS servers (8.8.8.8:53, 8.8.4.4:53) will be used.
    pub dns_servers: Vec<::std::net::SocketAddr>,
    /// SSL Pinning. every element is (hostname, vec![pin1,pin2,..])
    /// A pin is formatted as: sha256/base64(subjectPublicKeyInfo)
    /// mio_httpc will check if public key of server matches any of the pins before
    /// sending the HTTP request.
    pub pins: Vec<(String, Vec<String>)>,
}

impl HttpcCfg {
    pub fn new() -> HttpcCfg {
        HttpcCfg {
            cache_buffers: 8,
            ..Default::default()
        }
    }

    /// Will read pem files (extensions .crt or .pem) from path.
    /// Path can be to file or folder.
    pub fn certs_from_path(path: &str) -> ::std::io::Result<HttpcCfg> {
        let mut cfg = HttpcCfg::new();
        let certs = [OsStr::new("crt"), OsStr::new("pem")];
        let metadata = fs::metadata(path)?;
        if metadata.is_file() {
            let mut file = fs::File::open(path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;
            cfg.pem_ca.push(contents);
            return Ok(cfg);
        }
        for de in fs::read_dir(path)? {
            if de.is_err() {
                continue;
            }
            let de = de.unwrap();
            match de.path().extension() {
                Some(ex) if certs.contains(&ex) => {
                    let meta = fs::metadata(de.path())?;
                    if meta.len() < 1024 * 8 {
                        let mut file = fs::File::open(de.path())?;
                        let mut contents = Vec::new();
                        file.read_to_end(&mut contents)?;
                        cfg.pem_ca.push(contents);
                    }
                }
                _ => {}
            }
        }
        Ok(cfg)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseBody {
    Sized(usize),
    Streamed,
}
impl ::std::fmt::Display for ResponseBody {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            ResponseBody::Sized(sz) => write!(f, "ResponseBody::Sized({})", sz),
            ResponseBody::Streamed => write!(f, "ResponseBody::Streamed"),
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
    Error(crate::Error),
    /// HTTP Response and response body size.
    /// If there is a body it will follow, otherwise call is done.
    Response(Response, ResponseBody),
    /// How many bytes were received.
    ReceivedBody(usize),
    /// Request is done with body.
    DoneWithBody(Vec<u8>),
    /// We are not done sending request yet. State may switch back to sending
    /// if we are following redirects or need to send request again due to digest auth.
    Sending,
    /// Request is done, body has been returned or
    /// there is no response body.
    Done,
    /// Nothing yet to return.
    Wait,
}

/// Call structure.
#[derive(Debug, PartialEq)] // much fewer derives then ref on purpose. We want a single instance.
pub struct Call {
    id: u64,
    // two connections possible, we try connecting to
    // ipv4 and ipv6 resolved IP. First one to establish connection wins.
    con1: usize,
    con2: usize,
    pub(crate) fixed: bool,
} //(u64, usize);

impl Call {
    /// Get a CallRef that matches this call.
    pub fn get_ref(&self) -> CallRef {
        CallRef(self.id)
    }

    pub fn simple(self) -> SimpleCall {
        SimpleCall::from(self)
    }

    /// Is CallRef for this call.
    pub fn is_ref(&self, r: CallRef) -> bool {
        self.id == r.0
    }

    pub(crate) fn remove_con(&mut self, conid: usize) {
        if conid == self.con1 {
            self.con1 = usize::max_value();
        } else if conid == self.con2 {
            self.con2 = usize::max_value();
        }
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    // pub(crate) fn set_con1(&mut self, con: usize) {
    //     self.con1 = con;
    // }
    // pub(crate) fn set_con2(&mut self, con: usize) {
    //     self.con2 = con;
    // }
    pub(crate) fn new(id: u64, con1: usize, con2: usize, fixed: bool) -> Call {
        Call {
            id,
            con1,
            con2,
            fixed,
        }
    }
    pub(crate) fn con(&self) -> usize {
        if self.con1 == usize::max_value() {
            self.con2
        } else {
            self.con1
        }
    }
    pub(crate) fn cons(&self) -> [usize; 2] {
        [self.con1, self.con2]
    }

    // keep this functionality internal to lib
    pub(crate) fn clone(&self) -> Call {
        Call {
            id: self.id,
            con1: self.con1,
            con2: self.con2,
            fixed: self.fixed,
        }
    }

    pub(crate) fn empty() -> Call {
        Call::new(
            u64::max_value(),
            usize::max_value(),
            usize::max_value(),
            false,
        )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.con1 == self.con2 && self.con1 == usize::max_value()
    }
    // pub(crate) fn call_id(&self) -> u16 {
    //     ((self.0 >> 16) & 0xFFFF) as u16
    // }
    // pub(crate) fn con_id(&self) -> u16 {
    //     (self.0 & 0xFFFF) as u16
    // }
    // Once call finished it gets invalidated.
    // This is a fail-safe so we can destroy Call structure
    // from Httpc on error or request finished.
    pub(crate) fn invalidate(&mut self) {
        // *self = Call::empty();
        self.con1 = usize::max_value();
        self.con2 = usize::max_value();
    }
}

/// Reference to call. Used for matching mio Token with call.
/// If you have lots of calls, you can use this as a key in a HashMap
/// (you probably want fnv HashMap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallRef(u64);
impl CallRef {
    pub(crate) fn new(call_id: u64) -> CallRef {
        CallRef(call_id)
    }
}

#[allow(unused_imports)]
mod websocket;
pub use self::websocket::*;

mod simple_call;
pub use self::simple_call::*;

mod builder;
pub use self::builder::*;
