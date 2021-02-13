use crate::httpc::HttpcImpl;
use crate::resolve::DnsCache;
use crate::tls_api::TlsConnector;
use mio::Registry;
use percent_encoding::{percent_encode, utf8_percent_encode, AsciiSet, CONTROLS};
use pest::Parser;
use smallvec::SmallVec;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');
const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');
const USERINFO_ENCODE_SET: &AsciiSet = &PATH_SEGMENT_ENCODE_SET
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|');

#[derive(Debug)]
pub(crate) enum RecvStateInt {
    // Error(::Error),
    Response(crate::Response, crate::ResponseBody),
    DigestAuth(crate::Response, AuthenticateInfo),
    ReceivedBody(usize),
    DoneWithBody(Vec<u8>),
    Sending,
    Done,
    Wait,
    BasicAuth,
    Redirect(crate::Response),
    Retry(crate::Error),
}

#[derive(Debug)]
pub enum SendStateInt {
    SentBody(usize),
    WaitReqBody,
    Receiving,
    Done,
    Wait,
    Retry(crate::Error),
}

#[derive(Parser)]
#[grammar = "auth.pest"] // relative to src
struct AuthParser;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum DigestAlg {
    MD5,
    MD5Sess,
    // TODO use: https://github.com/malept/crypto-hash
    // Once they update to openssl 0.10.
    // Sha256,
    // Sha256Ses
    // Sha512,
    // Sha512Ses
}
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum DigestQop {
    Auth,
    AuthInt,
    None,
}

impl DigestQop {
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            DigestQop::Auth => b"auth",
            DigestQop::AuthInt => b"auth-int",
            DigestQop::None => b"auth",
        }
    }
}

pub struct AuthDigest<'a> {
    pub realm: &'a str,
    pub qop: DigestQop,
    pub nonce: &'a str,
    pub opaque: &'a str,
    pub alg: DigestAlg,
    pub stale: bool,
}

impl<'a> AuthDigest<'a> {
    pub fn parse(s: &'a str) -> crate::Result<AuthDigest<'a>> {
        // println!("Digest in {}", s);
        let mut realm = "";
        let mut nonce = "";
        let mut opaque = "";
        let mut qop = DigestQop::None;
        let mut stale = false;
        let mut alg = DigestAlg::MD5;
        let res_parse = AuthParser::parse(Rule::auth, s);
        if let Ok(pairs) = res_parse {
            for pair in pairs {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::auth_type => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.as_span().as_str();
                                if !s.eq_ignore_ascii_case("digest") {
                                    return Err(crate::Error::AuthenticateParse);
                                }
                                break;
                            }
                        }
                        Rule::realm => {
                            for inner_pair in inner_pair.into_inner() {
                                realm = inner_pair.as_span().as_str();
                                break;
                            }
                        }
                        Rule::qop => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.as_span().as_str();
                                if s.eq_ignore_ascii_case("auth") {
                                    qop = DigestQop::Auth;
                                    break;
                                } else if s.eq_ignore_ascii_case("auth-int") {
                                    qop = DigestQop::AuthInt;
                                    continue;
                                }
                            }
                        }
                        Rule::nonce => {
                            for inner_pair in inner_pair.into_inner() {
                                nonce = inner_pair.as_span().as_str();
                                break;
                            }
                        }
                        Rule::opaque => {
                            for inner_pair in inner_pair.into_inner() {
                                opaque = inner_pair.as_span().as_str();
                                break;
                            }
                        }
                        Rule::stale => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.as_span().as_str();
                                if s.eq_ignore_ascii_case("true") {
                                    stale = true;
                                } else {
                                    stale = false;
                                }
                                break;
                            }
                        }
                        Rule::algorithm => {
                            for inner_pair in inner_pair.into_inner() {
                                let a = inner_pair.as_span().as_str();
                                if a.eq_ignore_ascii_case("md5") {
                                    alg = DigestAlg::MD5;
                                } else if a.eq_ignore_ascii_case("md5-sess") {
                                    alg = DigestAlg::MD5Sess;
                                }
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            // println!("Digest out {} {} {} {:?} {:?}",realm,nonce,opaque,alg,qop);
            return Ok(AuthDigest {
                realm,
                nonce,
                opaque,
                alg,
                stale,
                qop,
            });
        } else if let Err(_e) = res_parse {
            // println!("Error parsing {}", e);
        }
        Err(crate::Error::AuthenticateParse)
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct AuthenticateInfo {
    pub(crate) nc: usize,
    pub(crate) hdr: String,
}

impl AuthenticateInfo {
    pub(crate) fn empty() -> AuthenticateInfo {
        AuthenticateInfo {
            nc: 0,
            hdr: String::new(),
        }
    }
    pub(crate) fn new(s: String) -> AuthenticateInfo {
        AuthenticateInfo { hdr: s, nc: 0 }
    }
}

pub struct ChunkIndex {
    // offset is num bytes from header
    offset: usize,
}

// read chunk by chunk and move data in buffer as it occurs.
// does not keep history
impl ChunkIndex {
    pub fn new() -> ChunkIndex {
        ChunkIndex { offset: 0 }
    }

    // Return true if 0 sized chunk found and stream finished.
    pub fn check_done(&mut self, max: usize, b: &[u8]) -> crate::Result<bool> {
        let mut off = self.offset;
        // For every chunk, shift bytes back over the NUM\r\n parts
        while off + 4 < b.len() {
            if let Some((num, next_off)) = self.get_chunk_size(&b[off..])? {
                if num > max {
                    return Err(crate::Error::ChunkOverlimit(num));
                }
                if num == 0 {
                    return Ok(true);
                }
                if off + num + next_off + 2 <= b.len() {
                    off += num + next_off + 2;
                    continue;
                }
            }
            break;
        }
        self.offset = off;
        Ok(false)
    }

    // copy full chunks to dst, move remainder (non-full chunk) back right after hdr.
    pub fn push_to(
        &mut self,
        hdr: usize,
        src: &mut Vec<u8>,
        dst: &mut Vec<u8>,
    ) -> crate::Result<usize> {
        let mut off = hdr;
        let mut num_copied = 0;
        loop {
            if let Some((num, next_off)) = self.get_chunk_size(&src[off..])? {
                if off + next_off + num + 2 <= src.len() {
                    dst.extend(&src[off + next_off..off + next_off + num]);
                    off += next_off + num + 2;
                    num_copied += num;
                    if num > 0 {
                        continue;
                    }
                }
            }
            if hdr != off {
                let sl = src.len();
                // unsafe {
                //     let src_p: *const u8 = src.as_ptr().offset(off as isize);
                //     let dst_p: *mut u8 = src.as_mut_ptr().offset(hdr as isize);
                //     ::std::ptr::copy(src_p, dst_p, sl - off);
                // }
                // src.truncate(hdr + sl - off);
                {
                    src.drain(hdr..off);
                }
                self.offset = 0;
            }
            break;
        }
        Ok(num_copied)
    }

    fn get_chunk_size(&mut self, b: &[u8]) -> crate::Result<Option<(usize, usize)>> {
        let blen = b.len();
        let mut num: usize = 0;
        let mut chunk_ext = false;
        for i in 0..blen {
            if i + 1 <= blen && b[i] == b'\r' && b[i + 1] == b'\n' {
                return Ok(Some((num, i + 2)));
            }
            if chunk_ext {
                continue;
            }
            if let Some(v) = ascii_hex_to_num(b[i]) {
                if let Some(num1) = num.checked_mul(16) {
                    num = num1;
                    if let Some(num2) = num.checked_add(v) {
                        num = num2;
                    } else {
                        return Err(crate::Error::ChunkedParse);
                    }
                } else {
                    return Err(crate::Error::ChunkedParse);
                }
            } else if b[i] == b';' {
                chunk_ext = true;
            } else {
                return Err(crate::Error::ChunkedParse);
            }
        }
        Ok(None)
    }
}

fn ascii_hex_to_num(ch: u8) -> Option<usize> {
    match ch {
        b'0'..=b'9' => Some((ch - b'0') as usize),
        b'a'..=b'f' => Some((ch - b'a' + 10) as usize),
        b'A'..=b'F' => Some((ch - b'A' + 10) as usize),
        _ => None,
    }
}
pub(crate) type IpList = SmallVec<[::std::net::IpAddr; 2]>;
type AuthBuf = SmallVec<[u8; 32]>;
type HostBuf = SmallVec<[u8; 64]>;
type PathBuf = SmallVec<[u8; 256]>;
type QueryBuf = SmallVec<[u8; 256]>;
type HeaderBuf = SmallVec<[u8; 1024 * 2]>;

#[derive(Debug, Default, Clone)]
pub(crate) struct CallBytes {
    pub us: AuthBuf,
    pub pw: AuthBuf,
    pub host: HostBuf,
    pub path: PathBuf,
    pub query: QueryBuf,
    pub headers: HeaderBuf,
}

// impl CallBytes {
//     fn host_as_str(&self) -> &str {
//         unsafe { from_utf8_unchecked(&self.host) }
//     }

//     fn us_as_str(&self) -> &str {
//         unsafe { from_utf8_unchecked(&self.us) }
//     }

//     fn pw_as_str(&self) -> &str {
//         unsafe { from_utf8_unchecked(&self.pw) }
//     }

//     fn path_as_str(&self) -> &str {
//         unsafe { from_utf8_unchecked(&self.path) }
//     }

//     fn query_as_str(&self) -> &str {
//         if self.query.len() > 0 {
//             unsafe { from_utf8_unchecked(&self.query[1..]) }
//         } else {
//             ""
//         }
//     }
// }

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Method {
    GET,
    PUT,
    POST,
    DELETE,
    OPTIONS,
    HEAD,
}
impl Default for Method {
    fn default() -> Method {
        Method::GET
    }
}
impl Method {
    fn from_str(s: &str) -> Method {
        if s.eq_ignore_ascii_case("get") {
            Method::GET
        } else if s.eq_ignore_ascii_case("post") {
            Method::POST
        } else if s.eq_ignore_ascii_case("put") {
            Method::PUT
        } else if s.eq_ignore_ascii_case("delete") {
            Method::DELETE
        } else if s.eq_ignore_ascii_case("options") {
            Method::OPTIONS
        } else if s.eq_ignore_ascii_case("head") {
            Method::HEAD
        } else {
            Method::GET
        }
    }
    pub fn as_str(&self) -> &'static str {
        match *self {
            Method::GET => "GET",
            Method::POST => "POST",
            Method::PUT => "PUT",
            Method::DELETE => "DELETE",
            Method::OPTIONS => "OPTIONS",
            Method::HEAD => "HEAD",
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum TransferEncoding {
    Identity,
    Chunked,
}
impl Default for TransferEncoding {
    fn default() -> TransferEncoding {
        TransferEncoding::Identity
    }
}

pub struct CallParam<'a> {
    pub poll: &'a Registry,
    pub dns: &'a mut DnsCache,
    pub cfg: &'a crate::HttpcCfg,
}

/// Start configure call.
#[derive(Debug, Default, Clone)]
pub(crate) struct CallBuilderImpl {
    // pub req: Request<Vec<u8>>,
    pub chunked_parse: bool,
    pub need_chunk_parse: bool,
    pub dur: Duration,
    pub max_response: usize,
    pub max_chunk: usize,
    pub dns_timeout: u64,
    pub ws: bool,
    pub auth: AuthenticateInfo,
    pub digest: bool,
    pub max_redirects: u8,
    pub gzip: bool,
    pub insecure: bool,
    pub reused: bool,
    pub method: Method,
    pub body: Vec<u8>,
    pub tls: bool,
    pub port: u16,
    pub content_len: usize,
    pub ua_set: bool,
    pub con_set: bool,
    pub host_set: bool,
    pub content_len_set: bool,
    pub transfer_encoding: TransferEncoding,
    pub bytes: Box<CallBytes>,
    pub evids: [usize; 2],
}

#[allow(dead_code)]
impl CallBuilderImpl {
    pub fn new() -> CallBuilderImpl {
        CallBuilderImpl {
            max_response: 1024 * 1024 * 10,
            max_chunk: 32 * 1024,
            chunked_parse: true,
            need_chunk_parse: false,
            gzip: true,
            dns_timeout: 100,
            max_redirects: 4,
            auth: AuthenticateInfo::empty(),
            port: 80,
            dur: Duration::from_millis(30000),
            evids: [usize::max_value(), usize::max_value()],
            ..Default::default()
        }
    }
    pub fn call<C: TlsConnector>(
        self,
        httpc: &mut HttpcImpl,
        poll: &Registry,
    ) -> crate::Result<crate::Call> {
        httpc.call::<C>(self, poll)
    }
    pub fn websocket(&mut self) -> &mut Self {
        self.ws = true;
        self
    }
    pub fn method(&mut self, m: &str) -> &mut Self {
        self.method = Method::from_str(m);
        self
    }
    pub fn is_fixed(&self) -> bool {
        !(self.evids[0] == usize::max_value() && self.evids[1] == usize::max_value())
    }
    pub fn url(&mut self, url: &str) -> crate::Result<&mut Self>
// where
    //     I: Deref<Target = str>,
    {
        let url = Url::parse(url.deref())?;
        if !url.has_host() {
            return Err(crate::Error::NoHost);
        }
        let host = url.host_str().unwrap();
        self.bytes.host.truncate(0);
        self.bytes.host.extend_from_slice(host.as_bytes());
        if let Some(port) = url.port() {
            self.port = port;
        }
        self.bytes.us.truncate(0);
        self.bytes.us.extend_from_slice(url.username().as_bytes());
        self.bytes.pw.truncate(0);
        if let Some(pw) = url.password() {
            self.bytes.pw.extend_from_slice(pw.as_bytes());
        }
        if url.scheme().eq_ignore_ascii_case("https") || url.scheme().eq_ignore_ascii_case("wss") {
            self.https();
        }
        self.bytes.path.truncate(0);
        self.bytes.path.extend_from_slice(url.path().as_bytes());
        self.bytes.query.truncate(0);
        if let Some(q) = url.query() {
            self.bytes.query.push(b'?');
            self.bytes.query.extend_from_slice(q.as_bytes());
        }
        Ok(self)
    }
    pub fn query(&mut self, k: &str, v: &str) -> &mut Self
// where
    //     I: Deref<Target = str>,
    {
        if self.bytes.query.len() == 0 {
            self.bytes.query.push(b'?');
        } else {
            self.bytes.query.push(b'&');
        }
        let enc = utf8_percent_encode(k, QUERY_ENCODE_SET);
        for v in enc {
            self.bytes.query.extend_from_slice(v.as_bytes());
        }
        self.bytes.query.push(b'=');
        let enc = utf8_percent_encode(v, QUERY_ENCODE_SET);
        for v in enc {
            self.bytes.query.extend_from_slice(v.as_bytes());
        }
        self
    }
    pub fn auth(&mut self, us: &str, pw: &str) -> &mut Self {
        self.bytes.us.extend_from_slice(us.as_bytes());
        self.bytes.pw.extend_from_slice(pw.as_bytes());
        // let enc = utf8_percent_encode(us, USERINFO_ENCODE_SET);
        // for v in enc {
        //     self.bytes.us.extend_from_slice(v.as_bytes());
        // }
        // let enc = utf8_percent_encode(pw, USERINFO_ENCODE_SET);
        // for v in enc {
        //     self.bytes.pw.extend_from_slice(v.as_bytes());
        // }
        self
    }
    pub fn host(&mut self, host: &str) -> &mut Self {
        self.bytes.host.extend_from_slice(host.as_bytes());
        self
    }
    pub fn https(&mut self) -> &mut Self {
        self.tls = true;
        if self.port == 80 {
            self.port = 443;
        }
        self
    }
    pub fn set_https(&mut self, v: bool) -> &mut Self {
        // no change
        if v == self.tls {
            return self;
        }
        // set tls
        if v && !self.tls {
            return self.https();
        }
        // turn off tls
        if self.port == 443 {
            self.port = 80;
        }
        self.tls = false;
        self
    }
    pub fn path(&mut self, inpath: &str) -> &mut Self {
        self.bytes.path.truncate(0);
        if inpath.len() > 0 && inpath.as_bytes()[0] != b'/' {
            self.bytes.path.push(b'/');
        }
        self.bytes.path.extend_from_slice(inpath.as_bytes());
        self
    }
    pub fn path_segm(&mut self, part: &str) -> &mut Self {
        if self.bytes.path.last().unwrap_or(&b'.') != &b'/' {
            self.bytes.path.push(b'/');
        }
        let enc = utf8_percent_encode(part, PATH_SEGMENT_ENCODE_SET);
        for v in enc {
            self.bytes.path.extend_from_slice(v.as_bytes());
        }
        self
    }
    pub fn header(&mut self, key: &str, value: &str) -> &mut Self {
        if key.eq_ignore_ascii_case("content-length") {
            if let Ok(bsz) = usize::from_str(value) {
                self.content_len = bsz;
                self.content_len_set = true;
                return self;
            }
        } else if key.eq_ignore_ascii_case("transfer-encoding") {
            if value.eq_ignore_ascii_case("chunked") {
                self.transfer_encoding = TransferEncoding::Chunked;
                self.content_len = usize::max_value();
            }
        } else if key.eq_ignore_ascii_case("user-agent") {
            self.ua_set = true;
        } else if key.eq_ignore_ascii_case("connection") {
            self.con_set = true;
        } else if key.eq_ignore_ascii_case("host") {
            self.host_set = true;
        }
        self.bytes.headers.extend_from_slice(key.as_bytes());
        self.bytes.headers.extend_from_slice(b": ");
        self.bytes.headers.extend_from_slice(value.as_bytes());
        self.bytes.headers.extend_from_slice(b"\r\n");
        self
    }
    pub fn dns_retry_ms(&mut self, n: u64) -> &mut Self {
        self.dns_timeout = n;
        self
    }
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.max_response = m;
        self
    }
    pub fn digest_auth(&mut self, b: bool) -> &mut Self {
        if self.auth.hdr.len() == 0 {
            self.digest = b;
        }
        self
    }
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.chunked_parse = b;
        self
    }
    pub fn gzip(&mut self, b: bool) -> &mut Self {
        self.gzip = b;
        self
    }
    pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
        self.max_chunk = v;
        self
    }
    pub fn timeout_ms(&mut self, v: u64) -> &mut Self {
        self.dur = Duration::from_millis(v);
        self
    }
    pub fn max_redirects(&mut self, v: u8) -> &mut Self {
        self.max_redirects = v;
        self
    }
    pub fn insecure(&mut self) -> &mut Self {
        self.insecure = true;
        self
    }
    pub fn get_url(&mut self) -> String {
        let mut s = Vec::new();
        if self.tls {
            s.extend_from_slice(b"https://")
        } else {
            s.extend_from_slice(b"http://")
        }
        if self.bytes.us.len() > 0 {
            let enc = percent_encode(&self.bytes.us, USERINFO_ENCODE_SET);
            for v in enc {
                s.extend_from_slice(v.as_bytes());
            }
            // s.extend_from_slice(&self.bytes.us);
        }
        if self.bytes.pw.len() > 0 {
            s.push(b':');
            let enc = percent_encode(&self.bytes.pw, USERINFO_ENCODE_SET);
            for v in enc {
                s.extend_from_slice(v.as_bytes());
            }
            // s.extend_from_slice(&self.bytes.pw);
            s.push(b'@');
        }
        s.extend_from_slice(&self.bytes.host);
        if !(self.tls && self.port == 443 || !self.tls && self.port == 80) {
            let mut ar = [0u8; 15];
            if let Ok(sz) = ::itoa::write(&mut ar[..], self.port) {
                s.push(b':');
                s.extend_from_slice(&ar[..sz]);
            }
        }
        if self.bytes.path.len() == 0 {
            s.push(b'/');
        } else {
            s.extend_from_slice(&self.bytes.path);
        }
        s.extend_from_slice(&self.bytes.query);

        String::from_utf8(s).expect("URL construction broken apparently...")
    }
    pub(crate) fn auth_recv(&mut self, v: AuthenticateInfo) -> &mut Self {
        self.digest = true;
        self.auth = v;
        self
    }
}

#[test]
pub fn test_auth() {
    let s = "Digest realm=\"http-auth@example.org\", qop=\"auth-int , auth\", algorithm=MD5-sess, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    AuthParser::parse(Rule::auth, s).unwrap();
    let da = AuthDigest::parse(s).unwrap();
    assert_eq!(da.realm, "http-auth@example.org");
    assert_eq!(da.nonce, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");
    assert_eq!(da.qop, DigestQop::Auth);
    assert_eq!(da.alg, DigestAlg::MD5Sess);
    assert_eq!(da.stale, false);

    let s = "Digest realm=\"http-auth@example.org\", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", stale=FALSE, qop=\"auth\"";
    AuthParser::parse(Rule::auth, s).unwrap();
    let da = AuthDigest::parse(s).unwrap();
    assert_eq!(da.realm, "http-auth@example.org");
    assert_eq!(da.nonce, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");
    assert_eq!(da.qop, DigestQop::Auth);
    assert_eq!(da.alg, DigestAlg::MD5);
    assert_eq!(da.stale, false);
}
