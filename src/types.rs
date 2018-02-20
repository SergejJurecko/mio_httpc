use dns_cache::DnsCache;
use mio::Poll;
use http::Request;
use std::time::Duration;
use httpc::HttpcImpl;
use tls_api::TlsConnector;
use pest::Parser;

#[derive(Debug)]
pub(crate) enum RecvStateInt {
    // Error(::Error),
    Response(::http::Response<Vec<u8>>, ::ResponseBody),
    DigestAuth(::http::Response<Vec<u8>>, AuthenticateInfo),
    ReceivedBody(usize),
    DoneWithBody(Vec<u8>),
    Sending,
    Done,
    Wait,
    BasicAuth,
    Redirect(::http::Response<Vec<u8>>),
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
    pub fn parse(s: &'a str) -> ::Result<AuthDigest<'a>> {
        // println!("Digest in {}",s);
        let mut realm = "";
        let mut nonce = "";
        let mut opaque = "";
        let mut qop = DigestQop::None;
        let mut stale = false;
        let mut alg = DigestAlg::MD5;
        if let Ok(pairs) = AuthParser::parse(Rule::auth, s) {
            for pair in pairs {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::auth_type => for inner_pair in inner_pair.into_inner() {
                            let s = inner_pair.into_span().as_str();
                            if !s.eq_ignore_ascii_case("digest") {
                                return Err(::Error::AuthenticateParse);
                            }
                            break;
                        },
                        Rule::realm => for inner_pair in inner_pair.into_inner() {
                            realm = inner_pair.into_span().as_str();
                            break;
                        },
                        Rule::qop => for inner_pair in inner_pair.into_inner() {
                            let s = inner_pair.into_span().as_str();
                            if s.eq_ignore_ascii_case("auth") {
                                qop = DigestQop::Auth;
                                break;
                            } else if s.eq_ignore_ascii_case("auth-int") {
                                qop = DigestQop::AuthInt;
                                continue;
                            }
                        },
                        Rule::nonce => for inner_pair in inner_pair.into_inner() {
                            nonce = inner_pair.into_span().as_str();
                            break;
                        },
                        Rule::opaque => for inner_pair in inner_pair.into_inner() {
                            opaque = inner_pair.into_span().as_str();
                            break;
                        },
                        Rule::stale => for inner_pair in inner_pair.into_inner() {
                            let s = inner_pair.into_span().as_str();
                            if s.eq_ignore_ascii_case("true") {
                                stale = true;
                            } else {
                                stale = false;
                            }
                            break;
                        },
                        Rule::algorithm => for inner_pair in inner_pair.into_inner() {
                            let a = inner_pair.into_span().as_str();
                            if a.eq_ignore_ascii_case("md5") {
                                alg = DigestAlg::MD5;
                            } else if a.eq_ignore_ascii_case("md5-sess") {
                                alg = DigestAlg::MD5Sess;
                            }
                            break;
                        },
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
        }
        Err(::Error::AuthenticateParse)
    }
}

#[derive(Debug)]
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
    pub fn check_done(&mut self, max: usize, b: &[u8]) -> ::Result<bool> {
        let mut off = self.offset;
        // For every chunk, shift bytes back over the NUM\r\n parts
        while off + 4 < b.len() {
            if let Some((num, next_off)) = self.get_chunk_size(&b[off..])? {
                if num > max {
                    return Err(::Error::ChunkOverlimit(num));
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
    pub fn push_to(&mut self, hdr: usize, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> ::Result<usize> {
        let mut off = hdr;
        let mut num_copied = 0;
        loop {
            if let Some((num, next_off)) = self.get_chunk_size(&src[off..])? {
                if off + next_off + num + 2 <= src.len() {
                    dst.extend(&src[off + next_off..off + next_off + num]);
                    off += next_off + num + 2;
                    num_copied += num;
                    continue;
                }
            }
            if hdr != off {
                let sl = src.len();
                unsafe {
                    let src_p: *const u8 = src.as_ptr().offset(off as isize);
                    let dst_p: *mut u8 = src.as_mut_ptr().offset(hdr as isize);
                    ::std::ptr::copy(src_p, dst_p, sl - off);
                }
                src.truncate(hdr + sl - off);
                self.offset = 0;
            }
            break;
        }
        Ok(num_copied)
    }

    fn get_chunk_size(&mut self, b: &[u8]) -> ::Result<Option<(usize, usize)>> {
        let blen = b.len();
        let mut num: usize = 0;
        for i in 0..blen {
            if i + 1 < blen && b[i] == b'\r' && b[i + 1] == b'\n' {
                return Ok(Some((num, i + 2)));
            }
            if let Some(v) = ascii_hex_to_num(b[i]) {
                if let Some(num1) = num.checked_mul(16) {
                    num = num1;
                    if let Some(num2) = num.checked_add(v) {
                        num = num2;
                    } else {
                        return Err(::Error::ChunkedParse);
                    }
                } else {
                    return Err(::Error::ChunkedParse);
                }
            } else {
                return Err(::Error::ChunkedParse);
            }
        }
        Ok(None)
    }
}

fn ascii_hex_to_num(ch: u8) -> Option<usize> {
    match ch {
        b'0'...b'9' => Some((ch - b'0') as usize),
        b'a'...b'f' => Some((ch - b'a' + 10) as usize),
        b'A'...b'F' => Some((ch - b'A' + 10) as usize),
        _ => None,
    }
}

pub struct CallParam<'a> {
    pub poll: &'a Poll,
    pub dns: &'a mut DnsCache,
    pub cfg: &'a ::HttpcCfg,
    // pub con: &'a mut Con,
    // pub ev: &'a Event,
}

/// Start configure call.
#[derive(Debug)]
pub struct CallBuilderImpl {
    pub req: Request<Vec<u8>>,
    pub chunked_parse: bool,
    pub dur: Duration,
    pub max_response: usize,
    pub max_chunk: usize,
    // pub root_ca: Vec<Vec<u8>>,
    pub dns_timeout: u64,
    pub ws: bool,
    pub(crate) auth: AuthenticateInfo,
    pub digest: bool,
    pub max_redirects: u8,
    pub gzip: bool,
}

#[allow(dead_code)]
impl CallBuilderImpl {
    pub fn new(req: Request<Vec<u8>>) -> CallBuilderImpl {
        CallBuilderImpl {
            max_response: 1024 * 1024 * 10,
            dur: Duration::from_millis(30000),
            max_chunk: 32 * 1024,
            req,
            chunked_parse: true,
            // root_ca: Vec::new(),
            dns_timeout: 100,
            ws: false,
            auth: AuthenticateInfo::empty(),
            digest: false,
            max_redirects: 4,
            gzip: true,
        }
    }
    pub fn call<C: TlsConnector>(self, httpc: &mut HttpcImpl, poll: &Poll) -> ::Result<::Call> {
        httpc.call::<C>(self, poll)
    }
    pub fn websocket(&mut self) -> &mut Self {
        self.ws = true;
        self
    }
    // pub fn add_root_ca_der(&mut self, v: Vec<u8>) -> &mut Self {
    //     self.root_ca.push(v);
    //     self
    // }
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
    pub(crate) fn auth(&mut self, v: AuthenticateInfo) -> &mut Self {
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
}
