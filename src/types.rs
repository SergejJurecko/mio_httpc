use dns_cache::DnsCache;
use mio::{Poll};
use http::{Request,Response};
use std::time::Duration;
use httpc::HttpcImpl;
use tls_api::{TlsConnector};
use pest::Parser;

#[derive(Parser)]
#[grammar = "auth.pest"] // relative to src
pub struct AuthParser;

#[derive(Debug,Eq,PartialEq,Clone,Copy)]
pub enum DigestAlg {
    Md5,
    Md5Ses,
}
#[derive(Debug,Eq,PartialEq,Clone,Copy)]
pub enum DigestQop {
    Auth,
    AuthInt,
}

pub struct AuthDigest<'a> {
    realm: &'a str,
    qop: DigestQop,
    nonce: &'a str,
    opaque: &'a str,
    alg: DigestAlg,
    stale: bool,
}

impl<'a> AuthDigest<'a> {
    pub fn parse(s: &'a str) ->  ::Result<AuthDigest<'a>> {
        let mut realm = "";
        let mut nonce = "";
        let mut opaque = "";
        let mut qop = DigestQop::Auth;
        let mut stale = false;
        let mut alg = DigestAlg::Md5;
        if let Ok(pairs) = AuthParser::parse(Rule::auth,s) {
            for pair in pairs {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::auth_type => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.into_span().as_str();
                                if !s.eq_ignore_ascii_case("digest") {
                                    return Err(::Error::AuthenticateParse);
                                }
                                break;
                            }
                        }
                        Rule::realm => {
                            for inner_pair in inner_pair.into_inner() {
                                realm = inner_pair.into_span().as_str();
                                break;
                            }
                        }
                        Rule::qop => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.into_span().as_str();
                                if s.eq_ignore_ascii_case("auth") {
                                    qop = DigestQop::Auth;
                                } else if s.eq_ignore_ascii_case("auth-int") {
                                    qop = DigestQop::AuthInt;
                                }
                                break;
                            }
                        }
                        Rule::nonce => {
                            for inner_pair in inner_pair.into_inner() {
                                nonce = inner_pair.into_span().as_str();
                                break;
                            }
                        }
                        Rule::opaque => {
                            for inner_pair in inner_pair.into_inner() {
                                opaque = inner_pair.into_span().as_str();
                                break;
                            }
                        }
                        Rule::stale => {
                            for inner_pair in inner_pair.into_inner() {
                                let s = inner_pair.into_span().as_str();
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
                                let a = inner_pair.into_span().as_str();
                                if a.eq_ignore_ascii_case("md5") {
                                    alg = DigestAlg::Md5;
                                } else if a.eq_ignore_ascii_case("md5-sess") {
                                    alg = DigestAlg::Md5Ses;
                                }
                                break;
                            }
                        }
                        _ => {
                        }
                    }
                    // println!("Text:    {}", inner_pair.clone().into_span().as_str());
                }
            }
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

pub struct ChunkIndex {
    // offset is num bytes from header
    offset: usize,
}

// read chunk by chunk and move data in buffer as it occurs. 
// does not keep history
impl ChunkIndex {
    pub fn new() -> ChunkIndex {
        ChunkIndex {
            offset: 0,
        }
    }

    // Return true if 0 sized chunk found and stream finished.
    pub fn check_done(&mut self, max:usize, b: &[u8]) -> ::Result<bool> {
        let mut off = self.offset;
        // For every chunk, shift bytes back over the NUM\r\n parts
        while off+4 < b.len() {
            if let Some((num,next_off)) = self.get_chunk_size(&b[off..])? {
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
    pub fn push_to(&mut self, hdr:usize, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> ::Result<usize> {
        let mut off = hdr;
        let mut num_copied = 0;
        loop {
            if let Some((num,next_off)) = self.get_chunk_size(&src[off..])? {
                if off + next_off + num + 2 <= src.len() {
                    dst.extend(&src[off+next_off..off+next_off+num]);
                    off += next_off+num+2;
                    num_copied += num;
                    continue;
                }
            }
            if hdr != off {
                let sl = src.len();
                unsafe {
                    let src_p:*const u8 = src.as_ptr().offset(off as isize);
                    let dst_p:*mut u8 = src.as_mut_ptr().offset(hdr as isize);
                    ::std::ptr::copy(src_p, dst_p, sl-off);
                }
                src.truncate(hdr+sl-off);
                self.offset = 0;
            }
            break;
        }
        Ok(num_copied)
    }

    fn get_chunk_size(&mut self, b: &[u8]) -> ::Result<Option<(usize,usize)>> {
        let blen = b.len();
        let mut num:usize = 0;
        for i in 0..blen {
            if i+1 < blen && b[i] == b'\r' && b[i+1] == b'\n' {
                return Ok(Some((num,i+2)));
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

fn ascii_hex_to_num(ch: u8) -> Option<usize>
{
    match ch {
        b'0' ... b'9' => Some((ch - b'0') as usize),
        b'a' ... b'f' => Some((ch - b'a' + 10) as usize),
        b'A' ... b'F' => Some((ch - b'A' + 10) as usize),
        _ => None,
    }
}

pub struct CallParam<'a> {
    pub poll: &'a Poll,
    pub dns: &'a mut DnsCache,
    // pub con: &'a mut Con,
    // pub ev: &'a Event,
}

/// Start configure call.
pub struct CallBuilderImpl {
    pub req: Request<Vec<u8>>,
    pub chunked_parse: bool,
    pub dur: Duration,
    pub max_response: usize,
    pub max_chunk: usize,
    pub root_ca: Vec<Vec<u8>>,
    pub dns_timeout: u64,
    pub ws: bool,
    pub presp: Option<Response<Vec<u8>>>,
    // pub digest: bool,
}

#[allow(dead_code)]
impl CallBuilderImpl {
    pub fn new(req: Request<Vec<u8>>) -> CallBuilderImpl {
        CallBuilderImpl {
            max_response: 1024*1024*10,
            dur: Duration::from_millis(30000),
            max_chunk: 32*1024,
            req,
            chunked_parse: true,
            root_ca: Vec::new(),
            dns_timeout: 100,
            ws: false,
            presp: None,
            // digest: false,
        }
    }
    pub fn call<C:TlsConnector>(self, httpc: &mut HttpcImpl, poll: &Poll) -> ::Result<::Call> {
        httpc.call::<C>(self, poll)
    }
    pub fn websocket(&mut self) -> &mut Self {
        self.ws = true;
        self
    }
    pub fn add_root_ca(&mut self, v: Vec<u8>) -> &mut Self {
        self.root_ca.push(v);
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
    // pub fn digest_auth(&mut self, b: bool) -> &mut Self {
    //     self.digest = b;
    //     self
    // }
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.chunked_parse = b;
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
    pub fn prev_resp(&mut self, v: Response<Vec<u8>>) -> &mut Self {
        self.presp = Some(v);
        self
    }
}

