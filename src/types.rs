use dns_cache::DnsCache;
use mio::{Poll,Event};
use http::{Request};
use std::time::Duration;
use httpc::PrivHttpc;
use tls_api::{TlsConnector};

pub struct ChunkIndex {
    // offset is num bytes from header
    offset: usize,
}

// read chunk by chunk and move data in buffer as it occurs. 
// does not keep history
impl ChunkIndex {
    pub fn new(hdr: usize) -> ChunkIndex {
        ChunkIndex {
            offset: hdr,
        }
    }

    // Return true if 0 sized chunk found and stream finished.
    pub fn check_done(&mut self, max:usize, b: &[u8]) -> ::Result<bool> {
        let mut off = self.offset;
        // For every chunk, shift bytes back over the NUM\r\n parts
        while off+4 < b.len() {
            let (num,next_off) = self.get_chunk_size(&b[off..])?;
            if num > max {
                return Err(::Error::ChunkOverlimit(num));
            }
            if num == 0 {
                return Ok(true);
            }
            if off + num + next_off + 2 <= b.len() {
                // unsafe {
                //     let src:*const u8 = b.as_ptr().offset((off+next_off) as isize);
                //     let dst:*mut u8 = b.as_mut_ptr().offset(off as isize);
                //     ::std::ptr::copy(src, dst, num);
                // }
                off += num + next_off + 2;
            } else {
                break;
            }
        }
        self.offset = off;
        Ok(false)
    }

    // copy full chunks to dst, move remainder (non-full chunk) back right after hdr.
    pub fn push_to(&mut self, max:usize, hdr:usize, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> ::Result<usize> {
        let mut off = hdr;
        let mut num_copied = 0;
        while off+2 < src.len() {
            let (num,next_off) = self.get_chunk_size(&src[off..])?;
            if off + next_off + num + 2 < src.len() {
                dst.extend(&src[off..off+num]);
                off += next_off+num+2;
                num_copied += next_off+num;
            } else {
                let sl = src.len();
                unsafe {
                    let src_p:*const u8 = src.as_ptr().offset(off as isize);
                    let dst_p:*mut u8 = src.as_mut_ptr().offset(hdr as isize);
                    ::std::ptr::copy(src_p, dst_p, sl-off);
                }
                src.truncate(hdr+sl-off);
                self.offset = hdr;
                break;
            }
        }
        Ok(num_copied)
    }

    fn get_chunk_size(&mut self, b: &[u8]) -> ::Result<(usize,usize)> {
        let blen = b.len();
        let mut num:usize = 0;
        let mut len = 0;
        for i in 0..blen {
            if i+1 < blen && b[i] == b'\r' && b[i+1] == b'\n' {
                len = i+2;
                break;
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
        Ok((num,len))
    }
}

fn ascii_hex_to_num(ch: u8) -> Option<usize>
{
    match ch {
        b'0' ... b'9' if ch < b'0' + 16 => Some((ch - b'0') as usize),
        b'a' ... b'z' if ch < b'a' + 6 => Some((ch - b'a' + 10) as usize),
        b'A' ... b'Z' if ch < b'A' + 6 => Some((ch - b'A' + 10) as usize),
        _ => None,
    }
}

pub struct CallParam<'a> {
    pub poll: &'a Poll,
    pub dns: &'a mut DnsCache,
    // pub con: &'a mut Con,
    pub ev: &'a Event,
}

/// Start configure call.
pub struct PrivCallBuilder {
    pub req: Request<Vec<u8>>,
    pub chunked_parse: bool,
    pub dur: Duration,
    pub max_response: usize,
    pub max_chunk: usize,
}

#[allow(dead_code)]
impl PrivCallBuilder {
    pub fn new(req: Request<Vec<u8>>) -> PrivCallBuilder {
        PrivCallBuilder {
            max_response: 1024*1024*10,
            dur: Duration::from_millis(30000),
            max_chunk: 32*1024,
            req,
            chunked_parse: true,
        }
    }
    pub fn call<C:TlsConnector>(self, httpc: &mut PrivHttpc, poll: &Poll) -> ::Result<::CallId> {
        httpc.call::<C>(self, poll)
    }
    pub fn max_response(&mut self, m: usize) -> &mut Self {
        self.max_response = m;
        self
    }
    pub fn chunked_parse(&mut self, b: bool) -> &mut Self {
        self.chunked_parse = b;
        self
    }
    pub fn chunked_max_chunk(&mut self, v: usize) -> &mut Self {
        self.max_chunk = v;
        self
    }
    pub fn timeout(&mut self, d: Duration) -> &mut Self {
        self.dur = d;
        self
    }
}

