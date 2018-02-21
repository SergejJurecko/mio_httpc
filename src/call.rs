use con::Con;
use mio::Ready;
use std::io::ErrorKind as IoErrorKind;
use tls_api::TlsConnector;
use httparse::{self, Response as ParseResp};
use http::response::Builder as RespBuilder;
use http::{self, Method, Request, Uri, Version};
use http::header::*;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::io::{Read, Write};
use {RecvState, SendState};
use types::*;
use data_encoding::{BASE64, HEXLOWER};
use byteorder::{ByteOrder, LittleEndian};
use std::ascii::AsciiExt;
use md5;
use libflate::gzip::Decoder;

#[derive(PartialEq)]
enum Dir {
    SendingHdr(usize),
    SendingBody(usize),
    // (bytes_rec, duplex)
    Receiving(usize, bool),
    Done,
}

enum TransferEncoding {
    Identity,
    Chunked,
}

pub struct CallImpl {
    b: CallBuilderImpl,
    start: Instant,
    buf: Vec<u8>,
    hdr_sz: usize,
    body_sz: usize,
    dir: Dir,
    chunked: ChunkIndex,
    send_encoding: TransferEncoding,
}

impl CallImpl {
    pub fn new(b: CallBuilderImpl, mut buf: Vec<u8>) -> CallImpl {
        buf.truncate(0);
        CallImpl {
            dir: Dir::SendingHdr(0),
            start: Instant::now(),
            b,
            buf,
            hdr_sz: 0,
            body_sz: 0,
            chunked: ChunkIndex::new(),
            send_encoding: TransferEncoding::Identity,
        }
    }

    pub fn can_retry(&self) -> bool {
        match self.dir {
            Dir::Receiving(sz, _) if sz > 0 => false,
            Dir::Done => false,
            Dir::SendingBody(pos) if pos > 0 && self.b.req.body().len() == 0 => false,
            _ => true,
        }
    }

    pub fn set_retry(&mut self) {
        self.dir = Dir::SendingHdr(0);
    }

    pub fn empty() -> CallImpl {
        let mut res = Self::new(CallBuilderImpl::new(Request::new(Vec::new())), Vec::new());
        res.dir = Dir::Done;
        res
    }

    #[inline]
    pub fn start_time(&self) -> Instant {
        self.start
    }

    pub fn peek_body(&mut self, off: &mut usize) -> &[u8] {
        if self.body_sz > 0 {
            if self.buf.len() > self.hdr_sz + *off {
                // there is some additional data after last offset and hdr
                return &self.buf[self.hdr_sz + (*off)..];
            } else if self.buf.len() > self.hdr_sz {
                // everything after hdr_sz has been processed
                self.buf.truncate(self.hdr_sz);
                *off = 0;
            }
        }
        &[]
    }

    pub fn try_truncate(&mut self, off: &mut usize) {
        if self.body_sz > 0 {
            if self.buf.len() > self.hdr_sz + *off {
                return;
            } else if self.buf.len() > self.hdr_sz {
                // everything after hdr_sz has been processed
                self.buf.truncate(self.hdr_sz);
                *off = 0;
            }
        }
    }

    pub fn settings(&self) -> &CallBuilderImpl {
        &self.b
    }

    pub fn is_done(&self) -> bool {
        self.dir == Dir::Done
    }

    pub fn stop(self) -> (CallBuilderImpl, Vec<u8>) {
        (self.b, self.buf)
    }

    pub fn duration(&self) -> Duration {
        self.start.elapsed()
    }

    fn reserve_space(&mut self, internal: bool, buf: &mut Vec<u8>) -> ::Result<usize> {
        let orig_len = buf.len();
        if internal && self.b.max_response <= orig_len {
            return Err(::Error::ResponseTooBig);
        }
        // Vec will actually reserve on an exponential scale.
        buf.reserve(4096 * 2);
        unsafe {
            let cap = buf.capacity();
            buf.set_len(cap);
        }
        Ok(orig_len)
    }

    fn extend_full_path(buf: &mut Vec<u8>, uri: &Uri) {
        buf.extend(uri.path().as_bytes());
        if let Some(q) = uri.query() {
            buf.extend(b"?");
            buf.extend(q.as_bytes());
        }
    }

    fn fill_send_req(&mut self, buf: &mut Vec<u8>) {
        buf.extend(self.b.req.method().as_str().as_bytes());
        buf.extend(b" ");
        Self::extend_full_path(buf, self.b.req.uri());
        buf.extend(b" HTTP/1.1\r\n");
        for (k, v) in self.b.req.headers().iter() {
            // if k == CONNECTION && self.b.ws {
            //     continue;
            // }
            buf.extend(k.as_str().as_bytes());
            buf.extend(b": ");
            buf.extend(v.as_bytes());
            buf.extend(b"\r\n");
        }
        let cl = self.b.req.headers().get(CONTENT_LENGTH);
        if None == cl && self.b.req.body().len() > 0 {
            let mut ar = [0u8; 15];
            self.body_sz = self.b.req.body().len();
            if let Ok(sz) = ::itoa::write(&mut ar[..], self.body_sz) {
                buf.extend(CONTENT_LENGTH.as_str().as_bytes());
                buf.extend(b": ");
                buf.extend(&ar[..sz]);
                buf.extend(b"\r\n");
            }
        } else if let Some(cl) = cl {
            if let Ok(cl1) = cl.to_str() {
                self.body_sz = usize::from_str(cl1).unwrap();
            }
        }
        if let Some(ref clh) = self.b.req.headers().get(http::header::TRANSFER_ENCODING) {
            if let Ok(clhs) = clh.to_str() {
                if "chunked".eq_ignore_ascii_case(clhs) {
                    self.send_encoding = TransferEncoding::Chunked;
                    self.body_sz = usize::max_value();
                }
            }
        }
        if None == self.b.req.headers().get(USER_AGENT) {
            buf.extend(USER_AGENT.as_str().as_bytes());
            buf.extend(b": ");
            buf.extend((env!("CARGO_PKG_NAME")).as_bytes());
            buf.extend(b" ");
            buf.extend((env!("CARGO_PKG_VERSION")).as_bytes());
            buf.extend(b"\r\n");
        }
        if self.b.gzip {
            buf.extend(ACCEPT_ENCODING.as_str().as_bytes());
            buf.extend(b": gzip\r\n");
        }
        if self.b.ws {
            buf.extend(CONNECTION.as_str().as_bytes());
            buf.extend(b": upgrade\r\n");
            buf.extend(b"upgrade: websocket\r\n");
            buf.extend(b"sec-websocket-key: ");
            let mut ar = [0u8; 16];
            let mut out = [0u8; 32];
            LittleEndian::write_u64(&mut ar, ::rand::random::<u64>());
            LittleEndian::write_u64(&mut ar[8..], ::rand::random::<u64>());
            let enc_len = BASE64.encode_len(ar.len());
            BASE64.encode_mut(&ar, &mut out[..enc_len]);
            buf.extend(&out[..enc_len]);
            buf.extend(b"\r\n");
            buf.extend(b"sec-websocket-version: 13\r\n");
        } else if None == self.b.req.headers().get(CONNECTION) {
            buf.extend(CONNECTION.as_str().as_bytes());
            buf.extend(b": keep-alive\r\n");
        }
        if None == self.b.req.headers().get(HOST) {
            if let Some(h) = self.b.req.uri().host() {
                buf.extend(HOST.as_str().as_bytes());
                buf.extend(b": ");
                buf.extend(h.as_bytes());
                buf.extend(b"\r\n");
            }
        }
        if let Some(auth) = self.b.req.uri().authority_part() {
            let mut auth = auth.as_str().split("@");
            if let Some(first) = auth.next() {
                if auth.next().is_some() {
                    let mut auth = first.split(":");
                    if let Some(us) = auth.next() {
                        if let Some(pw) = auth.next() {
                            if self.b.digest {
                                if self.b.auth.hdr.len() > 0 {
                                    if let Ok(dig) =
                                        ::types::AuthDigest::parse(self.b.auth.hdr.as_str())
                                    {
                                        buf.extend(AUTHORIZATION.as_str().as_bytes());
                                        buf.extend(b": Digest ");
                                        buf.extend(b"username=\"");
                                        buf.extend(us.as_bytes());
                                        buf.extend(b"\", ");
                                        buf.extend(b"realm=\"");
                                        buf.extend(dig.realm.as_bytes());
                                        buf.extend(b"\", ");
                                        if dig.qop != DigestQop::None {
                                            buf.extend(b"qop=");
                                            buf.extend(dig.qop.as_bytes());
                                            buf.extend(b", ");
                                        }
                                        buf.extend(b"uri=\"");
                                        Self::extend_full_path(buf, self.b.req.uri());
                                        buf.extend(b"\", ");
                                        buf.extend(b"opaque=\"");
                                        buf.extend(dig.opaque.as_bytes());
                                        buf.extend(b"\", ");
                                        buf.extend(b"nonce=\"");
                                        buf.extend(dig.nonce.as_bytes());
                                        buf.extend(b"\", ");
                                        let cnoncebin = ::rand::random::<[u8; 32]>();
                                        let mut cnonce = [0u8; 64];
                                        let cnonce_len = BASE64.encode_len(cnoncebin.len());
                                        BASE64.encode_mut(&cnoncebin, &mut cnonce[..cnonce_len]);
                                        buf.extend(b"cnonce=\"");
                                        buf.extend(&cnonce[..cnonce_len]);
                                        buf.extend(b"\", ");
                                        // For now only a single request per www auth data
                                        buf.extend(b"nc=00000001");
                                        // buf.extend(&cnonce[..enc_len]);
                                        buf.extend(b", ");
                                        let mut ha1 = [0u8; 32];
                                        let mut ha2 = [0u8; 32];
                                        let mut md5 = md5::Context::new();
                                        md5.consume(us.as_bytes());
                                        md5.consume(":");
                                        md5.consume(dig.realm.as_bytes());
                                        md5.consume(":");
                                        md5.consume(pw.as_bytes());
                                        let d = md5.compute();
                                        HEXLOWER.encode_mut(&d.0, &mut ha1);
                                        if dig.alg == DigestAlg::MD5Sess {
                                            let mut md5 = md5::Context::new();
                                            md5.consume(&ha1);
                                            md5.consume(":");
                                            md5.consume(dig.nonce.as_bytes());
                                            md5.consume(":");
                                            md5.consume(&cnonce[..cnonce_len]);
                                            let d = md5.compute();
                                            HEXLOWER.encode_mut(&d.0, &mut ha1);
                                        }
                                        if dig.qop == DigestQop::Auth || dig.qop == DigestQop::None
                                        {
                                            let mut md5 = md5::Context::new();
                                            md5.consume(self.b.req.method().as_str().as_bytes());
                                            md5.consume(":");
                                            md5.consume(self.b.req.uri().path().as_bytes());
                                            if let Some(q) = self.b.req.uri().query() {
                                                md5.consume(b"?");
                                                md5.consume(q.as_bytes());
                                            }
                                            let d = md5.compute();
                                            HEXLOWER.encode_mut(&d.0, &mut ha2);
                                        }
                                        let mut md5 = md5::Context::new();
                                        md5.consume(&ha1);
                                        md5.consume(":");
                                        md5.consume(dig.nonce.as_bytes());
                                        if dig.qop != DigestQop::None {
                                            md5.consume(":00000001:");
                                            md5.consume(&cnonce[..cnonce_len]);
                                            md5.consume(":");
                                            md5.consume(dig.qop.as_bytes());
                                        }
                                        md5.consume(":");
                                        md5.consume(&ha2);
                                        let d = md5.compute();
                                        HEXLOWER.encode_mut(&d.0, &mut ha1);
                                        buf.extend(b"response=\"");
                                        buf.extend(&ha1);
                                        buf.extend(b"\"\r\n");
                                    }
                                }
                            } else {
                                buf.extend(AUTHORIZATION.as_str().as_bytes());
                                buf.extend(b": Basic ");
                                let enc_len = BASE64.encode_len(us.len() + 1 + pw.len());
                                if BASE64.encode_len(us.len() + 1 + pw.len()) < 512 {
                                    let mut ar = [0u8; 512];
                                    let mut out = [0u8; 512];
                                    (&mut ar[..us.len()]).copy_from_slice(us.as_bytes());
                                    (&mut ar[us.len()..us.len() + 1]).copy_from_slice(b":");
                                    (&mut ar[us.len() + 1..us.len() + 1 + pw.len()])
                                        .copy_from_slice(pw.as_bytes());
                                    BASE64.encode_mut(
                                        &ar[..us.len() + 1 + pw.len()],
                                        &mut out[..enc_len],
                                    );
                                    buf.extend(&out[..enc_len]);
                                    buf.extend(b"\r\n");
                                }
                            }
                        }
                    }
                }
            }
        }
        buf.extend(b"\r\n");
        self.hdr_sz = buf.len();
    }

    pub fn event_send<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        b: Option<&[u8]>,
    ) -> ::Result<SendState> {
        match self.dir {
            Dir::Done => {
                return Ok(SendState::Done);
            }
            Dir::Receiving(_, false) => return Ok(SendState::Receiving),
            Dir::Receiving(_, true) => {
                if let Some(b) = b {
                    self.event_send_do::<C>(con, cp, 0, b)
                } else {
                    Ok(SendState::WaitReqBody)
                }
            }
            Dir::SendingHdr(pos) => {
                let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                if self.hdr_sz == 0 {
                    self.fill_send_req(&mut buf);
                }
                let hdr_sz = self.hdr_sz;

                let ret = self.event_send_do::<C>(con, cp, 0, &buf[pos..hdr_sz]);
                // println!("TrySent: {}", String::from_utf8(buf.clone())?);
                self.buf = buf;
                if let Dir::SendingBody(_) = self.dir {
                    self.buf.truncate(0);
                    // go again
                    return self.event_send::<C>(con, cp, b);
                } else if let Dir::Receiving(_, _) = self.dir {
                    self.buf.truncate(0);
                }
                ret
            }
            Dir::SendingBody(pos) if self.b.req.body().len() > 0 => {
                self.event_send_do::<C>(con, cp, pos, &[])
            }
            Dir::SendingBody(_pos) if b.is_some() => {
                let b = b.unwrap();
                self.event_send_do::<C>(con, cp, 0, &b[..])
            }
            Dir::SendingBody(_) => Ok(SendState::WaitReqBody), // _ => {
                                                               //     Ok(SendState::WaitReqBody)
                                                               // }
        }
    }

    fn maybe_gunzip(&self, buf: Vec<u8>) -> ::Result<Vec<u8>> {
        if self.b.gzip {
            let mut d = Decoder::new(&buf[..])?;
            let mut buf = Vec::new();
            d.read_to_end(&mut buf)?;
            return Ok(buf);
        }
        Ok(buf)
    }

    pub(crate) fn event_recv<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        b: Option<&mut Vec<u8>>,
    ) -> ::Result<RecvStateInt> {
        match self.dir {
            Dir::Done => {
                return Ok(RecvStateInt::Done);
            }
            Dir::Receiving(rec_pos, _) => {
                if self.hdr_sz == 0 || b.is_none() || self.b.chunked_parse || self.b.gzip {
                    let mut buf = ::std::mem::replace(&mut self.buf, Vec::new());
                    // Have we already received everything?
                    // Move body data to beginning of buffer
                    // and return with body.
                    if rec_pos > 0 && rec_pos >= self.body_sz {
                        unsafe {
                            let src: *const u8 = buf.as_ptr().offset(self.hdr_sz as isize);
                            let dst: *mut u8 = buf.as_mut_ptr();
                            ::std::ptr::copy(src, dst, self.body_sz);
                        }
                        buf.truncate(self.body_sz);
                        return Ok(RecvStateInt::DoneWithBody(self.maybe_gunzip(buf)?));
                    }
                    let mut ret = self.event_rec_do::<C>(con, cp, true, &mut buf);

                    if self.b.chunked_parse && self.hdr_sz > 0 {
                        match ret {
                            Err(_) => {}
                            // Ok(RecvStateInt::Error(_)) => {}
                            Ok(RecvStateInt::Response(_, _)) => {}
                            _ if b.is_some() && !self.b.gzip => {
                                let b = b.unwrap();
                                let nc = self.chunked.push_to(self.hdr_sz, &mut buf, b)?;
                                if nc == 0 {
                                    ret = Ok(RecvStateInt::Wait);
                                } else {
                                    ret = Ok(RecvStateInt::ReceivedBody(nc));
                                }
                            }
                            _ if Dir::Done == self.dir => {
                                let mut b = Vec::with_capacity(buf.len());
                                self.chunked.push_to(self.hdr_sz, &mut buf, &mut b)?;
                                ret = Ok(RecvStateInt::DoneWithBody(self.maybe_gunzip(b)?));
                            }
                            _ => {}
                        }
                    }
                    self.buf = buf;
                    ret
                } else {
                    let mut b = b.unwrap();
                    // Can we copy anything from internal buffer to
                    // a client provided one?
                    if self.buf.len() > self.hdr_sz {
                        (&mut b).extend(&self.buf[self.hdr_sz..]);
                        if rec_pos >= self.body_sz {
                            self.dir = Dir::Done;
                            return Ok(RecvStateInt::ReceivedBody(self.buf.len() - self.hdr_sz));
                        }
                        self.buf.truncate(self.hdr_sz);
                    }
                    self.event_rec_do::<C>(con, cp, false, b)
                }
            }
            Dir::SendingBody(_) => Ok(RecvStateInt::Sending),
            Dir::SendingHdr(_) => Ok(RecvStateInt::Sending),
        }
    }

    fn event_send_do<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        in_pos: usize,
        b: &[u8],
    ) -> ::Result<SendState> {
        con.signalled::<C, Vec<u8>>(cp, &self.b.req)?;
        // if !self.con.ready.is_writable() {
        //     return Ok(SendState::Nothing);
        // }
        let mut io_ret;
        loop {
            if b.len() > 0 {
                io_ret = con.write(&b[in_pos..]);
            } else {
                io_ret = con.write(&self.b.req.body()[in_pos..]);
            }
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::NotConnected {
                        return Ok(SendState::Wait);
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        con.reg(cp.poll, Ready::writable())?;
                        return Ok(SendState::Wait);
                    } else {
                        return Err(::Error::Closed);
                    }
                }
                &Ok(sz) if sz > 0 => {
                    if let Dir::SendingHdr(pos) = self.dir {
                        if self.hdr_sz == pos + sz {
                            if self.body_sz > 0 {
                                self.dir = Dir::SendingBody(0);
                                return Ok(SendState::Wait);
                            } else {
                                self.hdr_sz = 0;
                                self.body_sz = 0;
                                self.dir = Dir::Receiving(0, false);
                                return Ok(SendState::Receiving);
                            }
                        } else {
                            self.dir = Dir::SendingHdr(pos + sz);
                            return Ok(SendState::Wait);
                        }
                    } else if let Dir::SendingBody(pos) = self.dir {
                        if self.body_sz == pos + sz {
                            self.hdr_sz = 0;
                            self.body_sz = 0;
                            self.dir = Dir::Receiving(0, false);
                            return Ok(SendState::Receiving);
                        }
                        self.dir = Dir::SendingBody(pos + sz);
                        return Ok(SendState::SentBody(pos + sz));
                    } else {
                        return Ok(SendState::SentBody(sz));
                    }
                }
                _ => {
                    return Err(::Error::Closed);
                }
            }
        }
    }

    fn event_rec_do<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        internal: bool,
        buf: &mut Vec<u8>,
    ) -> ::Result<RecvStateInt> {
        let mut orig_len = self.reserve_space(internal, buf)?;
        let mut io_ret;
        let mut entire_sz = 0;
        con.signalled::<C, Vec<u8>>(cp, &self.b.req)?;
        // if !self.con.ready.is_readable() {
        //     return Ok(RecvState::Nothing);
        // }
        loop {
            io_ret = con.read(&mut buf[orig_len..]);
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        buf.truncate(orig_len);
                        con.reg(cp.poll, Ready::readable())?;
                        if entire_sz == 0 {
                            return Ok(RecvStateInt::Wait);
                        }
                        break;
                    }
                }
                &Ok(sz) if sz > 0 => {
                    entire_sz += sz;
                    if buf.len() == orig_len + sz {
                        orig_len = self.reserve_space(internal, buf)?;
                        continue;
                    }
                    buf.truncate(orig_len + sz);
                }
                _ => {}
            }
            break;
        }
        if entire_sz > 0 {
            io_ret = Ok(entire_sz);
        }
        match io_ret {
            Ok(0) => {
                return Err(::Error::Closed);
            }
            Ok(bytes_rec) => {
                if self.hdr_sz == 0 {
                    let mut headers = [httparse::EMPTY_HEADER; 32];
                    let mut presp = ParseResp::new(&mut headers);
                    println!("Got: {}", String::from_utf8(buf.clone())?);
                    let buflen = buf.len();
                    match presp.parse(buf) {
                        Ok(httparse::Status::Complete(hdr_sz)) => {
                            self.hdr_sz = hdr_sz;
                            let mut b = RespBuilder::new();
                            for h in presp.headers.iter() {
                                b.header(h.name, h.value);
                            }
                            if let Some(status) = presp.code {
                                b.status(status);
                            }
                            if let Some(v) = presp.version {
                                if v == 0 {
                                    b.version(Version::HTTP_10);
                                } else if v == 1 {
                                    b.version(Version::HTTP_11);
                                }
                            }
                            let resp = b.body(Vec::new())?;
                            if let Some(ref clh) = resp.headers().get(http::header::CONTENT_LENGTH)
                            {
                                if let Ok(clhs) = clh.to_str() {
                                    if let Ok(bsz) = usize::from_str(clhs) {
                                        self.body_sz = bsz;
                                    }
                                }
                            }
                            if let Some(ref clh) = resp.headers().get(http::header::CONNECTION) {
                                if let Ok(clhs) = clh.to_str() {
                                    if "close".eq_ignore_ascii_case(clhs) {
                                        con.set_to_close(true);
                                    }
                                }
                            }
                            if let Some(ref clh) =
                                resp.headers().get(http::header::CONTENT_ENCODING)
                            {
                                if let Ok(clhs) = clh.to_str() {
                                    if !"gzip".eq_ignore_ascii_case(clhs) {
                                        self.b.gzip = false;
                                    } else {
                                        self.b.gzip = true;
                                    }
                                } else {
                                    self.b.gzip = false;
                                }
                            } else {
                                self.b.gzip = false;
                            }
                            if let Some(ref clh) =
                                resp.headers().get(http::header::TRANSFER_ENCODING)
                            {
                                if let Ok(clhs) = clh.to_str() {
                                    if "chunked".eq_ignore_ascii_case(clhs) {
                                        self.body_sz = usize::max_value();
                                    } else {
                                        self.b.chunked_parse = false;
                                    }
                                } else {
                                    self.b.chunked_parse = false;
                                }
                            } else {
                                self.b.chunked_parse = false;
                            }

                            let status_code = resp.status().as_u16();
                            let auth_info = if status_code == 401 {
                                if let Some(ref clh) =
                                    resp.headers().get(http::header::WWW_AUTHENTICATE)
                                {
                                    if let Ok(s) = clh.to_str() {
                                        let mut auth_type = s.split_whitespace();
                                        if let Some(auth_type) = auth_type.next() {
                                            if auth_type.eq_ignore_ascii_case("digest") {
                                                if ::types::AuthDigest::parse(s).is_ok() {
                                                    self.dir == Dir::Done;
                                                    Some(AuthenticateInfo::new(String::from(s)))
                                                // return Ok(RecvStateInt::DigestAuth(resp,::AuthenticateInfo::new(String::from(s))));
                                                } else {
                                                    None
                                                }
                                            } else if auth_type.eq_ignore_ascii_case("basic")
                                                && self.b.digest
                                            {
                                                return Ok(RecvStateInt::BasicAuth);
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(auth_info) = auth_info {
                                return Ok(RecvStateInt::DigestAuth(resp, auth_info));
                            }
                            // If switching protocols body is unlimited
                            if status_code == 101 {
                                con.set_to_close(true);
                                self.body_sz = usize::max_value();
                                self.dir = Dir::Receiving(buflen - self.hdr_sz, true);
                                return Ok(RecvStateInt::Response(resp, ::ResponseBody::Streamed));
                            } else if status_code >= 300 && status_code < 400 {
                                return Ok(RecvStateInt::Redirect(resp));
                            // if let Some(ref clh) = resp.headers().get(http::header::LOCATION) {
                            //     if let Ok(s) = clh.to_str() {
                            //     }
                            // }
                            } else if self.body_sz == 0 {
                                self.dir == Dir::Done;
                            } else {
                                self.dir = Dir::Receiving(buflen - self.hdr_sz, false);
                            }
                            if self.b.chunked_parse {
                                if self.chunked
                                    .check_done(self.b.max_chunk, &buf[self.hdr_sz..])?
                                {
                                    self.dir = Dir::Done;
                                }
                                return Ok(RecvStateInt::Response(resp, ::ResponseBody::Streamed));
                            } else {
                                return Ok(RecvStateInt::Response(
                                    resp,
                                    ::ResponseBody::Sized(self.body_sz),
                                ));
                            }
                        }
                        Ok(httparse::Status::Partial) => {
                            return Ok(RecvStateInt::Wait);
                        }
                        Err(e) => {
                            return Err(From::from(e));
                        }
                    }
                } else {
                    let (pos, duplex) = if let Dir::Receiving(pos, duplex) = self.dir {
                        (pos, duplex)
                    } else {
                        (0, false)
                    };

                    // do not set done if internal
                    // This way next call will be either copied to provided buffer or returned.
                    if pos + bytes_rec >= self.body_sz && !internal {
                        self.dir = Dir::Done;
                    } else {
                        let mut chunked_done = false;
                        if self.b.chunked_parse {
                            if self.chunked
                                .check_done(self.b.max_chunk, &buf[self.hdr_sz..])?
                            {
                                chunked_done = true;
                                self.dir = Dir::Done;
                            }
                        }
                        if !chunked_done {
                            self.dir = Dir::Receiving(pos + bytes_rec, duplex);
                        }
                    }
                    return Ok(RecvStateInt::ReceivedBody(bytes_rec));
                }
            }
            Err(e) => {
                return Err(From::from(e));
            }
        }
    }
}
