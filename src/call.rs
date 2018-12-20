use byteorder::{ByteOrder, LittleEndian};
use connection::Con;
use data_encoding::{BASE64, HEXLOWER};
use httparse::{self, Response as ParseResp};
use libflate::gzip::Decoder;
use md5;
use mio::Ready;
use std::io::ErrorKind as IoErrorKind;
use std::io::{Read, Write};
use std::str::from_utf8;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tls_api::TlsConnector;
use types::*;

#[derive(PartialEq, Debug)]
enum Dir {
    SendingHdr(usize),
    SendingBody(usize),
    // (bytes_rec, duplex)
    Receiving(usize, bool),
    Done,
}

pub(crate) struct CallImpl {
    call_id: u64,
    b: CallBuilderImpl,
    start: Instant,
    buf_hdr: Vec<u8>,
    buf_body: Vec<u8>,
    hdr_sz: usize,
    body_sz: usize,
    dir: Dir,
    chunked: ChunkIndex,
    send_encoding: TransferEncoding,
}

impl CallImpl {
    pub fn new(
        call_id: u64,
        b: CallBuilderImpl,
        mut buf_hdr: Vec<u8>,
        mut buf_body: Vec<u8>,
    ) -> CallImpl {
        buf_hdr.truncate(0);
        buf_body.truncate(0);
        CallImpl {
            call_id,
            dir: Dir::SendingHdr(0),
            start: Instant::now(),
            b,
            buf_hdr,
            buf_body,
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
            Dir::SendingBody(pos) if pos > 0 && self.b.body.len() == 0 => false,
            _ => true,
        }
    }

    pub fn call_id(&self) -> u64 {
        self.call_id
    }

    // pub fn empty() -> CallImpl {
    //     let mut res = Self::new(CallBuilderImpl::new(), Vec::new(), Vec::new());
    //     res.dir = Dir::Done;
    //     res
    // }

    #[inline]
    pub fn start_time(&self) -> Instant {
        self.start
    }

    pub fn peek_body(&mut self, off: &mut usize) -> &[u8] {
        if self.body_sz > 0 {
            if self.buf_body.len() > *off {
                // there is some additional data after last offset
                // let diff = self.buf_body.len() - *off;
                // Copy down bytes so buffer does not grow unnecessarily.
                // This can happen if lots of data is being sent in websocket
                // over localhost as it does not give client enough time to clear data.
                if *off > 1024 * 1024 {
                    // unsafe {
                    //     ::std::ptr::copy(
                    //         self.buf_body.as_ptr().offset(*off as _),
                    //         self.buf_body.as_mut_ptr(),
                    //         diff,
                    //     );
                    // }
                    // self.buf_body.truncate(diff);
                    self.buf_body.drain(..*off);
                    *off = 0;
                }
                return &self.buf_body[(*off)..];
            } else if self.buf_body.len() > 0 {
                self.truncate();
                *off = 0;
            }
        }
        &[]
    }

    fn truncate(&mut self) {
        // If we had to grow to an unusually large size shrink it down to something managable.
        if self.buf_body.len() > 1024 * 1024 {
            self.buf_body.truncate(1024 * 1024);
            self.buf_body.shrink_to_fit();
        }
        self.buf_body.truncate(0);
    }

    pub fn try_truncate(&mut self, off: &mut usize) {
        if self.body_sz > 0 {
            if self.buf_body.len() > *off {
                return;
            } else if self.buf_body.len() > 0 {
                // everything after hdr_sz has been processed
                self.truncate();
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

    pub fn stop(self) -> (CallBuilderImpl, Vec<u8>, Vec<u8>) {
        (self.b, self.buf_hdr, self.buf_body)
    }

    // pub fn duration(&self) -> Duration {
    //     self.start.elapsed()
    // }

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

    // fn extend_full_path(buf: &mut Vec<u8>, uri: &Uri) {
    //     buf.extend(uri.path().as_bytes());
    //     if let Some(q) = uri.query() {
    //         buf.extend(b"?");
    //         buf.extend(q.as_bytes());
    //     }
    // }

    fn fill_send_req(&mut self, buf: &mut Vec<u8>) {
        buf.extend(self.b.method.as_str().as_bytes());
        buf.extend(b" ");
        // Self::extend_full_path(buf, self.b.req.uri());
        buf.extend(&self.b.bytes.path);
        buf.extend(&self.b.bytes.query);
        buf.extend(b" HTTP/1.1\r\n");
        buf.extend(&self.b.bytes.headers);
        // let cl = self.b.req.headers().get(CONTENT_LENGTH);
        let cl = self.b.content_len_set;
        if cl == false && self.b.body.len() > 0 {
            self.body_sz = self.b.body.len();
        // digest auth requires www-authenticate response first
        // and one must not send send data for that
        } else if cl && !(self.b.digest && self.b.auth.hdr.len() == 0) {
            self.body_sz = self.b.content_len;
        }
        if self.body_sz > 0 {
            let mut ar = [0u8; 15];
            if let Ok(sz) = ::itoa::write(&mut ar[..], self.body_sz) {
                buf.extend(b"Content-Length: ");
                buf.extend(&ar[..sz]);
                buf.extend(b"\r\n");
            }
        }
        if self.b.transfer_encoding == TransferEncoding::Chunked {
            self.send_encoding = TransferEncoding::Chunked;
            self.body_sz = usize::max_value();
        }
        if self.b.ua_set == false {
            // buf.extend(USER_AGENT.as_str().as_bytes());
            buf.extend(b"User-Agent");
            buf.extend(b": ");
            buf.extend((env!("CARGO_PKG_NAME")).as_bytes());
            buf.extend(b" ");
            buf.extend((env!("CARGO_PKG_VERSION")).as_bytes());
            buf.extend(b"\r\n");
        }
        if self.b.gzip && !self.b.ws {
            // buf.extend(ACCEPT_ENCODING.as_str().as_bytes());
            buf.extend(b"Accept-Encoding: gzip\r\n");
        }
        if self.b.ws {
            buf.extend(b"Connection: upgrade\r\n");
            buf.extend(b"Upgrade: websocket\r\n");
            buf.extend(b"Sec-Websocket-Key: ");
            let mut ar = [0u8; 16];
            let mut out = [0u8; 32];
            LittleEndian::write_u64(&mut ar, ::rand::random::<u64>());
            LittleEndian::write_u64(&mut ar[8..], ::rand::random::<u64>());
            let enc_len = BASE64.encode_len(ar.len());
            BASE64.encode_mut(&ar, &mut out[..enc_len]);
            buf.extend(&out[..enc_len]);
            buf.extend(b"\r\n");
            buf.extend(b"Sec-Websocket-Version: 13\r\n");
        } else if self.b.con_set == false {
            buf.extend(b"Connection: keep-alive\r\n");
        }
        if self.b.host_set == false {
            buf.extend(b"Host: ");
            buf.extend(&self.b.bytes.host);
            buf.extend(b"\r\n");
        }
        if self.b.digest && self.b.bytes.us.len() > 0 {
            if self.b.auth.hdr.len() > 0 {
                if let Ok(dig) = ::types::AuthDigest::parse(self.b.auth.hdr.as_str()) {
                    buf.extend(b"Authorization: Digest ");
                    buf.extend(b"username=\"");
                    buf.extend(&self.b.bytes.us);
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
                    // Self::extend_full_path(buf, self.b.req.uri());
                    buf.extend(&self.b.bytes.path);
                    buf.extend(&self.b.bytes.query);
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
                    md5.consume(&self.b.bytes.us);
                    md5.consume(":");
                    md5.consume(dig.realm.as_bytes());
                    md5.consume(":");
                    md5.consume(&self.b.bytes.pw);
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
                    if dig.qop == DigestQop::Auth || dig.qop == DigestQop::None {
                        let mut md5 = md5::Context::new();
                        md5.consume(self.b.method.as_str().as_bytes());
                        md5.consume(":");
                        md5.consume(&self.b.bytes.path);
                        md5.consume(&self.b.bytes.query);
                        // if let Some(q) = self.b.req.uri().query() {
                        //     md5.consume(b"?");
                        //     md5.consume(q.as_bytes());
                        // }
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
        } else if self.b.bytes.us.len() > 0 {
            buf.extend(b"Authorization: Basic ");
            let uslen = self.b.bytes.us.len();
            let pwlen = self.b.bytes.pw.len();
            let enc_len = BASE64.encode_len(uslen + 1 + pwlen);
            if BASE64.encode_len(uslen + 1 + pwlen) < 512 {
                let mut ar = [0u8; 512];
                let mut out = [0u8; 512];
                (&mut ar[..uslen]).copy_from_slice(&self.b.bytes.us);
                (&mut ar[uslen..uslen + 1]).copy_from_slice(b":");
                (&mut ar[uslen + 1..uslen + 1 + pwlen]).copy_from_slice(&self.b.bytes.pw);
                BASE64.encode_mut(&ar[..uslen + 1 + pwlen], &mut out[..enc_len]);
                buf.extend(&out[..enc_len]);
                buf.extend(b"\r\n");
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
    ) -> ::Result<SendStateInt> {
        match self.dir {
            Dir::Done => {
                return Ok(SendStateInt::Done);
            }
            Dir::Receiving(_, false) => return Ok(SendStateInt::Receiving),
            Dir::Receiving(_, true) => {
                if let Some(b) = b {
                    self.event_send_do::<C>(con, cp, 0, b)
                } else {
                    Ok(SendStateInt::WaitReqBody)
                }
            }
            Dir::SendingHdr(pos) => {
                let mut buf = ::std::mem::replace(&mut self.buf_hdr, Vec::new());
                if self.hdr_sz == 0 {
                    self.fill_send_req(&mut buf);
                }
                let hdr_sz = self.hdr_sz;

                let ret = self.event_send_do::<C>(con, cp, 0, &buf[pos..hdr_sz]);
                // println!("TrySent ({:?}): {}", ret, String::from_utf8(buf.clone())?);
                self.buf_hdr = buf;
                if let Dir::SendingBody(_) = self.dir {
                    self.buf_hdr.truncate(0);
                    // go again
                    return self.event_send::<C>(con, cp, b);
                } else if let Dir::Receiving(_, _) = self.dir {
                    self.buf_hdr.truncate(0);
                }
                ret
            }
            Dir::SendingBody(pos) if self.b.body.len() > 0 => {
                self.event_send_do::<C>(con, cp, pos, &[])
            }
            Dir::SendingBody(_pos) if b.is_some() => {
                let b = b.unwrap();
                self.event_send_do::<C>(con, cp, 0, &b[..])
            }
            Dir::SendingBody(_) => Ok(SendStateInt::WaitReqBody),
        }
    }

    fn maybe_gunzip(&self, inbuf: Vec<u8>, extbuf: Option<&mut Vec<u8>>) -> ::Result<Vec<u8>> {
        if self.b.gzip {
            let mut out = Vec::new();
            let mut d = Decoder::new(&inbuf[..])?;
            if let Some(ext) = extbuf {
                d.read_to_end(ext)?;
                return Ok(out);
            } else {
                d.read_to_end(&mut out)?;
                return Ok(out);
            }
        }
        Ok(inbuf)
    }

    pub(crate) fn event_recv<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        b: Option<&mut Vec<u8>>,
    ) -> ::Result<RecvStateInt> {
        match self.dir {
            Dir::Done if self.buf_body.len() == 0 => {
                return Ok(RecvStateInt::Done);
            }
            Dir::SendingBody(_) => Ok(RecvStateInt::Sending),
            Dir::SendingHdr(_) => Ok(RecvStateInt::Sending),
            _ => {
                let rec_pos = if let Dir::Receiving(rec_pos, _) = self.dir {
                    rec_pos
                } else {
                    self.buf_body.len()
                };
                if self.hdr_sz == 0 || b.is_none() || self.b.chunked_parse || self.b.gzip {
                    let (mut buf, is_hdr) = if self.hdr_sz == 0 {
                        (::std::mem::replace(&mut self.buf_hdr, Vec::new()), true)
                    } else {
                        (::std::mem::replace(&mut self.buf_body, Vec::new()), false)
                    };
                    // Have we already received everything?
                    // Move body data to beginning of buffer
                    // and return with body.
                    if rec_pos > 0 && rec_pos >= self.body_sz {
                        buf.truncate(self.body_sz);
                        if b.is_some() {
                            let mut b = b.unwrap();
                            let len_pre = b.len();
                            self.maybe_gunzip(buf, Some(b))?;
                            self.dir = Dir::Done;
                            return Ok(RecvStateInt::ReceivedBody(b.len() - len_pre));
                        } else {
                            return Ok(RecvStateInt::DoneWithBody(self.maybe_gunzip(buf, None)?));
                        }
                    }
                    let mut ret = if self.dir != Dir::Done {
                        self.event_rec_do::<C>(con, cp, true, &mut buf)
                    } else {
                        // if we are done and here, this is really only for chunked parse
                        Ok(RecvStateInt::Done)
                    };
                    if self.b.chunked_parse && self.hdr_sz > 0 {
                        match ret {
                            Err(_) => {}
                            Ok(RecvStateInt::Response(_, _)) => {}
                            _ if b.is_some() && !self.b.gzip && Dir::Done != self.dir => {
                                let b = b.unwrap();
                                let nc = self.chunked.push_to(0, &mut buf, b)?;
                                if nc == 0 {
                                    ret = Ok(RecvStateInt::Wait);
                                } else {
                                    ret = Ok(RecvStateInt::ReceivedBody(nc));
                                }
                            }
                            _ if Dir::Done == self.dir && b.is_none() => {
                                let mut chunkless = Vec::with_capacity(buf.len());
                                self.chunked.push_to(0, &mut buf, &mut chunkless)?;
                                ret = Ok(RecvStateInt::DoneWithBody(
                                    self.maybe_gunzip(chunkless, None)?,
                                ));
                            }
                            _ if Dir::Done == self.dir => {
                                let b = b.unwrap();
                                let len_pre = b.len();
                                if self.b.gzip {
                                    let mut chunkless = Vec::with_capacity(buf.len());
                                    self.chunked.push_to(0, &mut buf, &mut chunkless)?;
                                    self.maybe_gunzip(chunkless, Some(b))?;
                                } else {
                                    self.chunked.push_to(0, &mut buf, b)?;
                                };
                                return Ok(RecvStateInt::ReceivedBody(b.len() - len_pre));
                            }
                            _ => {}
                        }
                    }
                    if is_hdr {
                        self.buf_hdr = buf;
                    } else {
                        self.buf_body = buf;
                    }
                    ret
                } else {
                    let mut b = b.unwrap();
                    // Can we copy anything from internal buffer to
                    // a client provided one?
                    if self.buf_body.len() > 0 {
                        (&mut b).extend(&self.buf_body[..]);
                        if rec_pos >= self.body_sz {
                            self.dir = Dir::Done;
                            return Ok(RecvStateInt::ReceivedBody(self.buf_body.len()));
                        }
                        self.truncate();
                    }
                    self.event_rec_do::<C>(con, cp, false, b)
                }
            }
        }
    }

    fn event_send_do<C: TlsConnector>(
        &mut self,
        con: &mut Con,
        cp: &mut CallParam,
        in_pos: usize,
        b: &[u8],
    ) -> ::Result<SendStateInt> {
        if !con.is_signalled_wr() {
            return Ok(SendStateInt::Wait);
        }
        con.signalled::<C, Vec<u8>>(cp).map_err(|e| {
            con.set_to_close(true);
            e
        })?;
        // if !self.con.ready.is_writable() {
        //     return Ok(SendState::Nothing);
        // }
        let mut io_ret;
        loop {
            if b.len() > 0 {
                io_ret = con.write(&b[in_pos..]);
            } else {
                io_ret = con.write(&self.b.body[in_pos..]);
            }
            match &io_ret {
                &Err(ref ie) => {
                    if ie.kind() == IoErrorKind::Interrupted {
                        continue;
                    } else if ie.kind() == IoErrorKind::NotConnected {
                        return Ok(SendStateInt::Wait);
                    } else if ie.kind() == IoErrorKind::WouldBlock {
                        con.reg(cp.poll, Ready::writable())?;
                        return Ok(SendStateInt::Wait);
                    } else {
                        return Err(::Error::Closed);
                    }
                }
                &Ok(sz) if sz > 0 => {
                    if let Dir::SendingHdr(pos) = self.dir {
                        if self.hdr_sz == pos + sz {
                            if self.body_sz > 0 {
                                self.dir = Dir::SendingBody(0);
                                return Ok(SendStateInt::Wait);
                            } else {
                                self.hdr_sz = 0;
                                self.body_sz = 0;
                                self.dir = Dir::Receiving(0, false);
                                return Ok(SendStateInt::Receiving);
                            }
                        } else {
                            self.dir = Dir::SendingHdr(pos + sz);
                            return Ok(SendStateInt::Wait);
                        }
                    } else if let Dir::SendingBody(pos) = self.dir {
                        if self.body_sz == pos + sz {
                            self.hdr_sz = 0;
                            self.body_sz = 0;
                            self.dir = Dir::Receiving(0, false);
                            return Ok(SendStateInt::Receiving);
                        }
                        self.dir = Dir::SendingBody(pos + sz);
                        return Ok(SendStateInt::SentBody(sz));
                    } else {
                        return Ok(SendStateInt::SentBody(sz));
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
        if !con.is_signalled_rd() {
            return Ok(RecvStateInt::Wait);
        }
        let mut orig_len = self.reserve_space(internal, buf)?;
        let mut io_ret;
        let mut entire_sz = 0;
        con.signalled::<C, Vec<u8>>(cp).map_err(|e| {
            con.set_to_close(true);
            e
        })?;
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
                // if let Ok(sx) = String::from_utf8(Vec::from(&buf[..entire_sz])) {
                //     println!("Got: {}", sx);
                // }
                // println!("Got: {:?}", &buf[..bytes_rec]);
                if self.hdr_sz == 0 {
                    let mut auth_info = None;
                    let mut resp = ::Response::new();
                    // if let Ok(sx) = String::from_utf8(Vec::from(&buf[0..60])) {
                    //     println!("Got: {}", sx);
                    // }
                    match self.read_hdr(con, buf, &mut resp, &mut auth_info) {
                        Ok(()) => {
                            if self.hdr_sz == 0 {
                                return Ok(RecvStateInt::Wait);
                            }
                            buf.truncate(self.hdr_sz);
                            ::std::mem::swap(&mut resp.hdrs, buf);

                            if resp.status == 401 {
                                if let Some(auth) = auth_info {
                                    return Ok(RecvStateInt::DigestAuth(resp, auth));
                                } else if self.b.digest {
                                    return Ok(RecvStateInt::BasicAuth);
                                }
                            }
                            if resp.status == 101 {
                                return Ok(RecvStateInt::Response(resp, ::ResponseBody::Streamed));
                            } else if resp.status >= 300 && resp.status < 400 {
                                return Ok(RecvStateInt::Redirect(resp));
                            }
                            if self.b.chunked_parse {
                                return Ok(RecvStateInt::Response(resp, ::ResponseBody::Streamed));
                            } else {
                                return Ok(RecvStateInt::Response(
                                    resp,
                                    ::ResponseBody::Sized(self.body_sz),
                                ));
                            }
                        }
                        Err(e) => {
                            return Err(e);
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
                            if self.chunked.check_done(self.b.max_chunk, &buf)? {
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
                if let Dir::Receiving(_pos, false) = self.dir {
                    // If we do not know content-length and it is not chunked, return normal done response.
                    if self.body_sz == usize::max_value() && !self.b.chunked_parse {
                        self.dir = Dir::Done;
                        con.set_to_close(true);
                        return Ok(RecvStateInt::Done);
                    }
                }
                return Err(From::from(e));
            }
        }
    }

    fn read_hdr(
        &mut self,
        con: &mut Con,
        buf: &mut Vec<u8>,
        resp: &mut ::Response,
        auth_info: &mut Option<AuthenticateInfo>,
    ) -> ::Result<()> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut presp = ParseResp::new(&mut headers);
        let buflen = buf.len();
        match presp.parse(buf) {
            Ok(httparse::Status::Complete(hdr_sz)) => {
                self.hdr_sz = hdr_sz;
                if hdr_sz < buflen {
                    self.buf_body.extend_from_slice(&buf[hdr_sz..]);
                }
                resp.status = presp.code.unwrap_or(0);
                if resp.status == 204
                    || resp.status == 304
                    || resp.status >= 100 && resp.status < 200
                    || self.b.method == Method::HEAD
                {
                    self.body_sz = 0;
                } else {
                    self.body_sz = usize::max_value();
                }
                let mut chunked_parse = false;
                let mut gzip = false;
                for h in presp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        if let Ok(val) = from_utf8(h.value) {
                            if let Ok(bsz) = usize::from_str(val) {
                                self.body_sz = bsz;
                            }
                        }
                    } else if h.name.eq_ignore_ascii_case("connection") {
                        if let Ok(val) = from_utf8(h.value) {
                            if val.eq_ignore_ascii_case("close") {
                                con.set_to_close(true);
                            }
                        }
                    } else if h.name.eq_ignore_ascii_case("content-encoding") {
                        if let Ok(val) = from_utf8(h.value) {
                            if val.eq_ignore_ascii_case("gzip") {
                                gzip = true;
                            }
                        }
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        if let Ok(val) = from_utf8(h.value) {
                            if val.eq_ignore_ascii_case("chunked") {
                                self.body_sz = usize::max_value();
                                chunked_parse = true;
                            }
                        }
                    } else if h.name.eq_ignore_ascii_case("upgrade") {
                        if let Ok(val) = from_utf8(h.value) {
                            if val.eq_ignore_ascii_case("websocket") {
                                resp.ws = true;
                            }
                        }
                    } else if resp.status == 401 && h.name.eq_ignore_ascii_case("www-authenticate")
                    {
                        if let Ok(val) = from_utf8(h.value) {
                            let mut auth_type = val.split_whitespace();
                            if let Some(auth_type) = auth_type.next() {
                                if auth_type.eq_ignore_ascii_case("digest") {
                                    let de = ::types::AuthDigest::parse(val);
                                    if de.is_ok() {
                                        self.dir = Dir::Done;
                                        *auth_info = Some(AuthenticateInfo::new(String::from(val)));
                                    } else if let Err(_e) = de {
                                        // println!("Digest parse failed! {:?}", e);
                                    }
                                } else if auth_type.eq_ignore_ascii_case("basic") && self.b.digest {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                if !chunked_parse {
                    self.b.chunked_parse = false;
                }
                if !gzip {
                    self.b.gzip = false;
                }
                if auth_info.is_some() {
                    return Ok(());
                }
                // If switching protocols body is unlimited and timeout as well
                if resp.status == 101 {
                    con.set_to_close(true);
                    self.body_sz = usize::max_value();
                    self.b.dur = Duration::from_secs(3600 * 24 * 365);
                    self.dir = Dir::Receiving(buflen - self.hdr_sz, true);
                    return Ok(());
                } else if resp.status >= 300 && resp.status < 400 {
                    return Ok(());
                } else if self.body_sz == 0 {
                    self.dir = Dir::Done;
                } else {
                    self.dir = Dir::Receiving(buflen - self.hdr_sz, false);
                }
                if self.b.chunked_parse {
                    if self
                        .chunked
                        .check_done(self.b.max_chunk, &buf[self.hdr_sz..])?
                    {
                        self.dir = Dir::Done;
                    }
                }
                return Ok(());
            }
            Ok(httparse::Status::Partial) => return Ok(()),
            Err(e) => {
                return Err(From::from(e));
            }
        }
    }
}
