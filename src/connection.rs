use dns::{self, Dns};
use dns_cache::DnsCache;
use mio::event::Evented;
use mio::net::TcpStream;
use mio::{Poll, PollOpt, Ready, Token};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tls_api::{
    HandshakeError, MidHandshakeTlsStream, TlsConnector, TlsConnectorBuilder, TlsStream,
};
use {CallRef, Result};
// use http::{Request, Uri};
use call::CallImpl;
use fnv::FnvHashMap as HashMap;
use slab::Slab;
use smallvec::SmallVec;
use std::io::{Read, Write};
use types::{CallBuilderImpl, CallParam, RecvStateInt, SendStateInt};

// fn is_https(url: &Uri) -> Result<bool> {
//     if let Some(scheme) = url.scheme_part() {
//         if scheme == "https" {
//             return Ok(true);
//         } else if scheme == "http" {
//             return Ok(false);
//         } else if scheme == "ws" {
//             return Ok(false);
//         } else if scheme == "wss" {
//             return Ok(true);
//         } else {
//             return Err(::Error::InvalidScheme);
//         }
//     } else {
//         return Err(::Error::InvalidScheme);
//     }
// }

// fn url_port(url: &Uri) -> Result<u16> {
//     if let Some(p) = url.port() {
//         return Ok(p);
//     }
//     if is_https(url)? {
//         Ok(443)
//     } else {
//         Ok(80)
//     }
// }

fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    return Ok(tcp);
}

pub struct Con {
    token: Token,
    reg_for: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    mid_tls: Option<MidHandshakeTlsStream<TcpStream>>,
    dns: Option<Dns>,
    host: ConHost,
    con_port: u16,
    is_closed: bool,
    first_use: bool,
    // idle: bool,
    to_close: bool,
    idle_since: Instant,
    insecure: bool,
    signalled: bool,
    is_tls: bool,
}

impl Con {
    pub fn new<C: TlsConnector, T>(
        token: Token,
        cb: &CallBuilderImpl,
        cache: &mut DnsCache,
        // poll: &Poll,
        dns_timeout: u64,
        insecure: bool,
    ) -> Result<Con> {
        let rdy = Ready::writable();
        let port = cb.port; //url_port(req.uri())?;
        if cb.bytes.host.len() == 0 {
            return Err(::Error::NoHost);
        }
        let mut res = Con {
            con_port: port,
            is_closed: false,
            to_close: false,
            reg_for: rdy,
            first_use: true,
            token,
            sock: None,
            dns: None,
            insecure,
            host: ConHost::new(&cb.bytes.host),
            idle_since: Instant::now(),
            is_tls: cb.tls, //is_https(req.uri())?,
            tls: None,
            mid_tls: None,
            signalled: false,
        };
        res.create_sock(cache)?;
        if res.sock.is_none() {
            res.create_dns(dns_timeout)?;
        }
        Ok(res)
    }

    fn host(&self) -> &ConHost {
        &self.host
    }

    pub fn update_token(&mut self, poll: &Poll, fixed: bool, v: usize) -> Result<()> {
        self.token = if !fixed {
            Token(self.token.0 + v)
        } else {
            Token(v)
        };
        self.register(poll, self.token, self.reg_for, PollOpt::edge())?;
        Ok(())
    }

    fn create_dns(&mut self, dns_timeout: u64) -> Result<()> {
        self.reg_for = Ready::readable();
        self.dns = Some(Dns::new(self.host.as_ref(), dns_timeout)?);
        Ok(())
    }

    fn create_sock(&mut self, cache: &mut DnsCache) -> Result<()> {
        if let Some(ip) = cache.find(self.host.as_ref()) {
            self.sock = Some(connect(SocketAddr::new(ip, self.con_port))?);
        } else if let Ok(ip) = IpAddr::from_str(self.host.as_ref()) {
            self.sock = Some(connect(SocketAddr::new(ip, self.con_port))?);
        }
        Ok(())
    }

    // pub fn retry<C: TlsConnector, T>(
    //     &mut self,
    //     req: &Request<T>,
    //     cache: &mut DnsCache,
    //     poll: &Poll,
    //     dns_timeout: u64,
    // ) -> Result<()> {
    //     let _ = self.deregister(poll);
    //     self.create_sock(cache)?;
    //     self.reg_for = Ready::writable();
    //     if self.sock.is_none() {
    //         self.create_dns(dns_timeout)?;
    //     }
    //     self.register(poll, self.token, self.reg_for, PollOpt::edge())?;
    //     Ok(())
    // }

    pub fn reuse(&mut self, poll: &Poll) -> Result<()> {
        // self.deregister(poll)?;
        self.reg_for = Ready::writable() | Ready::readable();
        self.reregister(poll, self.token, self.reg_for, PollOpt::edge())?;
        Ok(())
    }

    pub fn timeout(&mut self, now: Instant, host: &str) {
        if let Some(ref mut dns) = self.dns {
            dns.check_retry(now, host);
        }
    }

    pub fn idle_timeout(&mut self, now: Instant) -> bool {
        if now - self.idle_since >= Duration::from_secs(60) {
            return true;
        }
        false
    }

    // pub fn close(&mut self) {
    //     self.sock = None;
    //     self.tls = None;
    //     // self.dns_sock = None;
    //     self.dns = None;
    //     self.is_closed = true;
    // }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }
    #[inline]
    pub fn is_first_use(&self) -> bool {
        self.first_use
    }
    pub fn set_idle(&mut self, b: bool) {
        self.first_use = false;
        if b {
            self.idle_since = Instant::now();
        }
        // self.idle = b;
    }
    pub fn first_use_done(&mut self) {
        self.first_use = false;
    }
    #[inline]
    pub fn set_to_close(&mut self, b: bool) {
        self.to_close = b;
    }
    // #[inline]
    // pub fn to_close(&self) -> bool {
    //     self.to_close
    // }

    pub fn reg(&mut self, poll: &Poll, rdy: Ready) -> ::std::io::Result<()> {
        if self.reg_for.contains(rdy) {
            return Ok(());
        }
        if self.reg_for.is_empty() {
            self.reg_for = rdy;
            self.register(poll, self.token, self.reg_for, PollOpt::edge())
        } else {
            self.reg_for |= rdy;
            self.reregister(poll, self.token, self.reg_for, PollOpt::edge())
        }
    }

    pub fn is_signalled(&self) -> bool {
        self.signalled
    }

    pub fn set_signalled(&mut self, v: bool) {
        self.signalled = v;
    }

    pub fn signalled<'a, C: TlsConnector, T>(
        &mut self,
        cp: &mut CallParam,
        req: &CallBuilderImpl,
    ) -> Result<()> {
        if !self.signalled {
            return Ok(());
        }
        if self.dns.is_some() {
            let dns = self.dns.take().unwrap();
            let mut buf: [u8; 512] = unsafe { ::std::mem::uninitialized() };
            if let Ok(sz) = dns.sock.recv(&mut buf[..]) {
                if let Some(ip) = dns::dns_parse(&buf[..sz]) {
                    // let host = req.uri().host().unwrap();
                    cp.dns.save(self.host.as_ref(), ip);
                    self.dns = None;
                    self.deregister(cp.poll)?;
                    self.sock = Some(connect(SocketAddr::new(ip, req.port))?);
                    self.reg_for = Ready::writable();
                    self.register(cp.poll, self.token, self.reg_for, PollOpt::edge())?;

                    return Ok(());
                }
            }
            self.dns = Some(dns);
        } else {
            if self.sock.is_some() && self.is_tls && self.tls.is_none() && self.mid_tls.is_none() {
                let mut connector = C::builder()?;
                for rca in cp.cfg.der_ca.iter() {
                    let _ = connector.add_der_certificate(rca);
                }
                for rca in cp.cfg.pem_ca.iter() {
                    let _ = connector.add_pem_certificate(rca);
                }
                if self.insecure {
                    let _ = connector.danger_accept_invalid_certs();
                }
                let connector = connector.build()?;
                self.reg(cp.poll, Ready::readable())?;
                let tcp = self.sock.take().unwrap();

                // let r = if self.insecure {
                //     connector
                //         .danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(
                //             tcp,
                //         )
                // } else {
                let r = connector.connect(self.host.as_ref(), tcp);
                // };
                self.handshake_resp::<C>(r)?;
            }
            if self.mid_tls.is_some() {
                self.reg(cp.poll, Ready::readable())?;
                let tls = self.mid_tls.take().unwrap();
                let r = tls.handshake();
                self.handshake_resp::<C>(r)?;
            }
        }
        Ok(())
    }

    fn handshake_resp<C: TlsConnector>(
        &mut self,
        r: ::std::result::Result<TlsStream<TcpStream>, HandshakeError<TcpStream>>,
    ) -> Result<()> {
        match r {
            Ok(tls) => {
                self.tls = Some(tls);
            }
            Err(HandshakeError::Interrupted(mid)) => {
                self.mid_tls = Some(mid);
            }
            Err(HandshakeError::Failure(e)) => {
                return Err(e);
            }
        }
        Ok(())
    }
}

impl Read for Con {
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        if let Some(ref mut tcp) = self.sock {
            tcp.read(buf)
        } else if let Some(ref mut tls) = self.tls {
            tls.read(buf)
        } else {
            Err(::std::io::Error::new(
                ::std::io::ErrorKind::WouldBlock,
                "No socket",
            ))
        }
    }
}

impl Write for Con {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        if let Some(ref mut tcp) = self.sock {
            tcp.write(buf)
        } else if let Some(ref mut tls) = self.tls {
            tls.write(buf)
        } else {
            Err(::std::io::Error::new(
                ::std::io::ErrorKind::WouldBlock,
                "No socket",
            ))
        }
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        if let Some(ref mut tcp) = self.sock {
            tcp.flush()
        } else if let Some(ref mut tls) = self.tls {
            tls.flush()
        } else {
            Err(::std::io::Error::new(
                ::std::io::ErrorKind::WouldBlock,
                "No socket",
            ))
        }
    }
}

impl Evented for Con {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.register(tcp, token, interest, opts)
        } else if let Some(ref tls) = self.tls {
            poll.register(tls.get_ref(), token, interest, opts)
        } else if let Some(ref dns) = self.dns {
            poll.register(&dns.sock, token, interest, opts)
        } else {
            Ok(())
        }
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.reregister(tcp, token, interest, opts)
        } else if let Some(ref tls) = self.tls {
            poll.reregister(tls.get_ref(), token, interest, opts)
        } else if let Some(ref dns) = self.dns {
            poll.reregister(&dns.sock, token, interest, opts)
        } else {
            Ok(())
        }
    }

    fn deregister(&self, poll: &Poll) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.deregister(tcp)
        } else if let Some(ref tls) = self.tls {
            poll.deregister(tls.get_ref())
        } else if let Some(ref dns) = self.dns {
            poll.deregister(&dns.sock)
        } else {
            Ok(())
        }
    }
}

struct ConHost {
    host: SmallVec<[u8; 32]>,
}

impl ConHost {
    pub fn new(uri: &[u8]) -> ConHost {
        let mut sv = SmallVec::new();
        sv.extend_from_slice(uri);
        ConHost { host: sv }
    }
}
use std::hash::{Hash, Hasher};
impl Hash for ConHost {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        state.write(&self.host);
    }
}
impl ::std::convert::AsRef<str> for ConHost {
    #[inline]
    fn as_ref(&self) -> &str {
        unsafe { ::std::str::from_utf8_unchecked(&self.host) }
    }
}

impl PartialEq for ConHost {
    fn eq(&self, uri: &ConHost) -> bool {
        self.host == uri.host
    }
}

impl Eq for ConHost {}

pub struct ConTable {
    cons: Slab<(Con, SmallVec<[CallImpl; 2]>)>,
    // connections with fixed tokens
    cons_fixed: HashMap<usize, (Con, CallImpl)>,
    // con that can be used for new requests
    keepalive: HashMap<ConHost, u16>,
}

impl ConTable {
    pub fn new() -> ConTable {
        ConTable {
            keepalive: HashMap::with_capacity_and_hasher(4, Default::default()),
            cons: Slab::with_capacity(4),
            cons_fixed: HashMap::with_capacity_and_hasher(4, Default::default()),
        }
    }

    pub fn open_cons(&self) -> usize {
        self.cons.len()
    }

    pub fn signalled_con(&mut self, id: usize) -> bool {
        if let Some(t) = self.cons.get_mut(id) {
            t.0.set_signalled(true);
            return true;
        }
        false
    }

    pub fn fixed_signalled_con(&mut self, k: usize) -> bool {
        if let Some((con, _)) = self.cons_fixed.get_mut(&k) {
            con.set_signalled(true);
            return true;
        }
        false
    }

    pub fn timeout_extend(&mut self, now: Instant, out: &mut Vec<CallRef>) {
        let mut cons_to_close: SmallVec<[u16; 16]> = SmallVec::new();
        for (con_id, &mut (ref mut con, ref mut calls)) in self.cons.iter_mut() {
            let mut call_id = 0;
            if con.is_closed() {
                continue;
            }
            if calls.len() == 0 {
                if con.idle_timeout(now) {
                    cons_to_close.push(con_id as _);
                }
                continue;
            }
            for call in calls.iter_mut() {
                if !call.is_done() {
                    if now - call.start_time() >= call.settings().dur {
                        out.push(CallRef::new(con_id as u16, call_id));
                    } else if call_id == 0 {
                        // if let Some(host) = call.settings().bytes.host() {
                        let host =
                            unsafe { ::std::str::from_utf8_unchecked(&call.settings().bytes.host) };
                        con.timeout(now, host);
                        // }
                    }
                }
                call_id += 1;
            }
        }
        for toclose in cons_to_close {
            self.close_con(toclose as usize);
        }
    }

    pub fn peek_body(&mut self, call: &::Call, off: &mut usize) -> &[u8] {
        if call.1 != usize::max_value() {
            if let Some((_con, call)) = self.cons_fixed.get_mut(&call.1) {
                return call.peek_body(off);
            }
            return &[];
        }
        let con = call.con_id() as usize;
        let call = call.call_id() as usize;
        self.cons[con as usize].1[call as usize].peek_body(off)
    }
    pub fn try_truncate(&mut self, call: &::Call, off: &mut usize) {
        if call.1 != usize::max_value() {
            if let Some((_con, call)) = self.cons_fixed.get_mut(&call.1) {
                call.try_truncate(off);
            }
            return;
        }
        let con = call.con_id() as usize;
        let call = call.call_id() as usize;
        self.cons[con as usize].1[call as usize].try_truncate(off);
    }
    pub fn event_send<C: TlsConnector>(
        &mut self,
        call: &::Call,
        cp: &mut CallParam,
        buf: Option<&[u8]>,
    ) -> Result<SendStateInt> {
        if call.1 != usize::max_value() {
            if let Some((con, call)) = self.cons_fixed.get_mut(&call.1) {
                return call.event_send::<C>(con, cp, buf);
            }
        }
        let con = call.con_id() as usize;
        let call = call.call_id() as usize;
        let conp = &mut self.cons[con];
        let res = conp.1[call].event_send::<C>(&mut conp.0, cp, buf);
        if res.is_err() && !conp.0.is_first_use() && conp.1[call].can_retry() {
            conp.0.set_to_close(true);
            return Ok(SendStateInt::Retry(res.unwrap_err()));
        }
        res
    }
    pub(crate) fn event_recv<C: TlsConnector>(
        &mut self,
        call: &::Call,
        cp: &mut CallParam,
        buf: Option<&mut Vec<u8>>,
    ) -> Result<RecvStateInt> {
        if call.1 != usize::max_value() {
            if let Some((con, call)) = self.cons_fixed.get_mut(&call.1) {
                return call.event_recv::<C>(con, cp, buf);
            }
        }
        let con = call.con_id() as usize;
        let call = call.call_id() as usize;
        let conp = &mut self.cons[con];
        let res = conp.1[call].event_recv::<C>(&mut conp.0, cp, buf);
        if res.is_err() && !conp.0.is_first_use() && conp.1[call].can_retry() {
            conp.0.set_to_close(true);
            return Ok(RecvStateInt::Retry(res.unwrap_err()));
        }
        res
    }

    pub fn add_fixed_con(&mut self, mut c: Con, call: CallImpl, poll: &Poll) -> Result<()> {
        c.update_token(poll, true, call.settings().evid)?;
        self.cons_fixed.insert(call.settings().evid, (c, call));
        Ok(())
    }

    pub fn push_con(&mut self, mut c: Con, call: CallImpl, poll: &Poll) -> Result<Option<u16>> {
        if self.cons.len() == (u16::max_value() as usize) {
            return Ok(None);
        }
        let entry = self.cons.vacant_entry();
        let key = entry.key();
        c.update_token(poll, false, key)?;
        let mut v = SmallVec::new();
        v.push(call);
        entry.insert((c, v));
        Ok(Some(key as u16))
    }

    pub fn push_ka_con(&mut self, con: u16, call: CallImpl) -> Result<()> {
        self.cons[con as usize].1.push(call);
        Ok(())
    }

    fn extract_call(call: ::Call, calls: &mut SmallVec<[CallImpl; 2]>) -> CallImpl {
        let callid = call.call_id() as usize;
        if callid + 1 == calls.len() {
            let res = calls.pop();
            while calls.last().is_some() {
                if calls.last().unwrap().is_done() {
                    let _ = calls.pop();
                } else {
                    break;
                }
            }
            res.unwrap()
        } else {
            ::std::mem::replace(&mut calls[callid], CallImpl::empty())
        }
    }

    pub fn try_keepalive(&mut self, host: &[u8], poll: &Poll) -> Option<u16> {
        let con_to_close;
        let nh = ConHost::new(host);
        if let Some(con) = self.keepalive.remove(&nh) {
            self.cons[con as usize].0.set_idle(false);
            if self.cons[con as usize].0.reuse(poll).is_ok() {
                return Some(con);
            } else {
                con_to_close = con;
            }
        } else {
            return None;
        }
        self.close_con(con_to_close as usize);
        None
    }

    pub fn close_call(&mut self, call: ::Call) -> (::types::CallBuilderImpl, Vec<u8>, Vec<u8>) {
        if call.1 != usize::max_value() {
            if let Some((_con, call)) = self.cons_fixed.remove(&call.1) {
                return call.stop();
            }
        }
        let con = call.con_id() as usize;
        let call: CallImpl = Self::extract_call(call, &mut self.cons[con].1);
        let (builder, hdr_buf, body_buf) = call.stop();
        // println!("close_call {} toclose={} {}",con, self.cons[con].0.to_close, self.cons.len());
        {
            let host = &builder.bytes.host;
            if !self.cons[con].0.to_close {
                if self.cons[con].1.len() == 0 {
                    self.cons[con].0.set_idle(true);
                } else {
                    self.cons[con].0.first_use_done();
                }
                let nh = ConHost::new(host);
                if self.keepalive.contains_key(&nh) {
                    let mut doclose = false;
                    {
                        if let Some(c) = self.keepalive.get(&nh) {
                            if *c != con as u16 {
                                doclose = true
                            }
                        }
                    }
                    if doclose {
                        self.close_con(con);
                    }
                } else {
                    self.keepalive.insert(nh, con as u16);
                }
            } else {
                self.close_con(con);
            }
        }
        (builder, hdr_buf, body_buf)
    }

    fn close_con(&mut self, toclose: usize) {
        let mut rm_kl = false;
        {
            if let Some(c) = self.keepalive.get(self.cons[toclose as usize].0.host()) {
                if *c == toclose as u16 {
                    rm_kl = true;
                }
            }
        }
        if rm_kl {
            self.keepalive.remove(self.cons[toclose as usize].0.host());
        }
        self.cons.remove(toclose);
    }
}
