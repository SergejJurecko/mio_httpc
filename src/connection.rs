use crate::call::CallImpl;
use crate::resolve::{self, Dns, DnsCache};
use crate::tls_api::{
    hash, HandshakeError, HashType, MidHandshakeTlsStream, TlsConnector, TlsConnectorBuilder,
    TlsStream,
};
use crate::types::{CallBuilderImpl, CallParam, IpList, RecvStateInt, SendStateInt};
use crate::{CallRef, HttpcCfg, Result};
use data_encoding::BASE64;
use fxhash::FxHashMap as HashMap;
use mio::event::Evented;
use mio::net::TcpStream;
use mio::{Poll, PollOpt, Ready, Token};
use slab::Slab;
use smallvec::SmallVec;
use std::io::ErrorKind as IoErrorKind;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    return Ok(tcp);
}

pub(crate) struct Con {
    call_id: u64,
    token: Token,
    reg_for: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    mid_tls: Option<MidHandshakeTlsStream<TcpStream>>,
    dns: Option<Dns>,
    host: ConHost,
    resolved: IpList,
    con_port: u16,
    is_closed: bool,
    first_use: bool,
    // idle: bool,
    to_close: bool,
    idle_since: Instant,
    insecure: bool,
    signalled_rd: bool,
    signalled_wr: bool,
    is_tls: bool,
    other: Option<usize>,
    ipv4: bool,
    dns_timeout: u64,
    do_other: bool,
}

impl Con {
    pub fn new<C: TlsConnector, T>(
        call_id: u64,
        token: Token,
        cb: &CallBuilderImpl,
        cache: &mut DnsCache,
        dns_timeout: u64,
        insecure: bool,
        cfg: &HttpcCfg,
    ) -> Result<Con> {
        let rdy = Ready::writable() | Ready::readable();
        let port = cb.port;
        if cb.bytes.host.len() == 0 {
            return Err(crate::Error::NoHost);
        }
        let mut res = Con {
            call_id,
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
            resolved: SmallVec::default(),
            is_tls: cb.tls,
            tls: None,
            mid_tls: None,
            signalled_rd: false,
            signalled_wr: false,
            other: None,
            ipv4: true,
            dns_timeout,
            do_other: true,
        };
        if res.create_sock(cache)?.is_none() {
            res.create_dns(cfg)?;
        }
        Ok(res)
    }

    fn clone_other(&mut self, other: usize, tk: usize) -> Con {
        let mut c = Con {
            call_id: self.call_id,
            con_port: self.con_port,
            is_closed: self.is_closed,
            to_close: self.to_close,
            reg_for: self.reg_for,
            first_use: self.first_use,
            token: Token(tk),
            sock: None,
            dns: None,
            insecure: self.insecure,
            host: self.host.clone(),
            idle_since: Instant::now(),
            resolved: IpList::new(),
            is_tls: self.is_tls,
            tls: None,
            mid_tls: None,
            signalled_rd: false,
            signalled_wr: false,
            other: Some(other),
            ipv4: !self.ipv4,
            dns_timeout: self.dns_timeout,
            do_other: false,
        };
        if self.resolved.len() > 0 {
            c.resolved.push(self.resolved.pop().unwrap());
        }
        c
    }

    fn set_other(&mut self, other: Option<usize>) {
        self.other = other;
    }

    fn get_other(&self) -> Option<usize> {
        self.other
    }

    fn call_id(&self) -> u64 {
        self.call_id
    }

    fn host(&self) -> &ConHost {
        &self.host
    }

    fn update_token(&mut self, poll: &Poll, v: usize, fixed: bool) -> Result<()> {
        if !fixed {
            self.token = Token(self.token.0 + v);
        } else {
            self.token = Token(v);
        }
        self.register(poll, self.token, self.reg_for, PollOpt::edge())?;
        Ok(())
    }

    fn create_dns(&mut self, cfg: &HttpcCfg) -> Result<()> {
        self.reg_for = Ready::readable();
        self.dns = Some(Dns::new(
            self.host.as_ref(),
            self.dns_timeout,
            &cfg.dns_servers,
            self.ipv4,
        )?);
        Ok(())
    }

    fn create_sock(&mut self, cache: &mut DnsCache) -> Result<Option<()>> {
        if let Some(ip) = self.resolved.pop() {
            self.sock = Some(connect(SocketAddr::new(ip, self.con_port))?);
        } else if let Some(ip) = cache.find(self.host.as_ref()) {
            self.resolved = ip;
            while self.resolved.len() > 0 && self.sock.is_none() {
                if let Ok(s) = connect(SocketAddr::new(self.resolved.pop().unwrap(), self.con_port))
                {
                    self.sock = Some(s);
                }
            }
            if self.sock.is_none() {
                return Ok(None);
            }
            self.do_other = self.resolved.len() > 0;
        } else if let Ok(ip) = IpAddr::from_str(self.host.as_ref()) {
            self.sock = Some(connect(SocketAddr::new(ip, self.con_port))?);
            self.do_other = false;
        } else {
            return Ok(None);
        }
        Ok(Some(()))
    }

    pub fn reuse(&mut self, poll: &Poll) -> Result<()> {
        self.reg_for = Ready::writable() | Ready::readable();
        self.reregister(poll, self.token, self.reg_for, PollOpt::edge())?;
        Ok(())
    }

    pub fn timeout(&mut self, now: Instant, host: &str) {
        if let Some(ref mut dns) = self.dns {
            dns.check_retry(now, host);
        }
    }

    fn idle_timeout(&mut self, now: Instant) -> bool {
        if now - self.idle_since >= Duration::from_secs(60) {
            return true;
        }
        false
    }

    #[inline]
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }
    #[inline]
    pub fn is_first_use(&self) -> bool {
        self.first_use
    }
    #[inline]
    pub fn set_idle(&mut self, b: bool) {
        self.first_use = false;
        if b {
            self.idle_since = Instant::now();
        }
    }
    #[inline]
    pub fn first_use_done(&mut self) {
        self.first_use = false;
    }
    #[inline]
    pub fn set_to_close(&mut self, b: bool) {
        self.to_close = b;
    }

    pub fn reg(&mut self, poll: &Poll, rdy: Ready) -> ::std::io::Result<()> {
        if self.reg_for.contains(rdy) {
            return Ok(());
        }
        if self.reg_for.is_empty() {
            self.reg_for = rdy;
            self.register(poll, self.token, self.reg_for, PollOpt::edge())
        } else {
            if !self.reg_for.contains(rdy) {
                self.reg_for |= rdy;
                return self.reregister(poll, self.token, self.reg_for, PollOpt::edge());
            }
            Ok(())
        }
    }

    #[inline]
    pub fn is_signalled_rd(&self) -> bool {
        self.signalled_rd
    }

    #[inline]
    fn set_signalled_rd(&mut self, v: bool) {
        self.signalled_rd = v;
    }

    #[inline]
    pub fn is_signalled_wr(&self) -> bool {
        self.signalled_wr
    }

    #[inline]
    fn set_signalled_wr(&mut self, v: bool) {
        self.signalled_wr = v;
    }

    fn connect_resolved(&mut self, poll: &Poll) -> Result<()> {
        let ip = self.resolved.pop().unwrap();
        self.sock = Some(connect(SocketAddr::new(ip, self.con_port))?);
        self.reg_for = Ready::writable() | Ready::readable();
        self.set_signalled_rd(false);
        self.set_signalled_wr(false);
        self.register(poll, self.token, self.reg_for, PollOpt::edge())?;
        Ok(())
    }

    fn signalled_dns(&mut self, poll: &Poll, cache: &mut DnsCache) -> Result<()> {
        if self.dns.is_none() {
            return Ok(());
        }
        let dns = self.dns.take().unwrap();
        let mut buf: [u8; 512] = unsafe { ::std::mem::uninitialized() };
        if let Ok(sz) = dns.sock.recv(&mut buf[..]) {
            resolve::dns_parse(&buf[..sz], &mut self.resolved);
            if self.resolved.len() > 0 {
                cache.save(self.host.as_ref(), self.resolved.clone());

                self.dns = None;
                self.deregister(poll)?;
                while self.resolved.len() > 0 {
                    match self.connect_resolved(poll) {
                        Ok(_) => break,
                        Err(e) => {
                            if self.resolved.len() == 0 {
                                return Err(e);
                            }
                        }
                    }
                }

                return Ok(());
            }
        }
        self.dns = Some(dns);
        Ok(())
    }

    pub fn signalled<'a, C: TlsConnector, T>(&mut self, cp: &mut CallParam) -> Result<()> {
        if !self.signalled_rd && !self.signalled_wr {
            return Ok(());
        }
        if self.sock.is_some() && self.is_tls && self.tls.is_none() && self.mid_tls.is_none() {
            let mut connector = C::builder()?;
            for rca in cp.cfg.der_ca.iter() {
                let _ = connector.add_der_certificate(rca);
            }
            for rca in cp.cfg.pem_ca.iter() {
                let _ = connector.add_pem_certificate(rca);
            }
            if self.insecure {
                let _ = connector.danger_accept_invalid_certs().unwrap();
            }
            let connector = connector.build()?;
            self.reg(cp.poll, Ready::readable())?;
            let tcp = self.sock.take().unwrap();
            let r = connector.connect(self.host.as_ref(), tcp);
            self.handshake_resp::<C>(r, cp.cfg)?;
        }
        if self.mid_tls.is_some() {
            self.reg(cp.poll, Ready::readable())?;
            let tls = self.mid_tls.take().unwrap();
            let r = tls.handshake();
            self.handshake_resp::<C>(r, cp.cfg)?;
        }

        Ok(())
    }

    fn handshake_resp<C: TlsConnector>(
        &mut self,
        r: ::std::result::Result<TlsStream<TcpStream>, HandshakeError<TcpStream>>,
        cfg: &crate::HttpcCfg,
    ) -> Result<()> {
        match r {
            Ok(tls) => {
                let mut pin_match = true;
                for pin in cfg.pins.iter() {
                    let host = self.host.as_ref();
                    if pin.0.eq_ignore_ascii_case(host) {
                        // If we found host, we now must find a pin match
                        pin_match = false;
                        let der = tls.peer_pubkey();
                        for pin in pin.1.iter() {
                            let hash_der;
                            let prefix = if pin.starts_with("sha256/") {
                                hash_der = hash(HashType::SHA256, &der);
                                "sha256/"
                            } else if pin.starts_with("sha1/") {
                                hash_der = hash(HashType::SHA256, &der);
                                "sha1/"
                            } else {
                                continue;
                            };
                            let mut base_buf = [0u8; 128];
                            let base_len = BASE64.encode_len(hash_der.len());
                            BASE64.encode_mut(&hash_der, &mut base_buf[..base_len]);
                            let base64_der = std::str::from_utf8(&base_buf[..base_len]).unwrap();
                            if base64_der.eq_ignore_ascii_case(&pin[prefix.len()..]) {
                                pin_match = true;
                                break;
                            }
                        }
                    }
                }
                if !pin_match {
                    return Err(crate::Error::InvalidPin);
                }
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
        let res = if let Some(ref mut tcp) = self.sock {
            tcp.read(buf)
        } else if let Some(ref mut tls) = self.tls {
            tls.read(buf)
        } else {
            return Err(::std::io::Error::new(
                ::std::io::ErrorKind::WouldBlock,
                "No socket",
            ));
        };
        match &res {
            &Err(ref ie) => {
                if ie.kind() == IoErrorKind::WouldBlock {
                    self.set_signalled_rd(false);
                }
            }
            _ => {}
        }
        res
    }
}

impl Write for Con {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        let res = if let Some(ref mut tcp) = self.sock {
            tcp.write(buf)
        } else if let Some(ref mut tls) = self.tls {
            tls.write(buf)
        } else {
            return Err(::std::io::Error::new(
                ::std::io::ErrorKind::WouldBlock,
                "No socket",
            ));
        };
        match &res {
            &Err(ref ie) => {
                if ie.kind() == IoErrorKind::WouldBlock {
                    self.set_signalled_wr(false);
                }
            }
            _ => {}
        }
        res
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
#[derive(Clone)]
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

enum CallVariant {
    Other(usize),
    Call(CallImpl),
    None,
}

impl CallVariant {
    fn is_none(&self) -> bool {
        match self {
            CallVariant::None => true,
            _ => false,
        }
    }
    // fn get_other(&self) -> Option<usize> {
    //     match self {
    //         CallVariant::Other(id) => Some(*id),
    //         _ => None,
    //     }
    // }
    fn as_ref(&self) -> Option<&CallImpl> {
        match self {
            CallVariant::Call(ref i) => Some(i),
            _ => None,
        }
    }
    fn as_mut(&mut self) -> Option<&mut CallImpl> {
        match self {
            CallVariant::Call(ref mut i) => Some(i),
            _ => None,
        }
    }
    fn take(&mut self) -> Option<CallImpl> {
        let mut swapped = CallVariant::None;
        ::std::mem::swap(self, &mut swapped);
        match swapped {
            CallVariant::Call(c) => Some(c),
            _ => None,
        }
    }
}

pub(crate) struct ConTable {
    cons: Slab<(Con, CallVariant)>,
    // connections with fixed tokens
    cons_fixed: HashMap<usize, (Con, CallVariant)>,
    // con that can be used for new requests
    keepalive: HashMap<ConHost, u16>,
}

impl ConTable {
    pub fn new() -> ConTable {
        ConTable {
            keepalive: HashMap::with_capacity_and_hasher(4, Default::default()),
            cons: Slab::with_capacity(4),
            cons_fixed: HashMap::default(),
            // cons_fixed: HashMap::with_capacity_and_hasher(4, Default::default()),
        }
    }

    pub fn open_cons(&self) -> usize {
        self.cons.len()
    }

    pub fn signalled_con(&mut self, fixed: bool, id: usize, rdy: Ready) -> Option<u64> {
        let mut rm = false;
        let res = if let Some(t) = if fixed {
            self.cons_fixed.get_mut(&id)
        } else {
            self.cons.get_mut(id)
        } {
            if t.1.is_none() {
                return None;
            }
            if rdy.is_readable() && t.0.dns.is_none() {
                t.0.set_signalled_rd(true);
            }
            if rdy.is_writable() && t.0.dns.is_none() {
                t.0.set_signalled_wr(true);
                rm = true;
            }
            Some(t.0.call_id)
        } else {
            None
        };
        if rm {
            self.remove_other(false, id);
        }

        res
    }

    fn remove_other(&mut self, fixed: bool, id: usize) {
        let mut rm = None;
        if let Some(t) = if fixed {
            self.cons_fixed.get_mut(&id)
        } else {
            self.cons.get_mut(id)
        } {
            if let Some(other) = t.0.get_other() {
                rm = Some(other);
            }
        }
        if let Some(other) = rm {
            self.remove_conid(fixed, other);
        }
    }

    fn remove_conid(&mut self, fixed: bool, id: usize) {
        let (c, mut call) = if fixed {
            self.cons_fixed.remove(&id).unwrap()
        } else {
            self.cons.remove(id)
        };
        if let Some(other) = c.get_other() {
            if let Some(other) = if fixed {
                self.cons_fixed.get_mut(&other)
            } else {
                self.cons.get_mut(other)
            } {
                other.0.set_other(None);
            }
            if let Some(call) = call.take() {
                // Other con won, move call to it
                let tuple = if fixed {
                    self.cons_fixed.get_mut(&other).unwrap()
                } else {
                    self.cons.get_mut(other).unwrap()
                };
                tuple.1 = CallVariant::Call(call);
            }
        }
    }

    pub fn timeout_extend(&mut self, now: Instant, out: &mut Vec<CallRef>) {
        let mut cons_to_close: SmallVec<[u16; 16]> = SmallVec::new();
        for (con_id, &mut (ref mut con, ref mut calls)) in self
            .cons
            .iter_mut()
            .chain(self.cons_fixed.iter_mut().map(|(c, call)| (*c, call)))
        {
            if con.is_closed() {
                continue;
            }
            if calls.is_none() {
                if con.idle_timeout(now) {
                    cons_to_close.push(con_id as _);
                }
                continue;
            }
            for call in calls.as_mut().iter_mut() {
                if !call.is_done() {
                    if now - call.start_time() >= call.settings().dur {
                        out.push(CallRef::new(call.call_id()));
                    } else {
                        // if let Some(host) = call.settings().bytes.host() {
                        let host =
                            unsafe { ::std::str::from_utf8_unchecked(&call.settings().bytes.host) };
                        con.timeout(now, host);
                        // }
                    }
                }
            }
        }
        for toclose in cons_to_close {
            self.close_con(toclose as usize);
        }
    }

    pub fn peek_body(&mut self, call: &crate::Call, off: &mut usize) -> &[u8] {
        let con = call.con();
        if call.fixed {
            return self
                .cons_fixed
                .get_mut(&con)
                .map(|t| t.1.as_mut().map(|c| c.peek_body(off)).unwrap_or(&[]))
                .unwrap_or(&[]);
        }
        // let call = call.call_id() as usize;
        self.cons[con as usize]
            .1
            .as_mut()
            .map(|c| c.peek_body(off))
            .unwrap_or(&[])
    }
    pub fn try_truncate(&mut self, call: &crate::Call, off: &mut usize) {
        let con = call.con();
        if call.fixed {
            self.cons_fixed
                .get_mut(&con)
                .map(|t| t.1.as_mut().map(|c| c.try_truncate(off)));
            return;
        }
        // let call = call.call_id() as usize;
        self.cons[con as usize]
            .1
            .as_mut()
            .map(|c| c.try_truncate(off));
    }
    pub fn event_send<C: TlsConnector>(
        &mut self,
        call: &mut crate::Call,
        cp: &mut CallParam,
        buf: Option<&[u8]>,
    ) -> Result<SendStateInt> {
        let cons = call.cons();
        let mut con = None;
        let mut rm = None;
        for c in cons.iter() {
            if *c != usize::max_value() {
                if let Some(t) = if call.fixed {
                    self.cons_fixed.get_mut(c)
                } else {
                    self.cons.get_mut(*c)
                } {
                    if t.0.call_id() != call.id() {
                        call.remove_con(*c);
                        continue;
                    }
                    let sig_resp = t.0.signalled_dns(cp.poll, cp.dns);
                    if let Ok(()) = sig_resp {
                        if t.0.dns.is_none() && t.0.is_signalled_wr() {
                            rm = t.0.get_other();
                            con = Some(*c);
                            break;
                        }
                    } else if sig_resp.is_err() {
                        rm = Some(*c);
                    }
                } else {
                    call.remove_con(*c);
                }
            }
        }
        if let Some(rm) = rm {
            // if let Some(main) =
            call.remove_con(rm);
            self.remove_conid(call.fixed, rm);
        }
        if con.is_none() {
            return Ok(SendStateInt::Wait);
        }
        let con = con.unwrap();
        // let call = call.call_id() as usize;
        let conp = if call.fixed {
            self.cons_fixed.get_mut(&con).unwrap()
        } else {
            &mut self.cons[con]
        };
        // Take CallImpl out so we can call it without borrowing issues.
        let mut call_impl = conp.1.take().unwrap();
        let res = call_impl.event_send::<C>(&mut conp.0, cp, buf);
        // put it back
        conp.1 = CallVariant::Call(call_impl);
        let cr = conp.1.as_ref().map(|c| c.can_retry()).unwrap_or(false);
        if res.is_err() && !conp.0.is_first_use() && cr {
            conp.0.set_to_close(true);
            return Ok(SendStateInt::Retry(res.unwrap_err()));
        }
        res
    }
    pub(crate) fn event_recv<C: TlsConnector>(
        &mut self,
        call: &mut crate::Call,
        cp: &mut CallParam,
        buf: Option<&mut Vec<u8>>,
    ) -> Result<RecvStateInt> {
        let con = call.con();
        let conp = if call.fixed {
            self.cons_fixed.get_mut(&con).unwrap()
        } else {
            &mut self.cons[con]
        };
        // check-out
        let mut call_impl = conp.1.take().unwrap();
        let res = call_impl.event_recv::<C>(&mut conp.0, cp, buf);
        // check-in
        conp.1 = CallVariant::Call(call_impl);
        if res.is_err()
            && !conp.0.is_first_use()
            && conp.1.as_ref().map(|c| c.can_retry()).unwrap_or(false)
        {
            conp.0.set_to_close(true);
            return Ok(RecvStateInt::Retry(res.unwrap_err()));
        }
        res
    }

    fn create_other(
        &mut self,
        orig: usize,
        poll: &Poll,
        cfg: &HttpcCfg,
        con_offset: usize,
    ) -> usize {
        let con1 = self
            .cons
            .get_mut(orig)
            .unwrap()
            .0
            .clone_other(orig, con_offset);
        let key = self.cons.insert((con1, CallVariant::Other(0)));
        let mut ok = false;
        if let Some(tuple) = self.cons.get_mut(key) {
            tuple.1 = CallVariant::Other(orig);
            match tuple.0.create_sock(&mut DnsCache::new()) {
                Ok(Some(())) => {
                    if let Ok(()) = tuple.0.update_token(poll, key, false) {
                        ok = true;
                    }
                }
                Ok(None) => {
                    if let Ok(_) = tuple.0.create_dns(cfg) {
                        if let Ok(()) = tuple.0.update_token(poll, key, false) {
                            ok = true;
                        }
                    }
                }
                _ => {}
            }
        }
        if ok {
            self.cons.get_mut(orig).unwrap().0.set_other(Some(key));
            key
        } else {
            self.cons.remove(key);
            usize::max_value()
        }
    }

    pub fn push_con(
        &mut self,
        mut c: Con,
        call: CallImpl,
        poll: &Poll,
        cfg: &HttpcCfg,
        con_offset: usize,
    ) -> Result<Option<(usize, usize)>> {
        if self.cons.len() >= (u16::max_value() as usize) - 2 {
            return Ok(None);
        }
        let do_other = c.do_other;
        let key = {
            let entry = self.cons.vacant_entry();
            let key = entry.key();
            c.update_token(poll, key, false)?;
            entry.insert((c, CallVariant::Call(call)));
            key
        };

        let key1 = if do_other {
            self.create_other(key, poll, cfg, con_offset)
        } else {
            usize::max_value()
        };
        Ok(Some((key, key1)))
    }

    pub fn push_fixed_con(
        &mut self,
        mut c: Con,
        call: CallImpl,
        poll: &Poll,
        cfg: &HttpcCfg,
    ) -> Result<(usize, usize)> {
        let id = call.settings().evids[0];
        let mut id1 = call.settings().evids[1];
        if id == usize::max_value() || id1 == usize::max_value() {
            return Err(crate::Error::NoSpace);
        }
        c.update_token(poll, id, true)?;
        if c.do_other {
            let mut c1 = c.clone_other(id, id1);
            let mut ok = false;
            match c1.create_sock(&mut DnsCache::new()) {
                Ok(Some(())) => {
                    if let Ok(()) = c1.update_token(poll, id1, true) {
                        ok = true;
                    }
                }
                Ok(None) => {
                    if let Ok(_) = c1.create_dns(cfg) {
                        if let Ok(()) = c1.update_token(poll, id1, true) {
                            ok = true;
                        }
                    }
                }
                _ => {}
            }
            if ok {
                c.set_other(Some(id1));
                self.cons_fixed.insert(id1, (c1, CallVariant::Other(id)));
            } else {
                id1 = usize::max_value();
            }
        }
        self.cons_fixed.insert(id, (c, CallVariant::Call(call)));
        Ok((id, id1))
    }

    pub fn push_ka_con(&mut self, con: u16, call: CallImpl) -> Result<()> {
        let con = con as usize;
        self.cons[con].0.call_id = call.call_id();
        self.cons[con].1 = CallVariant::Call(call);
        Ok(())
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

    pub fn close_call(
        &mut self,
        call: crate::Call,
    ) -> (crate::types::CallBuilderImpl, Vec<u8>, Vec<u8>) {
        let cons = call.cons();
        if call.fixed {
            let mut out = None;
            for c in cons.iter() {
                if let Some((_con, mut call)) = self.cons_fixed.remove(c) {
                    if let Some(call) = call.take() {
                        out = Some(call.stop());
                    }
                }
            }
            if let Some(out) = out {
                return out;
            }
        }
        let mut con = usize::max_value();
        for conid in cons.into_iter() {
            if *conid != usize::max_value() {
                if self.cons[*conid].1.as_ref().is_some() {
                    con = *conid;
                    break;
                }
            }
        }
        let call: CallImpl = self.cons[con].1.take().unwrap();
        let (builder, hdr_buf, body_buf) = call.stop();
        // println!("close_call {} toclose={} {}",con, self.cons[con].0.to_close, self.cons.len());
        {
            let host = &builder.bytes.host;
            if !self.cons[con].0.to_close {
                if self.cons[con].1.is_none() {
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
        let (con, _) = self.cons.remove(toclose);
        if let Some(other) = con.get_other() {
            self.cons.remove(other);
        }
    }
}
