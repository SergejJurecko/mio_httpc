use dns::{self,Dns};
use dns_cache::DnsCache;
use tls_api::{TlsConnector,TlsStream,TlsConnectorBuilder,HandshakeError, MidHandshakeTlsStream};
use ::{Result,CallRef};
use mio::net::{TcpStream};
use mio::event::Evented;
use mio::{Token,Ready,PollOpt,Poll};
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use std::time::Instant;
use http::{Request,Uri};
use std::io::{Read,Write};
use ::types::CallParam;
use fnv::FnvHashMap as HashMap;
use smallvec::SmallVec;
use ::call::CallImpl;

fn url_port(url: &Uri) -> Result<u16> {
    if let Some(p) = url.port() {
        return Ok(p);
    }
    if let Some(scheme) = url.scheme_part() {
        if scheme == "https" {
            return Ok(443);
        } else if scheme == "http" {
            return Ok(80);
        } else if scheme == "ws" {
            return Ok(80);
        } else if scheme == "wss" {
            return Ok(443);
        } else {
            return Err(::Error::InvalidScheme);
        }
    } else {
        return Err(::Error::InvalidScheme);
    }
}

fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    return Ok(tcp);
}

pub struct Con {
    token: Token,
    after_first: bool,
    reg_for: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    mid_tls: Option<MidHandshakeTlsStream<TcpStream>>,
    dns: Option<Dns>,
    con_port: u16,
    closed: bool,
    pub to_close: bool,
    root_ca: Vec<Vec<u8>>,
}

impl Con {
    pub fn new<C:TlsConnector,T>(token: Token, req: &Request<T>, cache: &mut DnsCache, 
            poll: &Poll, root_ca: Vec<Vec<u8>>, dns_timeout: u64) -> Result<Con> {
        let port = url_port(req.uri())?;
        let mut sock = None;
        let mut rdy = Ready::writable();
        if let Some(host) = req.uri().host() {
            if let Some(ip) = cache.find(host) {
                sock = Some(connect(SocketAddr::new(ip,port))?);
            } else if let Ok(ip) = IpAddr::from_str(host) {
                sock = Some(connect(SocketAddr::new(ip,port))?);
            }
        }
        let dns = if sock.is_none() {
            if let Some(host) = req.uri().host() {
                rdy = Ready::readable();
                Some(Dns::new(host,dns_timeout)?)
            } else {
                return Err(::Error::NoHost);
            }
        } else { None };
        let res = Con {
            con_port: port,
            closed: false,
            to_close: false,
            reg_for: rdy,
            after_first: false,
            token,
            sock,
            dns,
            // dns_sock,
            tls: None,
            mid_tls: None,
            root_ca,
        };
        res.register(poll, res.token, rdy, PollOpt::edge())?;
        Ok(res)
    }

    pub fn timeout(&mut self, host: &str) {
        if let Some(ref mut dns) = self.dns {
            dns.check_retry(host);
        }
    }

    pub fn close(&mut self) {
        self.sock = None;
        self.tls = None;
        // self.dns_sock = None;
        self.dns = None;
        self.closed = true;
    }

    #[inline]
    pub fn closed(&self) -> bool {
        self.closed
    }

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

    pub fn signalled<'a,C:TlsConnector,T>(&mut self, cp: &mut CallParam, req: &Request<T>) -> Result<()> {
        if self.dns.is_some() {
            let dns = self.dns.take().unwrap();
            let mut buf: [u8;512] = unsafe { ::std::mem::uninitialized() };
            if let Ok(sz) = dns.sock.recv(&mut buf[..]) {
                if let Some(ip) = dns::dns_parse(&buf[..sz]) {
                    let host = req.uri().host().unwrap();
                    cp.dns.save(host, ip);
                    let port = url_port(req.uri())?;
                    self.dns = None;
                    self.deregister(cp.poll)?;
                    self.sock = Some(connect(SocketAddr::new(ip,port))?);
                    self.reg_for = Ready::writable();
                    self.register(cp.poll, self.token, self.reg_for, PollOpt::edge())?;

                    return Ok(());
                }
            }
            self.dns = Some(dns);
        } else {
            if self.sock.is_some() && self.con_port == 443 && self.tls.is_none() && self.mid_tls.is_none() {
                let mut connector = C::builder()?;
                let root_ca = ::std::mem::replace(&mut self.root_ca, Vec::new());
                for rca in root_ca.into_iter() {
                    let _ = connector.add_root_certificate(::tls_api::Certificate::from_der(rca));
                }
                let connector = connector.build()?;
                let host = req.uri().host().unwrap();
                self.reg(cp.poll, Ready::readable())?;
                let tcp = self.sock.take().unwrap();
                let r = connector.connect(host, tcp);
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

    fn handshake_resp<C:TlsConnector>(&mut self, r: ::std::result::Result<TlsStream<TcpStream>, HandshakeError<TcpStream>>) -> Result<()> {
        match r {
            Ok(tls) => {
                self.tls = Some(tls);
            }
            Err(HandshakeError::Interrupted(mid)) => {
                self.mid_tls = Some(mid);
            }
            Err(e) => {
                return Err(::Error::TlsHandshake);
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
            Err(::std::io::Error::new(::std::io::ErrorKind::WouldBlock,"No socket"))
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
            Err(::std::io::Error::new(::std::io::ErrorKind::WouldBlock,"No socket"))
        }
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        if let Some(ref mut tcp) = self.sock {
            tcp.flush()
        } else if let Some(ref mut tls) = self.tls {
            tls.flush()
        } else {
            Err(::std::io::Error::new(::std::io::ErrorKind::WouldBlock,"No socket"))
        }
    }
}

impl Evented for Con {
    fn register(
        &self, 
        poll: &Poll, 
        token: Token, 
        interest: Ready, 
        opts: PollOpt
    ) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.register(tcp,token, interest, opts) 
        } else if let Some(ref tls) = self.tls {
            poll.register(tls.get_ref(),token, interest, opts)
        } else if let Some(ref dns) = self.dns {
            poll.register(&dns.sock,token, interest, opts)
        // } else if let Some(ref tls) = self.mid_tls {
        //     poll.register(tls.get_ref(),token, interest, opts)
        } else {
            Ok(())
        }
    }

    fn reregister(
        &self, 
        poll: &Poll, 
        token: Token, 
        interest: Ready, 
        opts: PollOpt
    ) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.reregister(tcp,token, interest, opts)
        } else if let Some(ref tls) = self.tls {
            poll.reregister(tls.get_ref(),token, interest, opts)
        } else if let Some(ref dns) = self.dns {
            poll.reregister(&dns.sock,token, interest, opts)
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

struct HostCons {
    uri: Uri,
}

impl HostCons {
    pub fn new(uri: Uri) -> HostCons {
        HostCons {
            uri,
        }
    }
}
use std::hash::{Hash, Hasher};
impl Hash for HostCons {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        if let Some(host) = self.uri.host() {
            Hash::hash_slice(host.as_bytes(), state);
        }
    }
}
impl ::std::borrow::Borrow<str> for HostCons {
    #[inline]
    fn borrow(&self) -> &str {
        self.uri.host().unwrap()
    }
}

impl PartialEq for HostCons {
    fn eq(&self, uri: &HostCons) -> bool {
        if let Some(host) = self.uri.host() {
            if let Some(host1) = uri.uri.host() {
                return host == host1;
            }
        }
        false
    }
}
impl PartialEq<str> for HostCons {
    fn eq(&self, host1: &str) -> bool {
        if let Some(host) = self.uri.host() {
            return host == host1;
        }
        false
    }
}
impl Eq for HostCons {}

pub struct ConTable {
    cons: Vec<(Con,SmallVec<[CallImpl;2]>)>,
    // cons that can be used for new requests
    keepalive: HashMap<HostCons,SmallVec<[u16;8]>>,
    empty_slots: usize,
}

impl ConTable {
    pub fn new() -> ConTable {
        ConTable {
            keepalive: HashMap::with_capacity_and_hasher(4, Default::default()),
            cons: Vec::with_capacity(4),
            empty_slots: 0,
        }
    }

    pub fn get_con(&mut self, id: usize) -> Option<&mut Con> {
        if id < self.cons.len() {
            let c = &mut self.cons[id].0;
            return Some(c);
        }
        None
    }

    pub fn timeout_extend(&mut self, now: Instant, out: &mut Vec<CallRef>) {
        let mut con_id = 0;
        for &mut (ref mut con, ref mut calls) in self.cons.iter_mut() {
            let mut call_id = 0;
            for call in calls.iter_mut() {
                if !call.is_done() {
                    if now - call.start_time() >= call.settings().dur {
                        out.push(CallRef::new(con_id, call_id));
                    } else if call_id == 0 {
                        if let Some(host) = call.settings().req.uri().host() {
                            con.timeout(host);
                        }
                    }
                }
                call_id += 1;
            }
            con_id += 1;
        }
    }

    pub fn peek_body(&mut self, con: u16, call: u16, off: &mut usize) -> &[u8] {
        self.cons[con as usize].1[call as usize].peek_body(off)
    }
    pub fn try_truncate(&mut self, con: u16, call:u16, off: &mut usize) {
        self.cons[con as usize].1[call as usize].try_truncate(off);
    }
    pub fn event_send<C:TlsConnector>(&mut self, con: u16, call:u16, cp: &mut CallParam, buf: Option<&[u8]>) -> Result<::SendState> {
        let conp = &mut self.cons[con as usize];
        conp.1[call as usize].event_send::<C>(&mut conp.0, cp, buf)
    }
    pub fn event_recv<C:TlsConnector>(&mut self, con: u16, call:u16, cp: &mut CallParam, buf: Option<&mut Vec<u8>>) -> Result<::RecvState> {
        let conp = &mut self.cons[con as usize];
        conp.1[call as usize].event_recv::<C>(&mut conp.0, cp, buf)
    }

    pub fn push_con(&mut self, mut c: Con, call: CallImpl) -> Option<u16> {
        if self.cons.len() == (u16::max_value() as usize) {
            return None;
        }
        if self.empty_slots*4 <= self.cons.len() {
            c.token = Token::from(c.token.0 + self.cons.len());
            let mut v = SmallVec::new();
            v.push(call);
            self.cons.push((c,v));
            Some((self.cons.len()-1) as u16)
        } else {
            for i in 0..self.cons.len() {
                if self.cons[i].0.closed() {
                    c.token = Token::from(c.token.0 + i);
                    self.cons[i].0 = c;
                    self.cons[i].1.push(call);
                    self.empty_slots -= 1;
                    return Some(i as u16);
                }
            }
            return None;
        }
    }

    fn extract_call(callid: u16, calls: &mut SmallVec<[CallImpl;2]>) -> CallImpl {
        let callid = callid as usize;
        if callid+1 == calls.len() {
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

    pub fn close_call(&mut self, con: u16, call: u16) -> (Vec<u8>, Vec<u8>) {
        let con = con as usize;
        let call:CallImpl = Self::extract_call(call, &mut self.cons[con].1);
        let (builder, call_buf) = call.stop();
        let (parts, req_buf) = builder.req.into_parts();
        let uri = parts.uri;
        // if !self.cons[con].0.to_close && uri.host().is_some() {
        //     if self.keepalive.contains_key(uri.host().unwrap()) {
        //         let v = self.keepalive.get_mut(uri.host().unwrap()).unwrap();
        //         v.push(con as u16);
        //     } else {
        //         let mut v = SmallVec::new();
        //         v.push(con as u16);
        //         self.keepalive.insert(HostCons::new(uri), v);
        //     }
        // } else {
            self.close_con(con as u16);
        // }
        (call_buf, req_buf)
    }

    fn close_con(&mut self, pos: u16) {
        let pos = pos as usize;
        self.cons[pos].0.close();
        self.empty_slots += 1;
        loop {
            if self.cons.last().is_some() {
                if self.cons.last().unwrap().0.closed() {
                    self.empty_slots -= 1;
                    let _ = self.cons.pop();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
}