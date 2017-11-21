use dns::{self,Dns};
use dns_cache::DnsCache;
use tls_api::{TlsConnector,TlsStream,TlsConnectorBuilder,HandshakeError, MidHandshakeTlsStream};
use ::Result;
use mio::net::{TcpStream,UdpSocket};
use mio::event::Evented;
use mio::{Token,Ready,PollOpt,Poll};
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use http::{Request,Uri};
use std::io::{Read,Write};
use ::types::CallParam;
use fnv::FnvHashMap as HashMap;

fn url_port(url: &Uri) -> Result<u16> {
    if let Some(p) = url.port() {
        return Ok(p);
    }
    if let Some(scheme) = url.scheme() {
        if scheme == "https" {
            return Ok(443);
        } else if scheme == "http" {
            return Ok(80);
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
    // pub req: Request<T>,
    nuses: usize,
    reg_for: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    mid_tls: Option<MidHandshakeTlsStream<TcpStream>>,
    _dns: Option<Dns>,
    dns_sock: Option<UdpSocket>,
    con_port: u16,
    closed: bool,
    pub to_close: bool,
    root_ca: Vec<Vec<u8>>,
}

impl Con {
    pub fn new<C:TlsConnector,T>(token: Token, req: &Request<T>, cache: &mut DnsCache, poll: &Poll, root_ca: Vec<Vec<u8>>) -> Result<Con> {
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
        let mut dns_sock = None;
        let dns = if sock.is_none() {
            let mut r = Dns::new();
            if let Some(host) = req.uri().host() {
                rdy = Ready::readable();
                dns_sock = Some(r.start_lookup(token.0, host)?);
            } else {
                return Err(::Error::NoHost);
            }
            Some(r)
        } else { None };
        let res = Con {
            con_port: port,
            closed: false,
            to_close: false,
            reg_for: rdy,
            nuses: 0,
            token,
            sock,
            _dns: dns,
            dns_sock,
            tls: None,
            mid_tls: None,
            root_ca,
        };
        res.register(poll, res.token, rdy, PollOpt::edge())?;
        Ok(res)
    }

    pub fn close(&mut self) {
        self.sock = None;
        self.tls = None;
        self.dns_sock = None;
        self._dns = None;
        self.closed = true;
    }

    #[inline]
    pub fn closed(&self) -> bool {
        self.closed
    }

    pub fn reg(&mut self, poll: &Poll, rdy: Ready) -> ::std::io::Result<()> {
        if self.reg_for.is_empty() {
            self.reg_for = rdy;
            self.register(poll, self.token, self.reg_for, PollOpt::edge())
        } else {
            self.reg_for = rdy;
            self.reregister(poll, self.token, self.reg_for, PollOpt::edge())
        }
    }

    pub(crate) fn signalled<'a,C:TlsConnector,T>(&mut self, cp: &mut CallParam, req: &Request<T>) -> Result<()> {
        if self.dns_sock.is_some() {
            let udp = self.dns_sock.take().unwrap();
            let mut buf: [u8;512] = unsafe { ::std::mem::uninitialized() };
            if let Ok(sz) = udp.recv(&mut buf[..]) {
                if let Some(ip) = dns::dns_parse(&buf[..sz]) {
                    let host = req.uri().host().unwrap();
                    cp.dns.save(host, ip);
                    let port = url_port(req.uri())?;
                    // self.sock = Some(TcpStream::connect(&SocketAddr::new(ip,port))?);
                    self.dns_sock = Some(udp);
                    self.deregister(cp.poll)?;
                    self.dns_sock = None;
                    self.sock = Some(connect(SocketAddr::new(ip,port))?);
                    self.reg_for = Ready::writable();
                    self.register(cp.poll, self.token, self.reg_for, PollOpt::edge())?;

                    return Ok(());
                }
            }
            self.dns_sock = Some(udp);
        } else {
            if self.sock.is_some() && self.con_port == 443 && self.tls.is_none() && self.mid_tls.is_none() {
                let mut connector = C::builder()?;
                let root_ca = ::std::mem::replace(&mut self.root_ca, Vec::new());
                for rca in root_ca.into_iter() {
                    connector.add_root_certificate(::tls_api::Certificate::from_der(rca))?;
                }
                let connector = connector.build()?;
                let host = req.uri().host().unwrap();
                // Switch to level trigger for tls.
                self.reg_for = Ready::readable();
                self.reregister(cp.poll, self.token, self.reg_for, PollOpt::level())?;
                let tcp = self.sock.take().unwrap();
                let r = connector.connect(host, tcp);
                self.handshake_resp::<C>(r)?;
            }
            if self.mid_tls.is_some() {
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
        } else if let Some(ref udp) = self.dns_sock {
            poll.register(udp,token, interest, opts)
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
        } else if let Some(ref udp) = self.dns_sock {
            poll.reregister(udp,token, interest, opts)
        } else {
            Ok(())
        }
    }
    
    fn deregister(&self, poll: &Poll) -> ::std::io::Result<()> {
        if let Some(ref tcp) = self.sock {
            poll.deregister(tcp)
        } else if let Some(ref tls) = self.tls {
            poll.deregister(tls.get_ref())
        } else if let Some(ref udp) = self.dns_sock {
            poll.deregister(udp)
        } else {
            Ok(())
        }
    }
}

pub struct ConTable {
    cons: Vec<Con>,
    open_cons: HashMap<String,Con>,
    empty_slots: usize,
}

impl ConTable {
    pub fn new() -> ConTable {
        ConTable {
            open_cons: HashMap::default(),
            cons: Vec::with_capacity(4),
            empty_slots: 0,
        }
    }

    pub fn get_con(&mut self, id: usize) -> Option<&mut Con> {
        if id < self.cons.len() {
            let c = &mut self.cons[id];
            return Some(c);
        }
        None
    }

    pub fn push_con(&mut self, mut c: Con) -> Option<u16> {
        if self.cons.len() == (u16::max_value() as usize) {
            return None;
        }
        if self.empty_slots*4 <= self.cons.len() {
            c.token = Token::from(c.token.0 + self.cons.len());
            self.cons.push(c);
            Some((self.cons.len()-1) as u16)
        } else {
            for i in 0..self.cons.len() {
                if self.cons[i].closed() {
                    c.token = Token::from(c.token.0 + i);
                    self.cons[i] = c;
                    self.empty_slots -= 1;
                    return Some(i as u16);
                }
            }
            return None;
        }
    }

    pub fn close_con(&mut self, pos: u16) {
        let pos = pos as usize;
        self.cons[pos].close();
        self.empty_slots += 1;
        loop {
            if self.cons.last().is_some() {
                if self.cons.last().unwrap().closed() {
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