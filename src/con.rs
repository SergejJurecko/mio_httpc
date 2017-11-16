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
use ::call::CallParam;

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
    pub token: Token,
    // pub req: Request<T>,
    nuses: usize,
    pub ready: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    mid_tls: Option<MidHandshakeTlsStream<TcpStream>>,
    _dns: Option<Dns>,
    dns_sock: Option<UdpSocket>,
    con_port: u16,
    closed: bool,
}

impl Con {
    pub fn new<C:TlsConnector,T>(token: Token, req: &Request<T>, cache: &mut DnsCache, poll: &Poll) -> Result<Con> {
        let port = url_port(req.uri())?;
        let mut sock = None;
        let mut rdy = Ready::writable() | Ready::writable();
        if let Some(host) = req.uri().host() {
            if let Some(ip) = cache.find(host) {
                sock = Some(connect(SocketAddr::new(ip,port))?);
            } else if let Ok(ip) = IpAddr::from_str(host) {
                sock = Some(connect(SocketAddr::new(ip,port))?);
            }
        }
        let mut dns_sock = None;
        let dns = if sock.is_none() {
            let r = Dns::new();
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
            ready: Ready::empty(),
            nuses: 0,
            token,
            sock,
            _dns: dns,
            dns_sock,
            tls: None,
            mid_tls: None,
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
                    // println!("Got ADDR={}:{}",ip,port);
                    self.dns_sock = Some(udp);
                    self.deregister(cp.poll)?;
                    self.dns_sock = None;
                    self.sock = Some(connect(SocketAddr::new(ip,port))?);
                    self.ready = Ready::writable() | Ready::writable();
                    self.register(cp.poll, self.token, self.ready, PollOpt::edge())?;

                    return Ok(());
                }
            }
            self.dns_sock = Some(udp);
        } else {
            if cp.ev.readiness().is_readable() {
                println!("writable!");
                if self.sock.is_some() && self.con_port == 443 && self.tls.is_none() && self.mid_tls.is_none() {
                    println!("START TLS");
                    let connector: C = C::builder()?.build()?;
                    let host = req.uri().host().unwrap();
                    let tcp = self.sock.take().unwrap();
                    let r = connector.connect(host, tcp);
                    self.handshake_resp::<C>(r)?;
                }
            }
            if self.mid_tls.is_some() && cp.ev.readiness().is_readable() {
                println!("MID TLS");
                let tls = self.mid_tls.take().unwrap();
                let r = tls.handshake();
                self.handshake_resp::<C>(r)?;
            }
            self.ready |= cp.ev.readiness();
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
            println!("REad tcp?");
            tcp.read(buf)
        } else if let Some(ref mut tls) = self.tls {
            println!("read tls");
            tls.read(buf)
        } else {
            Err(::std::io::Error::new(::std::io::ErrorKind::WouldBlock,"No socket"))
        }
    }
}

impl Write for Con {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        if let Some(ref mut tcp) = self.sock {
            println!("Write tcp?");
            tcp.write(buf)
        } else if let Some(ref mut tls) = self.tls {
            println!("write tls");
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
            // Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
            // Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
            // Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
            Ok(())
        }
    }
}