use dns::{self,Dns};
use dns_cache::DnsCache;
// use url::Url;
use tls_api::{TlsConnector,TlsStream,TlsConnectorBuilder};
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

fn connect<C: TlsConnector>(addr: SocketAddr, host: &str) -> Result<(Option<TcpStream>,Option<TlsStream<TcpStream>>)> {
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_nodelay(true)?;
    if addr.port() == 443 {
        let connector: C = C::builder()?.build()?;
        if let Ok(t) = connector.connect(host, tcp) {
            return Ok((None,Some(t)));
        } else {
            return Err(::Error::TlsHandshake);
        }
    }
    return Ok((Some(tcp),None));
}

pub struct Con {
    pub token: Token,
    // pub req: Request<T>,
    nuses: usize,
    pub ready: Ready,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    _dns: Option<Dns>,
    dns_sock: Option<UdpSocket>,
    closed: bool,
}

impl Con {
    pub fn new<C:TlsConnector,T>(token: Token, req: &Request<T>, cache: &mut DnsCache, poll: &Poll) -> Result<Con> {
        let port = url_port(req.uri())?;
        let mut sock = None;
        let mut tls = None;
        let mut rdy = Ready::writable() | Ready::writable();
        if let Some(host) = req.uri().host() {
            if let Some(ip) = cache.find(host) {
                let r = connect::<C>(SocketAddr::new(ip,port), host)?;
                sock = r.0;
                tls = r.1;
            } else if let Ok(ip) = IpAddr::from_str(host) {
                let r = connect::<C>(SocketAddr::new(ip,port), host)?;
                sock = r.0;
                tls = r.1;
            }
        }
        let mut dns_sock = None;
        let dns = if sock.is_none() && tls.is_none() {
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
            closed: false,
            ready: Ready::empty(),
            nuses: 0,
            token,
            sock,
            _dns: dns,
            dns_sock,
            tls,
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
                    let r = connect::<C>(SocketAddr::new(ip,port), host)?;
                    self.sock = r.0;
                    self.tls = r.1;
                    self.register(cp.poll, self.token, Ready::writable() | Ready::writable(), PollOpt::edge())?;
                    return Ok(());
                }
            }
            self.dns_sock = Some(udp);
        } else {
            self.ready |= cp.ev.readiness();
            // if let Some(ref mut tcp) = self.sock {
            //     return Ok(tcp.read(buf)?);
            // } else if let Some(ref mut tls) = self.tls {
            //     return Ok(tls.read(buf)?);
            // }
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
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
        }
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        if let Some(ref mut tcp) = self.sock {
            tcp.flush()
        } else if let Some(ref mut tls) = self.tls {
            tls.flush()
        } else {
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
        } else {
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
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
            Err(::std::io::Error::new(::std::io::ErrorKind::NotConnected,"No socket"))
        }
    }
}