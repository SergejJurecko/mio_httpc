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
use std::io::Read;

pub struct Con<T> {
    pub token: Token,
    pub req: Request<T>,
    sock: Option<TcpStream>,
    tls: Option<TlsStream<TcpStream>>,
    _dns: Option<Dns>,
    dns_sock: Option<UdpSocket>,
}

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

fn connect<C: TlsConnector>(addr: SocketAddr) -> Result<(Option<TcpStream>,Option<TlsStream<TcpStream>>)> {
    let tcp = TcpStream::connect(&addr)?;
    if addr.port() == 443 {
        let connector: C = C::builder()?.build()?;
        if let Ok(t) = connector.connect("google.com", tcp) {
            return Ok((None,Some(t)));
        } else {
            return Err(::Error::TlsHandshake);
        }
    }
    return Ok((Some(tcp),None));
}

impl<T> Con<T> {
    pub fn new<C:TlsConnector>(token: Token, req: Request<T>, cache: &mut DnsCache, poll: &Poll) -> Result<Con<T>> {
        let port = url_port(req.uri())?;
        let mut sock = None;
        let mut tls = None;
        let mut rdy = Ready::writable();
        if let Some(host) = req.uri().host() {
            if let Some(ip) = cache.find(host) {
                let r = connect::<C>(SocketAddr::new(ip,port))?;
                sock = r.0;
                tls = r.1;
            } else if let Ok(ip) = IpAddr::from_str(host) {
                let r = connect::<C>(SocketAddr::new(ip,port))?;
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
            token,
            req,
            sock,
            _dns: dns,
            dns_sock,
            tls,
        };
        res.register(poll, res.token, rdy, PollOpt::edge())?;
        Ok(res)
    }

    pub fn signalled<'a, C:TlsConnector>(&mut self, poll: &Poll, buf: &'a mut [u8]) -> Result<usize> {
        if let Some(ref mut tcp) = self.sock {
            return Ok(tcp.read(buf)?);
        } else if let Some(ref mut tls) = self.tls {
            return Ok(tls.read(buf)?);
        } else if self.dns_sock.is_some() {
            let udp = self.dns_sock.take().unwrap();
            // let mut buf: [u8;512] = unsafe { ::std::mem::uninitialized() };
            if let Ok(sz) = udp.recv(buf) {
                if let Some(ip) = dns::dns_parse(&buf[..sz]) {
                    let port = url_port(self.req.uri())?;
                    // self.sock = Some(TcpStream::connect(&SocketAddr::new(ip,port))?);
                    let r = connect::<C>(SocketAddr::new(ip,port))?;
                    self.sock = r.0;
                    self.tls = r.1;
                    self.register(poll, self.token, Ready::writable(), PollOpt::edge())?;
                    return Ok(0);
                }
            }
            self.dns_sock = Some(udp);
        }
        Ok(0)
    }
}

impl<T> Evented for Con<T> {
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