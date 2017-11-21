// pub use self::implemented::Dns;
use std::io;
use std::net::{IpAddr, SocketAddr,Ipv4Addr, SocketAddrV4, SocketAddrV6, Ipv6Addr};
// use std::str::FromStr;
use mio::net::UdpSocket;
// use mio::Poll;
use ::dns_parser;
// use std::collections::VecDeque;
// use std::time::{Instant,Duration};
use rand::os::OsRng;
use rand::Rng;
// use dns_cache::DnsCache;
use ::dns_parser::{Packet,RRData};

pub(crate) fn dns_parse(buf:&[u8]) -> Option<IpAddr> {
    let packet = Packet::parse(buf).unwrap();
    for a in packet.answers {
        match a.data {
            RRData::A(ip) => {
                return Some(IpAddr::V4(ip));
            }
            RRData::AAAA(ip) => {
                return Some(IpAddr::V6(ip));
            }
            _ => {
            }
        }
    }
    None
}
pub struct Dns {
    rng: OsRng,
    srvs: [IpAddr;2],
    // cache: DnsCache,
    // sock4: Option<UdpSocket>,
    // sock6: Option<UdpSocket>,
    // clients: VecDeque<Client>,
}

impl Dns {
    pub fn new() -> Dns {
        Dns {
            rng: OsRng::new().unwrap(),
            // cache: DnsCache::new(),
            srvs: get_dns_servers(),
        }
    }

    // pub fn check_cached(&mut self, host: &str) -> Option<IpAddr> {
    //     self.cache.find(host)
    // }

    fn get_socket_v4(&self) -> io::Result<UdpSocket> {
        let s4a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0,0,0,0),0));
        let s4 = UdpSocket::bind(&s4a)?;
        Ok(s4)
    }

    fn get_socket_v6(&self) -> io::Result<UdpSocket> {
        let s6a = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0,0,0,0,0,0,0,0), 0, 0, 0));
        let s6 = UdpSocket::bind(&s6a)?;
        Ok(s6)
    }

    pub fn start_lookup(&mut self, _id: usize,  host: &str) -> io::Result<UdpSocket> {
        if let Ok(sock) = self.get_socket_v4() {
            if let Ok(_) = self.lookup_on(&sock, 0, host) {
                return Ok(sock)
            }
        }
        let s = self.get_socket_v6()?;
        self.lookup_on(&s, 0, host)?;
        Ok(s)
    }

    pub fn lookup_on(&mut self, sock: &UdpSocket, mut pos: usize, host: &str) -> io::Result<()> {
        let len_srvs = self.srvs.len();
        let mut last_err = io::Error::new(io::ErrorKind::Other,"");
        let rnd = (self.rng.next_u32() & 0x0000_FFFF) as u16;
        for _ in 0..len_srvs {
            let srv = pos % self.srvs.len();
            pos += 1;
            let sockaddr = SocketAddr::new(self.srvs[srv], 53);

            let mut buf_send = [0; 512];
            let nsend = {
                let mut builder = dns_parser::Builder::new(&mut buf_send[..]);
                let _ = builder.start(rnd, true);
                let _ = builder.add_question(host, 
                    dns_parser::QueryType::A,
                    dns_parser::QueryClass::IN);
                builder.finish()
            };
            let res = sock.send_to(&buf_send[..nsend], &sockaddr);
            if let Ok(_) = res {
                return Ok(());
            } else if let Err(e) = res {
                last_err = e;
            }
        }
        Err(last_err)
    }

    // pub fn check_result(&mut self) -> Option<(usize,usize,IpAddr)> {
    //     None
    // }
}

#[cfg(target_os = "macos")]
pub fn get_dns_servers() -> [IpAddr;2] {
    let out = ::std::process::Command::new("scutil")
        .arg("--dns")
        .output();
    if let Ok(out) = out {
        if let Ok(s) = String::from_utf8(out.stdout) {
            return scutil_parse(s);
        }
    }
    get_google()
}

#[cfg(unix)]
#[cfg(not(target_os = "macos"))]
pub fn get_dns_servers() -> [IpAddr;2] {
    if let Ok(mut file) = ::std::fs::File::open("/etc/resolv.conf") {
        let mut contents = String::new();
        use std::io::Read;
        if file.read_to_string(&mut contents).is_ok() {
            return resolv_parse(contents);
        }
    }
    get_google()
}

#[cfg(windows)]
pub fn get_dns_servers() -> Vec<IpAddr> {
    get_google()
}

fn get_google() -> [IpAddr;2] {
    ["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()]
}

#[cfg(unix)]
#[cfg(not(target_os = "macos"))]
fn resolv_parse(s: String) -> [IpAddr;2] {
    // let mut out = Vec::with_capacity(2);
    let z = IpAddr::from(Ipv4Addr::new(0,0,0,0));
    let mut out = [z, z];
    let mut pos = 0;
    for line in s.lines() {
        let mut words = line.split_whitespace();
        if let Some(s) = words.next() {
            if s.starts_with("nameserver") {
                if let Some(s) = words.next() {
                    if let Ok(adr) = s.parse() {
                        out[pos] = adr;
                        pos += 1;
                        if pos >= 2 {
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

fn scutil_parse(s: String) -> [IpAddr;2] {
    // let mut out = Vec::with_capacity(2);
    let z = IpAddr::from(Ipv4Addr::new(0,0,0,0));
    let mut out = [z, z];
    let mut pos = 0;
    for line in s.lines() {
        let mut words = line.split_whitespace();
        if let Some(s) = words.next() {
            if s.starts_with("nameserver[") {
                if let Some(s) = words.next() {
                    if s == ":" {
                        if let Some(s) = words.next() {
                            if let Ok(adr) = s.parse() {
                                out[pos] = adr;
                                pos += 1;
                                if pos >= 2 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}



