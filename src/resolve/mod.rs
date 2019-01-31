#![allow(dead_code)]
use mio::net::UdpSocket;
use std::io::{self,ErrorKind as IoErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
// use mio::Poll;
use crate::dns_parser;
use crate::dns_parser::{Packet, RRData};
use rand;
use smallvec::SmallVec;
use std::time::{Duration, Instant};


mod cache;
pub use self::cache::DnsCache;
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple;

pub(crate) fn dns_parse(buf: &[u8], vec: &mut SmallVec<[IpAddr; 2]>) {
    let packet = Packet::parse(buf).unwrap();
    let mut have_ip4 = false;
    let mut have_ip6 = false;
    for a in packet.answers {
        match a.data {
            RRData::A(ip) if !have_ip4 => {
                have_ip4 = true;
                // println!("GOT IP {}", ip);
                vec.push(IpAddr::V4(ip));
            }
            RRData::AAAA(ip) if !have_ip6 => {
                // println!("GOT IP6 {}", ip);
                have_ip6 = true;
                vec.push(IpAddr::V6(ip));
            }
            _ => {}
        }
        if vec.len() == vec.capacity() {
            return;
        }
    }
}
pub struct Dns {
    srvs: SmallVec<[SocketAddr; 4]>,
    pub sock: UdpSocket,
    pos: u8,
    last_send: Instant,
    retry_in: Duration,
    ipv4: bool,
    sent: bool,
}

impl Dns {
    pub fn new(host: &str, retry_in: u64, servers: &[SocketAddr], ipv4: bool) -> crate::Result<Dns> {
        let mut srvs = SmallVec::with_capacity(2);
        for s in servers.iter() {
            srvs.push(*s);
        }
        if srvs.len() == 0 {
            get_dns_servers(ipv4, &mut srvs);
        }
        if srvs.len() == 0 {
            get_google(&mut srvs)
        }
        let (sent,sock) = Self::start_lookup(ipv4, &srvs[..], host)?;
        Ok(Dns {
            ipv4,
            srvs,
            sock,
            pos: 0,
            last_send: Instant::now(),
            retry_in: Duration::from_millis(retry_in),
            sent,
        })
    }

    pub fn check_retry(&mut self, now: Instant, host: &str) {
        if now - self.last_send >= self.retry_in {
            let mut pos = self.pos as usize;
            let _ = Self::lookup_on(self.ipv4, &self.srvs, &self.sock, &mut pos, host);
            self.pos = (pos & 0xff) as u8;
            self.last_send = now;
            let secdur = Duration::from_millis(1000);
            self.retry_in = if (self.retry_in * 2) > secdur {
                secdur
            } else {
                self.retry_in * 2
            };
        }
    }

    pub fn try_send(&mut self, host: &str) {
        if !self.sent {
            let now = Instant::now();
            let mut pos = self.pos as usize;
            if let Ok(true) = Self::lookup_on(self.ipv4, &self.srvs, &self.sock, &mut pos, host) {
                self.pos = (pos & 0xff) as u8;
                self.last_send = now;
                self.sent = true;
            }
        }
    }

    // pub fn check_cached(&mut self, host: &str) -> Option<IpAddr> {
    //     self.cache.find(host)
    // }

    fn get_socket_v4() -> io::Result<UdpSocket> {
        let s4a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        let s4 = UdpSocket::bind(&s4a)?;
        Ok(s4)
    }

    fn get_socket_v6() -> io::Result<UdpSocket> {
        let s6a = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            0,
            0,
            0,
        ));
        let s6 = UdpSocket::bind(&s6a)?;
        Ok(s6)
    }

    fn start_lookup(ipv4: bool, srvs: &[SocketAddr], host: &str) -> crate::Result<(bool,UdpSocket)> {
        let mut pos = 0;
        if ipv4 {
            let sock = Self::get_socket_v4()?;
            let sent = Self::lookup_on(ipv4, srvs, &sock, &mut pos, host)?;
            return Ok((sent,sock));
        }
        let s = Self::get_socket_v6()?;
        let sent = Self::lookup_on(ipv4, srvs, &s, &mut pos, host)?;
        Ok((sent,s))
    }

    fn lookup_on(
        ipv4: bool,
        srvs: &[SocketAddr],
        sock: &UdpSocket,
        pos: &mut usize,
        host: &str,
    ) -> crate::Result<bool> {
        let len_srvs = srvs.len();
        let mut last_err = io::Error::new(io::ErrorKind::Other, "");
        // let rnd = (self.rng.next_u32() & 0x0000_FFFF) as u16;
        let rnd = rand::random::<u16>();
        for _ in 0..len_srvs {
            let srv = *pos % srvs.len();
            *pos += 1;
            // let sockaddr = SocketAddr::new(srvs[srv], 53);
            let sockaddr = srvs[srv];

            let mut buf_send = [0; 512];
            let nsend = {
                let mut builder = dns_parser::Builder::new(&mut buf_send[..]);
                let _ = builder.start(rnd, true);
                if ipv4 {
                    let _ = builder.add_question(
                        host,
                        dns_parser::QueryType::A,
                        dns_parser::QueryClass::IN,
                    );
                } else {
                    let _ = builder.add_question(
                        host,
                        dns_parser::QueryType::AAAA,
                        dns_parser::QueryClass::IN,
                    );
                }

                builder.finish()
            };
            let res = sock.send_to(&buf_send[..nsend], &sockaddr);
            if let Ok(_) = res {
                return Ok(true);
            } else if let Err(e) = res {
                last_err = e;
            }
        }
        if last_err.kind() == IoErrorKind::WouldBlock {
            return Ok(false);
        }
        Err(From::from(last_err))
    }

    // pub fn check_result(&mut self) -> Option<(usize,usize,IpAddr)> {
    //     None
    // }
}

// #[cfg(target_os = "macos")]
// pub fn get_dns_servers(srvs: &mut SmallVec<[IpAddr; 4]>) {
//     let out = ::std::process::Command::new("scutil").arg("--dns").output();
//     if let Ok(out) = out {
//         if let Ok(s) = String::from_utf8(out.stdout) {
//             scutil_parse(srvs, s);
//         }
//     }
//     if srvs.len() == 0 {
//         get_google(srvs)
//     }
// }
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn get_dns_servers(ipv4: bool, srvs: &mut SmallVec<[SocketAddr; 4]>) {
    unsafe {
        let mut sockaddr = ::std::mem::zeroed::<[apple::res_9_sockaddr_union; 4]>();
        let mut state = ::std::mem::zeroed::<apple::__res_9_state>();
        if apple::res_9_ninit(&mut state) >= 0 {
            let n = apple::res_9_getservers(&mut state, &mut sockaddr[0] as _, sockaddr.len() as _);
            if n > 0 {
                for i in 0..(n as usize) {
                    if sockaddr[i].sin.sin_len > 0 {
                        let ip4 = Ipv4Addr::from(u32::from_be(sockaddr[i].sin.sin_addr.s_addr));
                        if ip4.is_unspecified()
                            || ip4.is_broadcast()
                            || ip4.is_multicast()
                            || ip4.is_documentation()
                        {
                            continue;
                        }
                        srvs.push(SocketAddr::new(IpAddr::V4(ip4), 53));
                    }
                    if sockaddr[i].sin6.sin6_len > 0 {
                        let s = sockaddr[i].sin6.sin6_addr.__u6_addr.__u6_addr16;
                        let ip6 = IpAddr::V6(Ipv6Addr::new(
                            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                        ));
                        if ip6.is_unspecified() || ip6.is_multicast() || ipv4 {
                            continue;
                        }
                        srvs.push(SocketAddr::new(ip6, 53));
                    }
                }
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "ios")))]
pub fn get_dns_servers(_ipv4: bool, srvs: &mut SmallVec<[SocketAddr; 4]>) {
    if let Ok(mut file) = ::std::fs::File::open("/etc/resolv.conf") {
        let mut contents = String::new();
        use std::io::Read;
        if file.read_to_string(&mut contents).is_ok() {
            resolv_parse(srvs, contents);
        }
    }
}

#[cfg(windows)]
pub fn get_dns_servers(ipv4: bool, srvs: &mut SmallVec<[SocketAddr; 4]>) {
    if let Ok(v) = ipconfig::get_adapters() {
        for ad in v {
            for ip in ad.dns_servers() {
                if ipv4 && ip.is_ipv6() {
                    continue;
                }
                let sad = SocketAddr::new(*ip,53);
                if !srvs.contains(&sad) {
                    srvs.push(sad);
                }
            }
        }
    }
}

fn get_google(srvs: &mut SmallVec<[SocketAddr; 4]>) {
    srvs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
    srvs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53));
}

fn resolv_parse(srvs: &mut SmallVec<[SocketAddr; 4]>, s: String) {
    // let mut out = Vec::with_capacity(2);
    for line in s.lines() {
        let mut words = line.split_whitespace();
        if let Some(s) = words.next() {
            if s.starts_with("nameserver") {
                if let Some(s) = words.next() {
                    if let Ok(adr) = s.parse() {
                        // out[pos] = adr;
                        srvs.push(adr);
                    }
                }
            }
        }
    }
}

// fn scutil_parse(srvs: &mut SmallVec<[SocketAddr; 4]>, s: String) {
//     for line in s.lines() {
//         let mut words = line.split_whitespace();
//         if let Some(s) = words.next() {
//             if s.starts_with("nameserver[") {
//                 if let Some(s) = words.next() {
//                     if s == ":" {
//                         if let Some(s) = words.next() {
//                             if let Ok(adr) = s.parse() {
//                                 srvs.push(adr);
//                             }
//                         }
//                     }
//                 }
//             }
//         }
//     }
// }
