use super::{Error, Name, SoaRecord, Type};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RRData<'a> {
    CNAME(Name<'a>),
    NS(Name<'a>),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name<'a>,
    },
    SOA(SoaRecord<'a>),
    PTR(Name<'a>),
    MX {
        preference: u16,
        exchange: Name<'a>,
    },
    TXT(String),
    // Anything that can't be parsed yet
    Unknown(&'a [u8]),
}

impl<'a> RRData<'a> {
    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8]) -> Result<RRData<'a>, Error> {
        match typ {
            Type::A => {
                if rdata.len() != 4 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::A(Ipv4Addr::from(crate::read_u32_be(rdata))))
            }
            Type::AAAA => {
                if rdata.len() != 16 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::AAAA(Ipv6Addr::new(
                    crate::read_u16_be(&rdata[0..2]),
                    crate::read_u16_be(&rdata[2..4]),
                    crate::read_u16_be(&rdata[4..6]),
                    crate::read_u16_be(&rdata[6..8]),
                    crate::read_u16_be(&rdata[8..10]),
                    crate::read_u16_be(&rdata[10..12]),
                    crate::read_u16_be(&rdata[12..14]),
                    crate::read_u16_be(&rdata[14..16]),
                )))
            }
            Type::CNAME => Ok(RRData::CNAME(r#try!(Name::scan(rdata, original)))),
            Type::NS => Ok(RRData::NS(r#try!(Name::scan(rdata, original)))),
            Type::MX => {
                if rdata.len() < 3 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::MX {
                    preference: crate::read_u16_be(&rdata[..2]),
                    exchange: r#try!(Name::scan(&rdata[2..], original)),
                })
            }
            Type::PTR => Ok(RRData::PTR(r#try!(Name::scan(rdata, original)))),
            Type::SOA => {
                let mut pos = 0;
                let primary_name_server = r#try!(Name::scan(rdata, original));
                pos += primary_name_server.byte_len();
                let mailbox = r#try!(Name::scan(&rdata[pos..], original));
                pos += mailbox.byte_len();
                if rdata[pos..].len() < 20 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::SOA(SoaRecord {
                    primary_ns: primary_name_server,
                    mailbox: mailbox,
                    serial: crate::read_u32_be(&rdata[pos..(pos + 4)]),
                    refresh: crate::read_u32_be(&rdata[(pos + 4)..(pos + 8)]),
                    retry: crate::read_u32_be(&rdata[(pos + 8)..(pos + 12)]),
                    expire: crate::read_u32_be(&rdata[(pos + 12)..(pos + 16)]),
                    minimum_ttl: crate::read_u32_be(&rdata[(pos + 16)..(pos + 20)]),
                }))
            }
            Type::SRV => {
                if rdata.len() < 7 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::SRV {
                    priority: crate::read_u16_be(&rdata[..2]),
                    weight: crate::read_u16_be(&rdata[2..4]),
                    port: crate::read_u16_be(&rdata[4..6]),
                    target: r#try!(Name::scan(&rdata[6..], original)),
                })
            }
            Type::TXT => {
                let len = rdata.len();
                if len < 1 {
                    return Err(Error::WrongRdataLength);
                }
                let mut ret_string = String::new();
                let mut pos = 0;
                while pos < len {
                    let rdlen = rdata[pos] as usize;
                    pos += 1;
                    if len < rdlen + pos {
                        return Err(Error::WrongRdataLength);
                    }
                    match str::from_utf8(&rdata[pos..(pos + rdlen)]) {
                        Ok(val) => ret_string.push_str(val),
                        Err(e) => return Err(Error::TxtDataIsNotUTF8 { error: e }),
                    }
                    pos += rdlen;
                }
                Ok(RRData::TXT(ret_string))
            }
            _ => Ok(RRData::Unknown(rdata)),
        }
    }
}
