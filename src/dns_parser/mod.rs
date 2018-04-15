// Modified from https://github.com/tailhook/dns-parser

// Removed panics, unnecessary allocations.

mod builder;
mod enums;
mod error;
mod header;
mod name;
mod parser;
mod rrdata;
mod structs;

pub use self::builder::Builder;
pub use self::enums::{Class, Opcode, QueryClass, QueryType, ResponseCode, Type};
pub use self::error::DnsError as Error;
pub use self::header::Header;
pub use self::name::Name;
pub use self::rrdata::RRData;
pub use self::structs::{OptRecord, Packet, Question, ResourceRecord, SoaRecord};
