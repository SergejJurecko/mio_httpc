// Modified from https://github.com/tailhook/dns-parser

// Removed panics, unnecessary allocations.

mod enums;
mod structs;
mod name;
mod parser;
mod error;
mod header;
mod rrdata;
mod builder;

pub use self::enums::{Type, QueryType, Class, QueryClass, ResponseCode, Opcode};
pub use self::structs::{Question, ResourceRecord, OptRecord, Packet, SoaRecord};
pub use self::name::{Name};
pub use self::error::{Error};
pub use self::header::{Header};
pub use self::rrdata::{RRData};
pub use self::builder::{Builder};
