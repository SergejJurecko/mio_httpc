use std::str::Utf8Error;
// use failure::Error;

#[derive(Debug)]
pub enum DnsError {
    ///invalid compression pointer not pointing backwards when parsing label
    BadPointer,

    ///packet is smaller than header size
    HeaderTooShort,

    ///packet is has incomplete data
    UnexpectedEOF,

    ///wrong (too short or too long) size of RDATA
    WrongRdataLength,

    ///packet has non-zero reserved bits
    ReservedBitsAreNonZero,

    ///label in domain name has unknown label format
    UnknownLabelFormat,

    ///query type is invalid
    InvalidQueryType { code: u16 },

    /// query class is invalid
    InvalidQueryClass { code: u16 },

    ///type is invalid
    InvalidType { code: u16 },

    ///class is invalid
    InvalidClass { code: u16 },

    ///invalid characters encountered while reading label
    LabelIsNotAscii,

    ///invalid characters encountered while reading TXT
    TxtDataIsNotUTF8 { error: Utf8Error },

    /// WrongState,
    AdditionalOPT,
}
