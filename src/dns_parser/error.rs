use std::str::Utf8Error;
// use failure::Error;

#[derive(Debug, Fail)]
pub enum DnsError {
    #[fail(display = "invalid compression pointer not pointing backwards when parsing label")]
    BadPointer,

    #[fail(display = "packet is smaller than header size")]
    HeaderTooShort,

    #[fail(display = "packet is has incomplete data")]
    UnexpectedEOF,

    #[fail(display = "wrong (too short or too long) size of RDATA")]
    WrongRdataLength,

    #[fail(display = "packet has non-zero reserved bits")]
    ReservedBitsAreNonZero,

    #[fail(display = "label in domain name has unknown label format")]
    UnknownLabelFormat,

    #[fail(display = "query type {} is invalid", code)]
    InvalidQueryType { code: u16 },

    #[fail(display = "query class {} is invalid", code)]
    InvalidQueryClass { code: u16 },

    #[fail(display = "type {} is invalid", code)]
    InvalidType { code: u16 },

    #[fail(display = "class {} is invalid", code)]
    InvalidClass { code: u16 },

    #[fail(display = "invalid characters encountered while reading label")]
    LabelIsNotAscii,

    #[fail(display = "invalid characters encountered while reading TXT")]
    TxtDataIsNotUTF8 { error: Utf8Error },

    #[fail(display = "parser is in the wrong state")]
    WrongState,

    #[fail(display = "additional OPT record found")]
    AdditionalOPT,
}
