use byteorder::{ByteOrder, BigEndian};
use super::{Opcode, ResponseCode, Header, QueryType, QueryClass};

/// Allows to build a DNS packet
///
/// Both query and answer packets may be built with this interface, although,
/// much of functionality is not implemented yet.
pub struct Builder<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> Builder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Builder {
        Builder {
            buf,
            off: 0,
        }
    }
    /// Creates a new query
    ///
    /// Initially all sections are empty. You're expected to fill
    /// the questions section with `add_question`
    pub fn start(&mut self, id: u16, recursion: bool) -> Result<(),()> {
        // let mut buf = Vec::with_capacity(512);
        if self.buf.len() <= 12 {
            return Err(());
        }
        let head = Header {
            id: id,
            query: true,
            opcode: Opcode::StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: recursion,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        // self.buf[0..12].copy_from_slice(&[0u8; 12]);
        head.write(&mut self.buf[..12]);
        self.off = 12;
        Ok(())
    }
    /// Adds a question to the packet
    ///
    /// # Panics
    ///
    /// * Answers, nameservers or additional section has already been written
    /// * There are already 65535 questions in the buffer.
    /// * When name is invalid
    pub fn add_question(&mut self, qname: &str, qtype: QueryType, qclass: QueryClass) -> Result<(),()> {
        if &self.buf[6..12] != b"\x00\x00\x00\x00\x00\x00" {
            // panic!("Too late to add a question");
            return Err(());
        }
        if let Ok(ns) = Self::write_name(self.buf, self.off, qname) {
            self.off = ns;
        } else {
            return Err(());
        }
        BigEndian::write_u16(&mut self.buf[self.off..], qtype as u16);
        self.off += 2;
        BigEndian::write_u16(&mut self.buf[self.off..], qclass as u16);
        self.off += 2;
        let oldq = BigEndian::read_u16(&self.buf[4..6]);
        if oldq == 65535 {
            return Err(());
        }
        BigEndian::write_u16(&mut self.buf[4..6], oldq+1);
        Ok(())
    }

    fn write_name(buf: &mut [u8], mut off: usize, name: &str) -> Result<usize,()> {
        for part in name.split('.') {
            if part.len() >= 63 || part.len() + off + 1 > buf.len() {
                return Err(());
            }
            buf[off] = part.len() as u8;
            off += 1;
            buf[off..off+part.len()].copy_from_slice(part.as_bytes());
            off += part.len();
        }
        buf[off] = 0;
        off += 1;
        Ok(off)
    }

    pub fn finish(self) -> usize {
        self.off
    }
    // / Returns the final packet
    // /
    // / When packet is not truncated method returns `Ok(packet)`. If
    // / packet is truncated the method returns `Err(packet)`. In both
    // / cases the packet is fully valid.
    // /
    // / In the server implementation you may use
    // / `x.build().unwrap_or_else(|x| x)`.
    // /
    // / In the client implementation it's probably unwise to send truncated
    // / packet, as it doesn't make sense. Even panicking may be more
    // / appropriate.
    // TODO(tailhook) does the truncation make sense for TCP, and how
    // to treat it for EDNS0?
    // pub fn build(mut self) -> Result<Vec<u8>,Vec<u8>> {
    //     // TODO(tailhook) optimize labels
    //     if self.buf.len() > 512 {
    //         Header::set_truncated(&mut self.buf[..12]);
    //         Err(self.buf)
    //     } else {
    //         Ok(self.buf)
    //     }
    // }
}

#[cfg(test)]
mod test {
    use super::QueryType as QT;
    use super::QueryClass as QC;
    use super::Builder;

    // #[test]
    // fn build_query() {
    //     let mut bld = Builder::new_query(1573, true);
    //     bld.add_question("example.com", QT::A, QC::IN);
    //     let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
    //                   \x07example\x03com\x00\x00\x01\x00\x01";
    //     assert_eq!(&bld.build().unwrap()[..], &result[..]);
    // }

    // #[test]
    // fn build_srv_query() {
    //     let mut bld = Builder::new_query(23513, true);
    //     bld.add_question("_xmpp-server._tcp.gmail.com", QT::SRV, QC::IN);
    //     let result = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
    //         \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
    //     assert_eq!(&bld.build().unwrap()[..], &result[..]);
    // }
}
