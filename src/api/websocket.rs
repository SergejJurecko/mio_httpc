use byteorder::{BigEndian, ByteOrder};
use mio::Poll;
use {Call, CallRef, Httpc, RecvState, ResponseBody, SendState};

/// WebSocket packet received from server.
pub enum WSPacket<'a> {
    /// Nothing to return yet.
    None,
    /// (fin,text)
    Text(bool, &'a str),
    /// (fin, bin)
    Binary(bool, &'a [u8]),
    /// Ping may contain data.
    /// You should send pong back.
    Ping(&'a [u8]),
    /// Pong may contain data.
    Pong(&'a [u8]),
    /// (StatusCode,Data)
    /// Close may contain data.
    /// You should call close after receiving this (if you did not already).
    Close(Option<u16>, &'a [u8]),
}

// impl<'a> WSPacket<'a> {
//     fn is_close(&self) -> bool {
//         match *self {
//             WSPacket::Close(_, _) => true,
//             _ => false,
//         }
//     }
// }

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum State {
    InitSending,
    InitReceiving,
    Active,
    Finish,
    Done,
}

impl State {
    fn is_init(&self) -> bool {
        match *self {
            State::InitSending => true,
            State::InitReceiving => true,
            _ => false,
        }
    }
}

/// WebSocket interface.
///
/// WebSocket does not send pings/pongs automatically or close replies.
///
/// If received ping, you should send pong back.
/// You can also just send pong which will not invoke a response.
/// You should send ping periodically as you never know if your connection
/// is actually alive without it.
///
/// If WSPacket::Close(_) returned you should call close and then finish.
/// If you want to initiate close, you should call close and wait for WSPacket::Close(_),
/// then call finish. That is the standard way of closing ws connections.
pub struct WebSocket {
    id: Call,
    state: State,
    send_lover: usize,
    // offset in buffer of packets returned.
    recv_lover: usize,
    cur_op: u8,
    closing: bool,
    send_buf: Vec<u8>,
    send_buf_pos: usize,
    send_middle: bool,
    curframe: [u8; 16],
    curframe_len: u8,
    curframe_pos: u8,
}

impl WebSocket {
    pub(crate) fn new(id: Call, send_buf: Vec<u8>) -> WebSocket {
        WebSocket {
            send_buf,
            send_buf_pos: 0,
            send_middle: false,
            closing: false,
            cur_op: 0,
            id,
            state: State::InitSending,
            send_lover: 0,
            recv_lover: 0,
            curframe: [0u8; 16],
            curframe_len: 0,
            curframe_pos: 0,
        }
    }

    pub fn call(&self) -> &Call {
        &self.id
    }

    pub fn empty() -> WebSocket {
        let mut r = Self::new(Call::empty(), Vec::new());
        r.state = State::Done;
        r
    }

    pub fn is_empty(&self) -> bool {
        self.state == State::Done
    }

    /// True if websocket is established. False if still initiating or closed.
    pub fn is_active(&self) -> bool {
        self.state == State::Active
    }

    /// How many bytes are in send buffer waiting to be sent.
    /// Does not take into account any send_bin_inplace packets.
    pub fn sendq_len(&self) -> usize {
        self.send_buf.len() - self.send_buf_pos
    }

    pub fn is_ref(&self, r: CallRef) -> bool {
        self.id.is_ref(r)
    }

    /// For quick comparison with httpc::event response.
    /// If cid is none will return false.
    pub fn is_call(&self, cid: &Option<CallRef>) -> bool {
        if let &Some(ref b) = cid {
            return self.id.0 == b.0;
        }
        false
    }

    /// If using Option<WebSocket> in a struct, you can quickly compare
    /// callid from httpc::event. If either is none will return false.
    pub fn is_opt_call(a: &Option<WebSocket>, b: &Option<CallRef>) -> bool {
        if let &Some(ref a) = a {
            if let &Some(ref b) = b {
                return a.id.0 == b.0;
            }
        }
        false
    }

    fn limit_body(limit: usize, body: Option<&[u8]>) -> Option<&[u8]> {
        if let Some(body) = body {
            if body.len() > limit {
                return Some(&body[..limit]);
            }
        }
        body
    }

    /// Ping server. Body if present is capped at 125 bytes.
    pub fn ping(&mut self, body: Option<&[u8]>) {
        self.send_buf_append(9, None, true, Self::limit_body(125, body))
    }

    /// A reply to ping or not. Both are valid. Body if present is capped at 125 bytes.
    pub fn pong(&mut self, body: Option<&[u8]>) {
        self.send_buf_append(10, None, true, Self::limit_body(125, body))
    }

    /// A reply to close or initiate close.
    /// close must be sent by both parties.
    /// Body if present is capped at 125 bytes.
    pub fn close(&mut self, status: Option<u16>, body: Option<&[u8]>) {
        self.send_buf_append(8, status, true, Self::limit_body(123, body))
    }

    // only append do not send.
    fn send_buf_append(&mut self, op: u8, status: Option<u16>, fin: bool, body: Option<&[u8]>) {
        let body_sz = if let Some(body) = body {
            body.len()
        } else {
            0
        };
        let mut send_buf = ::std::mem::replace(&mut self.send_buf, Vec::new());
        let start_pos = send_buf.len();
        send_buf.resize(start_pos + body_sz + 16, 0);
        let pkt = if let Some(body) = body { body } else { &[] };
        let mut mask = [0u8; 4];
        let fsz = self.fill_frame(fin, op, pkt, &mut send_buf[start_pos..], &mut mask[..]);
        let mut mask_pos = 0;
        let status_sz = if let Some(status) = status {
            BigEndian::write_u16(&mut send_buf[start_pos + fsz..], status);
            Self::mask_inplace(&mask, &mut send_buf[start_pos + fsz..start_pos + fsz + 2]);
            mask_pos = 2;
            2
        } else {
            0
        };
        if let Some(body) = body {
            Self::mask_to(
                &mask,
                mask_pos,
                body,
                &mut send_buf[start_pos + fsz + status_sz..],
            );
        }
        if fsz + status_sz < 16 {
            let len = send_buf.len();
            send_buf.truncate(len - (16 - fsz - status_sz));
        }
        self.send_buf = send_buf;
        // self.do_send_buf(htp, poll)
    }

    fn do_send_buf(&mut self, htp: &mut Httpc, poll: &Poll) -> ::Result<()> {
        let mut send_buf = ::std::mem::replace(&mut self.send_buf, Vec::new());
        let send_buf_pos = self.send_buf_pos;
        let sent = self.call_send(htp, poll, &send_buf[send_buf_pos..])?;
        if sent + send_buf_pos == send_buf.len() {
            send_buf.truncate(0);
            self.send_buf_pos = 0;
        } else {
            self.send_buf_pos += sent;
        }
        self.send_buf = send_buf;
        Ok(())
    }

    /// Actually close connection.
    /// If any other call returns error, you should always call finish afterwards.
    pub fn finish(mut self, htp: &mut Httpc) {
        self.stop(htp);
    }

    /// Actually close connection and replace self with an empty websocket.
    pub fn finish_inplace(&mut self, htp: &mut Httpc) {
        let mut s = ::std::mem::replace(self, Self::empty());
        s.stop(htp);
    }

    fn stop(&mut self, htp: &mut Httpc) {
        self.state = State::Done;
        let call = ::std::mem::replace(&mut self.id, Call::empty());
        let buf = ::std::mem::replace(&mut self.send_buf, Vec::new());
        if buf.capacity() > 0 {
            htp.reuse(buf);
        }
        htp.call_close(call);
    }

    /// Send text packet. Data gets copied out into an internal buffer, as it must be
    /// masked before sending.
    /// No bytes will have been sent after calling this. Actual sending is done by recv_packet or perform.
    pub fn send_text(&mut self, fin: bool, pkt: &str) {
        self.send_buf_append(1, None, fin, Some(pkt.as_bytes()));
        // self.do_send_buf(htp,poll)
    }

    /// Send binary packet. Data gets copied out into an internal buffer, as it must be
    /// masked before sending.
    /// No bytes will have been sent after calling this. Actual sending is done by recv_packet or perform.
    pub fn send_bin(&mut self, fin: bool, pkt: &[u8]) {
        self.send_buf_append(2, None, fin, Some(pkt));
        // self.do_send_buf(htp,poll)
    }

    /// Send websocket packet. It will create a frame for entire size of pkt slice.
    /// It is assumed slice always starts at unsent data. If pkt was not sent completely
    /// it will remember how many bytes it has leftover for current packet. You must always use
    /// previous result to move pkt slice forward.
    ///
    /// If starting from the middle, fin is ignored and will be used to start the next packet.
    ///
    /// inplace send will mask pkt directly and send it. This is the most efficient method but leaves
    /// pkt scrambled.
    pub fn send_bin_inplace(
        &mut self,
        htp: &mut Httpc,
        poll: &Poll,
        fin: bool,
        pkt: &mut [u8],
    ) -> ::Result<usize> {
        if self.state.is_init() {
            self.perform(htp, poll)?;
            return Ok(0);
        }
        if self.state == State::Done {
            return Err(::Error::Closed);
        }
        if self.state == State::Finish {
            self.stop(htp);
            return Err(::Error::Closed);
        }
        if self.send_buf.len() > 0 && self.send_lover == 0 && self.curframe_pos == 0 {
            self.do_send_buf(htp, poll)?;
            if self.send_buf.len() > 0 {
                return Ok(0);
            }
        }

        let mut consumed = 0;
        let mut pkt_offset = 0;
        loop {
            if self.send_lover == 0 && self.curframe_pos == 0 {
                let mut frame = [0u8; 16];
                let mut mask = [0u8; 4];
                self.curframe_len = self.fill_frame(fin, 2, pkt, &mut frame, &mut mask) as u8;
                let len = self.curframe_len as usize;
                let sent = self.call_send(htp, poll, &frame[0..len])?;
                if sent == len {
                    Self::mask_inplace(&mask, &mut pkt[pkt_offset..]);
                    let sent = self.call_send(htp, poll, &pkt[pkt_offset..])?;
                    consumed += sent;
                    if sent != pkt.len() - pkt_offset {
                        self.send_lover = pkt.len() - sent - pkt_offset;
                    }
                } else if sent > 0 {
                    // some bytes have been sent, we are commited to this mask.
                    Self::mask_inplace(&mask[..], &mut pkt[pkt_offset..]);
                    self.curframe.copy_from_slice(&frame[..]);
                    self.curframe_pos = sent as u8;
                    self.send_lover = pkt.len() - pkt_offset;
                }
                break;
            } else if self.curframe_pos == 0 {
                let slover = self.send_lover;
                let sent = self.call_send(htp, poll, &pkt[0..slover])?;
                consumed += sent;
                if sent == self.send_lover {
                    pkt_offset = self.send_lover;
                    self.send_lover = 0;
                } else {
                    self.send_lover -= sent;
                    break;
                }
            } else {
                let mut frame = [0u8; 16];
                frame.copy_from_slice(&self.curframe[..]);
                let pos = self.curframe_pos as usize;
                let len = self.curframe_len as usize;
                let sent = self.call_send(htp, poll, &frame[pos..len])?;
                if sent == len {
                    self.curframe_pos = 0;
                    self.curframe_len = 0;
                } else {
                    self.curframe_pos += sent as u8;
                    break;
                }
            }
        }
        Ok(consumed)
    }

    fn call_send(&mut self, htp: &mut Httpc, poll: &Poll, pkt: &[u8]) -> ::Result<usize> {
        match htp.call_send(poll, &mut self.id, Some(pkt)) {
            SendState::Wait => Ok(0),
            SendState::Receiving => {
                self.stop(htp);
                Err(::Error::Closed)
            }
            SendState::SentBody(sz) => Ok(sz),
            SendState::Error(e) => {
                self.stop(htp);
                Err(From::from(e))
            }
            SendState::WaitReqBody => {
                self.stop(htp);
                Err(::Error::MissingBody)
            }
            SendState::Done => {
                self.stop(htp);
                Err(::Error::Closed)
            }
        }
    }

    fn mask_inplace(mask: &[u8], pkt: &mut [u8]) {
        let mut mpos = 0;
        let len = pkt.len();
        for i in 0..len {
            pkt[i] = pkt[i] ^ mask[mpos];
            mpos = (mpos + 1) & 3;
        }
    }

    fn mask_to(mask: &[u8], mut mpos: usize, src: &[u8], dst: &mut [u8]) {
        mpos &= 3;
        let mut i = 0;
        for &byte in src.iter() {
            dst[i] = byte ^ mask[mpos];
            i += 1;
            mpos = (mpos + 1) & 3;
        }
    }

    fn fill_frame(
        &mut self,
        fin: bool,
        mut op: u8,
        pkt: &[u8],
        frame: &mut [u8],
        mask_bytes: &mut [u8],
    ) -> usize {
        let mut pos = 0;
        if op <= 2 {
            if self.send_middle {
                op = 0;
            }
            self.send_middle = !fin;
        }
        if fin {
            frame[pos] = op | 0b1000_0000;
        } else {
            frame[pos] = op;
        }
        pos += 1;
        if pkt.len() <= 125 {
            frame[pos] = (pkt.len() as u8) | 0b1000_0000;
            pos += 1;
        } else if pkt.len() <= u16::max_value() as usize {
            frame[pos] = 126 | 0b1000_0000;
            pos += 1;
            BigEndian::write_u16(&mut frame[pos..pos + 2], pkt.len() as u16);
            pos += 2;
        } else {
            frame[pos] = 127 | 0b1000_0000;
            pos += 1;
            BigEndian::write_u64(&mut frame[pos..pos + 8], pkt.len() as u64);
            pos += 8;
        }
        let mask = ::rand::random::<u32>();
        BigEndian::write_u32(&mut frame[pos..pos + 4], mask);
        BigEndian::write_u32(mask_bytes, mask);
        // self.curframe_len = (pos+4) as u8;
        pos + 4
    }

    /// You should call this in a loop until you get WSPacket::None.
    pub fn recv_packet<'a>(&mut self, htp: &'a mut Httpc, poll: &Poll) -> ::Result<WSPacket<'a>> {
        if self.state.is_init() {
            self.perform(htp, poll)?;
            return Ok(WSPacket::None);
        } else if self.state == State::Done {
            return Err(::Error::Closed);
        } else {
            self.perform(htp, poll)?;
        }
        self.read_packet(htp)
    }

    fn read_packet<'a>(&mut self, htp: &'a mut Httpc) -> ::Result<WSPacket<'a>> {
        // We can only return one packet at a time, but we can receive multiple packets at the same time.
        // So we use recv_lover as a receive buffer offset.
        // peek_body will fix recv_lover and set it to 0 if everything has been read from buffer.
        let slice = htp.peek_body(&self.id, &mut self.recv_lover);
        if let Some((fin, op, mut pos, mut len)) = self.parse_packet(slice) {
            self.recv_lover += pos + len;
            match op {
                _ if self.cur_op == 1 || op == 1 => {
                    if op != 0 && !fin {
                        self.cur_op = 1;
                    }
                    if let Ok(s) = ::std::str::from_utf8(&slice[pos..pos + len]) {
                        return Ok(WSPacket::Text(fin, s));
                    } else {
                        self.state = State::Finish;
                        return Err(::Error::WebSocketParse);
                    }
                }
                _ if self.cur_op == 2 || op == 2 => {
                    if op != 0 && !fin {
                        self.cur_op = 2;
                    }
                    return Ok(WSPacket::Binary::<'a>(fin, &slice[pos..pos + len]));
                }
                8 => {
                    if !self.closing {
                        self.closing = true;
                    }
                    if len >= 2 {
                        let v = BigEndian::read_u16(&slice[pos..pos + 2]);
                        pos += 2;
                        len -= 2;
                        return Ok(WSPacket::Close::<'a>(Some(v), &slice[pos..pos + len]));
                    } else {
                        return Ok(WSPacket::Close::<'a>(None, &[]));
                    }
                }
                9 => {
                    return Ok(WSPacket::Ping::<'a>(&slice[pos..pos + len]));
                }
                10 => {
                    return Ok(WSPacket::Pong::<'a>(&slice[pos..pos + len]));
                }
                _ => {
                    self.state = State::Finish;
                    return Err(::Error::WebSocketParse);
                }
            }
        }
        Ok(WSPacket::None)
    }

    fn parse_packet(&self, pkt: &[u8]) -> Option<(bool, u8, usize, usize)> {
        // let mut rdr = Reader::new(Input::from(pkt));
        let mut pos = 0;
        let b: u8 = *pkt.get(pos)?;
        pos += 1;
        let fin = ((b & 0b1000_0000) >> 7) == 1;
        let op = b & 0b0000_1111;
        let b: u8 = *pkt.get(pos)?;
        pos += 1;
        let mut len: u64 = (b & 0b0111_1111) as u64;
        let nb = if len == 126 {
            len = 0;
            2
        } else if len == 127 {
            len = 0;
            8
        } else {
            0
        };
        for _ in 0..nb {
            len <<= 8;
            len |= (*pkt.get(pos)?) as u64;
            pos += 1;
        }
        if len > u32::max_value() as u64 {
            return None;
        }
        let len = len as usize;
        if (len as usize) + pos <= pkt.len() {
            return Some((fin, op, pos, len));
        }
        None
    }

    fn switch(&mut self, htp: &mut Httpc, poll: &Poll, resp: ::Response) -> ::Result<()> {
        if resp.status != 101 {
            self.stop(htp);
            return Err(::Error::WebSocketFail(resp));
        }
        if !resp.ws {
            self.stop(htp);
            return Err(::Error::WebSocketFail(resp));
        }
        self.state = State::Active;
        if self.send_buf.len() > 0 {
            return self.do_send_buf(htp, poll);
        }
        Ok(())
    }

    /// Perform socket operation.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &Poll) -> ::Result<()> {
        if self.state == State::Active {
            if self.send_buf.len() > 0 {
                self.do_send_buf(htp, poll)?;
            }
            htp.try_truncate(&self.id, &mut self.recv_lover);
        }
        if self.state == State::Done {
            return Err(::Error::Closed);
        }
        if self.state == State::Finish {
            self.stop(htp);
            return Err(::Error::Closed);
        }
        if self.state == State::InitSending {
            match htp.call_send(poll, &mut self.id, None) {
                SendState::Wait => {}
                SendState::Receiving => {
                    self.state = State::InitReceiving;
                }
                SendState::SentBody(_) => {}
                SendState::Error(e) => {
                    self.stop(htp);
                    return Err(From::from(e));
                }
                SendState::WaitReqBody => {
                    self.stop(htp);
                    return Err(::Error::MissingBody);
                }
                SendState::Done => {
                    self.stop(htp);
                    return Err(::Error::Closed);
                }
            }
        }
        if self.state == State::InitReceiving || self.state == State::Active {
            loop {
                match htp.call_recv(poll, &mut self.id, None) {
                    RecvState::DoneWithBody(_b) => {
                        self.stop(htp);
                        return Err(::Error::Closed);
                    }
                    RecvState::Done => {
                        self.stop(htp);
                        return Err(::Error::Closed);
                    }
                    RecvState::Error(e) => {
                        self.stop(htp);
                        return Err(From::from(e));
                    }
                    RecvState::Response(r, body) => match body {
                        ResponseBody::Streamed => {
                            return self.switch(htp, poll, r);
                        }
                        _ => {
                            self.stop(htp);
                            return Err(::Error::Closed);
                        }
                    },
                    RecvState::Wait => {
                        break;
                    }
                    RecvState::Sending => {
                        self.state = State::InitSending;
                        break;
                    }
                    RecvState::ReceivedBody(_) => {}
                }
            }
        }
        Ok(())
    }
}
