use ::{CallRef,Call,Httpc,SendState, RecvState, ResponseBody};
use mio::Poll;

/// WebSocket packet received from server.
pub enum WSPacket<'a> {
    /// Nothing to return yet.
    None,
    /// (fin,text)
    Text(bool,&'a str),
    /// (fin, bin)
    Binary(bool,&'a [u8]),
    /// Ping may contain data.
    /// You should send pong back.
    Ping(&'a [u8]),
    /// Pong may contain data.
    Pong(&'a [u8]),
    /// Close may contain data.
    /// You should call close.
    Close(&'a [u8]),
}

impl<'a> WSPacket<'a> {
    fn is_close(&self) -> bool {
        match *self {
            WSPacket::Close(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
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
           State::InitSending =>  true,
           State::InitReceiving =>  true,
           _ => false,
        }
    }
}

/// WebSocket interface.
///
/// WebSocket does not send pings automatically or close replies.
/// 
/// If received ping, you should send pong back.
/// You can also just send pong which will not invoke a response.
/// 
/// If WSPacket::Close(_) returned you should call close and then finish.
/// If you want to initiate close, you should call close and wait for WSPacket::Close(_),
/// then call finish. At leas that is the standard way of destroying connection.
pub struct WebSocket {
    id: Call,
    state: State,
    send_lover: usize,
    recv_lover: usize,
    cur_op: u8,
    closing: bool,
}

impl WebSocket {
    pub(crate) fn new(id: Call) -> WebSocket {
        WebSocket {
            closing: false,
            cur_op: 0,
            id,
            state: State::InitSending,
            send_lover: 0,
            recv_lover: 0,
        }
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

    /// Ping server.
    pub fn ping(&self, body: Option<&[u8]>) {
    }

    /// A reply to ping or not. Both are valid.
    pub fn pong(&self, body: Option<&[u8]>) {
    }

    /// A reply to close or initiate close.
    /// close must be send by both parties. 
    pub fn close(&self, htp: &mut Httpc, body: Option<&[u8]>) {
        // htp.call_close(self.id);
    }

    /// Actually close connection.
    /// If any other call returns error, you should always call finish afterwards.
    pub fn finish(mut self, htp: &mut Httpc) {
        self.stop(htp);
    }

    fn switch(&mut self, htp: &mut Httpc, resp: ::Response<Vec<u8>>) -> ::Result<()> {
        if resp.status() != ::StatusCode::SWITCHING_PROTOCOLS {
            self.stop(htp);
            return Err(::Error::WebSocketFail(resp));
        }
        let mut is_wsupg = false;
        if let Some(upg) = resp.headers().get(::UPGRADE) {
            if upg != "websocket" {
                is_wsupg = true;
            }
        }
        if !is_wsupg {
            self.stop(htp);
            return Err(::Error::WebSocketFail(resp));
        }
        self.state = State::Active;
        Ok(())
    }

    fn stop(&mut self, htp: &mut Httpc) {
        self.state = State::Done;
        let call = ::std::mem::replace(&mut self.id, Call::empty());
        htp.call_close(call);
    }

    /// Send websocket packet. It will create a packet for entire size of pkt slice.
    /// It is assumed slice always starts at unsent data. If pkt was not sent completely
    /// it will remember how many bytes it has leftover for current packet.
    pub fn send_bin(&mut self, htp: &mut Httpc, poll: &Poll, pkt: &[u8]) -> ::Result<usize> {
        if self.state.is_init() {
            self.perform(htp, poll)?;
            return Ok(0);
        } else if self.state == State::Done {
            return Err(::Error::Closed);
        } else if self.state == State::Finish {
            self.stop(htp);
            return Err(::Error::Closed);
        }
        Ok(0)
    }

    pub fn send_text(&mut self, htp: &mut Httpc, poll: &Poll, pkt: &[u8]) -> ::Result<usize> {
        Ok(0)
    }

    /// You should call this in a loop until you get WSPacket::None.
    pub fn recv_packet<'a>(&mut self, htp: &'a mut Httpc, poll: &Poll) -> ::Result<WSPacket<'a>> {
        if self.state.is_init() {
            self.perform(htp, poll)?;
            return Ok(WSPacket::None);
        } else if self.state == State::Done {
            return Err(::Error::Closed);
        } else {
            self.perform(htp,poll)?;
        }
        self.read_packet(htp)
    }

    fn read_packet<'a>(&mut self, htp: &'a mut Httpc) -> ::Result<WSPacket<'a>> {
        let slice = htp.peek_body(&self.id, &mut self.recv_lover);
        if let Some((fin, op, mut pos,len)) = self.parse_packet(&slice[self.recv_lover..]) {
            pos += self.recv_lover;
            self.recv_lover += pos + len;
            match op {
                _ if self.cur_op == 1 || op == 1 => {
                    if op != 0 && !fin {
                        self.cur_op = 1;
                    }
                    let s = ::std::str::from_utf8(&slice[pos..pos+len])?;
                    return Ok(WSPacket::Text(fin,s));
                }
                _ if self.cur_op == 2 || op == 2 => {
                    if op != 0 && !fin {
                        self.cur_op = 2;
                    }
                    return Ok(WSPacket::Binary::<'a>(fin,&slice[pos..pos+len]));
                }
                8 => {
                    if !self.closing {
                        // send close
                        self.closing = true;
                    }
                    return Ok(WSPacket::Close::<'a>(&slice[pos..pos+len]));
                }
                9 => {
                    return Ok(WSPacket::Ping::<'a>(&slice[pos..pos+len]));
                }
                10 => {
                    return Ok(WSPacket::Pong::<'a>(&slice[pos..pos+len]));
                }
                _ => {
                    self.state = State::Finish;
                    return Err(::Error::WebSocketParse);
                }
            }
        }
        Ok(WSPacket::None)
    }

    fn parse_packet(&self, pkt: &[u8]) -> Option<(bool, u8,usize,usize)> {
        // let mut rdr = Reader::new(Input::from(pkt));
        let mut pos = 0;
        let b:u8 = *pkt.get(pos)?;
        pos += 1;
        let fin = ((b & 0b1000_0000) >> 7) == 1;
        let op = b & 0b0000_1111;
        let b:u8 = *pkt.get(pos)?;
        pos += 1;
        let mut len:u64 = (b & 0b0111_1111) as u64;
        let nb = if len == 126 { len=0; 2 } else if len == 127 { len = 0; 8 } else { 0 };
        for i in 0..nb {
            len <<= 8;
            len |= (*pkt.get(pos)?) as u64;
            pos += 1;
        }
        if len > u32::max_value() as u64 {
            return None;
        }
        let len = len as usize;
        if (len as usize) + pos <= pkt.len() {
            return Some((fin, op,pos,len));
        }
        None
    }

    /// Perform socket operation.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &Poll) -> ::Result<()> {
        if self.state == State::Active {
            return Ok(());
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
        if self.state == State::InitReceiving {
            loop {
                match htp.call_recv(poll, &mut self.id, None) {
                    RecvState::DoneWithBody(b) => {
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
                    RecvState::Response(r,body) => {
                        match body {
                            ResponseBody::Sized(0) => {
                                return self.switch(htp, r);
                            }
                            _ => {
                                self.stop(htp);
                                return Err(::Error::Closed);
                            }
                        }
                    }
                    RecvState::Wait => {}
                    RecvState::Sending => {}
                    RecvState::ReceivedBody(_) => {}
                }
            }
        }
        Ok(())
    }
}

