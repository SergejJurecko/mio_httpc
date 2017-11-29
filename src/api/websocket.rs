use ::{CallRef,Call,Httpc,SendState, RecvState, ResponseBody};

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
pub enum WSState {
    /// WebSocket has not finished initiating.
    Init,
    /// Nothing to return.
    NoData,
    /// How many bytes were sent
    Sent(usize),
    /// WS us closed
    Closed,
}

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
enum State {
    InitSending,
    InitReceiving,
    Active,
    Done,
}

pub struct WebSocket {
    id: Call,
    state: State,
}

impl WebSocket {
    pub(crate) fn new(id: Call) -> WebSocket {
        WebSocket {
            id,
            state: State::InitSending,
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

    /// Is request finished.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    fn switch(&mut self, resp: ::Response<Vec<u8>>) -> ::Result<WSState> {
        if resp.status() != ::StatusCode::SWITCHING_PROTOCOLS {
            return Err(::Error::WebSocketFail(resp));
        }
        let mut is_wsupg = false;
        if let Some(upg) = resp.headers().get(::UPGRADE) {
            if upg != "websocket" {
                is_wsupg = true;
            }
        }
        if !is_wsupg {
            return Err(::Error::WebSocketFail(resp));
        }
        self.state = State::Active;
        Ok(WSState::NoData)
    }

    /// Perform operation. Returns true if request is finished.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &::mio::Poll) -> ::Result<WSState> {
        if self.state == State::Active {
            return Ok(WSState::NoData);
        }
        if self.state == State::Done {
            return Ok(WSState::Closed);
        }
        if self.state == State::InitSending {
            match htp.call_send(poll, &mut self.id, None) {
                SendState::Wait => {}
                SendState::Receiving => {
                    self.state = State::InitReceiving;
                }
                SendState::SentBody(_) => {}
                SendState::Error(e) => {
                    self.state = State::Done;
                    return Err(From::from(e));
                }
                SendState::WaitReqBody => {
                    self.state = State::Done;
                    return Err(::Error::MissingBody);
                }
                SendState::Done => {
                    self.state = State::Done;
                    return Err(::Error::Closed);
                }
            }
        }
        if self.state == State::InitReceiving {
            loop {
                match htp.call_recv(poll, &mut self.id, None) {
                    RecvState::DoneWithBody(b) => {
                        self.state = State::Done;
                        return Err(::Error::Closed);
                    }
                    RecvState::Done => {
                        self.state = State::Done;
                        return Err(::Error::Closed);
                    }
                    RecvState::Error(e) => {
                        self.state = State::Done;
                        return Err(From::from(e));
                    }
                    RecvState::Response(r,body) => {
                        match body {
                            ResponseBody::Sized(0) => {
                                self.state = State::Done;
                                return self.switch(r);
                            }
                            _ => {
                                self.state = State::Done;
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
        Ok(WSState::Init)
    }
}

