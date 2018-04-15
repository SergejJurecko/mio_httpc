use {Call, CallRef, Httpc, RecvState, ResponseBody, SendState};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Sending,
    Receiving,
    Done,
}

/// Simplified API for non-streaming requests and responses.
/// If body exists it needs to be provided to Request. If response has a body
/// it is returned in Response.
pub struct SimpleCall {
    state: State,
    id: Call,
    resp: Option<::Response>,
    resp_body: Option<Vec<u8>>,
}

impl SimpleCall {
    pub fn is_ref(&self, r: CallRef) -> bool {
        self.id.is_ref(r)
    }

    pub fn call(&self) -> &Call {
        &self.id
    }

    /// Replaces self with an empty SimpleCall and returns result if any.
    pub fn finish_inplace(&mut self) -> Option<(::Response, Vec<u8>)> {
        let out = ::std::mem::replace(self, SimpleCall::empty());
        out.finish()
    }

    /// Consume and return response with body.
    pub fn finish(mut self) -> Option<(::Response, Vec<u8>)> {
        let r = self.resp.take();
        let b = self.resp_body.take();
        if let Some(rs) = r {
            if let Some(rb) = b {
                // ::std::mem::replace(rs.body_mut(), rb);
                return Some((rs, rb));
            }
            return Some((rs, Vec::new()));
        }
        None
    }

    /// Abort and replace self with an empty call.
    pub fn abort_inplace(&mut self, htp: &mut Httpc) {
        let out = ::std::mem::replace(self, SimpleCall::empty());
        htp.call_close(out.id);
    }

    /// Consume and abort call.
    pub fn abort(self, htp: &mut Httpc) {
        htp.call_close(self.id);
    }

    /// For quick comparison with httpc::event response.
    /// If cid is none will return false.
    pub fn is_call(&self, cid: &Option<CallRef>) -> bool {
        if let &Some(ref b) = cid {
            return self.id.0 == b.0;
        }
        false
    }

    /// If using Option<SimpleCall> in a struct, you can quickly compare
    /// callid from httpc::event. If either is none will return false.
    pub fn is_opt_callid(a: &Option<SimpleCall>, b: &Option<CallRef>) -> bool {
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

    /// Perform operation. Returns true if request is finished.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &::mio::Poll) -> ::Result<bool> {
        if self.is_done() {
            return Ok(true);
        }
        if self.state == State::Sending {
            match htp.call_send(poll, &mut self.id, None) {
                SendState::Wait => {}
                SendState::Receiving => {
                    self.state = State::Receiving;
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
                    return Ok(true);
                }
            }
        }
        if self.state == State::Receiving {
            loop {
                match htp.call_recv(poll, &mut self.id, None) {
                    RecvState::DoneWithBody(b) => {
                        self.resp_body = Some(b);
                        self.state = State::Done;
                        return Ok(true);
                    }
                    RecvState::Done => {
                        self.state = State::Done;
                        return Ok(true);
                    }
                    RecvState::Error(e) => {
                        self.state = State::Done;
                        return Err(From::from(e));
                    }
                    RecvState::Response(r, body) => {
                        self.resp = Some(r);
                        match body {
                            ResponseBody::Sized(0) => {
                                self.state = State::Done;
                                return Ok(true);
                            }
                            _ => {}
                        }
                    }
                    RecvState::Wait => {
                        break;
                    }
                    RecvState::Sending => {
                        self.state = State::Sending;
                        return self.perform(htp, poll);
                    }
                    RecvState::ReceivedBody(_s) => {}
                }
            }
        }
        Ok(false)
    }

    /// An empty SimpleCall not associated with a valid mio::Token/CallId.
    /// Exists to be overwritten with an actual valid request.
    /// Always returns is_done true.
    pub fn empty() -> SimpleCall {
        SimpleCall {
            state: State::Done,
            id: ::Call::empty(),
            resp: None,
            resp_body: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.id.is_empty()
    }
}
impl From<Call> for SimpleCall {
    fn from(v: Call) -> SimpleCall {
        SimpleCall {
            state: State::Sending,
            id: v,
            resp: None,
            resp_body: None,
        }
    }
}
