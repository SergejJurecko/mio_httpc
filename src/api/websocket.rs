use ::{CallId,Httpc};

pub struct WebSocket {
    id: ::CallId,
    done: bool,
}

impl WebSocket {
    pub(crate) fn new(id: ::CallId) -> WebSocket {
        WebSocket {
            id,
            done: false,
        }
    }

    /// For quick comparison with httpc::event response.
    /// If cid is none will return false.
    pub fn is_callid(&self, cid: &Option<CallId>) -> bool {
        if let &Some(ref b) = cid {
            return self.id == *b;
        }
        false
    }

    /// If using Option<WebSocket> in a struct, you can quickly compare 
    /// callid from httpc::event. If either is none will return false.
    pub fn is_opt_callid(a: &Option<WebSocket>, b: &Option<CallId>) -> bool {
        if let &Some(ref a) = a {
            if let &Some(ref b) = b {
                return a.id == *b;
            }
        }
        false
    }

    /// Is request finished.
    pub fn is_done(&self) -> bool {
        self.done
    }
    /// Perform operation. Returns true if request is finished.
    pub fn perform(&mut self, htp: &mut Httpc, poll: &::mio::Poll, ev: &::mio::Event) -> ::Result<()> {
        Ok(())
    }
}

