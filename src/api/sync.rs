use {CallBuilder, HeaderMap, HeaderValue, Httpc, Request, SimpleCall};
use mio::{Events, Poll};

type Response = ::Result<(u16, HeaderMap<HeaderValue>, Vec<u8>)>;

/// Simplest possible call interface. Will block until complete.
pub struct SyncCall<'a> {
    max_resp: usize,
    hdrs: &'a [(&'a str, &'a str)],
    tofile: &'a str,
    fromfile: &'a str,
    timeout: u64,
}

impl<'a> SyncCall<'a> {
    pub fn new() -> SyncCall<'a> {
        SyncCall {
            max_resp: usize::max_value(),
            hdrs: &[],
            tofile: "",
            fromfile: "",
            timeout: 10000,
        }
    }
    /// How many milliseconds to wait for request to complete
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout = timeout_ms;
        self
    }
    /// Http headers
    pub fn headers(mut self, hdrs: &'a [(&'a str, &'a str)]) -> Self {
        self.hdrs = hdrs;
        self
    }
    /// Max size of body
    pub fn max_resp(mut self, max_resp: usize) -> Self {
        self.max_resp = max_resp;
        self
    }
    // TODO:
    // /// Write body directly to file
    // pub fn to_file(mut self, path: &'a str) -> Self {
    //     self.tofile = path;
    //     self
    // }
    // /// Read POST/PUT from file
    // pub fn from_file(mut self, path: &'a str) -> Self {
    //     self.fromfile = path;
    //     self
    // }

    /// Execute GET to uri
    pub fn get(self, uri: &str) -> Response {
        self.exec(uri, "GET", &[])
    }
    /// Execute POST to uri with body. If from_file set buf is ignored.
    pub fn post(self, uri: &str, buf: &[u8]) -> Response {
        self.exec(uri, "POST", buf)
    }
    /// Execute PUT to uri with body. If from_file set buf is ignored.
    pub fn put(self, uri: &str, buf: &[u8]) -> Response {
        self.exec(uri, "PUT", buf)
    }
    /// Execute OPTIONS to uri
    pub fn options(self, uri: &str) -> Response {
        self.exec(uri, "OPTIONS", &[])
    }
    /// Execute DELETE to uri
    pub fn delete(self, uri: &str, buf: &[u8]) -> Response {
        self.exec(uri, "DELETE", buf)
    }
    /// Execute HEAD to uri
    pub fn heae(self, uri: &str) -> Response {
        self.exec(uri, "HEAD", &[])
    }

    fn exec(self, uri: &str, method: &'static str, body: &[u8]) -> Response {
        let poll = Poll::new()?;
        let mut htp = Httpc::new(0, None);
        let mut events = Events::with_capacity(2);

        let mut req_builder = Request::builder();
        for &(k, v) in self.hdrs.iter() {
            req_builder.header(k, v);
        }
        req_builder.method(method);
        req_builder.uri(uri);
        let req = req_builder.body(body.to_vec())?;
        let call = CallBuilder::new(req)
            .timeout_ms(self.timeout)
            .max_response(self.max_resp)
            .chunked_parse(true)
            .digest_auth(true)
            .call(&mut htp, &poll)?;
        let mut call = SimpleCall::from(call);
        loop {
            poll.poll(&mut events, Some(::std::time::Duration::from_millis(100)))?;
            for cref in htp.timeout().into_iter() {
                if call.is_ref(cref) {
                    return Err(::Error::TimeOut);
                }
            }

            for ev in events.iter() {
                let cref = htp.event(&ev);

                if call.is_call(&cref) {
                    if call.perform(&mut htp, &poll)? {
                        if let Some(mut resp) = call.finish() {
                            let v = ::extract_body(&mut resp);
                            let hdrs =
                                ::std::mem::replace(resp.headers_mut(), HeaderMap::default());
                            return Ok((resp.status().as_u16(), hdrs, v));
                        }
                        return Ok((0, HeaderMap::default(), Vec::new()));
                    }
                }
            }
        }
    }
}
