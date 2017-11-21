
mio_httpc is an async http client that runs on top of mio only. 

No call will block, not even for DNS resolution as it is implemented internally to avoid blocking.

It uses [http crate](https://crates.io/crates/http) for Request/Response types.

mio_httpc requires you specify one of the TLS implementations using features: rustls, native, openssl. Not picking any feature will NOT work, as all calls will be no-op.

# WARNING

rustls is unreliable at the moment. I'm not sure if the issue is rustls or [tls-api-rustls](https://crates.io/crates/tls-api-rustls).

openssl and native backends work well.

# EXAMPLE


```
cargo run --example get --features "native" -- "https://edition.cnn.com"
```

```rust
extern crate mio_httpc;
extern crate mio;

use mio_httpc::{Request,CallBuilder,Httpc,SimpleCall};
use mio::{Poll,Events};

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10);
    let mut req = Request::builder();
    let args: Vec<String> = ::std::env::args().collect();
    let req = req.uri(args[1].as_str()).body(Vec::new()).expect("can not build request");

    let call_id = CallBuilder::new(req).call(&mut htp, &poll).expect("Call start failed");
    let mut call = SimpleCall::from(call_id);

    'outer: loop {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            let cid = htp.event(&ev);

            if call.is_callid(&cid) {
                if call.perform(&mut htp, &poll, &ev).expect("Call failed") {
                    let mut resp = call.close().expect("No response");
                    let v = mio_httpc::extract_body(&mut resp);
                    if let Ok(s) = String::from_utf8(v) {
                        println!("Body: {}",s);
                    }
                    break 'outer;
                }
            }
        }
    }
}

```

# TODO

- [x] Basic API
- [x] Configurable TLS backend
- [x] Chunked encoding download
- [x] Basic Auth
- [ ] Con pool
- [ ] DNS retries
- [ ] Timeouts
- [ ] Websockets
- [ ] HTTP2
