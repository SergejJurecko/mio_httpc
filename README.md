
mio_httpc is an async http client that runs on top of mio only. 

No call will block, not even for DNS resolution as it is implemented internally to avoid blocking.

It uses [http crate](https://crates.io/crates/http) for Request/Response types.

mio_httpc requires you specify one of the TLS implementations using features: rustls, native, openssl. Not picking any feature will NOT work, as all calls will be no-op.

### WARNING

openssl and native backends work well.

rustls is unreliable at the moment. I'm not sure if the issue is rustls or [tls-api-rustls](https://crates.io/crates/tls-api-rustls).

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

    let call = CallBuilder::new(req).timeout_ms(500).call(&mut htp, &poll).expect("Call start failed");
    let mut call = SimpleCall::from(call);

    let to = ::std::time::Duration::from_millis(100);
    'outer: loop {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, Some(to)).unwrap();
        for cref in htp.timeout().into_iter() {
            if call.is_ref(cref) {
                println!("Request timed out");
                break 'outer;
            }
        }

        for ev in events.iter() {
            let cref = htp.event(&ev);

            if call.is_call(&cref) {
                if call.perform(&mut htp, &poll).expect("Call failed") {
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
- [ ] Chunked encoding upload
- [x] Basic Auth
- [ ] Con pool
- [x] DNS retries
- [x] Timeouts
- [x] Websockets
- [ ] HTTP2
