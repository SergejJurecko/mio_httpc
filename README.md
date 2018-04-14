
mio_httpc is an async http client that runs on top of mio only. 

For convenience it also provides a SyncCall interface. This is a simple one-line HTTP client operation.

No call will block (except SyncCall), not even for DNS resolution as it is implemented internally to avoid blocking.

It uses [http crate](https://crates.io/crates/http) for Request/Response types.

For https to work mio_httpc requires you specify one of the TLS implementations using features: native, openssl or rtls (rustls).

[Documentation](https://docs.rs/mio_httpc/)


## TODO/FEATURE LIST

- [x] Basic API
- [x] Configurable TLS backend
- [x] Chunked encoding download
- [ ] Chunked encoding upload
- [x] Basic Auth
- [x] Digest Auth
- [x] Automatic redirects
- [x] Keep-alive connection pool
- [x] DNS retries
- [x] Timeouts
- [x] Websockets
- [x] gzip body decoding
- [ ] HTTP2

## EXAMPLES

**Sync call**

```rust
extern crate mio_httpc;
use mio_httpc::SyncCall;
 
 // One line blocking call.
 
 let (response_data, body) = SyncCall::new().timeout_ms(5000).get(uri).expect("Request failed");
 
```

**Basic async get**

```
cargo run --example get --features "native" -- "https://edition.cnn.com"

// or
cargo run --example get --features "openssl" -- "https://edition.cnn.com"

// or
cargo run --example get --features "rtls" -- "https://edition.cnn.com"
```

```rust
extern crate mio_httpc;
extern crate mio;

use mio_httpc::{CallBuilder,Httpc};
use mio::{Poll,Events};

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10,None);
    let args: Vec<String> = ::std::env::args().collect();
    let mut call = CallBuilder::get()
        .url(args[1].as_str()).expect("Can not parse url")
        .timeout_ms(500)
        .call_simple(&mut htp, &poll)
        .expect("Call start failed");

    let to = ::std::time::Duration::from_millis(100);
    let mut events = Events::with_capacity(8);
    'outer: loop {
        poll.poll(&mut events, Some(to)).unwrap();
        for cref in htp.timeout().into_iter() {
            if call.is_ref(cref) {
                println!("Request timed out");
                call.abort(&mut htp);
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

**Websockets**

```
cargo run --example ws --features="native" -- "wss://demos.kaazing.com/echo"
```

```rust
extern crate mio_httpc;
extern crate mio;

use mio_httpc::{CallBuilder,Httpc,WebSocket,WSPacket};
use mio::{Poll,Events};
// ws://demos.kaazing.com/echo

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10,None);
    let args: Vec<String> = ::std::env::args().collect();

    let mut ws = CallBuilder::get()
        .url(args[1].as_str()).expect("Can not parse url")
        .websocket(&mut htp, &poll)
        .expect("Call start failed");

    let to = ::std::time::Duration::from_millis(800);
    'outer: loop {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, Some(to)).unwrap();
        for cref in htp.timeout().into_iter() {
            if ws.is_ref(cref) {
                println!("Request timed out");
                break 'outer;
            }
        }

        if events.len() == 0 {
            // ws.ping(None);
            println!("send yo");
            ws.send_text(true, "yo!");
        }

        for ev in events.iter() {
            let cref = htp.event(&ev);

            if ws.is_call(&cref) {
                if ws.is_active() {
                    loop {
                        match ws.recv_packet(&mut htp, &poll).expect("Failed recv") {
                            WSPacket::Pong(_) => {
                                println!("Got pong!");
                            }
                            WSPacket::Ping(_) => {
                                println!("Got ping!");
                                ws.pong(None);
                            }
                            WSPacket::None => {
                                break;
                            }
                            WSPacket::Close(_,_) => {
                                println!("Got close!");
                                ws.close(None, None);
                                break 'outer;
                            }
                            WSPacket::Text(fin,txt) => {
                                println!("Got text={}, fin={}",txt,fin);
                            }
                            WSPacket::Binary(fin,b) => {
                                println!("Got bin={}B, fin={}",b.len(),fin);
                            }
                        }
                    }
                } else {
                    if ws.sendq_len() == 0 {
                        ws.ping(None);
                    }
                }
            }
        }
        // Any ping/pong/close/send_text/send_bin has just been buffered.
        // perform and recv_packet actually send over socket.
        ws.perform(&mut htp, &poll).expect("Call failed");
    }
    ws.perform(&mut htp, &poll);
    ws.finish(&mut htp);
}
```

