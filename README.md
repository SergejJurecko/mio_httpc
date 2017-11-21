
mio_httpc is an async http client that runs on top of mio only. 

No call will block, not even for DNS resolution as it is implemented internally to avoid blocking.

It uses [http crate](https://crates.io/crates/http) for Request/Response types.

mio_httpc requires you specify one of the TLS implementations using features: rustls, native, openssl. Not picking any feature will NOT work, as all calls will be no-op.

# WARNING

rustls is unreliable at the moment. I'm not sure if the issue is rustls or [tls-api-rustls](https://crates.io/crates/tls-api-rustls).

openssl and native backends work well.

# EXAMPLE

Check examples/get.rs

```
cargo run --example get --features "native" -- "https://edition.cnn.com"
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
