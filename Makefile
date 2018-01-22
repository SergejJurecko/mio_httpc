all:
	cargo build --features="openssl"
	cargo build --features="native"
	cargo build --features="rustls"	

check:
	cargo check
	cargo check --features="openssl"
	cargo check --features="native"
	cargo check --features="rustls webpki-roots"	

run_cnn:
	cargo run --example get --features "native" -- "https://edition.cnn.com"

# make run_streaming URL="https://www.reddit.com"
run_streaming:
	cargo run --example get_streaming --features "native" -- $(URL)

run:
	cargo run --example get --features "native" -- $(URL)
