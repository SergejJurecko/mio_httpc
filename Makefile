all:
	cargo build --features="openssl"
	cargo build --features="native"
	cargo build --features="rtls"

check:
	cargo check
	cargo check --features="openssl"
	cargo check --features="native"
	cargo check --features="rtls"

run_cnn:
	cargo run --example get --features "native" -- "https://edition.cnn.com"

# make run_streaming URL="https://www.reddit.com"
run_streaming:
	cargo run --example get_streaming --features "native" -- $(URL)

run:
	cargo run --example get --features "native" -- $(URL)

openssl:
	OPENSSL_DIR=/usr/local/opt/openssl/ \
	OPENSSL_LIB_DIR=/usr/local/opt/openssl/lib/ \
	OPENSSL_INCLUDE_DIR=/usr/local/opt/openssl/include/ \
	cargo run --example get --features "openssl" -- "https://edition.cnn.com"