all:
	cargo build --features="openssl"
	cargo build --features="native"
	cargo build --features="rustls"	

check:
	cargo check
	cargo check --features="openssl"
	cargo check --features="native"
	cargo check --features="rustls"	


