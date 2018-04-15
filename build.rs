use std::env;

fn main() {
    // HAS
    match env::var("DEP_OPENSSL_VERSION") {
        Ok(ref v) if v == "101" => {}
        Ok(ref v) if v == "102" => {
            println!("cargo:rustc-cfg=has_alpn");
        }
        Ok(ref v) if v == "110" => {
            println!("cargo:rustc-cfg=has_alpn");
        }
        _ => {}
    }
}
