extern crate mio_httpc;

use mio_httpc::CallBuilder;

fn main() {
    let args: Vec<String> = ::std::env::args().collect();
    let uri = if args.len() == 1 {
        "https://www.reddit.com"
    } else {
        args[1].as_str()
    };

    println!("Calling: {}",uri);

    let (resp, body) = CallBuilder::get()
        .timeout_ms(5000)
        .url(uri).expect("Invalid url")
        .exec().expect("Request failed");

    println!("Status={}", resp.status);
    println!("Hdrs={}", resp.headers());
    if let Ok(s) = String::from_utf8(body) {
        println!("Body: {}",s);
    }
}