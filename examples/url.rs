extern crate mio_httpc;

use mio_httpc::CallBuilder;

fn main() {
    let b = CallBuilder::get()
        .https()
        .host("www.example.com")
        .auth("user name", "my password")
        .port(12345)
        .path_segm("a/")
        .path_segm("b")
        .query("spaced key", "123")
        .query("key", "<>")
        .get_url();

    println!("URL={}", b);
}
