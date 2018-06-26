extern crate mio;
extern crate mio_httpc;

use mio::{Events, Poll};
use mio_httpc::{CallBuilder, Httpc, HttpcCfg, SimpleCall};

fn do_call(htp: &mut Httpc, poll: &Poll, mut call: SimpleCall) {
    let to = ::std::time::Duration::from_millis(100);
    let mut events = Events::with_capacity(8);
    'outer: loop {
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
                if call.perform(htp, &poll).expect("Call failed") {
                    let (resp, body) = call.finish().expect("No response");
                    println!("done req = {}", resp.status);
                    for h in resp.headers() {
                        println!("Header={}", h);
                    }
                    if let Ok(s) = String::from_utf8(body.clone()) {
                        println!("Body: {}", s);
                    } else {
                        println!("Non utf8 body sized: {}", body.len());
                    }
                    break 'outer;
                }
            }
        }
    }
}

fn main() {
    let poll = Poll::new().unwrap();
    let mut args: Vec<String> = ::std::env::args().collect();

    if args.len() == 1 {
        args.push("https://www.reddit.com".to_string());
    }

    let cfg = if let Ok(cfg) = HttpcCfg::certs_from_path(".") {
        Some(cfg)
    } else {
        None
    };
    let cfg = None;
    let mut htp = Httpc::new(10, cfg);

    for i in 1..args.len() {
        println!("Get {}", args[i].as_str());
        let call = CallBuilder::get()
            .url(args[i].as_str())
            .expect("Invalid url")
            .timeout_ms(10000)
            .digest_auth(true)
            .insecure_do_not_verify_domain()
            .simple_call(&mut htp, &poll)
            .expect("Call start failed");
        do_call(&mut htp, &poll, call);

        println!("Open connections={}", htp.open_connections());
    }
}
