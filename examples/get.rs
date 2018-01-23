extern crate mio_httpc;
extern crate mio;

use mio_httpc::{Request,CallBuilder,Httpc,SimpleCall};
use mio::{Poll,Events};

fn do_call(htp: &mut Httpc, poll: &Poll, req: Request<Vec<u8>>) {
    let call = CallBuilder::new(req).timeout_ms(500).digest_auth(true).call(htp, &poll).expect("Call start failed");
    let mut call = SimpleCall::from(call);

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
                    let mut resp = call.close().expect("No response");
                    // println!("done req");
                    // println!("Resp={:?}",resp);
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

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10);
    let args: Vec<String> = ::std::env::args().collect();

    for i in 1..args.len() {
        println!("Get {}",args[i].as_str());
        let mut req = Request::builder();
        let req = req.uri(args[i].as_str()).body(Vec::new()).expect("can not build request");
        do_call(&mut htp, &poll, req);

        println!("Open connections={}",htp.open_connections());
    }
}