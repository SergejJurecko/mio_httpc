extern crate mio_httpc;
extern crate mio;

use mio_httpc::{Request,CallBuilder,Httpc,SimpleCall};
use mio::{Poll,Events};

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10);
    let mut req = Request::builder();
    let args: Vec<String> = ::std::env::args().collect();
    let req = req.uri(args[1].as_str()).body(Vec::new()).expect("can not build request");

    let call_id = CallBuilder::new(req).timeout_ms(500).call(&mut htp, &poll).expect("Call start failed");
    let mut call = SimpleCall::from(call_id);

    let to = ::std::time::Duration::from_millis(100);
    'outer: loop {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, Some(to)).unwrap();
        for cid in htp.timeout().into_iter() {
            if cid == *call.id() {
                println!("Request timed out");
                break 'outer;
            }
        }

        for ev in events.iter() {
            let cid = htp.event(&ev);

            if call.is_callid(&cid) {
                if call.perform(&mut htp, &poll, &ev).expect("Call failed") {
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