extern crate mio_httpc;
extern crate mio;
extern crate http;

use mio_httpc::{CallBuilder,Httpc,SendState,RecvState};
use mio::{Poll,Events};
use http::Request;

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10);
    let mut req = Request::builder();
    // "http://127.0.0.1:26002"
    // "https://www.rust-lang.org/"
    // http://127.0.0.1:3000
    let req = req.uri("http://www.tvim.tv").body(Vec::new()).expect("can not build request");
    let call_id = CallBuilder::new(req).call(&mut htp, &poll).expect("Call start failed");

    let mut sending = true;
    let mut done = false;
    let mut recv_vec = Vec::new();
    while !done {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            let cid = htp.event(&ev).expect("Event not from http request");
            assert_eq!(cid, call_id);

            if sending {
                // None because we are not sending any body
                match htp.call_send(&poll, &ev, cid, None) {
                    SendState::Done => {
                        panic!("Done while sending");
                    }
                    SendState::Error(e) => {
                        panic!("Failed while sending {}",e);
                    }
                    SendState::Wait => {}
                    SendState::Receiving => {
                        println!("Switching to receiving!");
                        sending = false;
                    }
                    _ => {}
                }
            } 
            // no else here because when it switches to receiving you should call call_recv immediately
            if !sending {
                // Loop until receiving RecvState::Wait or an error.
                loop {
                    match htp.call_recv(&poll, &ev, cid, Some(&mut recv_vec)) {
                        RecvState::Done => {
                            println!("Done");
                            done = true;
                            break;
                        }
                        RecvState::Response(resp,bsz) => {
                            // recv_vec.reserve(bsz);
                            println!("Got response {:?} body_sz={} will follow",resp,bsz);
                            // Call again either to get chunk or be done
                        }
                        RecvState::ReceivedBody(sz) => {
                            println!("Got chunk {} bytes",sz);
                        }
                        RecvState::DoneWithBody(_) => {
                            panic!("We provided vec, should not get body as well!");
                        }
                        RecvState::Error(e) => {
                            panic!("Get failed {}",e);
                        }
                        RecvState::Sending => {
                            panic!("Still sending");
                        }
                        RecvState::Wait => {
                            println!("Nothing yet for recv");
                            break;
                        }
                    }
                }
            }
        }
    }
    if let Ok(s) = String::from_utf8(recv_vec) {
        println!("Body: {}",s);
    }
}
