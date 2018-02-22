extern crate mio;
extern crate mio_httpc;

use mio_httpc::{CallBuilder, Httpc, RecvState, SendState};
use mio::{Events, Poll};

fn main() {
    let poll = Poll::new().unwrap();
    let mut htp = Httpc::new(10, None);
    let args: Vec<String> = ::std::env::args().collect();
    let mut call = CallBuilder::get(args[1].as_str())
        .call(&mut htp, &poll)
        .expect("Call start failed");

    let mut sending = true;
    let mut done = false;
    let mut recv_vec = Vec::new();
    while !done {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            // println!("ev {}",ev.token().0);
            let cid = htp.event(&ev).expect("Event not from http request");
            assert!(call.is_ref(cid));

            if sending {
                // None because we are not sending any body
                match htp.call_send(&poll, &mut call, None) {
                    SendState::Done => {
                        panic!("Done while sending");
                    }
                    SendState::Error(e) => {
                        panic!("Failed while sending {}", e);
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
                // This is so socket is always drained entirely. Otherwise poll will not return
                // anything. Httpc uses edge triggered sockets.
                loop {
                    match htp.call_recv(&poll, &mut call, Some(&mut recv_vec)) {
                        RecvState::Done => {
                            println!("Done");
                            done = true;
                            break;
                        }
                        RecvState::Response(resp, bsz) => {
                            println!("Got response {:?}\nbody_sz={}", resp, bsz);
                            if bsz.is_empty() {
                                println!("Finish as content-length is 0");
                                done = true;
                                break;
                            }
                            // recv_vec.reserve(bsz);
                        }
                        RecvState::ReceivedBody(sz) => {
                            println!("Got chunk {} bytes", sz);
                        }
                        // If no Vec<u8> provied to call_recv the final body is returned with this.
                        RecvState::DoneWithBody(rt) => {
                            if let Ok(s) = String::from_utf8(rt) {
                                println!("Body: {}", s);
                            }
                            panic!("We provided vec, should not get body as well!");
                        }
                        RecvState::Error(e) => {
                            panic!("Get failed {}", e);
                        }
                        RecvState::Sending => {
                            println!("Switch to sending, must be redirect!");
                            sending = true;
                            break;
                        }
                        RecvState::Wait => {
                            break;
                        }
                    }
                }
            }
        }
    }
    if let Ok(s) = String::from_utf8(recv_vec) {
        println!("Body: {}", s);
    }
}
