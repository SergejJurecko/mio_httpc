extern crate mio;
extern crate mio_httpc;

use mio_httpc::{CallBuilder, Httpc, HttpcCfg, Request, SimpleCall};
use mio::{Events, Poll};

fn do_call(htp: &mut Httpc, poll: &Poll, req: Request<Vec<u8>>) {
    let call = CallBuilder::new(req)
        .timeout_ms(10000)
        .digest_auth(true)
        // .insecure_do_not_verify_domain()
        .call(htp, &poll)
        .expect("Call start failed");
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
                    let mut resp = call.finish().expect("No response");
                    // println!("done req");
                    println!("Headers={:?}", resp.headers());
                    let v = mio_httpc::extract_body(&mut resp);
                    if let Ok(s) = String::from_utf8(v.clone()) {
                        println!("Body: {}", s);
                    } else {
                        println!("Non utf8 body sized: {}", v.len());
                    }
                    break 'outer;
                }
            }
        }
    }
}

use std::fs::{read_dir, File};
use std::ffi::OsStr;
use std::io::Read;

fn read_certs() -> ::std::io::Result<HttpcCfg> {
    let mut cfg = HttpcCfg::new();
    let certs = [OsStr::new("crt"), OsStr::new("pem")];
    let der = [OsStr::new("der")];
    for de in read_dir(".")? {
        let de = de?;
        match de.path().extension() {
            Some(ex) if der.contains(&ex) => {
                println!("Adding {:?}", de.path());
                let mut file = File::open(de.path())?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                cfg.der_ca.push(contents);
            }
            Some(ex) if certs.contains(&ex) => {
                println!("Adding {:?}", de.path());
                let mut file = File::open(de.path())?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                cfg.pem_ca.push(contents);
            }
            _ => {}
        }
    }
    Ok(cfg)
}

fn main() {
    let poll = Poll::new().unwrap();
    let args: Vec<String> = ::std::env::args().collect();

    let cfg = if let Ok(cfg) = read_certs() {
        Some(cfg)
    } else {
        None
    };
    let mut htp = Httpc::new(10, cfg);

    for i in 1..args.len() {
        println!("Get {}", args[i].as_str());
        let mut req = Request::builder();
        let req = req.uri(args[i].as_str())
            .body(Vec::new())
            .expect("can not build request");
        do_call(&mut htp, &poll, req);

        println!("Open connections={}", htp.open_connections());
    }
}
