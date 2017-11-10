use fnv::FnvHashMap as HashMap;
// use time;
use std::time::{Instant,Duration};
use std::net::IpAddr;

pub struct DnsCache {
    hm: HashMap<String,(Instant,IpAddr)>,
    last_check: Instant,
}

static MAX_AGE:u64 = 5*60*1000;

fn too_old(now: Instant, age: Instant) -> bool {
    now.duration_since(age) > Duration::from_millis(MAX_AGE)
}

impl DnsCache {
    pub fn new() -> DnsCache {
        DnsCache {
            last_check: Instant::now() - Duration::from_millis(MAX_AGE),
            hm: HashMap::default(),
        }
    }

    pub fn find(&mut self, url: &str) -> Option<IpAddr> {
        let now = Instant::now();
        if too_old(now, self.last_check) {
            self.cleanup(now);
        }
        if let Some(&(_, v)) =  self.hm.get(url) {
            return Some(v);
        }
        None
    }

    pub fn save(&mut self, url: &str, ip: IpAddr) {
        let now = Instant::now();
        self.hm.insert(String::from(url), (now, ip));
        self.cleanup(now);
    }

    fn cleanup(&mut self, now: Instant) {
        self.hm.retain(|_, &mut (age,_)| {
            !too_old(now, age)
        });
        self.last_check = now;
    }
}