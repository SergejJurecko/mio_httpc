use fnv::FnvHashMap as HashMap;
// use time;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct DnsCache {
    hm: HashMap<String, (Instant, IpAddr)>,
    last_check: Instant,
}

static MAX_AGE: u64 = 5 * 60 * 1000;

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

    pub fn find(&mut self, host: &str) -> Option<IpAddr> {
        let now = Instant::now();
        if too_old(now, self.last_check) {
            self.cleanup(now);
        }
        if let Some(&(_, v)) = self.hm.get(host) {
            return Some(v);
        }
        None
    }

    pub fn save(&mut self, host: &str, ip: IpAddr) {
        let now = Instant::now();
        self.hm.insert(String::from(host), (now, ip));
        self.cleanup(now);
    }

    fn cleanup(&mut self, now: Instant) {
        self.hm.retain(|_, &mut (age, _)| !too_old(now, age));
        self.last_check = now;
    }
}
