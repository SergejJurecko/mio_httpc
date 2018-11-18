use fnv::FnvHashMap as HashMap;
// use time;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct CacheEntry {
    expires: Instant,
    ip: IpAddr,
}

pub struct DnsCache {
    max_age: Duration,
    cache: HashMap<String, CacheEntry>,
    next_expiration_check: Instant,
}

impl DnsCache {
    pub fn new() -> DnsCache {
        let max_age = Duration::from_millis(5 * 60 * 1000);
        DnsCache {
            max_age,
            next_expiration_check: Instant::now() + max_age,
            cache: HashMap::default(),
        }
    }

    pub fn find(&mut self, host: &str) -> Option<IpAddr> {
        let now = Instant::now();
        if self.next_expiration_check < now {
            self.cleanup(now);
        }
        if let Some(&CacheEntry { ip, .. }) = self.cache.get(host) {
            return Some(ip);
        }
        None
    }

    pub fn save(&mut self, host: &str, ip: IpAddr) {
        let now = Instant::now();
        let expires = now + self.max_age;
        self.cache.insert(
            String::from(host),
            CacheEntry { expires, ip },
        );
        self.cleanup(now);
    }

    fn cleanup(&mut self, now: Instant) {
        let mut smallest_expiration = now + self.max_age;
        self.cache.retain(|_, &mut CacheEntry { expires, .. }| {
            if expires < smallest_expiration {
                smallest_expiration = expires
            }
            expires > now
        });
        self.next_expiration_check = smallest_expiration;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;

    fn ip(index: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, index))
    }

    fn new_cache() -> DnsCache {
        let max_age = Duration::from_millis(100);
        DnsCache {
            max_age,
            next_expiration_check: Instant::now() + max_age,
            cache: HashMap::default(),
        }
    }

    #[test]
    fn test_cache() {
        let mut cache = new_cache();

        // 0 ms after start
        assert!(cache.find("h1").is_none());
        cache.save("h1", ip(1));
        assert_eq!(ip(1), cache.find("h1").unwrap());

        thread::sleep(Duration::from_millis(50));
        // 50 ms after start
        assert_eq!(ip(1), cache.find("h1").unwrap());
        cache.save("h2", ip(2));
        assert_eq!(ip(2), cache.find("h2").unwrap());

        thread::sleep(Duration::from_millis(60));
        // 110 ms after start
        assert!(cache.find("h1").is_none());
        assert_eq!(ip(2), cache.find("h2").unwrap());
        cache.save("h3", ip(3));
        assert_eq!(ip(3), cache.find("h3").unwrap());

        thread::sleep(Duration::from_millis(60));
        // 170 ms after start
        assert!(cache.find("h2").is_none());
        assert_eq!(ip(3), cache.find("h3").unwrap());

        thread::sleep(Duration::from_millis(50));
        // 220 ms after start
        assert!(cache.find("h3").is_none());
    }
}
