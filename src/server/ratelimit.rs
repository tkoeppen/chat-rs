//! Per-source-IP sliding-window connection rate limiter.
//!
//! Cheap to check (O(N) on the per-IP queue, where N is the limit). The
//! `cleanup` pass is called periodically by the sweeper to prevent the
//! HashMap from growing without bound under churn from many distinct IPs.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    by_ip: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    window: Duration,
    max: usize,
}

impl RateLimiter {
    pub fn new(max_per_window: usize, window: Duration) -> Self {
        Self {
            by_ip: Mutex::new(HashMap::new()),
            window,
            max: max_per_window,
        }
    }

    /// Records a connection from `ip`. Returns `true` if it's allowed,
    /// `false` if the limit for the current window has been exceeded.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.by_ip.lock().expect("ratelimit mutex poisoned");
        let entry = map.entry(ip).or_default();
        let now = Instant::now();
        while entry
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.window)
        {
            entry.pop_front();
        }
        if entry.len() >= self.max {
            return false;
        }
        entry.push_back(now);
        true
    }

    /// Drop empty / fully-expired entries so a flood of distinct IPs can't
    /// grow the map indefinitely.
    pub fn cleanup(&self) {
        let mut map = self.by_ip.lock().expect("ratelimit mutex poisoned");
        let now = Instant::now();
        map.retain(|_, q| {
            while q
                .front()
                .is_some_and(|t| now.duration_since(*t) > self.window)
            {
                q.pop_front();
            }
            !q.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_below_limit_blocks_above() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip), "4th connect within window must be denied");
    }

    #[test]
    fn distinct_ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.check(a));
        assert!(
            rl.check(b),
            "different IP should not be affected by a's quota"
        );
        assert!(!rl.check(a));
    }

    #[test]
    fn cleanup_drops_empty() {
        let rl = RateLimiter::new(1, Duration::from_millis(1));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(rl.check(ip));
        std::thread::sleep(Duration::from_millis(5));
        rl.cleanup();
        // After cleanup, the entry should be gone, so check passes again.
        assert!(rl.check(ip));
    }
}
