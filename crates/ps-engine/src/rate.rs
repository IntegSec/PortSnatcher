//! Two-axis token-bucket rate limiter: global pps + per-target pps.
//!
//! Both consulted before any outbound packet. The returned `bool` does not
//! itself emit any event — the scheduler emits `RateCapEngaged` once per
//! polling cycle in which the cap was hit, to avoid per-packet noise.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug)]
struct Bucket {
    capacity: u32,
    tokens: f64,
    rate_per_sec: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate_per_sec: u32) -> Self {
        Self {
            capacity: rate_per_sec,
            tokens: rate_per_sec as f64,
            rate_per_sec: rate_per_sec as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate_per_sec).min(self.capacity as f64);
        self.last_refill = now;
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    global: Mutex<Bucket>,
    per_target_rate: u32,
    per_target: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(global_pps: u32, per_target_pps: u32) -> Self {
        let global_pps = global_pps.max(1);
        let per_target_pps = per_target_pps.max(1);
        Self {
            global: Mutex::new(Bucket::new(global_pps)),
            per_target_rate: per_target_pps,
            per_target: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(&self, target: IpAddr) -> bool {
        self.try_acquire_at(target, Instant::now())
    }

    pub fn try_acquire_at(&self, target: IpAddr, now: Instant) -> bool {
        let mut g = self.global.lock().unwrap();
        if !g.try_take(now) {
            return false;
        }
        drop(g);
        let mut p = self.per_target.lock().unwrap();
        let b = p
            .entry(target)
            .or_insert_with(|| Bucket::new(self.per_target_rate));
        if !b.try_take(now) {
            let mut g = self.global.lock().unwrap();
            g.tokens = (g.tokens + 1.0).min(g.capacity as f64);
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn fresh_bucket_grants_capacity() {
        let rl = RateLimiter::new(5, 5);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.try_acquire(ip));
        }
        assert!(!rl.try_acquire(ip));
    }

    #[test]
    fn bucket_refills_over_time() {
        let rl = RateLimiter::new(10, 10);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let start = Instant::now();
        for _ in 0..10 {
            assert!(rl.try_acquire_at(ip, start));
        }
        let later = start + Duration::from_millis(500);
        let acquired_after: usize = (0..10).filter(|_| rl.try_acquire_at(ip, later)).count();
        assert!(acquired_after >= 4 && acquired_after <= 6);
    }

    #[test]
    fn per_target_throttles_independently() {
        let rl = RateLimiter::new(100, 2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.try_acquire(a));
        assert!(rl.try_acquire(a));
        assert!(!rl.try_acquire(a));
        assert!(rl.try_acquire(b));
    }
}
