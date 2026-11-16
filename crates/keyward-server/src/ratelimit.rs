//! In-memory rate limiting (per IP) and login lockout (per username).
//!
//! State is per process and lost on restart; that is acceptable for a
//! single-instance self-hosted server and keeps the design simple.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;

const MAX_TRACKED: usize = 10_000;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Token bucket per client IP.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_ms: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, i64)>>,
}

impl RateLimiter {
    /// `per_minute` requests per minute, bursts up to the same number.
    pub fn per_minute(per_minute: u32) -> Self {
        Self {
            capacity: f64::from(per_minute),
            refill_per_ms: f64::from(per_minute) / 60_000.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Take one token for `ip`. `Err(seconds)` says when to retry.
    pub fn check(&self, ip: IpAddr, now_ms: i64) -> Result<(), u64> {
        let mut b = lock(&self.buckets);
        if b.len() > MAX_TRACKED {
            let (cap, rate) = (self.capacity, self.refill_per_ms);
            b.retain(|_, (tokens, last)| *tokens + (now_ms - *last) as f64 * rate < cap);
        }
        let (tokens, last) = b.entry(ip).or_insert((self.capacity, now_ms));
        let elapsed = (now_ms - *last).max(0) as f64;
        *tokens = (*tokens + elapsed * self.refill_per_ms).min(self.capacity);
        *last = now_ms;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            let wait_ms = (1.0 - *tokens) / self.refill_per_ms;
            Err((wait_ms / 1000.0).ceil() as u64)
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Failures {
    count: u32,
    locked_until_ms: i64,
}

/// Locks a username after repeated failed logins. Unknown usernames are
/// tracked exactly like real ones so lockout does not reveal which exist.
#[derive(Debug)]
pub struct LoginLockout<K = String> {
    threshold: u32,
    lock_ms: i64,
    entries: Mutex<HashMap<K, Failures>>,
}

impl<K: Eq + Hash + Clone> LoginLockout<K> {
    pub fn new(threshold: u32, lock_secs: i64) -> Self {
        Self {
            threshold,
            lock_ms: lock_secs.saturating_mul(1000),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// `Err(seconds)` while the key is locked.
    pub fn check(&self, key: &K, now_ms: i64) -> Result<(), u64> {
        match lock(&self.entries).get(key) {
            Some(f) if f.locked_until_ms > now_ms => {
                Err(((f.locked_until_ms - now_ms) as f64 / 1000.0).ceil() as u64)
            }
            _ => Ok(()),
        }
    }

    pub fn record_failure(&self, key: &K, now_ms: i64) {
        let mut e = lock(&self.entries);
        if e.len() > MAX_TRACKED {
            e.retain(|_, f| f.locked_until_ms > now_ms);
        }
        let f = e.entry(key.clone()).or_default();
        if f.locked_until_ms != 0 && f.locked_until_ms <= now_ms {
            *f = Failures::default(); // previous lock expired: start over
        }
        f.count += 1;
        if f.count >= self.threshold {
            f.locked_until_ms = now_ms + self.lock_ms;
        }
    }

    pub fn record_success(&self, key: &K) {
        lock(&self.entries).remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let r = RateLimiter::per_minute(3);
        let ip: IpAddr = [10, 0, 0, 1].into();
        for _ in 0..3 {
            r.check(ip, 0).unwrap();
        }
        let wait = r.check(ip, 0).unwrap_err();
        assert_eq!(wait, 20);
        r.check(ip, 20_000).unwrap();
        // other IPs are independent
        r.check([10, 0, 0, 2].into(), 0).unwrap();
    }

    #[test]
    fn lockout_after_threshold_and_expiry() {
        let l = LoginLockout::new(3, 60);
        let k = "alice".to_owned();
        for t in 0..2 {
            l.record_failure(&k, t);
            l.check(&k, t).unwrap();
        }
        l.record_failure(&k, 2);
        assert_eq!(l.check(&k, 2).unwrap_err(), 60);
        assert!(l.check(&k, 59_000).is_err());
        l.check(&k, 62_001).unwrap();
        // after expiry the counter restarts
        l.record_failure(&k, 63_000);
        l.check(&k, 63_000).unwrap();
    }

    #[test]
    fn success_resets() {
        let l = LoginLockout::new(2, 60);
        let k = "bob".to_owned();
        l.record_failure(&k, 0);
        l.record_success(&k);
        l.record_failure(&k, 0);
        l.check(&k, 0).unwrap();
    }
}
