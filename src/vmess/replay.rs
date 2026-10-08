use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;
use std::time::SystemTime;

use parking_lot::Mutex;

use super::vmess_handler::{AUTH_ID_TIME_WINDOW_SECS, unix_time_secs};

static AUTH_IDS: OnceLock<Mutex<ReplayCache>> = OnceLock::new();

pub(super) fn admit(identity: [u8; 16], auth_id: [u8; 16], timestamp: u64) -> io::Result<()> {
    let mut cache = AUTH_IDS
        .get_or_init(|| Mutex::new(ReplayCache::new(65536)))
        .lock();
    cache.admit(
        identity,
        auth_id,
        timestamp,
        unix_time_secs(SystemTime::now())?,
    )
}

struct ReplayCache {
    expires: HashMap<([u8; 16], [u8; 16]), u64>,
    last_now: u64,
    capacity: usize,
}

impl ReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            expires: HashMap::new(),
            last_now: 0,
            capacity,
        }
    }

    fn admit(
        &mut self,
        identity: [u8; 16],
        auth_id: [u8; 16],
        timestamp: u64,
        now: u64,
    ) -> io::Result<()> {
        // Expired IDs must not become admissible again after a local clock rollback.
        if now < self.last_now {
            return Err(io::Error::other(
                "VMess authentication paused after clock rollback",
            ));
        }
        if now > self.last_now {
            self.expires.retain(|_, expires| *expires >= now);
            self.last_now = now;
        }
        if timestamp.abs_diff(now) > AUTH_ID_TIME_WINDOW_SECS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VMess authentication timestamp outside allowed window",
            ));
        }
        let key = (identity, auth_id);
        if self.expires.contains_key(&key) || self.expires.len() >= self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMess replay or replay cache capacity exhausted",
            ));
        }
        self.expires
            .insert(key, timestamp.saturating_add(AUTH_ID_TIME_WINDOW_SECS));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_id_remains_protected_through_inclusive_expiry() {
        let mut cache = ReplayCache::new(2);
        assert!(cache.admit([1; 16], [2; 16], 1120, 1000).is_ok());
        for now in [1120, 1239, 1240] {
            assert!(cache.admit([1; 16], [2; 16], 1120, now).is_err());
        }
        assert!(cache.admit([1; 16], [2; 16], 1120, 1241).is_err());
        assert!(cache.expires.is_empty());
        assert!(cache.admit([1; 16], [2; 16], 1120, 1240).is_err());
        assert!(cache.admit([1; 16], [3; 16], 1241, 1241).is_ok());
    }

    #[test]
    fn timestamp_edges_capacity_and_identities() {
        let mut cache = ReplayCache::new(2);
        for timestamp in [879, 1121] {
            assert!(cache.admit([1; 16], [2; 16], timestamp, 1000).is_err());
        }
        assert!(cache.expires.is_empty());
        assert!(cache.admit([1; 16], [2; 16], 880, 1000).is_ok());
        assert!(cache.admit([3; 16], [2; 16], 1120, 1000).is_ok());
        assert!(cache.admit([4; 16], [2; 16], 1000, 1000).is_err());
        assert!(cache.admit([1; 16], [2; 16], 880, 1000).is_err());
        assert!(cache.admit([4; 16], [2; 16], 1001, 1001).is_ok());
        assert!(cache.admit([3; 16], [2; 16], 1120, 1001).is_err());
    }

    #[test]
    fn process_cache_admits_a_concurrent_identity_only_once() {
        let identity = rand::random();
        let auth_id = rand::random();
        let timestamp = unix_time_secs(SystemTime::now()).unwrap();
        let admitted = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| admit(identity, auth_id, timestamp).is_ok()))
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, 1);
        assert!(admit(identity, auth_id, timestamp).is_err());
    }
}
