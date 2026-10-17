use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::config::vless::VlessEncryptionLimits;

pub(crate) struct ClientSession {
    pub(crate) ticket: [u8; 16],
    pub(crate) pfs: Zeroizing<[u8; 64]>,
    pub(crate) expires_at: Instant,
}

#[derive(Default)]
pub(crate) struct ClientSessionCache {
    current: Mutex<Option<Arc<ClientSession>>>,
}

impl ClientSessionCache {
    pub(crate) fn snapshot(&self, now: Instant) -> Option<Arc<ClientSession>> {
        let mut current = self.current.lock();
        if current
            .as_ref()
            .is_some_and(|session| session.expires_at <= now)
        {
            *current = None;
        }
        current.clone()
    }

    pub(crate) fn publish(&self, session: Arc<ClientSession>, now: Instant) {
        if session.expires_at > now {
            *self.current.lock() = Some(session);
        }
    }

    fn invalidate_if_current(&self, used: &Arc<ClientSession>) {
        let mut current = self.current.lock();
        if current
            .as_ref()
            .is_some_and(|session| Arc::ptr_eq(session, used))
        {
            *current = None;
        }
    }
}

pub(crate) struct ResumeGuard {
    pub(crate) cache: Arc<ClientSessionCache>,
    pub(crate) used: Arc<ClientSession>,
}

impl ResumeGuard {
    // Deliberately not a Drop hook: cancellation is not a peer failure.
    pub(crate) fn invalidate(&self) {
        self.cache.invalidate_if_current(&self.used);
    }
}

struct ServerSession {
    pfs: Zeroizing<[u8; 64]>,
    retain_until: Instant,
    used_nfs: HashSet<[u8; 32]>,
}

pub(crate) struct ServerSessions {
    entries: HashMap<[u8; 16], ServerSession>,
    expiry: BTreeSet<(Instant, [u8; 16])>,
    replay_count: usize,
    limits: VlessEncryptionLimits,
    last_capacity_warning: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReserveError {
    Stale,
    Replay,
    Capacity,
}

impl ServerSessions {
    pub(crate) fn new(limits: VlessEncryptionLimits) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: BTreeSet::new(),
            replay_count: 0,
            limits,
            last_capacity_warning: None,
        }
    }

    fn remove(&mut self, ticket: &[u8; 16]) {
        if let Some(session) = self.entries.remove(ticket) {
            self.replay_count -= session.used_nfs.len();
            self.expiry.remove(&(session.retain_until, *ticket));
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&(deadline, ticket)) = self.expiry.first() {
            if deadline > now {
                break;
            }
            self.remove(&ticket);
        }
    }

    pub(crate) fn can_issue(&mut self, now: Instant) -> bool {
        self.prune(now);
        self.entries.len() < self.limits.max_sessions - self.limits.max_sessions / 4
            && self.replay_count < self.limits.max_replays - self.limits.max_replays / 4
    }

    fn warn_capacity(&mut self, now: Instant) {
        if self
            .last_capacity_warning
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(60))
        {
            log::warn!(
                "VLESS encryption cache capacity reached ({} sessions, {} replay markers); new tickets may be disabled and resumptions rejected; size limits for connection rate and ticket lifetime",
                self.entries.len(),
                self.replay_count
            );
            self.last_capacity_warning = Some(now);
        }
    }

    pub(crate) fn insert(
        &mut self,
        ticket: [u8; 16],
        pfs: Zeroizing<[u8; 64]>,
        maximum_lifetime: u16,
        now: Instant,
    ) -> bool {
        let can_issue = self.can_issue(now);
        if self.entries.contains_key(&ticket) {
            return false;
        }
        if !can_issue {
            self.warn_capacity(now);
            return false;
        }
        let retain_until = now + Duration::from_secs(u64::from(maximum_lifetime) + 120);
        self.entries.insert(
            ticket,
            ServerSession {
                pfs,
                retain_until,
                used_nfs: HashSet::new(),
            },
        );
        self.expiry.insert((retain_until, ticket));
        true
    }

    pub(crate) fn reserve(
        &mut self,
        ticket: &[u8; 16],
        nfs: &[u8; 32],
        now: Instant,
    ) -> Result<Zeroizing<[u8; 64]>, ReserveError> {
        self.prune(now);
        let session = self.entries.get_mut(ticket).ok_or(ReserveError::Stale)?;
        // Replay membership needs equality, not retention of the exchange secret.
        let marker = *blake3::hash(nfs).as_bytes();
        if session.used_nfs.contains(&marker) {
            return Err(ReserveError::Replay);
        }
        if self.replay_count >= self.limits.max_replays
            || session.used_nfs.len() >= self.limits.max_replays_per_session
        {
            self.remove(ticket);
            self.warn_capacity(now);
            return Err(ReserveError::Capacity);
        }
        session.used_nfs.insert(marker);
        self.replay_count += 1;
        Ok(session.pfs.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(ticket: u8, now: Instant) -> Arc<ClientSession> {
        Arc::new(ClientSession {
            ticket: [ticket; 16],
            pfs: Zeroizing::new([ticket; 64]),
            expires_at: now + Duration::from_secs(1),
        })
    }

    #[test]
    fn old_failures_cannot_invalidate_a_new_publication() {
        let now = Instant::now();
        let cache = Arc::new(ClientSessionCache::default());
        let old = session(1, now);
        let new = session(2, now);
        cache.publish(old.clone(), now);
        let guard = ResumeGuard {
            cache: cache.clone(),
            used: old,
        };
        cache.publish(new.clone(), now);
        guard.invalidate();
        assert!(Arc::ptr_eq(&cache.snapshot(now).unwrap(), &new));
        drop(ResumeGuard {
            cache: cache.clone(),
            used: new.clone(),
        });
        assert!(cache.snapshot(now).is_some());
        ResumeGuard {
            cache: cache.clone(),
            used: new,
        }
        .invalidate();
        assert!(cache.snapshot(now).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn publication_does_not_extend_lifetime() {
        let cache = ClientSessionCache::default();
        let ticket = session(1, Instant::now());
        tokio::time::advance(Duration::from_secs(2)).await;
        cache.publish(ticket, Instant::now());
        assert!(cache.snapshot(Instant::now()).is_none());
    }

    fn limits() -> VlessEncryptionLimits {
        VlessEncryptionLimits {
            max_sessions: 8,
            max_replays: 8,
            max_replays_per_session: 2,
        }
    }

    #[test]
    fn capacity_invalidates_whole_ticket_not_individual_markers() {
        let now = Instant::now();
        let mut cache = ServerSessions::new(limits());
        assert!(cache.insert([1; 16], Zeroizing::new([9; 64]), 600, now));
        assert!(cache.reserve(&[1; 16], &[1; 32], now).is_ok());
        assert_eq!(
            cache.reserve(&[1; 16], &[1; 32], now),
            Err(ReserveError::Replay)
        );
        assert!(cache.reserve(&[1; 16], &[2; 32], now).is_ok());
        assert_eq!(
            cache.reserve(&[1; 16], &[3; 32], now),
            Err(ReserveError::Capacity)
        );
        assert_eq!(
            cache.reserve(&[1; 16], &[1; 32], now),
            Err(ReserveError::Stale)
        );
        assert_eq!(cache.replay_count, 0);
        assert!(cache.expiry.is_empty());
    }

    #[test]
    fn high_water_and_collisions_preserve_existing_sessions() {
        let now = Instant::now();
        let mut cache = ServerSessions::new(limits());
        for i in 0..6 {
            assert!(cache.insert([i; 16], Zeroizing::new([i; 64]), 600, now));
        }
        assert!(!cache.can_issue(now));
        assert!(!cache.insert([0; 16], Zeroizing::new([99; 64]), 600, now));
        assert!(cache.last_capacity_warning.is_none());
        assert!(!cache.insert([9; 16], Zeroizing::new([99; 64]), 600, now));
        assert_eq!(cache.last_capacity_warning, Some(now));
        assert!(!cache.insert(
            [9; 16],
            Zeroizing::new([99; 64]),
            600,
            now + Duration::from_secs(59)
        ));
        assert_eq!(cache.last_capacity_warning, Some(now));
        assert!(!cache.insert(
            [9; 16],
            Zeroizing::new([99; 64]),
            600,
            now + Duration::from_secs(60)
        ));
        assert_eq!(
            cache.last_capacity_warning,
            Some(now + Duration::from_secs(60))
        );
        assert_eq!(
            cache.reserve(&[0; 16], &[1; 32], now).unwrap().as_ref(),
            &[0; 64]
        );
        assert!(cache.can_issue(now + Duration::from_secs(720)));
        assert!(cache.entries.is_empty());
        assert!(cache.expiry.is_empty());
        assert_eq!(cache.replay_count, 0);
    }

    #[test]
    fn aggregate_limit_and_expiry_index_remain_exact_under_churn() {
        let now = Instant::now();
        let mut cache = ServerSessions::new(VlessEncryptionLimits {
            max_replays: 2,
            ..limits()
        });
        for i in 0..2 {
            assert!(cache.insert([i; 16], Zeroizing::new([i; 64]), 0, now));
        }
        assert!(cache.reserve(&[0; 16], &[0; 32], now).is_ok());
        assert!(cache.reserve(&[1; 16], &[0; 32], now).is_ok());
        assert!(!cache.can_issue(now));
        assert_eq!(
            cache.reserve(&[0; 16], &[1; 32], now),
            Err(ReserveError::Capacity)
        );
        assert_eq!(cache.replay_count, 1);
        for i in 0..1000 {
            let now = now + Duration::from_secs(i * 120);
            cache.prune(now);
            assert!(cache.insert([3; 16], Zeroizing::new([3; 64]), 0, now));
            assert_eq!(cache.expiry.len(), cache.entries.len());
        }
    }

    #[test]
    fn concurrent_duplicates_have_one_irrevocable_reservation() {
        let now = Instant::now();
        let cache = Arc::new(Mutex::new(ServerSessions::new(limits())));
        cache
            .lock()
            .insert([1; 16], Zeroizing::new([1; 64]), 600, now);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                std::thread::spawn(move || cache.lock().reserve(&[1; 16], &[1; 32], now).is_ok())
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
        assert_eq!(cache.lock().replay_count, 1);
    }
}
