use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;

use super::salt_checker::SaltChecker;

#[derive(Debug)]
struct TimeEntry {
    instant: Instant,
    salt: Arc<[u8]>,
}

#[derive(Debug)]
pub struct TimedSaltChecker {
    state: Arc<Mutex<SaltState>>,
    cleanup: Option<tokio::task::AbortHandle>,
}

#[derive(Debug)]
struct SaltState {
    last_salts: VecDeque<TimeEntry>,
    known_salts: HashSet<Arc<[u8]>>,
    timeout_secs: u64,
    capacity: usize,
}

impl TimedSaltChecker {
    pub fn new(timeout_secs: u64) -> Self {
        Self::with_capacity(timeout_secs, 65536)
    }

    fn with_capacity(timeout_secs: u64, capacity: usize) -> Self {
        let state = Arc::new(Mutex::new(SaltState {
            last_salts: VecDeque::new(),
            known_salts: HashSet::new(),
            timeout_secs,
            capacity,
        }));
        let weak = Arc::downgrade(&state);
        let cleanup = tokio::runtime::Handle::try_current().ok().map(|runtime| {
            runtime
                .spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(1));
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else { break };
                        state.lock().expire();
                    }
                })
                .abort_handle()
        });
        Self { state, cleanup }
    }
}

impl Drop for TimedSaltChecker {
    fn drop(&mut self) {
        if let Some(task) = &self.cleanup {
            task.abort();
        }
    }
}

impl SaltState {
    fn expire(&mut self) {
        while let Some(time_entry) = self.last_salts.front() {
            if time_entry.instant.elapsed().as_secs() < self.timeout_secs {
                break;
            }
            self.known_salts.remove(&time_entry.salt);
            self.last_salts.pop_front();
        }
        if self.known_salts.len() < self.known_salts.capacity() / 4 {
            self.known_salts.shrink_to(self.known_salts.len().max(128));
            self.last_salts.shrink_to(self.last_salts.len().max(128));
        }
    }
}

impl SaltChecker for TimedSaltChecker {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool {
        let mut state = self.state.lock();
        state.expire();
        // Reject new work at capacity. Evicting live entries would admit replays.
        if state.known_salts.contains(salt) || state.known_salts.len() >= state.capacity {
            return false;
        }

        let salt: Arc<[u8]> = salt.into();
        state.known_salts.insert(salt.clone());
        state.last_salts.push_back(TimeEntry {
            instant: Instant::now(),
            salt,
        });

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn capacity_is_replay_safe_and_idle_entries_expire() {
        let mut checker = TimedSaltChecker::with_capacity(60, 2);
        assert!(checker.insert_and_check(b"first"));
        assert!(checker.insert_and_check(b"second"));
        assert!(!checker.insert_and_check(b"third"));
        assert!(!checker.insert_and_check(b"first"));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(checker.state.lock().known_salts.is_empty());
        assert!(checker.insert_and_check(b"third"));
        let task = checker.cleanup.clone().unwrap();
        drop(checker);
        tokio::task::yield_now().await;
        assert!(task.is_finished());
    }
}
