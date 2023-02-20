use std::collections::{HashSet, VecDeque};
use std::time::Instant;

use crate::salt_checker::SaltChecker;

#[derive(Debug)]
struct TimeEntry {
    instant: Instant,
    salt: Box<[u8]>,
}

#[derive(Debug)]
pub struct TimedSaltChecker {
    last_salts: VecDeque<TimeEntry>,
    known_salts: HashSet<Box<[u8]>>,
    timeout_secs: u64,
}

impl TimedSaltChecker {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            last_salts: VecDeque::with_capacity(2000),
            known_salts: HashSet::with_capacity(2000),
            timeout_secs,
        }
    }
}

impl SaltChecker for TimedSaltChecker {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool {
        while let Some(time_entry) = self.last_salts.front() {
            if time_entry.instant.elapsed().as_secs() < self.timeout_secs {
                break;
            }
            self.known_salts.remove(&time_entry.salt);
            self.last_salts.pop_front();
        }

        if self.known_salts.contains(salt) {
            return false;
        }

        self.known_salts.insert(salt.to_vec().into_boxed_slice());
        self.last_salts.push_back(TimeEntry {
            instant: Instant::now(),
            salt: salt.to_vec().into_boxed_slice(),
        });

        true
    }
}
