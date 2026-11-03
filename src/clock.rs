use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

static CURRENT: RwLock<Option<Arc<Publication>>> = RwLock::new(None);

#[derive(Debug, Default)]
pub(crate) struct Clock {
    offset_micros: AtomicI64,
}

impl Clock {
    fn at(&self, raw: SystemTime) -> io::Result<SystemTime> {
        apply(raw, self.offset_micros.load(Ordering::Relaxed))
    }

    pub(crate) fn set_offset(&self, offset_micros: i64) -> io::Result<()> {
        apply(SystemTime::now(), offset_micros)?
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(io::Error::other)?;
        self.offset_micros.store(offset_micros, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn copy_offset_from(&self, previous: &Self) {
        self.offset_micros.store(
            previous.offset_micros.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
}

fn apply(raw: SystemTime, offset_micros: i64) -> io::Result<SystemTime> {
    let duration = Duration::from_micros(offset_micros.unsigned_abs());
    let corrected = if offset_micros < 0 {
        raw.checked_sub(duration)
    } else {
        raw.checked_add(duration)
    };
    corrected.ok_or_else(|| io::Error::other("application clock is out of range"))
}

pub(crate) fn now() -> io::Result<SystemTime> {
    let raw = SystemTime::now();
    match CURRENT.read().as_ref() {
        Some(current) => current.clock.at(raw),
        None => Ok(raw),
    }
}

pub(crate) fn unix_seconds() -> io::Result<u64> {
    Ok(now()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}

struct Publication {
    clock: Arc<Clock>,
}

pub(crate) struct Published(Arc<Publication>);

impl Drop for Published {
    fn drop(&mut self) {
        let mut current = CURRENT.write();
        if current
            .as_ref()
            .is_some_and(|value| Arc::ptr_eq(value, &self.0))
        {
            *current = None;
        }
    }
}

pub(crate) fn publish(clock: Arc<Clock>) -> Published {
    // Publication identity differs from clock identity when reload reuses a sample.
    let publication = Arc::new(Publication { clock });
    *CURRENT.write() = Some(publication.clone());
    Published(publication)
}

#[derive(Debug)]
struct ApplicationTime;

impl TimeProvider for ApplicationTime {
    fn current_time(&self) -> Option<UnixTime> {
        let duration = now().ok()?.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        Some(UnixTime::since_unix_epoch(duration))
    }
}

pub(crate) fn time_provider() -> Arc<dyn TimeProvider> {
    Arc::new(ApplicationTime)
}

#[cfg(test)]
pub(crate) fn test_offset(offset_micros: i64) -> Published {
    let clock = Arc::new(Clock::default());
    clock.set_offset(offset_micros).unwrap();
    publish(clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_correction_and_epoch_boundaries() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(apply(epoch, 0).unwrap(), epoch);
        assert_eq!(apply(epoch, 1).unwrap(), epoch + Duration::from_micros(1));
        assert_eq!(apply(epoch, -1).unwrap(), epoch - Duration::from_micros(1));
        let clock = Clock::default();
        clock.offset_micros.store(-1, Ordering::Relaxed);
        assert!(clock.at(epoch).unwrap().duration_since(epoch).is_err());
        assert_eq!(
            apply(epoch + Duration::from_secs(1), -1_000_000).unwrap(),
            epoch
        );
        assert!(clock.set_offset(i64::MIN).is_err());
        assert_eq!(clock.at(epoch).unwrap(), epoch - Duration::from_micros(1));
        if let Some(limit) = epoch.checked_add(Duration::new(i64::MAX as u64, 999_999_999)) {
            assert!(apply(limit, 1).is_err());
        }
    }

    #[test]
    fn publication_updates_existing_providers_and_preserves_ownership() {
        const CHILD: &str = "SHOES_CLOCK_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            shoes_test_support::isolated::run_isolated(
                "clock::tests::publication_updates_existing_providers_and_preserves_ownership",
                CHILD,
                "1",
            );
            return;
        }
        let provider = time_provider();
        let raw = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = Arc::new(Clock::default());
        clock.set_offset(600_000_000).unwrap();
        let old = publish(clock.clone());
        assert!(
            provider
                .current_time()
                .unwrap()
                .as_secs()
                .abs_diff(raw + 600)
                <= 1
        );
        let new = publish(clock.clone());
        drop(old);
        assert!(unix_seconds().unwrap().abs_diff(raw + 600) <= 1);
        clock.set_offset(-600_000_000).unwrap();
        assert!(
            provider
                .current_time()
                .unwrap()
                .as_secs()
                .abs_diff(raw - 600)
                <= 1
        );
        let replacement = test_offset(1_200_000_000);
        clock.set_offset(3_600_000_000).unwrap();
        drop(new);
        assert!(unix_seconds().unwrap().abs_diff(raw + 1200) <= 1);
        drop(replacement);
        assert!(unix_seconds().unwrap().abs_diff(raw) <= 1);
    }
}
