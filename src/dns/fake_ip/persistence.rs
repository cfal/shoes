use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Entry, Range, State, canonical_hostname, invalid};

const RESERVATION_SIZE: u128 = 256;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const SNAPSHOT_ENTRY_BYTES: usize = 700;
const SNAPSHOT_BASE_BYTES: usize = 4096;
pub(super) const MAX_PERSISTENT_ENTRIES: usize =
    (MAX_SNAPSHOT_BYTES - SNAPSHOT_BASE_BYTES) / SNAPSHOT_ENTRY_BYTES;

#[derive(Debug)]
pub(super) struct SnapshotStore {
    path: PathBuf,
    _lock: File,
    pub(super) serial: parking_lot::Mutex<()>,
}

impl Drop for SnapshotStore {
    fn drop(&mut self) {
        // A concurrent fork can retain the open-file description until exec.
        let _ = self._lock.unlock();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    version: u32,
    owner: String,
    ipv4_range: Option<String>,
    ipv6_range: Option<String>,
    max_entries: usize,
    cursor_v4: Option<IpAddr>,
    cursor_v6: Option<IpAddr>,
    entries: Vec<(String, Entry)>,
}

fn cursor(range: &Option<Range>) -> Option<IpAddr> {
    range.clone().map(|mut range| range.take())
}

impl Snapshot {
    pub(super) fn from_state(state: &State) -> Self {
        let mut snapshot = Self {
            version: 2,
            owner: state.owner.clone(),
            ipv4_range: state.v4.as_ref().map(|range| range.network.to_string()),
            ipv6_range: state.v6.as_ref().map(|range| range.network.to_string()),
            max_entries: state.forward.cap().get(),
            cursor_v4: cursor(&state.v4),
            cursor_v6: cursor(&state.v6),
            entries: state
                .forward
                .iter()
                .rev()
                .map(|(name, entry)| (name.clone(), entry.clone()))
                .collect(),
        };
        for (range, count) in [
            (&state.v4, state.v4_reserved),
            (&state.v6, state.v6_reserved),
        ] {
            if let Some(range) = range {
                snapshot.reserve(range.clone(), count);
            }
        }
        snapshot
    }

    fn reserve(&mut self, mut range: Range, count: usize) {
        let reserved: HashSet<IpAddr> = (0..count).map(|_| range.take()).collect();
        if range.network.is_ipv6() {
            self.cursor_v6 = cursor(&Some(range));
        } else {
            self.cursor_v4 = cursor(&Some(range));
        }
        // Persisted old owners must disappear before their addresses can be reused.
        for (_, entry) in &mut self.entries {
            if entry.v4.is_some_and(|ip| reserved.contains(&ip)) {
                entry.v4 = None;
            }
            if entry.v6.is_some_and(|ip| reserved.contains(&ip)) {
                entry.v6 = None;
            }
        }
        self.entries
            .retain(|(_, entry)| entry.v4.is_some() || entry.v6.is_some());
    }

    fn restore(self, state: &mut State) -> io::Result<()> {
        let expected = Self::from_state(state);
        if self.version != 2
            || self.owner != expected.owner
            || self.ipv4_range != expected.ipv4_range
            || self.ipv6_range != expected.ipv6_range
            || self.max_entries != expected.max_entries
            || self.entries.len() > self.max_entries
        {
            return Err(invalid(
                "incompatible fake DNS snapshot; explicit state migration/reset required",
            ));
        }
        for (range, next) in [
            (&mut state.v4, self.cursor_v4),
            (&mut state.v6, self.cursor_v6),
        ] {
            match (range, next) {
                (Some(range), Some(ip)) if allocatable(range, ip) => range.cursor = numeric(ip),
                (None, None) => (),
                _ => return Err(invalid("invalid fake DNS snapshot cursor")),
            }
        }
        for (name, entry) in self.entries {
            if canonical_hostname(&name).as_deref() != Some(&name)
                || state.forward.contains(&name)
                || (entry.v4.is_none() && entry.v6.is_none())
            {
                return Err(invalid("invalid fake DNS snapshot domain"));
            }
            for (ip, range) in [(entry.v4, &state.v4), (entry.v6, &state.v6)] {
                if let Some(ip) = ip
                    && (!range.as_ref().is_some_and(|range| allocatable(range, ip))
                        || state.reverse.insert(ip, name.clone()).is_some())
                {
                    return Err(invalid("invalid or duplicated fake DNS snapshot address"));
                }
            }
            state.forward.put(name, entry);
        }
        Ok(())
    }
}

fn numeric(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ip) => u32::from(ip) as u128,
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn allocatable(range: &Range, ip: IpAddr) -> bool {
    range.network.contains(ip) && numeric(ip) >= range.first && numeric(ip) <= range.last
}

fn state_path(path: &Path) -> io::Result<PathBuf> {
    // Resolve the parent only: atomic replacement and locking use this filename,
    // not the target of a snapshot-file symlink.
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let filename = path
        .file_name()
        .ok_or_else(|| invalid("invalid fake DNS state path"))?;
    Ok(parent.join(filename))
}

impl SnapshotStore {
    pub(super) fn matches_path(&self, path: &Path) -> io::Result<bool> {
        Ok(self.path == state_path(path)?)
    }

    pub(super) fn open(path: &Path, state: &mut State) -> io::Result<Self> {
        let limit = state
            .forward
            .cap()
            .get()
            .saturating_mul(SNAPSHOT_ENTRY_BYTES)
            .saturating_add(SNAPSHOT_BASE_BYTES)
            .saturating_add(
                serde_json::to_vec(&state.owner)
                    .map_err(invalid_json)?
                    .len(),
            );
        if limit > MAX_SNAPSHOT_BYTES {
            return Err(invalid(
                "fake DNS snapshot owner and capacity exceed size bound",
            ));
        }
        let limit = limit as u64;
        let path = state_path(path)?;
        let lock_path = path.with_file_name(format!(
            "{}.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock().map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("fake DNS state already owned: {error}"),
            )
        })?;
        let store = Self {
            path,
            _lock: lock,
            serial: parking_lot::Mutex::new(()),
        };
        match File::open(&store.path) {
            Ok(file) => {
                if file.metadata()?.len() > limit {
                    return Err(invalid("fake DNS snapshot exceeds configured bound"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if file.metadata()?.permissions().mode() & 0o077 != 0 {
                        return Err(invalid(
                            "fake DNS snapshot must have private permissions (0600)",
                        ));
                    }
                }
                let snapshot: Snapshot =
                    serde_json::from_reader(BufReader::new(file.take(limit + 1)))
                        .map_err(invalid_json)?;
                snapshot.restore(state)?;
                state.checkpoint_revision = Some(state.revision);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        Ok(store)
    }

    pub(super) fn reservation(&self, state: &State, ipv6: bool) -> io::Result<(Snapshot, usize)> {
        let range = if ipv6 {
            state.v6.clone()
        } else {
            state.v4.clone()
        }
        .ok_or_else(|| invalid("fake IP family disabled"))?;
        let capacity = range.last - range.first + 1;
        let count = RESERVATION_SIZE.min(capacity / 2) as usize;
        let mut snapshot = Snapshot::from_state(state);
        snapshot.reserve(range, count);
        Ok((snapshot, count))
    }

    pub(super) fn write(&self, snapshot: &Snapshot) -> io::Result<()> {
        let path = self.path.with_file_name(format!(
            ".{}.{}",
            self.path.file_name().unwrap().to_string_lossy(),
            rand::random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        let result = (|| {
            let mut writer = BufWriter::new(&mut file);
            serde_json::to_writer(&mut writer, snapshot).map_err(invalid_json)?;
            writer.flush()?;
            drop(writer);
            file.sync_all()?;
            std::fs::rename(&path, &self.path)?;
            #[cfg(unix)]
            File::open(self.path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(path);
        }
        result
    }
}

fn invalid_json(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::super::FakeIpPool;
    use super::*;
    use crate::dns::fake_ip::FakeIpOptions;

    fn options(path: &Path) -> FakeIpOptions {
        FakeIpOptions {
            state_file: Some(path.to_path_buf()),
            ipv6_range: Some("2001:2::/112".into()),
            ..Default::default()
        }
    }

    #[test]
    fn owner_drop_releases_lock_despite_an_inherited_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let options = options(&directory.path().join("state.json"));
        let pool = FakeIpPool::new(&options).unwrap();
        let inherited = pool.store.as_ref().unwrap()._lock.try_clone().unwrap();
        assert!(FakeIpPool::new(&options).is_err());
        drop(pool);
        let replacement = FakeIpPool::new(&options).unwrap();
        drop(inherited);
        assert!(FakeIpPool::new(&options).is_err());
        drop(replacement);
        assert!(FakeIpPool::new(&options).is_ok());
    }

    #[test]
    fn long_snapshot_owner_can_reopen_after_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let options = FakeIpOptions {
            max_entries: 1,
            ..options(&directory.path().join("state.json"))
        };
        let owner = "a\n\"".repeat(4096);
        let pool = FakeIpPool::new_scoped(&options, &owner).unwrap();
        let ip = pool.allocate("a.test", false).unwrap();
        pool.checkpoint().unwrap();
        drop(pool);
        let pool = FakeIpPool::new_scoped(&options, &owner).unwrap();
        assert_eq!(pool.restore(ip).unwrap().as_deref(), Some("a.test"));
    }

    #[test]
    fn snapshot_owner_and_capacity_must_fit_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let options = FakeIpOptions {
            ipv4_range: Some("198.0.0.0/8".into()),
            max_entries: MAX_PERSISTENT_ENTRIES,
            ..options(&path)
        };
        let error = FakeIpPool::new_scoped(&options, &"a".repeat(8192)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("owner and capacity exceed size bound")
        );
        assert!(!path.exists());
    }

    #[test]
    fn unchanged_checkpoint_does_not_rewrite_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let options = options(&path);
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        pool.allocate("a.test", false).unwrap();
        pool.checkpoint().unwrap();
        let old_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        pool.checkpoint().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            old_time
        );
        drop(pool);
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        pool.checkpoint().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            old_time
        );
        pool.allocate("b.test", false).unwrap();
        pool.checkpoint().unwrap();
        assert_ne!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            old_time
        );
        let snapshot: Snapshot = serde_json::from_reader(File::open(path).unwrap()).unwrap();
        assert!(snapshot.entries.iter().any(|(name, _)| name == "b.test"));
    }

    #[test]
    fn cache_hits_and_restores_checkpoint_lru_order() {
        for restore in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("state.json");
            let mut options = options(&path);
            options.max_entries = 2;
            let pool = FakeIpPool::with_seed(&options, 0).unwrap();
            let first = pool.allocate("first.test", false).unwrap();
            let second = pool.allocate("second.test", false).unwrap();
            pool.checkpoint().unwrap();
            if restore {
                assert_eq!(pool.restore(first).unwrap().as_deref(), Some("first.test"));
            } else {
                assert_eq!(pool.allocate("first.test", false).unwrap(), first);
            }
            pool.checkpoint().unwrap();
            drop(pool);
            let pool = FakeIpPool::with_seed(&options, 0).unwrap();
            pool.allocate("third.test", false).unwrap();
            assert!(pool.restore(second).is_err());
            assert_eq!(pool.restore(first).unwrap().as_deref(), Some("first.test"));
        }
    }

    #[test]
    fn failed_checkpoint_keeps_changes_pending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let options = options(&path);
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        pool.allocate("first.test", false).unwrap();
        pool.checkpoint().unwrap();
        let second = pool.allocate("second.test", false).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(pool.checkpoint().is_err());
        std::fs::remove_dir(&path).unwrap();
        pool.checkpoint().unwrap();
        drop(pool);
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        assert_eq!(
            pool.restore(second).unwrap().as_deref(),
            Some("second.test")
        );
    }

    #[test]
    fn checkpoint_restores_dual_family_maps_and_reserved_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let options = options(&directory.path().join("state.json"));
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        let v4 = pool.allocate("a.test", false).unwrap();
        let v6 = pool.allocate("a.test", true).unwrap();
        pool.checkpoint().unwrap();
        drop(pool);
        let pool = FakeIpPool::new(&options).unwrap();
        assert_eq!(pool.restore(v4).unwrap().as_deref(), Some("a.test"));
        assert_eq!(pool.restore(v6).unwrap().as_deref(), Some("a.test"));
        assert_eq!(
            pool.allocate("b.test", false).unwrap().to_string(),
            "198.18.1.2"
        );
        assert_eq!(
            pool.allocate("b.test", true).unwrap().to_string(),
            "2001:2::102"
        );
    }

    #[test]
    fn crash_skips_uncheckpointed_batch_and_second_family_cannot_erase_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let options = options(&directory.path().join("state.json"));
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        let v4 = pool.allocate("a.test", false).unwrap();
        pool.allocate("a.test", true).unwrap();
        let later = pool.allocate("b.test", false).unwrap();
        drop(pool);
        let pool = FakeIpPool::new(&options).unwrap();
        assert_eq!(pool.restore(v4).unwrap().as_deref(), Some("a.test"));
        assert_eq!(
            pool.restore(later).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            pool.allocate("after.test", false).unwrap().to_string(),
            "198.18.1.2"
        );
    }

    #[test]
    fn wrap_reservation_invalidates_persisted_old_owners() {
        let directory = tempfile::tempdir().unwrap();
        let options = FakeIpOptions {
            ipv4_range: Some("198.18.0.0/29".into()),
            ipv6_range: None,
            max_entries: 5,
            ..options(&directory.path().join("state.json"))
        };
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        let first = pool.allocate("a.test", false).unwrap();
        for i in 0..4 {
            pool.allocate(&format!("n{i}.test"), false).unwrap();
        }
        pool.checkpoint().unwrap();
        assert_eq!(pool.allocate("reused.test", false).unwrap(), first);
        drop(pool);
        let pool = FakeIpPool::new(&options).unwrap();
        assert_eq!(
            pool.restore(first).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn rejects_double_owner_corruption_and_incompatible_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut options = options(&path);
        let pool = FakeIpPool::new(&options).unwrap();
        assert!(FakeIpPool::new(&options).is_err());
        pool.checkpoint().unwrap();
        drop(pool);
        options.max_entries -= 1;
        assert!(FakeIpPool::new(&options).is_err());
        std::fs::write(&path, b"{}").unwrap();
        assert!(FakeIpPool::new(&options).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    }

    #[test]
    fn state_files_cannot_use_reserved_lock_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let original = options(&directory.path().join("state.json"));
        for name in [
            "state.json.lock",
            "state.json.LOCK",
            ".lock",
            "state.lock.lock",
        ] {
            let path = directory.path().join(name);
            let colliding = options(&path);
            for error in [
                FakeIpPool::validate(&colliding).unwrap_err(),
                FakeIpPool::new(&colliding).unwrap_err(),
            ] {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(error.to_string().contains("suffix .lock is reserved"));
            }
            assert!(!path.exists());
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        let _original_pool = FakeIpPool::new(&original).unwrap();
        assert!(FakeIpPool::new(&original).is_err());
    }

    #[test]
    fn preparation_is_nonwriting_and_snapshot_owner_is_checked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let options = options(&path);
        let pool = FakeIpPool::new_scoped(&options, "owner-a").unwrap();
        assert!(!path.exists());
        pool.checkpoint().unwrap();
        drop(pool);
        assert!(FakeIpPool::new_scoped(&options, "owner-b").is_err());
        assert!(FakeIpPool::new_scoped(&options, "owner-a").is_ok());
    }

    #[test]
    fn small_persistent_ranges_skip_instead_of_reserving_a_full_cycle() {
        for prefix in [24, 25, 26, 27, 28, 29] {
            let directory = tempfile::tempdir().unwrap();
            let options = FakeIpOptions {
                ipv4_range: Some(format!("198.18.0.0/{prefix}")),
                ipv6_range: None,
                max_entries: 1,
                ..options(&directory.path().join("state.json"))
            };
            let pool = FakeIpPool::with_seed(&options, 0).unwrap();
            let first = pool.allocate("first.test", false).unwrap();
            drop(pool);
            let pool = FakeIpPool::new(&options).unwrap();
            assert_ne!(pool.allocate("second.test", false).unwrap(), first);
        }
        let directory = tempfile::tempdir().unwrap();
        let options = FakeIpOptions {
            ipv4_range: Some("198.18.0.0/30".into()),
            ipv6_range: None,
            max_entries: 1,
            ..options(&directory.path().join("one.json"))
        };
        assert!(FakeIpPool::new(&options).is_err());
    }

    #[test]
    fn restart_after_a_full_window_does_not_immediately_recycle_recent_answers() {
        for prefix in [24, 25, 26, 27, 28, 29] {
            for clean in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let options = FakeIpOptions {
                    ipv4_range: Some(format!("198.18.0.0/{prefix}")),
                    ipv6_range: None,
                    max_entries: (1usize << (32 - prefix)) - 3,
                    ..options(&directory.path().join("state.json"))
                };
                let pool = FakeIpPool::with_seed(&options, 0).unwrap();
                let count = ((1usize << (32 - prefix)) - 3) / 2;
                let issued: Vec<_> = (0..=count)
                    .map(|i| pool.allocate(&format!("n{i}.test"), false).unwrap())
                    .collect();
                if clean {
                    pool.shutdown_checkpoint().unwrap();
                }
                drop(pool);
                let pool = FakeIpPool::new(&options).unwrap();
                let next = pool.allocate("after.test", false).unwrap();
                assert!(!issued.iter().rev().take(count).any(|ip| *ip == next));
                if clean {
                    let IpAddr::V4(previous) = issued.last().unwrap() else {
                        panic!()
                    };
                    assert_eq!(next, IpAddr::V4((u32::from(*previous) + 1).into()));
                }
            }
        }
    }

    #[test]
    fn alternating_families_keep_both_reservations_and_shutdown_freezes_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let options = options(&path);
        let pool = FakeIpPool::with_seed(&options, 0).unwrap();
        pool.allocate("a.test", false).unwrap();
        pool.allocate("a.test", true).unwrap();
        let saved = std::fs::read(&path).unwrap();
        for i in 0..10 {
            pool.allocate(&format!("b{i}.test"), false).unwrap();
            pool.allocate(&format!("b{i}.test"), true).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        pool.shutdown_checkpoint().unwrap();
        assert!(pool.allocate("a.test", false).is_err());
        assert!(pool.allocate("after.test", true).is_err());
    }
}
