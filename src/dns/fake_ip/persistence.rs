use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Entry, Range, State, canonical_hostname, invalid};

const RESERVATION_SIZE: u128 = 256;

#[derive(Debug)]
pub(super) struct SnapshotStore {
    path: PathBuf,
    _lock: File,
    pub(super) serial: parking_lot::Mutex<()>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    version: u32,
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
        Self {
            version: 1,
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
        }
    }

    fn restore(self, state: &mut State) -> io::Result<()> {
        let expected = Self::from_state(state);
        if self.version != 1
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
                if let Some(ip) = ip {
                    if !range.as_ref().is_some_and(|range| allocatable(range, ip))
                        || state.reverse.insert(ip, name.clone()).is_some()
                    {
                        return Err(invalid("invalid or duplicated fake DNS snapshot address"));
                    }
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

impl SnapshotStore {
    pub(super) fn open(path: &Path, state: &mut State) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = parent.canonicalize()?.join(
            path.file_name()
                .ok_or_else(|| invalid("invalid fake DNS state path"))?,
        );
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
                let limit = state
                    .forward
                    .cap()
                    .get()
                    .saturating_mul(700)
                    .saturating_add(4096)
                    .min(256 * 1024 * 1024) as u64;
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
                    serde_json::from_reader(file.take(limit + 1)).map_err(invalid_json)?;
                snapshot.restore(state)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => store.checkpoint(state)?,
            Err(error) => return Err(error),
        }
        Ok(store)
    }

    pub(super) fn reservation(&self, state: &State, ipv6: bool) -> io::Result<(Snapshot, usize)> {
        let mut range = if ipv6 {
            state.v6.clone()
        } else {
            state.v4.clone()
        }
        .ok_or_else(|| invalid("fake IP family disabled"))?;
        let count = RESERVATION_SIZE.min(range.last - range.first + 1) as usize;
        let reserved: HashSet<IpAddr> = (0..count).map(|_| range.take()).collect();
        let mut snapshot = Snapshot::from_state(state);
        if ipv6 {
            snapshot.cursor_v6 = cursor(&Some(range));
        } else {
            snapshot.cursor_v4 = cursor(&Some(range));
        }
        // Before reuse, invalidate persisted old owners as well as reserving the cursor.
        for (_, entry) in &mut snapshot.entries {
            if entry.v4.is_some_and(|ip| reserved.contains(&ip)) {
                entry.v4 = None;
            }
            if entry.v6.is_some_and(|ip| reserved.contains(&ip)) {
                entry.v6 = None;
            }
        }
        snapshot
            .entries
            .retain(|(_, entry)| entry.v4.is_some() || entry.v6.is_some());
        Ok((snapshot, count))
    }

    pub(super) fn checkpoint(&self, state: &State) -> io::Result<()> {
        self.write(&Snapshot::from_state(state))
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
            serde_json::to_writer(&mut file, snapshot).map_err(invalid_json)?;
            file.flush()?;
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
    fn checkpoint_restores_dual_family_maps_and_exact_cursor() {
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
            "198.18.0.3"
        );
        assert_eq!(
            pool.allocate("b.test", true).unwrap().to_string(),
            "2001:2::3"
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
            "198.18.1.3"
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
        drop(pool);
        options.max_entries -= 1;
        assert!(FakeIpPool::new(&options).is_err());
        std::fs::write(&path, b"{}").unwrap();
        assert!(FakeIpPool::new(&options).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
    }
}
