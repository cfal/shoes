use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MAX_CACHE_BYTES: usize = 1024 * 1024;
pub type ExplicitSelections = BTreeMap<String, String>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    selected: ExplicitSelections,
}

pub struct SelectionStore {
    path: PathBuf,
    lock: File,
    #[cfg(test)]
    pub(super) fail_at: Option<FailPoint>,
}

#[derive(Debug)]
pub struct SaveError {
    pub source: io::Error,
    pub replaced: bool,
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.replaced {
            write!(
                f,
                "cache replaced but durability is uncertain: {}",
                self.source
            )
        } else {
            write!(f, "selection cache was not replaced: {}", self.source)
        }
    }
}

impl std::error::Error for SaveError {}

pub fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let filename = path
        .file_name()
        .ok_or_else(|| invalid("cache path must name a file"))?;
    if filename.to_string_lossy().ends_with(".lock") {
        return Err(invalid("the .lock suffix is reserved"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?.join(filename))
}

pub fn lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("validated file path")
        .to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

fn private_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("selection cache and lock must be regular files"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid(
                "selection cache and lock must be owned by the current user with private permissions",
            ));
        }
    }
    Ok(())
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}

pub fn encoded(selections: &ExplicitSelections) -> io::Result<Vec<u8>> {
    if selections
        .iter()
        .any(|(group, member)| !valid_name(group) || !valid_name(member))
    {
        return Err(invalid("invalid selector identity in selection cache"));
    }
    let bytes = serde_json::to_vec(&Snapshot {
        version: 1,
        selected: selections.clone(),
    })
    .map_err(io::Error::other)?;
    if bytes.len() > MAX_CACHE_BYTES {
        return Err(invalid("selection cache exceeds 1 MiB"));
    }
    Ok(bytes)
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}

impl SelectionStore {
    pub fn open(path: &Path) -> io::Result<(Self, ExplicitSelections)> {
        let path = absolute_path(path)?;
        for target in [&path, &lock_path(&path)] {
            match std::fs::symlink_metadata(target) {
                Ok(metadata) if !metadata.file_type().is_file() => {
                    return Err(invalid("selection cache and lock must be regular files"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let lock = private_options()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path(&path))?;
        private_file(&lock)?;
        lock.try_lock().map_err(|error| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("selection cache already owned: {error}"),
            )
        })?;
        let store = Self {
            path,
            lock,
            #[cfg(test)]
            fail_at: None,
        };
        let selected = match private_options().read(true).open(&store.path) {
            Ok(file) => {
                private_file(&file)?;
                let mut bytes = Vec::new();
                file.take((MAX_CACHE_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_CACHE_BYTES {
                    return Err(invalid("selection cache exceeds 1 MiB"));
                }
                let snapshot: Snapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("invalid selection cache JSON"))?;
                if snapshot.version != 1 {
                    return Err(invalid("unsupported selection cache version"));
                }
                encoded(&snapshot.selected)?;
                snapshot.selected
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok((store, selected))
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&mut self, selected: &ExplicitSelections) -> Result<(), SaveError> {
        let mut replaced = false;
        let mut temporary = None;
        let result = (|| {
            let bytes = encoded(selected)?;
            match std::fs::symlink_metadata(&self.path) {
                Ok(metadata) if !metadata.file_type().is_file() => {
                    return Err(invalid("selection cache target is not a regular file"));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let temp = self.path.with_file_name(format!(
                ".{}.{}",
                self.path.file_name().unwrap().to_string_lossy(),
                rand::random::<u64>(),
            ));
            let mut file = private_options().write(true).create_new(true).open(&temp)?;
            temporary = Some(temp.clone());
            #[cfg(test)]
            self.fail(FailPoint::Write)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            #[cfg(test)]
            self.fail(FailPoint::Rename)?;
            std::fs::rename(&temp, &self.path)?;
            replaced = true;
            #[cfg(test)]
            self.fail(FailPoint::DirectorySync)?;
            #[cfg(unix)]
            File::open(self.path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if let Some(path) = temporary {
            let _ = std::fs::remove_file(path);
        }
        result.map_err(|source| SaveError { source, replaced })
    }

    #[cfg(test)]
    fn fail(&mut self, point: FailPoint) -> io::Result<()> {
        if self.fail_at == Some(point) {
            self.fail_at = None;
            Err(io::Error::other("injected selection cache failure"))
        } else {
            Ok(())
        }
    }
}

impl Drop for SelectionStore {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FailPoint {
    Write,
    Rename,
    DirectorySync,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices(value: &str) -> ExplicitSelections {
        BTreeMap::from([("outbound".into(), value.into())])
    }

    #[cfg(unix)]
    #[test]
    fn fifo_cache_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(SelectionStore::open(&path).is_err());
    }

    #[test]
    fn saves_explicit_choices_without_startup_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let (mut store, selected) = SelectionStore::open(&path).unwrap();
        assert!(selected.is_empty());
        assert!(!path.exists());
        assert!(SelectionStore::open(&path).is_err());
        store.save(&choices("east")).unwrap();
        let before = std::fs::read(&path).unwrap();
        drop(store);
        let (store, selected) = SelectionStore::open(&path).unwrap();
        assert_eq!(selected, choices("east"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(store.path(), path);
    }

    #[test]
    fn save_failures_distinguish_replacement_and_allow_retry() {
        for fault in [
            FailPoint::Write,
            FailPoint::Rename,
            FailPoint::DirectorySync,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("cache.db");
            let (mut store, _) = SelectionStore::open(&path).unwrap();
            store.save(&choices("east")).unwrap();
            store.fail_at = Some(fault);
            let error = store.save(&choices("west")).unwrap_err();
            assert_eq!(error.replaced, fault == FailPoint::DirectorySync);
            assert_eq!(error.to_string().contains("uncertain"), error.replaced);
            let disk: Snapshot = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(
                disk.selected,
                choices(if error.replaced { "west" } else { "east" })
            );
            store.save(&choices("east")).unwrap();
            drop(store);
            let (_, selected) = SelectionStore::open(&path).unwrap();
            assert_eq!(selected, choices("east"));
        }
    }

    #[test]
    fn invalid_cache_is_not_overwritten() {
        for bytes in [b"not-json".as_slice(), br#"{"version":2,"selected":{}}"#] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("cache.db");
            let mut file = private_options()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(bytes).unwrap();
            drop(file);
            assert!(SelectionStore::open(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn write_limit_matches_restore_limit() {
        let value = "\\\"".repeat(100);
        let empty_size = encoded(&BTreeMap::new()).unwrap().len();
        let entry_size = serde_json::to_vec(&("group-00000", &value)).unwrap().len() - 1;
        let count = (MAX_CACHE_BYTES - empty_size + 1) / entry_size;
        let mut selected: BTreeMap<_, _> = (0..count)
            .map(|index| (format!("group-{index:05}"), value.clone()))
            .collect();
        let last = encoded(&selected).unwrap();
        selected.insert(format!("group-{count:05}"), value);
        assert!(last.len() <= MAX_CACHE_BYTES);
        assert!(encoded(&selected).is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let (mut store, _) = SelectionStore::open(&path).unwrap();
        let valid: Snapshot = serde_json::from_slice(&last).unwrap();
        store.save(&valid.selected).unwrap();
        assert!(store.save(&selected).is_err());
        drop(store);
        let (_, restored) = SelectionStore::open(&path).unwrap();
        assert_eq!(restored, valid.selected);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_targets_and_locks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let target = directory.path().join("target");
        symlink(&target, &path).unwrap();
        assert!(SelectionStore::open(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(!lock_path(&path).exists());
        symlink(&target, lock_path(&path)).unwrap();
        assert!(SelectionStore::open(&path).is_err());
        assert!(!target.exists());
    }
}
