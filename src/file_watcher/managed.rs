use std::collections::VecDeque;
use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_RECEIPTS: usize = 1024;
static INSTALLED: Mutex<VecDeque<(PathBuf, Stamp)>> = Mutex::new(VecDeque::new());

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    mode: u32,
    owner: (u32, u32),
    links: u64,
}

impl From<&Metadata> for Stamp {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            mode: metadata.mode(),
            owner: (metadata.uid(), metadata.gid()),
            links: metadata.nlink(),
        }
    }
}

pub(crate) fn publish(
    path: &Path,
    metadata: &Metadata,
    rename: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    // Serialize callback inspection with rename and receipt insertion. No fsync
    // runs under this lock; a failed rename leaves the prior receipt intact.
    let mut installed = INSTALLED.lock().unwrap();
    rename()?;
    installed.retain(|(existing, _)| existing != path);
    installed.push_back((path.to_owned(), Stamp::from(metadata)));
    if installed.len() > MAX_RECEIPTS {
        installed.pop_front();
    }
    Ok(())
}

pub(super) fn is_installed_version(path: &Path) -> bool {
    let stamp = INSTALLED
        .lock()
        .unwrap()
        .iter()
        .find(|(installed, _)| installed == path)
        .map(|(_, stamp)| stamp.clone());
    stamp.is_some_and(|stamp| {
        // Do not follow links: external retargets and replacements must notify.
        // Rename changes ctime, so it is deliberately excluded from the receipt.
        std::fs::symlink_metadata(path).is_ok_and(|metadata| Stamp::from(&metadata) == stamp)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes, Permissions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Duration;

    #[tokio::test]
    async fn managed_renames_only_suppress_the_installed_version() {
        for external in ["replace", "touch", "chmod", "symlink", "delete", "config"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("cache.json");
            let stage = dir.path().join("stage");
            let config = dir.path().join("config.yaml");
            std::fs::write(&path, "old").unwrap();
            std::fs::write(&config, "config").unwrap();
            let (tx, mut changes) = tokio::sync::mpsc::channel(1);
            let _watcher = crate::file_watcher::watch(&[&path, &config], tx).unwrap();
            std::fs::write(&stage, "new").unwrap();
            publish(&path, &std::fs::metadata(&stage).unwrap(), || {
                std::fs::rename(&stage, &path)
            })
            .unwrap();
            assert!(is_installed_version(&path));
            assert!(
                tokio::time::timeout(Duration::from_millis(100), changes.recv())
                    .await
                    .is_err(),
                "managed {external}"
            );
            match external {
                "replace" => {
                    std::fs::write(&stage, "external").unwrap();
                    std::fs::rename(&stage, &path).unwrap();
                }
                "touch" => {
                    let file = File::open(&path).unwrap();
                    let modified =
                        file.metadata().unwrap().modified().unwrap() + Duration::from_secs(1);
                    file.set_times(FileTimes::new().set_modified(modified))
                        .unwrap();
                }
                "chmod" => std::fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap(),
                "symlink" => {
                    std::fs::remove_file(&path).unwrap();
                    symlink(&config, &path).unwrap();
                }
                "delete" => std::fs::remove_file(&path).unwrap(),
                "config" => std::fs::write(&config, "external").unwrap(),
                _ => unreachable!(),
            }
            if external != "config" {
                assert!(!is_installed_version(&path), "external {external}");
            }
            tokio::time::timeout(Duration::from_secs(3), changes.recv())
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn failed_rename_preserves_the_previous_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        std::fs::write(&path, "original").unwrap();
        publish(&path, &std::fs::metadata(&path).unwrap(), || Ok(())).unwrap();
        let stage = dir.path().join("stage");
        std::fs::write(&stage, "replacement").unwrap();
        assert!(
            publish(&path, &std::fs::metadata(&stage).unwrap(), || Err(
                io::Error::other("injected")
            ))
            .is_err()
        );
        assert!(is_installed_version(&path));
    }
}
