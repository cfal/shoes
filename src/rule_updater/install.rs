use super::MAX_BYTES;
use crate::rule_set::{CACHE_LOCK_SUFFIX, CACHE_STAGE_SUFFIX};
use crate::rules::invalid;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub(crate) fn cache_file(path: &Path) -> io::Result<File> {
    let (directory, name) = checked_path(path)?;
    let file = open_at(&directory, &c_name(&name)?, libc::O_RDONLY)?;
    check_file(&file.metadata()?, false)?;
    Ok(file)
}

pub(super) struct Install {
    path: PathBuf,
    directory: File,
    destination: CString,
    stage: CString,
    pub(super) file: File,
    lock: File,
    lock_name: CString,
    original: Option<Metadata>,
    old_digest: Option<blake3::Hash>,
    #[cfg(test)]
    preparation_gate: Option<PreparationGate>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Unchanged,
    Updated,
    DurabilityUncertain,
}

impl Outcome {
    pub(super) fn changed(&self) -> bool {
        !matches!(self, Self::Unchanged)
    }
}

impl Install {
    pub(super) async fn open_async(path: &Path) -> io::Result<Self> {
        let path = path.to_owned();
        blocking(move || Self::open(&path)).await
    }

    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let (directory, name) = checked_path(path)?;
        let path = crate::rule_set::source_identity(path)?;
        let mut lock_name = name.clone();
        lock_name.push(CACHE_LOCK_SUFFIX);
        let lock_name = c_name(&lock_name)?;
        let lock = open_at(&directory, &lock_name, libc::O_RDWR | libc::O_CREAT)?;
        check_file(&lock.metadata()?, true)?;
        lock.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "destination update already owned",
            )
        })?;
        let destination = c_name(&name)?;
        let (original, old_digest) = match open_at(&directory, &destination, libc::O_RDONLY) {
            Ok(mut old) => {
                let original = old.metadata()?;
                check_file(&original, false)?;
                let digest = if original.len() <= MAX_BYTES {
                    Some(hash(&mut old)?)
                } else {
                    None
                };
                if stamp(&original) != stamp(&old.metadata()?) {
                    return Err(invalid("destination changed while reading"));
                }
                (Some(original), digest)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(error),
        };
        let mut stage_name = name;
        stage_name.push(CACHE_STAGE_SUFFIX);
        let stage = c_name(&stage_name)?;
        match open_at(&directory, &stage, libc::O_RDONLY) {
            Ok(file) => {
                let metadata = file.metadata()?;
                check_file(&metadata, false)?;
                let destination_mode = original.as_ref().map_or(0o600, MetadataExt::mode);
                let excess_permissions = metadata.mode() & 0o077 & !destination_mode;
                if excess_permissions != 0 {
                    return Err(invalid(
                        "stale staging permissions exceed destination permissions",
                    ));
                }
                // Reserved sidecar, left by an uncatchable termination. Lock is held.
                unlink_at(&directory, &stage)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let file = open_at(
            &directory,
            &stage,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )?;
        Ok(Self {
            path,
            directory,
            destination,
            stage,
            file,
            lock,
            lock_name,
            original,
            old_digest,
            #[cfg(test)]
            preparation_gate: None,
        })
    }

    pub(super) async fn check_unchanged(self, digest: blake3::Hash) -> io::Result<(Self, bool)> {
        blocking(move || {
            let unchanged = self.unchanged(digest)?;
            Ok((self, unchanged))
        })
        .await
    }

    pub(super) async fn finish_async(self, digest: blake3::Hash) -> io::Result<Outcome> {
        let (install, unchanged) = blocking(move || {
            let unchanged = self.prepare_finish(digest)?;
            Ok((self, unchanged))
        })
        .await?;
        if unchanged {
            return Ok(Outcome::Unchanged);
        }
        // Only the owning future can publish. A cancelled blocking preparation
        // drops Install without renaming, even if its filesystem work finishes later.
        install.publish()?;
        blocking(move || Ok(install.sync_published())).await
    }

    #[cfg(test)]
    pub(super) fn finish(&mut self, digest: blake3::Hash) -> io::Result<Outcome> {
        if self.prepare_finish(digest)? {
            return Ok(Outcome::Unchanged);
        }
        self.publish()?;
        Ok(self.sync_published())
    }

    fn prepare_finish(&self, digest: blake3::Hash) -> io::Result<bool> {
        if self.unchanged(digest)? {
            return Ok(true);
        }
        self.file.set_permissions(std::fs::Permissions::from_mode(
            self.original.as_ref().map_or(0o600, MetadataExt::mode) & 0o777,
        ))?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        #[cfg(test)]
        if let Some(gate) = &self.preparation_gate {
            gate.entered.notify_one();
            gate.release
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        Ok(false)
    }

    fn publish(&self) -> io::Result<()> {
        self.check_ownership()?;
        #[cfg(test)]
        self.fail_before_rename()?;
        let fd = self.directory.as_raw_fd();
        crate::file_watcher::managed::publish(&self.path, &self.file.metadata()?, || {
            if unsafe { libc::renameat(fd, self.stage.as_ptr(), fd, self.destination.as_ptr()) }
                != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }

    fn sync_published(&self) -> Outcome {
        let sync = self.directory.sync_all();
        #[cfg(test)]
        let sync = if FAIL_AFTER_RENAME.with(|flag| flag.replace(false)) {
            Err(io::Error::other("injected directory sync failure"))
        } else {
            sync
        };
        if sync.is_err() {
            log::warn!(
                "Validated rule file replaced, but directory sync failed; durability uncertain"
            );
            return Outcome::DurabilityUncertain;
        }
        Outcome::Updated
    }

    pub(super) fn unchanged(&self, digest: blake3::Hash) -> io::Result<bool> {
        self.check_ownership()?;
        Ok(Some(digest) == self.old_digest)
    }

    fn check_ownership(&self) -> io::Result<()> {
        check_directory(&self.directory.metadata()?)?;
        match open_at(&self.directory, &self.destination, libc::O_RDONLY) {
            Ok(file) => {
                let current = file.metadata()?;
                check_file(&current, false)?;
                if Some(stamp(&current)) != self.original.as_ref().map(stamp) {
                    return Err(invalid(
                        "destination changed during update; not replacing it",
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && self.original.is_none() => {}
            Err(error) => return Err(error),
        }
        for (name, file) in [(&self.lock_name, &self.lock), (&self.stage, &self.file)] {
            let current = open_at(&self.directory, name, libc::O_RDONLY)?.metadata()?;
            check_file(&current, false)?;
            if stamp(&current) != stamp(&file.metadata()?) {
                return Err(invalid("update sidecar replaced during update"));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_before_rename(&self) -> io::Result<()> {
        if FAIL_RENAME.with(|flag| flag.replace(false)) {
            return Err(io::Error::other("injected rename failure"));
        }
        Ok(())
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)?
}

impl Drop for Install {
    fn drop(&mut self) {
        if let Ok(current) = open_at(&self.directory, &self.stage, libc::O_RDONLY)
            && let (Ok(current), Ok(owned)) = (current.metadata(), self.file.metadata())
            && (current.dev(), current.ino()) == (owned.dev(), owned.ino())
        {
            let _ = unlink_at(&self.directory, &self.stage);
        }
    }
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| invalid("path contains NUL"))
}

fn open_at(directory: &File, name: &CString, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unlink_at(directory: &File, name: &CString) -> io::Result<()> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn check_file(metadata: &Metadata, private: bool) -> io::Result<()> {
    let forbidden_mode = if private { 0o7077 } else { 0o7022 };
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & forbidden_mode != 0
    {
        return Err(invalid(
            "file must be owned, regular, singly linked, not group- or world-writable, and have no special mode bits; sidecars must be private",
        ));
    }
    Ok(())
}

fn checked_path(path: &Path) -> io::Result<(File, std::ffi::OsString)> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("parent traversal is not allowed"));
    }
    let path = std::path::absolute(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("destination must name a file"))?
        .to_string_lossy();
    if name.ends_with(CACHE_LOCK_SUFFIX) || name.ends_with(CACHE_STAGE_SUFFIX) {
        return Err(invalid("updater sidecar suffixes are reserved"));
    }
    let parent = path.parent().unwrap();
    let mut directory = File::open("/")?;
    for component in parent.components() {
        if let Component::Normal(name) = component {
            directory = open_at(
                &directory,
                &c_name(name)?,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
        }
    }
    check_directory(&directory.metadata()?)?;
    Ok((directory, path.file_name().unwrap().to_os_string()))
}

fn check_directory(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "destination directory must be owned by current user and not group- or world-writable",
        ));
    }
    Ok(())
}

fn stamp(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn hash(file: &mut File) -> io::Result<blake3::Hash> {
    if file.metadata()?.len() > MAX_BYTES {
        return Err(invalid("existing rule file exceeds 64 MiB"));
    }
    let mut digest = blake3::Hasher::new();
    let mut reader = file.take(MAX_BYTES + 1);
    let mut bytes = 0;
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > MAX_BYTES {
            return Err(invalid("existing rule file exceeds 64 MiB"));
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize())
}

#[cfg(test)]
thread_local! { pub(super) static FAIL_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { pub(super) static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[cfg(test)]
struct PreparationGate {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    dropped: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl Drop for PreparationGate {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_blocking_preparation_cannot_publish_or_stall_the_runtime() {
        let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut install = Install::open_async(&path).await.unwrap();
        install.file.write_all(b"new").unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(tokio::sync::Notify::new());
        let (release, receiver) = std::sync::mpsc::channel();
        install.preparation_gate = Some(PreparationGate {
            entered: entered.clone(),
            release: std::sync::Mutex::new(receiver),
            dropped: dropped.clone(),
        });
        let task = tokio::spawn(install.finish_async(blake3::hash(b"new")));
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        // The current-thread executor must remain usable while the worker is blocked.
        assert_eq!(tokio::spawn(async { 42 }).await.unwrap(), 42);
        assert_eq!(
            Install::open(&path).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), dropped.notified())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        assert!(!dir.path().join("rules.json.shoes-update.tmp").exists());
        drop(Install::open(&path).unwrap());
    }
}
