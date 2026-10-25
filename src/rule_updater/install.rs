use super::MAX_BYTES;
use crate::rule_set::{CACHE_LOCK_SUFFIX, CACHE_STAGE_SUFFIX};
use crate::rules::invalid;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

pub(crate) fn cache_file(path: &Path) -> io::Result<File> {
    let (directory, name) = checked_path(path)?;
    let file = open_at(&directory, &c_name(&name)?, libc::O_RDONLY)?;
    check_file(&file.metadata()?, false)?;
    Ok(file)
}

pub(super) struct Install {
    directory: File,
    destination: CString,
    stage: CString,
    pub(super) file: File,
    lock: File,
    lock_name: CString,
    original: Option<Metadata>,
    old_digest: Option<blake3::Hash>,
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
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let (directory, name) = checked_path(path)?;
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
            directory,
            destination,
            stage,
            file,
            lock,
            lock_name,
            original,
            old_digest,
        })
    }

    pub(super) fn finish(&mut self, digest: blake3::Hash) -> io::Result<Outcome> {
        if self.unchanged(digest)? {
            return Ok(Outcome::Unchanged);
        }
        self.file.set_permissions(std::fs::Permissions::from_mode(
            self.original.as_ref().map_or(0o600, MetadataExt::mode) & 0o777,
        ))?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.check_ownership()?;
        #[cfg(test)]
        self.fail_before_rename()?;
        let fd = self.directory.as_raw_fd();
        if unsafe { libc::renameat(fd, self.stage.as_ptr(), fd, self.destination.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
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
            return Ok(Outcome::DurabilityUncertain);
        }
        Ok(Outcome::Updated)
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
            "file must be owned, regular, singly linked and not writable by others; sidecars must be private",
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
            "destination directory must be owned by current user and not writable by others",
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
