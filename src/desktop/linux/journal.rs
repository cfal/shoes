use std::fs::{File, OpenOptions};
use std::io::{self, BufReader};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::spec::Spec;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u8,
    pub namespace: String,
    pub token: String,
    pub spec: Spec,
    pub ifindex: Option<u32>,
    pub dns_pending: bool,
    pub firewall_pending: bool,
}

impl Record {
    pub(super) fn table(&self) -> String {
        format!("shoes_{}", self.token)
    }
    pub(super) fn alias(&self) -> String {
        format!("shoes:{}", self.token)
    }
}

pub(super) struct Journal {
    lock: File,
    directory: File,
    path: PathBuf,
    pub namespace: String,
}

fn private(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed TUN state must be private and owned by the effective user",
        ));
    }
    Ok(())
}

impl Journal {
    pub(super) fn lease(&self) -> BorrowedFd<'_> {
        self.lock.as_fd()
    }

    pub(super) fn lock() -> io::Result<Self> {
        let metadata = std::fs::metadata("/proc/self/ns/net")?;
        let namespace = format!("{}-{}", metadata.dev(), metadata.ino());
        let root = PathBuf::from("/run/shoes");
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root)?;
        private(&directory.metadata()?)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join(format!("netns-{namespace}.lock")))?;
        let metadata = lock.metadata()?;
        private(&metadata)?;
        if !metadata.is_file() {
            return Err(io::Error::other("invalid managed TUN lock file"));
        }
        lock.try_lock().map_err(|error| {
            io::Error::other(format!(
                "managed TUN is already active in this namespace: {error}"
            ))
        })?;
        Ok(Self {
            lock,
            directory,
            path: root.join(format!("netns-{namespace}.json")),
            namespace,
        })
    }

    pub(super) fn load(&self) -> io::Result<Option<Record>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        private(&metadata)?;
        if !metadata.is_file() {
            return Err(io::Error::other("invalid managed TUN journal"));
        }
        let record: Record =
            serde_json::from_reader(BufReader::new(file)).map_err(io::Error::other)?;
        if record.version != 1
            || record.namespace != self.namespace
            || record.token.len() != 32
            || !record.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::other("managed TUN journal identity is invalid"));
        }
        Ok(Some(record))
    }

    pub(super) fn save(&self, record: &Record) -> io::Result<()> {
        let path = self.path.with_extension("pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        private(&file.metadata()?)?;
        serde_json::to_writer(&mut file, record).map_err(io::Error::other)?;
        file.sync_all()?;
        std::fs::rename(path, &self.path)?;
        self.directory.sync_all()
    }

    pub(super) fn clear(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => self.directory.sync_all(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
