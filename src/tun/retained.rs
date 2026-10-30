use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

pub(crate) struct RetainedDevice {
    fd: OwnedFd,
    pub(super) offload: bool,
}

impl RetainedDevice {
    #[cfg(target_os = "linux")]
    pub(crate) fn create(name: &str, requested_offload: Option<bool>) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN device name",
            ));
        }
        let create = |offload: bool| -> io::Result<Self> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/dev/net/tun")?;
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (target, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
                *target = source as libc::c_char;
            }
            // EXCL prevents accidentally attaching to a device created after preflight.
            request.ifr_ifru.ifru_flags = (libc::IFF_TUN
                | libc::IFF_NO_PI
                | libc::IFF_TUN_EXCL
                | if offload { libc::IFF_VNET_HDR } else { 0 })
                as libc::c_short;
            if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
                return Err(io::Error::last_os_error());
            }
            if offload {
                super::offload::configure(file.as_raw_fd())?;
            }
            Ok(Self {
                fd: file.into(),
                offload,
            })
        };
        match create(requested_offload.unwrap_or(true)) {
            Err(error) if requested_offload.is_none() => {
                log::warn!("Managed TUN offload unavailable: {error}; trying ordinary packets");
                create(false)
            }
            result => result,
        }
    }

    pub(super) fn duplicate(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }
}
