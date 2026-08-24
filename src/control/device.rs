//! Where the TUN device comes from.
//!
//! Two hosts, two answers. A macOS Network Extension, iOS and Android are each
//! handed a descriptor by the platform and keep ownership of it. Linux, and
//! Windows once a wintun backend lands, are handed nothing and create the
//! device themselves.
//!
//! `TunConfig` already describes a device, so this is not another description
//! of one — it is which shapes of `TunConfig` a given host can honour.

use crate::config::TunConfig;

/// Who owns the TUN device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePolicy {
    /// The host hands over a descriptor it owns and will close itself.
    /// macOS Network Extension, iOS, Android.
    BorrowedFd,
    /// shoes creates the device and owns it. Linux, and Windows once the
    /// wintun backend lands.
    Owned,
}

impl DevicePolicy {
    /// Whether the service closes the descriptor when it is done with it.
    ///
    /// Derived rather than configured, because the owner closes and nobody
    /// else. As a free parameter this was a constant one caller could get
    /// wrong in either direction: leak a descriptor, or close one the host
    /// still holds and is reading from.
    pub fn close_fd_on_drop(&self) -> bool {
        matches!(self, DevicePolicy::Owned)
    }
}

/// Check a TUN config against what this host can provide.
pub fn validate(config: &TunConfig, policy: DevicePolicy) -> std::io::Result<()> {
    match policy {
        DevicePolicy::BorrowedFd if config.device_fd.is_none() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN config missing device_fd - must be injected by caller",
        )),
        DevicePolicy::Owned if config.device_fd.is_some() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN config sets device_fd, but this host creates its own device",
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TunConfig` derives only Debug/Clone/Deserialize/Serialize -- there is
    /// no Default impl, and several fields take their defaults from serde
    /// attributes rather than from Rust. So build it the way the real code
    /// does, by deserializing.
    fn tun_config(device_fd: Option<i32>) -> TunConfig {
        let yaml = match device_fd {
            Some(fd) => format!("device_fd: {fd}\n"),
            None => "device_name: tun0\naddress: 10.0.0.2\n".to_string(),
        };
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn test_borrowed_fd_requires_a_descriptor() {
        let err = validate(&tun_config(None), DevicePolicy::BorrowedFd).unwrap_err();
        assert!(
            err.to_string().contains("device_fd"),
            "expected a device_fd complaint, got: {err}"
        );
    }

    /// A host that creates its own device but also names a descriptor has two
    /// sources and no way to say which wins, so it is refused rather than
    /// silently resolved.
    #[test]
    fn test_owned_refuses_a_descriptor() {
        let err = validate(&tun_config(Some(7)), DevicePolicy::Owned).unwrap_err();
        assert!(
            err.to_string().contains("device_fd"),
            "expected a device_fd complaint, got: {err}"
        );
    }

    #[test]
    fn test_each_policy_accepts_its_own_shape() {
        assert!(validate(&tun_config(Some(7)), DevicePolicy::BorrowedFd).is_ok());
        assert!(validate(&tun_config(None), DevicePolicy::Owned).is_ok());
    }

    #[test]
    fn test_ownership_decides_who_closes() {
        assert!(!DevicePolicy::BorrowedFd.close_fd_on_drop());
        assert!(DevicePolicy::Owned.close_fd_on_drop());
    }
}
