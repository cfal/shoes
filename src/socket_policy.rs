use std::io;
use std::sync::Arc;

use crate::resolver::Resolver;

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Policy {
    interface: String,
    bypass_mark: u32,
    mark_mask: u32,
    addresses: Vec<ipnetwork::IpNetwork>,
    bootstrap: Arc<dyn Resolver>,
}

#[cfg(target_os = "linux")]
static POLICY: parking_lot::RwLock<Option<Policy>> = parking_lot::RwLock::new(None);

#[cfg(target_os = "linux")]
pub(crate) struct SocketPolicy(());

#[cfg(target_os = "linux")]
impl SocketPolicy {
    pub(crate) fn install(
        interface: String,
        bypass_mark: u32,
        mark_mask: u32,
        addresses: Vec<ipnetwork::IpNetwork>,
        bootstrap: Arc<dyn Resolver>,
    ) -> io::Result<Self> {
        let mut current = POLICY.write();
        if current.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "managed socket policy is already installed",
            ));
        }
        if bypass_mark == 0 || bypass_mark & !mark_mask != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid managed bypass mark",
            ));
        }
        *current = Some(Policy {
            interface,
            bypass_mark,
            mark_mask,
            addresses,
            bootstrap,
        });
        Ok(Self(()))
    }
}

#[cfg(target_os = "linux")]
impl Drop for SocketPolicy {
    fn drop(&mut self) {
        // Resolver destruction must not hold the global policy lock.
        let policy = POLICY.write().take();
        drop(policy);
    }
}

pub(crate) fn bootstrap() -> Option<Arc<dyn Resolver>> {
    #[cfg(target_os = "linux")]
    return POLICY
        .read()
        .as_ref()
        .map(|policy| policy.bootstrap.clone());
    #[cfg(not(target_os = "linux"))]
    None
}

pub(crate) fn apply(socket: socket2::SockRef<'_>, interface: Option<&str>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(policy) = POLICY.read().as_ref() {
        if interface == Some(policy.interface.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed egress cannot bind to the TUN interface",
            ));
        }
        let mark = (socket.mark()? & !policy.mark_mask) | policy.bypass_mark;
        socket.set_mark(mark)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (socket, interface);
    Ok(())
}

pub(crate) fn check_native_hostname() -> io::Result<()> {
    if bootstrap().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed TUN requires literal listener addresses; native hostname lookup is disabled",
        ));
    }
    Ok(())
}

pub(crate) fn check_dns_endpoint(address: std::net::IpAddr) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(policy) = POLICY.read().as_ref() {
        let address = address.to_canonical();
        if address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || policy.addresses.iter().any(|range| range.contains(address))
            || local_address(address)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed DNS upstream cannot use a host-local address or TUN subnet",
            ));
        }
    }
    let _ = address;
    Ok(())
}

pub(crate) fn check_outbound_address(address: std::net::IpAddr) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if POLICY.read().as_ref().is_some_and(|policy| {
        policy
            .addresses
            .iter()
            .any(|range| range.contains(address.to_canonical()))
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed TUN subnet cannot be an outbound target",
        ));
    }
    let _ = address;
    Ok(())
}

#[cfg(target_os = "linux")]
fn local_address(address: std::net::IpAddr) -> io::Result<bool> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut addresses = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addresses) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = Addresses(addresses);
    let mut current = addresses.0;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            let ip = unsafe {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                        (*(entry.ifa_addr as *const libc::sockaddr_in))
                            .sin_addr
                            .s_addr
                            .to_ne_bytes(),
                    ))),
                    libc::AF_INET6 => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        (*(entry.ifa_addr as *const libc::sockaddr_in6))
                            .sin6_addr
                            .s6_addr,
                    ))),
                    _ => None,
                }
            };
            if ip == Some(address) {
                return Ok(true);
            }
        }
        current = entry.ifa_next;
    }
    Ok(false)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Unavailable;
    impl Drop for Unavailable {
        fn drop(&mut self) {
            assert!(POLICY.try_write().is_some());
        }
    }

    impl Resolver for Unavailable {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            Box::pin(async { Err(io::Error::other("controlled bootstrap failed")) })
        }
    }

    #[tokio::test]
    async fn managed_resolution_never_falls_back_to_native_and_policy_is_process_scoped() {
        const CHILD: &str = "SHOES_SOCKET_POLICY_TEST";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "socket_policy::tests::managed_resolution_never_falls_back_to_native_and_policy_is_process_scoped", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed;"),
                "socket policy test failed: {}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let install = || {
            SocketPolicy::install(
                "test0".into(),
                0x40000000,
                0x60000000,
                vec!["10.233.0.1/30".parse().unwrap()],
                Arc::new(Unavailable),
            )
        };
        let policy = install().unwrap();
        assert!(install().is_err());
        assert!(crate::socket_util::new_tcp_socket(Some("test0".into()), false).is_err());
        match crate::socket_util::new_tcp_socket(None, false) {
            Ok(socket) => assert_eq!(socket2::SockRef::from(&socket).mark().unwrap(), 0x40000000),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
        match crate::socket_util::new_udp_socket(false, None) {
            Ok(socket) => assert_eq!(socket2::SockRef::from(&socket).mark().unwrap(), 0x40000000),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
        match crate::socket_util::new_tcp_listener("127.0.0.1:0".parse().unwrap(), 16, None) {
            Ok(socket) => assert_eq!(socket2::SockRef::from(&socket).mark().unwrap(), 0x40000000),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
        let error = crate::resolver::NativeResolver::new()
            .resolve_location(&crate::address::NetLocation::from_str("localhost:53", None).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "controlled bootstrap failed");
        assert!(
            crate::address::NetLocationPortRange::from_str("localhost:80")
                .unwrap()
                .to_socket_addrs()
                .is_err()
        );
        assert!(
            crate::address::NetLocationPortRange::from_str("127.0.0.1:80")
                .unwrap()
                .to_socket_addrs()
                .is_ok()
        );
        let scoped = crate::address::NetLocationPortRange::from_str("[fe80::1%2]:80-81")
            .unwrap()
            .to_socket_addrs()
            .unwrap();
        assert_eq!(
            scoped,
            vec![
                "[fe80::1%2]:80".parse().unwrap(),
                "[fe80::1%2]:81".parse().unwrap()
            ]
        );
        for address in ["127.0.0.53", "::ffff:127.0.0.1", "10.233.0.2"] {
            assert!(check_dns_endpoint(address.parse().unwrap()).is_err());
        }
        assert!(check_dns_endpoint("192.0.2.53".parse().unwrap()).is_ok());
        drop(policy);
        assert!(bootstrap().is_none());
        check_native_hostname().unwrap();
        let policy = install().unwrap();
        assert!(bootstrap().is_some());
        drop(policy);
        assert!(bootstrap().is_none());
    }
}
