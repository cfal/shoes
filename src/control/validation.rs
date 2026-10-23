use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use super::store::{absolute_path, lock_path};
use crate::config::{BindLocation, Config, Transport, ValidatedConfigs};

pub fn validate_resources(validated: &ValidatedConfigs) -> io::Result<()> {
    let mut paths = HashSet::new();
    for group in &validated.dns_groups {
        if let Some(path) = group
            .fake_ip
            .as_ref()
            .and_then(|options| options.state_file.as_ref())
        {
            let path = absolute_path(path)?;
            paths.insert(lock_path(&path));
            paths.insert(path);
        }
    }
    let mut reserve = |path: &std::path::Path| -> io::Result<()> {
        let path = absolute_path(path)?;
        if !paths.insert(path.clone()) || !paths.insert(lock_path(&path)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controller/cache/fake-IP paths or ownership locks overlap",
            ));
        }
        Ok(())
    };
    if let Some(path) = &validated.control.cache_file_path {
        reserve(path)?;
    }
    let mut addresses = Vec::new();
    let mut socket_count = 0;
    for listener in &validated.control.listeners {
        match &listener.bind {
            BindLocation::Path(path) => {
                reserve(path)?;
                socket_count += 1;
            }
            BindLocation::Address(ranges) => {
                for range in ranges.iter() {
                    for address in range.to_socket_addrs()? {
                        if addresses.iter().any(|other| overlaps(*other, address)) {
                            return Err(io::Error::new(
                                io::ErrorKind::AddrInUse,
                                "Clash API listener addresses overlap",
                            ));
                        }
                        addresses.push(address);
                        socket_count += 1;
                        if socket_count > 16 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Clash API exceeds 16 bound sockets",
                            ));
                        }
                    }
                }
            }
            BindLocation::Unspecified {} => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Clash API has no listener address",
                ));
            }
        }
    }
    if socket_count > 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Clash API exceeds 16 bound sockets",
        ));
    }
    for config in &validated.configs {
        if let Config::Server(server) = config {
            match &server.bind_location {
                BindLocation::Path(path) if !paths.is_empty() => {
                    let parent = path
                        .parent()
                        .filter(|parent| !parent.as_os_str().is_empty())
                        .unwrap_or(std::path::Path::new("."));
                    let parent = match parent.canonicalize() {
                        Ok(parent) => parent,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    if path
                        .file_name()
                        .is_some_and(|name| paths.contains(&parent.join(name)))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "proxy socket overlaps controller or state path",
                        ));
                    }
                }
                BindLocation::Address(ranges)
                    if server.transport == Transport::Tcp && !addresses.is_empty() =>
                {
                    for range in ranges.iter() {
                        if range
                            .to_socket_addrs()?
                            .iter()
                            .any(|address| addresses.iter().any(|other| overlaps(*address, *other)))
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::AddrInUse,
                                "proxy listener overlaps Clash API listener",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() == 0 || a.port() != b.port() {
        return false;
    }
    let a = a.ip().to_canonical();
    let b = b.ip().to_canonical();
    match (a, b) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            a == b || a.is_unspecified() || b.is_unspecified()
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            a == b || a.is_unspecified() || b.is_unspecified()
        }
        // IPv6 wildcard listeners may also accept IPv4 connections.
        (std::net::IpAddr::V6(v6), _) | (_, std::net::IpAddr::V6(v6)) => v6.is_unspecified(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn listener_overlap_respects_address_families_and_dual_stack_wildcards() {
        for (a, b, expected) in [
            ("0.0.0.0:9090", "[::1]:9090", false),
            ("0.0.0.0:9090", "127.0.0.1:9090", true),
            ("[::]:9090", "127.0.0.1:9090", true),
            ("[::]:9090", "0.0.0.0:9090", true),
            ("[::]:9090", "[::1]:9090", true),
            ("127.0.0.1:9090", "[::ffff:127.0.0.1]:9090", true),
            ("0.0.0.0:9090", "[::ffff:127.0.0.1]:9090", true),
            ("127.0.0.1:9090", "[::1]:9090", false),
            ("0.0.0.0:9090", "127.0.0.1:9091", false),
            ("0.0.0.0:0", "0.0.0.0:0", false),
        ] {
            let a = a.parse().unwrap();
            let b = b.parse().unwrap();
            assert_eq!(overlaps(a, b), expected, "{a}, {b}");
            assert_eq!(overlaps(b, a), expected, "{b}, {a}");
        }
    }

    #[test]
    fn ipv4_controller_wildcard_allows_ipv6_loopback_listeners() {
        use serde_json::json;
        for second in [
            json!({"clash_api_address":"[::1]:9090", "secret":"test"}),
            json!({"address":"[::1]:9090", "protocol":{"type":"socks"}, "rules":"allow-all-direct"}),
        ] {
            let configs = serde_yaml::from_str(
                &json!([
                    {"clash_api_address":"0.0.0.0:9090", "secret":"test"}, second
                ])
                .to_string(),
            )
            .unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            validate_resources(&validated).unwrap();
        }
    }

    #[test]
    fn cache_only_configuration_reserves_state_and_lock_paths() {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("cache.db");
        for socket in [cache.clone(), lock_path(&cache)] {
            let configs = serde_yaml::from_str(
                &serde_json::json!([
                    {"cache_file_path":cache},
                    {"path":socket,"protocol":{"type":"socks"},"rules":"allow-all-direct"}
                ])
                .to_string(),
            )
            .unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            let error = validate_resources(&validated).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert_eq!(
                error.to_string(),
                "proxy socket overlaps controller or state path"
            );
        }
    }

    #[test]
    fn state_reservations_do_not_restrict_unrelated_proxy_socket_paths() {
        let directory = tempfile::tempdir().unwrap();
        for socket in [
            directory.path().join("proxy.lock"),
            directory.path().join("missing/proxy.sock"),
        ] {
            let configs = serde_yaml::from_str(
                &serde_json::json!([
                    {"cache_file_path":directory.path().join("cache.db")},
                    {"path":socket,"protocol":{"type":"socks"},"rules":"allow-all-direct"}
                ])
                .to_string(),
            )
            .unwrap();
            let validated = crate::config::create_server_configs(configs).unwrap();
            validate_resources(&validated).unwrap();
        }
    }
}
