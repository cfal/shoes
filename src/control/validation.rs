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
                    if paths.contains(&absolute_path(path)?) {
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
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

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
            assert!(validate_resources(&validated).is_err());
        }
    }
}
