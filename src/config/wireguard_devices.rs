use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddrV6;

use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::IpNetwork;

use super::client_visit::visit_client;
use super::types::wireguard::{WireguardDeviceConfig, invalid};
use super::{
    ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection, ServerProxyConfig,
    ValidatedConfigs,
};
use crate::address::{Address, NetLocation};
use crate::option_util::NoneOrOne;

#[derive(PartialEq, Eq, Hash)]
struct ClientIdentity {
    endpoint: NetLocation,
    local_key: [u8; 32],
    remote_key: [u8; 32],
}

#[derive(Default)]
struct ClientRegistry {
    identities: HashMap<ClientIdentity, usize>,
    devices: Vec<WireguardDeviceConfig>,
    settings: Vec<serde_yaml::Value>,
}

impl ClientRegistry {
    fn register(&mut self, client: &mut ClientConfig) -> io::Result<()> {
        normalize_client(client)?;
        if !client.protocol.is_wireguard() {
            return Ok(());
        }
        // Compares effective carrier socket defaults without rewriting ordinary clients.
        let mut settings = client.clone();
        // The leaf's placement chooses this device; only its carriers affect device identity.
        settings.control = None;
        let mut selection_paths = Vec::new();
        visit_client(&mut settings, &mut |carrier| {
            selection_paths.push(
                carrier
                    .control
                    .as_ref()
                    .map(crate::control::catalog::MemberOrigin::policy_path)
                    .unwrap_or_default(),
            );
            if carrier.bind_interface.is_unspecified() {
                carrier.bind_interface = NoneOrOne::None;
            }
            if carrier
                .tcp_settings
                .as_ref()
                .is_some_and(|tcp| tcp.no_delay)
            {
                carrier.tcp_settings = None;
            }
            Ok(())
        })?;
        // Serialization excludes generation-local IDs and prepared connectors.
        let settings = serde_yaml::to_value((settings, selection_paths))
            .map_err(|_| invalid("cannot compare WireGuard client settings"))?;
        let ClientProxyConfig::Wireguard(config) = &mut client.protocol else {
            unreachable!("checked WireGuard protocol")
        };
        let identity = ClientIdentity {
            endpoint: client.address.clone(),
            local_key: PublicKey::from(&StaticSecret::from(config.private_key.0)).to_bytes(),
            remote_key: config.public_key.0,
        };
        if let Some(&index) = self.identities.get(&identity) {
            if settings != self.settings[index] {
                return Err(invalid(format!(
                    "conflicting WireGuard client settings for {}; the same endpoint and key pair must use identical settings",
                    client.address,
                )));
            }
            config.endpoint_id = self.devices[index].id.clone();
            return Ok(());
        }

        let mut device =
            config.device(&client.address, client.bind_interface.clone().into_option());
        validate_carrier_mtu(&device)?;
        let index = self.devices.len();
        config.endpoint_id = format!("client-{index}");
        device.id = config.endpoint_id.clone();
        self.identities.insert(identity, index);
        self.devices.push(device);
        self.settings.push(settings);
        Ok(())
    }
}

fn normalize_client(client: &mut ClientConfig) -> io::Result<()> {
    let ClientProxyConfig::Wireguard(config) = &mut client.protocol else {
        return Ok(());
    };
    if client.bind_interface.is_unspecified() {
        client.bind_interface = NoneOrOne::None;
    }
    if let Address::Hostname(host) = client.address.address()
        && host.starts_with('[')
    {
        let endpoint: SocketAddrV6 = client
            .address
            .to_string()
            .parse()
            .map_err(|_| invalid("invalid scoped WireGuard peer endpoint"))?;
        client.address = NetLocation::from_str(&endpoint.to_string(), None)?;
    }
    let address = match client.address.address() {
        Address::Hostname(host) if !host.starts_with('[') => {
            Address::from(&host.to_ascii_lowercase())?
        }
        Address::Ipv6(ip) if ip.to_ipv4_mapped().is_some() => {
            Address::Ipv4(ip.to_ipv4_mapped().unwrap())
        }
        address => address.clone(),
    };
    client.address = NetLocation::new(address, client.address.port());
    // X25519 ignores these scalar bits, so equivalent encodings share one identity.
    config.private_key.0[0] &= 248;
    config.private_key.0[31] &= 127;
    config.private_key.0[31] |= 64;
    if config
        .pre_shared_key
        .as_ref()
        .is_some_and(|key| key.0 == [0; 32])
    {
        config.pre_shared_key = None;
    }
    normalize_cidrs(&mut config.addresses, false)?;
    normalize_cidrs(&mut config.allowed_ips, true)?;
    config.resource_limits = config.device(&client.address, None).limits();
    if let Some(chain) = &mut config.peer_client_chain {
        for hop in chain.hops.iter_mut() {
            if let ClientChainHop::Pool(pool) = hop
                && pool.iter().count() == 1
            {
                let selection = pool.iter().next().unwrap().clone();
                *hop = ClientChainHop::Single(selection);
            }
        }
    }
    Ok(())
}

fn normalize_cidrs(prefixes: &mut Vec<String>, routes: bool) -> io::Result<()> {
    for prefix in prefixes.iter_mut() {
        let network: IpNetwork = prefix
            .parse()
            .map_err(|_| invalid("invalid WireGuard CIDR"))?;
        *prefix = if routes {
            IpNetwork::new(network.network(), network.prefix())
                .map_err(io::Error::other)?
                .to_string()
        } else {
            IpNetwork::from(network.ip()).to_string()
        };
    }
    prefixes.sort();
    prefixes.dedup();
    Ok(())
}

fn validate_carrier_mtu(device: &WireguardDeviceConfig) -> io::Result<()> {
    let Some(chain) = &device.peer_client_chain else {
        return Ok(());
    };
    if chain.hops.iter().count() != 1 {
        return Ok(());
    }
    let check = |selection: &ConfigSelection<ClientConfig>| {
        let ConfigSelection::Config(client) = selection else {
            unreachable!("expanded client group")
        };
        if let ClientProxyConfig::Wireguard(carrier) = &client.protocol {
            // IPv6 UDP plus WireGuard header, tag and worst-case padding.
            let required = device.mtu.next_multiple_of(16) + 80;
            if carrier.mtu < required {
                return Err(invalid(format!(
                    "WireGuard peer_client_chain requires carrier MTU >= {required}"
                )));
            }
        }
        Ok(())
    };
    match chain.hops.iter().next().unwrap() {
        ClientChainHop::Single(selection) => check(selection),
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter() {
                check(selection)?;
            }
            Ok(())
        }
    }
}

pub(super) fn collect_devices(
    validated: &mut ValidatedConfigs,
    groups: &mut HashMap<String, Vec<ClientConfig>>,
) -> io::Result<()> {
    let mut clients = ClientRegistry::default();
    // Unused groups are validated for conflicts but do not start devices.
    let mut sorted_groups: Vec<_> = groups.iter_mut().collect();
    sorted_groups.sort_by_key(|(name, _)| *name);
    for (_, group) in sorted_groups {
        for client in group {
            visit_client(client, &mut |client| clients.register(client))?;
        }
    }
    validated.visit_clients(&mut |client| clients.register(client))?;
    if !validated.control.listeners.is_empty() {
        super::validate::refresh_catalog_clients(validated, groups)?;
    }
    let referenced_dns: HashSet<_> = validated
        .configs
        .iter()
        .filter_map(|config| match config {
            Config::Server(server) => server.dns.as_ref(),
            Config::TunServer(tun) => tun.dns.as_ref(),
            _ => None,
        })
        .filter_map(|dns| dns.resolved_group())
        .collect();
    // WireGuard-routed DNS cannot be a bootstrap dependency; only listeners and TUNs activate it.
    validated.dns_groups.retain(|group| {
        referenced_dns.contains(group.name.as_str())
            || !group.specs.iter().any(|spec| {
                spec.client_chains
                    .iter()
                    .any(super::validate::chain_uses_wireguard)
            })
    });
    let mut used = HashSet::new();
    validated.visit_clients(&mut |client| {
        if let ClientProxyConfig::Wireguard(config) = &client.protocol {
            used.insert(config.endpoint_id.clone());
        }
        Ok(())
    })?;
    validated.wireguard_endpoints = clients
        .devices
        .into_iter()
        .filter(|device| used.contains(&device.id))
        .collect();
    let mut listeners = Vec::new();
    let mut binds = HashSet::new();
    for config in std::mem::take(&mut validated.configs) {
        if let Config::Server(server) = &config
            && let ServerProxyConfig::Wireguard(protocol) = &server.protocol
        {
            let mut device = protocol.device(server)?;
            if let Some(listen) = device.listen
                && !binds.insert(listen)
            {
                return Err(invalid(format!(
                    "duplicate WireGuard server listen address: {listen}"
                )));
            }
            validate_carrier_mtu(&device)?;
            device.id = protocol.server_id();
            validated.wireguard_endpoints.push(device);
        } else {
            listeners.push(config);
        }
    }
    validated.configs = listeners;
    Ok(())
}

#[cfg(test)]
mod tests;
