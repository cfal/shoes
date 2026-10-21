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
        visit_client(&mut settings, &mut |carrier| {
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
        let settings = serde_yaml::to_value(settings)
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
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn key(byte: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn client() -> Value {
        use base64::Engine;
        let public = PublicKey::from(&StaticSecret::from([41; 32]));
        json!({
            "address": "vpn.example:51820",
            "protocol": {
                "type": "wireguard", "private_key": key(42),
                "public_key": base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                "addresses": ["10.77.0.2/32", "fd77::2/128"],
            },
        })
    }

    fn server() -> Value {
        use base64::Engine;
        let public = PublicKey::from(&StaticSecret::from([42; 32]));
        json!({
            "address": "[::]:51820",
            "protocol": {
                "type": "wireguard", "private_key": key(41), "addresses": ["10.77.0.1/32"],
                "peers": [{"public_key": base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                           "allowed_ips": ["10.77.0.2/32"]}],
            },
            "rules": "block-all",
        })
    }

    #[test]
    fn servers_keep_inbound_sniff_setting() {
        for sniff in [false, true] {
            let mut config = server();
            config["sniff"] = json!(sniff);
            let validated = validate(json!([config])).unwrap();
            let inbound = validated.wireguard_endpoints[0].inbound.as_ref().unwrap();
            assert_eq!(inbound.sniff, sniff);
        }
    }

    #[test]
    fn server_names_and_public_keys_have_separate_stable_identities() {
        let original = validate(json!([server()]))
            .unwrap()
            .wireguard_endpoints
            .remove(0)
            .id;
        assert!(original.starts_with("server:key:"));
        let mut unnamed = server();
        unnamed["protocol"]["wireguard_name"] = json!("");
        let mut equivalent_key = [41; 32];
        equivalent_key[0] ^= 7;
        equivalent_key[31] ^= 128;
        use base64::Engine;
        unnamed["protocol"]["private_key"] =
            json!(base64::engine::general_purpose::STANDARD.encode(equivalent_key));
        assert_eq!(
            validate(json!([unnamed])).unwrap().wireguard_endpoints[0].id,
            original
        );
        let mut blank = server();
        blank["protocol"]["wireguard_name"] = Value::Null;
        assert_eq!(
            validate(json!([blank])).unwrap().wireguard_endpoints[0].id,
            original
        );

        let mut named = server();
        named["address"] = json!("[::]:51821");
        named["protocol"]["wireguard_name"] = json!(original.strip_prefix("server:key:").unwrap());
        let validated = validate(json!([server(), named.clone()])).unwrap();
        assert_ne!(
            validated.wireguard_endpoints[0].id,
            validated.wireguard_endpoints[1].id
        );
        let expected = validated.wireguard_endpoints[1].id.clone();
        named["protocol"]["private_key"] = json!(key(44));
        let protocol: ServerProxyConfig =
            serde_yaml::from_str(&named["protocol"].to_string()).unwrap();
        let roundtrip = serde_yaml::to_string(&protocol).unwrap();
        let ServerProxyConfig::Wireguard(protocol) = serde_yaml::from_str(&roundtrip).unwrap()
        else {
            panic!("expected WireGuard protocol");
        };
        assert_eq!(protocol.server_id(), expected);
        let validated = validate(json!([named])).unwrap();
        assert_eq!(validated.wireguard_endpoints[0].id, expected);
    }

    #[test]
    fn server_identities_cannot_turn_private_dns_references_into_urls() {
        let mut identities = HashSet::new();
        for name in [
            "region://gateway",
            "//edge",
            "/",
            "%2F",
            "gateway",
            "Gateway",
        ] {
            for fake_ip in [false, true] {
                let mut config = server();
                config["protocol"]["wireguard_name"] = json!(name);
                config["dns"] = json!({"fake_ip": fake_ip});
                let validated = validate(json!([config])).unwrap();
                let device = &validated.wireguard_endpoints[0];
                assert!(!device.id.contains('/'));
                if fake_ip {
                    assert!(identities.insert(device.id.clone()));
                }
                assert_eq!(
                    device
                        .inbound
                        .as_ref()
                        .unwrap()
                        .dns
                        .as_ref()
                        .unwrap()
                        .resolved_group(),
                    Some(format!("__inline_fake_dns:wireguard:{}", device.id).as_str())
                );
            }
        }
        for fake_ip in [false, true] {
            let mut config = server();
            config["protocol"]["private_key"] =
                json!("CCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            config["dns"] = json!({"fake_ip": fake_ip});
            let validated = validate(json!([config])).unwrap();
            let device = &validated.wireguard_endpoints[0];
            assert_eq!(
                device.id,
                "server:key:__326N9SoT-V7q8es5GvY-Pop9oC_6MG7LMYJCNWgTs"
            );
            assert_eq!(
                device
                    .inbound
                    .as_ref()
                    .unwrap()
                    .dns
                    .as_ref()
                    .unwrap()
                    .resolved_group(),
                Some(format!("__inline_fake_dns:wireguard:{}", device.id).as_str())
            );
        }
    }

    #[test]
    fn duplicate_server_identities_reject_with_or_without_fake_dns() {
        for name in [None, Some(""), Some("gateway")] {
            for fake_ip in [None, Some(false), Some(true)] {
                let mut first = server();
                if let Some(name) = name {
                    first["protocol"]["wireguard_name"] = json!(name);
                }
                if let Some(fake_ip) = fake_ip {
                    first["dns"] = json!({"fake_ip":fake_ip});
                }
                let mut second = first.clone();
                second["address"] = json!("[::]:51821");
                if name == Some("gateway") {
                    second["protocol"]["private_key"] = json!(key(44));
                }
                let error = validate(json!([first, second])).err().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    error
                        .to_string()
                        .contains("duplicate WireGuard server identity"),
                    "{error}"
                );
                assert!(!error.to_string().contains(&key(41)));
            }
        }
        let mut second = server();
        second["protocol"]["wireguard_name"] = json!("other");
        let error = validate(json!([server(), second])).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("duplicate WireGuard server listen address"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn server_private_dns_ownership_survives_reordering_clients_and_key_rotation() {
        use crate::dns::{build_dns_registry, build_dns_registry_reusing};

        let mut first = server();
        first["protocol"]["wireguard_name"] = json!("first");
        first["dns"] = json!({"fake_ip":true});
        let mut second = first.clone();
        second["address"] = json!("[::]:51821");
        second["protocol"]["wireguard_name"] = json!("second");
        let initial = validate(json!([first.clone(), second.clone()])).unwrap();
        let group_names: Vec<_> = initial
            .wireguard_endpoints
            .iter()
            .map(|device| {
                let group = device
                    .inbound
                    .as_ref()
                    .unwrap()
                    .dns
                    .as_ref()
                    .unwrap()
                    .resolved_group()
                    .unwrap();
                assert_eq!(group, format!("__inline_fake_dns:wireguard:{}", device.id));
                group.to_owned()
            })
            .collect();
        let mut registry = build_dns_registry(initial.dns_groups).await.unwrap();
        let mut mappings = Vec::new();
        for (group, hostname) in group_names.iter().zip(["first.example", "second.example"]) {
            let context = registry
                .get_by_name(group)
                .unwrap()
                .fake_dns_context()
                .unwrap();
            mappings.push((
                group.clone(),
                hostname,
                context.allocate(hostname, false).unwrap(),
            ));
        }
        first["protocol"]["private_key"] = json!(key(44));
        for enabled in [true, false, true] {
            first["dns"]["fake_ip"] = json!(enabled);
            second["dns"]["fake_ip"] = json!(enabled);
            let mut configs = copies(client());
            configs
                .as_array_mut()
                .unwrap()
                .extend([second.clone(), first.clone()]);
            let validated = validate(configs).unwrap();
            assert!(
                validated
                    .wireguard_endpoints
                    .iter()
                    .any(|device| device.inbound.is_none())
            );
            for device in validated
                .wireguard_endpoints
                .iter()
                .filter(|device| device.inbound.is_some())
            {
                let group = device
                    .inbound
                    .as_ref()
                    .unwrap()
                    .dns
                    .as_ref()
                    .unwrap()
                    .resolved_group()
                    .unwrap();
                let index = match device.listen.unwrap().port() {
                    51820 => 0,
                    51821 => 1,
                    port => panic!("unexpected server port {port}"),
                };
                assert_eq!(group, group_names[index]);
                assert_eq!(group, format!("__inline_fake_dns:wireguard:{}", device.id));
            }
            let next = build_dns_registry_reusing(
                validated.dns_groups,
                crate::resources::limits(),
                Some(&registry),
            )
            .await
            .unwrap();
            for (group, hostname, ip) in &mappings {
                let context = next.get_by_name(group).unwrap().fake_dns_context();
                if enabled {
                    assert_eq!(
                        context.unwrap().restore(*ip).unwrap().as_deref(),
                        Some(*hostname)
                    );
                } else {
                    assert!(context.is_none());
                }
            }
            registry = next;
        }
    }

    #[test]
    fn proxied_servers_with_shared_keys_require_distinct_names() {
        let mut first = server();
        first.as_object_mut().unwrap().remove("address");
        first["protocol"]["peer_client_chain"] = json!("direct");
        first["protocol"]["peers"][0]["endpoint"] = json!("peer.example:51820");
        first["protocol"]["peers"][0]["persistent_keepalive"] = json!(25);
        let mut second = first.clone();
        assert!(
            validate(json!([first, second]))
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate WireGuard server identity")
        );
        first["protocol"]["wireguard_name"] = json!("first");
        second["protocol"]["wireguard_name"] = json!("second");
        let validated = validate(json!([first, second])).unwrap();
        assert_eq!(validated.wireguard_endpoints[0].id, "server:name:Zmlyc3Q");
        assert_eq!(validated.wireguard_endpoints[1].id, "server:name:c2Vjb25k");
    }

    #[test]
    fn servers_parse_literal_binds_and_reject_duplicates_and_implicit_policy() {
        for address in ["0.0.0.0:51820", "[::]:51820", "[fe80::1%3]:51820"] {
            let mut config = server();
            config["address"] = json!(address);
            let validated = validate(json!([config])).unwrap();
            assert!(validated.configs.is_empty());
            assert_eq!(
                validated.wireguard_endpoints[0].listen,
                Some(address.parse().unwrap())
            );
        }
        assert!(
            validate(json!([server(), server()]))
                .err()
                .unwrap()
                .to_string()
                .contains("duplicate")
        );
        for address in [
            json!("0.0.0.0:0"),
            json!("[::]:0"),
            json!("[fe80::1%3]:0"),
            json!("localhost:51820"),
            json!("127.0.0.1:51820-51821"),
            json!(["127.0.0.1:51820", "127.0.0.1:51821"]),
        ] {
            let mut config = server();
            config["address"] = address;
            assert!(validate(json!([config])).is_err());
        }
        for rules in [Value::Null, json!([])] {
            let mut config = server();
            config["rules"] = rules;
            assert!(
                validate(json!([config]))
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("WireGuard server requires nonempty explicit rules")
            );
        }
        let mut config = server();
        config.as_object_mut().unwrap().remove("rules");
        assert!(validate(json!([config])).is_err());
    }

    #[test]
    fn empty_rule_groups_are_rejected_during_deserialization() {
        let error = serde_yaml::from_str::<super::super::groups::RuleConfigGroup>(
            "rule_group: empty\nrules: []\n",
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("rule group cannot be empty"),
            "{error}"
        );
    }

    #[test]
    fn servers_reject_conflicting_bind_fields() {
        for fields in [
            json!({"address": "127.0.0.1:51820", "addresses": ["[::]:51820", "127.0.0.1:51821"]}),
            json!({"address": "127.0.0.1:51820", "path": "/unused.sock"}),
            json!({"addresses": ["[::]:51820"], "path": "/unused.sock"}),
        ] {
            let mut config = server();
            let object = config.as_object_mut().unwrap();
            object.remove("address");
            object.extend(fields.as_object().unwrap().clone());
            assert!(validate(json!([config])).is_err(), "accepted {fields}");
        }
    }

    #[test]
    fn servers_reject_port_range_syntax_for_a_single_distinct_port() {
        for address in [
            "127.0.0.1:51820-51820",
            "127.0.0.1:51820,51820",
            "[::]:51820-51820",
            "[fe80::1%3]:51820,51820",
        ] {
            let mut config = server();
            config["address"] = json!(address);
            assert!(validate(json!([config])).is_err(), "accepted {address}");
        }
    }

    #[test]
    fn proxied_servers_roundtrip_without_a_listener_and_require_return_mappings() {
        let mut config = server();
        config.as_object_mut().unwrap().remove("address");
        config["protocol"]["peer_client_chain"] = json!("direct");
        config["protocol"]["peers"][0]["endpoint"] = json!("peer.example:51820");
        config["protocol"]["peers"][0]["persistent_keepalive"] = json!(25);
        let raw: Vec<Config> =
            serde_yaml::from_str(&serde_yaml::to_string(&json!([config])).unwrap()).unwrap();
        let serialized = serde_yaml::to_value(raw).unwrap();
        assert!(serialized[0].as_mapping().unwrap().get("address").is_none());
        let validated =
            super::super::create_server_configs(serde_yaml::from_value(serialized).unwrap())
                .unwrap();
        assert!(validated.wireguard_endpoints[0].listen.is_none());
        for (pointer, value) in [
            ("/protocol/peers/0/endpoint", Value::Null),
            ("/protocol/peers/0/persistent_keepalive", json!(0)),
            ("/protocol/peer_client_chain", Value::Null),
        ] {
            let mut invalid = config.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(validate(json!([invalid])).is_err(), "accepted {pointer}");
        }
        config["address"] = json!("0.0.0.0:51820");
        assert!(validate(json!([config])).is_err());
    }

    #[test]
    fn wireguard_implies_udp_and_rejects_stream_transport_settings() {
        for transport in ["tcp", "quic"] {
            let mut client = client();
            client["transport"] = json!(transport);
            assert!(validate(copies(client)).is_err());
            let mut server = server();
            server["transport"] = json!(transport);
            assert!(validate(json!([server])).is_err());
        }
        let mut explicit = client();
        explicit["transport"] = json!("udp");
        assert_eq!(
            validate(copies(explicit))
                .unwrap()
                .wireguard_endpoints
                .len(),
            1
        );
        let mut explicit = server();
        explicit["transport"] = json!("udp");
        validate(json!([explicit])).unwrap();
        let mut client = client();
        client["tcp_settings"] = json!({});
        assert!(validate(copies(client)).is_err());
        let mut server = server();
        server["tcp_settings"] = json!({});
        assert!(validate(json!([server])).is_err());
    }

    #[test]
    fn client_and_server_never_share_a_device() {
        let client = client();
        let mut server = server();
        server["protocol"]["private_key"] = client["protocol"]["private_key"].clone();
        server["protocol"]["peers"][0]["public_key"] = client["protocol"]["public_key"].clone();
        let mut configs = copies(client);
        configs.as_array_mut().unwrap().push(server);
        assert_eq!(validate(configs).unwrap().wireguard_endpoints.len(), 2);
    }

    #[test]
    fn server_overrides_reject_other_active_and_retained_fake_ranges() {
        let mut inbound = server();
        inbound["rules"] = json!([{
            "masks":"0.0.0.0/0", "action":"allow", "override_address":"198.18.0.5:443"
        }]);
        let mut config = json!([
            {"dns_group":"fake", "dns_servers":"system", "fake_ip":true},
            inbound,
        ]);
        let error = validate(config.clone()).err().unwrap();
        assert!(error.to_string().contains("rule override"), "{error}");
        config[0]["fake_ip"] = false.into();
        let mut validated = validate(config).unwrap();
        let error = validated
            .validate_network_endpoints(&["198.18.0.0/15".parse().unwrap()])
            .unwrap_err();
        assert!(error.to_string().contains("rule override"), "{error}");
    }

    fn validate(values: Value) -> io::Result<ValidatedConfigs> {
        super::super::create_server_configs(
            serde_yaml::from_str(&serde_yaml::to_string(&values).unwrap())
                .map_err(io::Error::other)?,
        )
    }

    fn copies(second: Value) -> Value {
        json!([
            {"client_group": "one", "client_proxies": [client()]},
            {"client_group": "two", "client_proxies": [second]},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"},
             "rules": [{"masks": "0.0.0.0/0", "action": "allow",
                        "client_chain": [{"pool": ["one", "two", client()]}]}]},
        ])
    }

    #[test]
    fn copied_clients_share_after_defaults_and_normalization() {
        let mut second = client();
        second["address"] = json!("VPN.EXAMPLE:51820");
        second["bind_interface"] = Value::Null;
        let config = &mut second["protocol"];
        config["mtu"] = json!(1408);
        config["persistent_keepalive"] = json!(0);
        config["allowed_ips"] = json!(["::/0", "0.0.0.0/0", "::/0"]);
        config["addresses"] = json!(["fd77:0::2/128", "10.77.0.2/32"]);
        config["pre_shared_key"] = json!(key(0));
        config["resource_limits"] =
            json!({"max_tcp_connections": 256, "tcp_memory_bytes": 33554432});
        use base64::Engine;
        let mut equivalent_key = [42; 32];
        equivalent_key[0] ^= 7;
        equivalent_key[31] ^= 128;
        config["private_key"] =
            json!(base64::engine::general_purpose::STANDARD.encode(equivalent_key));
        let mut validated = validate(copies(second)).unwrap();
        assert_eq!(validated.wireguard_endpoints.len(), 1);
        assert_eq!(validated.wireguard_endpoints[0].peers.len(), 1);
        let mut ids = Vec::new();
        validated
            .visit_clients(&mut |client| {
                if let ClientProxyConfig::Wireguard(config) = &client.protocol {
                    ids.push(config.endpoint_id.clone());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.iter().all(|id| id == &ids[0]));
    }

    #[test]
    fn conflicting_copies_reject_every_device_setting_without_disclosing_keys() {
        for (field, value) in [
            ("mtu", json!(1280)),
            ("addresses", json!(["10.77.0.3/32"])),
            ("allowed_ips", json!(["192.0.2.0/24"])),
            ("persistent_keepalive", json!(25)),
            ("pre_shared_key", json!(key(99))),
            ("resource_limits", json!({"max_udp_sessions": 2})),
            (
                "peer_client_chain",
                json!([{"protocol": {"type": "direct"}}]),
            ),
        ] {
            let mut second = client();
            second["protocol"][field] = value;
            let error = validate(copies(second)).err().unwrap().to_string();
            assert!(
                error.contains("conflicting WireGuard client settings"),
                "{field}: {error}"
            );
            assert!(!error.contains(&key(42)) && !error.contains(&key(99)));
        }
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
        {
            let mut second = client();
            second["bind_interface"] = json!("lo");
            assert!(
                validate(copies(second))
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("conflicting")
            );
        }
    }

    #[test]
    fn copied_clients_share_with_equivalent_carrier_socket_defaults() {
        let mut first = client();
        first["protocol"]["peer_client_chain"] = json!("direct");
        for chain in [
            json!("direct"),
            json!("relay"),
            json!([{"protocol": {"type": "direct"}}]),
            json!([{"protocol": {"type": "direct"}, "bind_interface": null}]),
            json!([{"protocol": {"type": "direct"}, "tcp_settings": {}}]),
            json!([{"protocol": {"type": "direct"}, "tcp_settings": {"no_delay": true}}]),
            json!([{"pool": [{"protocol": {"type": "direct"}, "tcp_settings": {}}]}]),
        ] {
            let mut second = client();
            second["protocol"]["peer_client_chain"] = chain.clone();
            let configs = json!([
                {"client_group": "one", "client_proxies": [first]},
                {"client_group": "relay", "client_proxies": [{"protocol": {"type": "direct"}}]},
                {"address": "0.0.0.0:1080", "protocol": {"type": "socks"},
                 "rules": [{"masks": "0.0.0.0/0", "action": "allow",
                            "client_chain": [{"pool": ["one", second]}]}]},
            ]);
            let validated =
                validate(configs.clone()).unwrap_or_else(|error| panic!("{chain}: {error}"));
            assert_eq!(validated.wireguard_endpoints.len(), 1);

            let mut conflict = configs;
            conflict[2]["rules"][0]["client_chain"][0]["pool"][1]["protocol"]["peer_client_chain"] =
                json!([{"protocol": {"type": "direct"}, "tcp_settings": {"no_delay": false}}]);
            assert!(
                validate(conflict)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("conflicting")
            );
        }
    }

    #[test]
    fn copied_clients_share_local_addresses_with_different_prefix_lengths() {
        let mut second = client();
        second["protocol"]["addresses"] = json!(["10.77.0.2/24", "fd77::2/64"]);
        let validated = validate(copies(second)).unwrap();
        assert_eq!(validated.wireguard_endpoints.len(), 1);
        assert_eq!(
            validated.wireguard_endpoints[0].addresses,
            ["10.77.0.2/32", "fd77::2/128"]
        );
    }

    #[test]
    fn different_client_identities_do_not_share() {
        for (pointer, value) in [
            ("/address", json!("other.example:51820")),
            ("/protocol/private_key", json!(key(44))),
            ("/protocol/public_key", json!(key(45))),
        ] {
            let mut second = client();
            *second.pointer_mut(pointer).unwrap() = value;
            assert_eq!(
                validate(copies(second)).unwrap().wireguard_endpoints.len(),
                2
            );
        }
    }

    #[test]
    fn scoped_endpoints_share_by_address_and_numeric_scope() {
        let mut first = client();
        first["address"] = json!("[FE80:0:0::1%03]:51820");
        let mut second = first.clone();
        second["address"] = json!("[fe80::1%3]:51820");
        let configs = json!([
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"},
             "rules": [{"masks": "0.0.0.0/0", "action": "allow",
                        "client_chain": [{"pool": [first, second]}]}]},
        ]);
        let validated = validate(configs.clone()).unwrap();
        assert_eq!(validated.wireguard_endpoints.len(), 1);
        assert_eq!(
            validated.wireguard_endpoints[0].peers[0]
                .endpoint
                .as_deref(),
            Some("[fe80::1%3]:51820")
        );
        let mut different_scope = configs;
        different_scope[0]["rules"][0]["client_chain"][0]["pool"][1]["address"] =
            json!("[fe80::1%4]:51820");
        assert_eq!(
            validate(different_scope).unwrap().wireguard_endpoints.len(),
            2
        );
    }

    #[test]
    fn unused_groups_validate_without_starting_devices() {
        let configs = json!([{"client_group": "unused", "client_proxies": [client()]}]);
        assert!(
            validate(configs.clone())
                .unwrap()
                .wireguard_endpoints
                .is_empty()
        );
        let mut invalid = configs;
        invalid[0]["client_proxies"][0]["protocol"]["mtu"] = json!(9000);
        assert!(validate(invalid).is_err());
    }

    #[test]
    fn unused_wireguard_dns_groups_validate_without_starting_devices() {
        let configs = json!([
            {"dns_group": "unused", "dns_servers": [{"url": "tcp://192.0.2.53", "client_chain": [client()]}]},
            {"dns_group": "direct", "dns_servers": ["system"]},
            {"address": "0.0.0.0:1080", "protocol": {"type": "socks"}},
        ]);
        let validated = validate(configs.clone()).unwrap();
        assert!(validated.wireguard_endpoints.is_empty());
        assert_eq!(validated.dns_groups.len(), 1);
        assert_eq!(validated.dns_groups[0].name, "direct");

        let mut invalid = configs.clone();
        invalid[0]["dns_servers"][0]["client_chain"][0]["protocol"]["mtu"] = json!(9000);
        assert!(validate(invalid).is_err());

        let mut conflict = configs.clone();
        let mut second = client();
        second["protocol"]["pre_shared_key"] = json!(key(99));
        conflict[0]["dns_servers"][0]["client_chain"] =
            json!({"chain": [{"pool": [client(), second]}]});
        let error = validate(conflict).err().unwrap();
        assert!(error.to_string().contains("conflicting"), "{error}");

        for root in [
            json!({"address": "0.0.0.0:1080", "protocol": {"type": "socks"}}),
            json!({"device_fd": 7, "rules": "block-all"}),
            server(),
        ] {
            let mut referenced = configs.clone();
            referenced[2] = root;
            referenced[2]["dns"] = json!({"servers": "unused"});
            let validated = validate(referenced).unwrap();
            assert!(
                validated
                    .dns_groups
                    .iter()
                    .any(|group| group.name == "unused")
            );
            assert!(
                validated
                    .wireguard_endpoints
                    .iter()
                    .any(|device| device.inbound.is_none())
            );
        }

        let mut composed = configs;
        composed[2]["dns"] = json!({"servers": ["unused", "direct"]});
        let validated = validate(composed).unwrap();
        assert_eq!(validated.wireguard_endpoints.len(), 1);
        assert_eq!(validated.dns_groups.len(), 2);
        assert!(
            validated
                .dns_groups
                .iter()
                .all(|group| group.name != "unused")
        );
    }

    #[test]
    fn old_endpoint_forms_and_client_peer_lists_are_rejected() {
        for value in [
            json!([{"wireguard": "old", "private_key": key(42), "addresses": ["10.77.0.2/32"], "peers": []}]),
            json!([{"client_group": "old", "client_proxies": [{"protocol": {"type": "wireguard", "endpoint": "old"}}]}]),
        ] {
            assert!(validate(value).is_err());
        }
        for field in [
            "peers",
            "endpoint",
            "wireguard_name",
            "inbound",
            "listen",
            "outer_client_chain",
            "upstream_client_chain",
        ] {
            let mut invalid = client();
            invalid["protocol"][field] = json!([]);
            assert!(validate(copies(invalid)).is_err(), "accepted {field}");
        }
    }
}
