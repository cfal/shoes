use std::io;
use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::config::{
    Config, TunConfig,
    tun::{LinuxTunOptions, next_ip_address},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Spec {
    pub name: String,
    pub addresses: Vec<IpNetwork>,
    pub mtu: u16,
    pub offload: Option<bool>,
    pub routes: Vec<IpNetwork>,
    pub excludes: Vec<IpNetwork>,
    pub bootstrap_dns: Vec<SocketAddr>,
    pub redirect: bool,
    pub auto_dns: bool,
    pub dns_hijack: bool,
    pub icmp: bool,
    pub linux: LinuxTunOptions,
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

impl Spec {
    pub(crate) fn from_configs(configs: &[Config]) -> io::Result<Option<Self>> {
        let mut selected = None;
        for config in configs {
            let Config::TunServer(tun) = config else {
                continue;
            };
            if !tun.auto_route {
                if tun.has_managed_options() {
                    return Err(invalid("TUN network automation options require auto_route"));
                }
                continue;
            }
            if selected.is_some() {
                return Err(invalid("only one auto_route TUN is supported per process"));
            }
            selected = Some(Self::new(tun)?);
        }
        Ok(selected)
    }

    fn new(tun: &TunConfig) -> io::Result<Self> {
        if tun.address.is_some() || tun.netmask.is_some() || tun.destination.is_some() {
            return Err(invalid(
                "managed TUN uses addresses CIDRs, not manual address/netmask/destination settings",
            ));
        }
        if tun.device_fd.is_some() || tun.packet_information == Some(true) {
            return Err(invalid(
                "auto_route requires a Shoes-created Linux TUN without packet information",
            ));
        }
        let name = tun.device_name.as_deref().unwrap_or_default();
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || name == "."
            || name == ".."
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(invalid(
                "managed TUN device_name must be 1-15 ASCII letters, digits, '.', '_' or '-'",
            ));
        }
        if !tun.tcp_enabled || !tun.udp_enabled {
            return Err(invalid("managed TUN requires both TCP and UDP handling"));
        }
        if tun.addresses.is_empty() || tun.addresses.len() > 2 {
            return Err(invalid(
                "managed TUN requires one address per configured IP family",
            ));
        }
        if let [first, second] = tun.addresses.as_slice()
            && first.is_ipv6() == second.is_ipv6()
        {
            return Err(invalid(
                "managed TUN permits at most one address per IP family",
            ));
        }
        for network in &tun.addresses {
            let ip = network.ip();
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip != ip.to_canonical()
            {
                return Err(invalid("invalid managed TUN address"));
            }
        }
        if tun.mtu < 576 || (tun.addresses.iter().any(IpNetwork::is_ipv6) && tun.mtu < 1280) {
            return Err(invalid(
                "managed TUN MTU must be at least 576 (1280 with IPv6)",
            ));
        }
        let routes = if tun.route_address.is_empty() {
            vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
        } else {
            tun.route_address.clone()
        };
        for route in &routes {
            if !tun
                .addresses
                .iter()
                .any(|address| address.is_ipv6() == route.is_ipv6())
            {
                return Err(invalid(
                    "route_address selects an unconfigured IP family; configure both families or explicitly restrict route_address",
                ));
            }
        }
        if tun.bootstrap_dns.is_empty() || tun.bootstrap_dns.len() > 8 {
            return Err(invalid(
                "auto_route requires 1-8 literal bootstrap_dns socket addresses",
            ));
        }
        for endpoint in &tun.bootstrap_dns {
            let ip = endpoint.ip();
            if endpoint.port() == 0
                || matches!(endpoint, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0 || address.ip().is_unicast_link_local())
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip != ip.to_canonical()
                || tun.addresses.iter().any(|network| network.contains(ip))
            {
                return Err(invalid(
                    "bootstrap_dns must use nonlocal real upstream IP addresses, not a localhost stub or TUN subnet",
                ));
            }
        }
        let linux = tun.linux.clone().unwrap_or_default();
        if linux.table <= 255
            || linux.rule_priority == 0
            || linux.rule_priority >= 32766
            || !linux.capture_mark.is_power_of_two()
            || !linux.bypass_mark.is_power_of_two()
            || linux.capture_mark == linux.bypass_mark
            || linux.mark_mask != (linux.capture_mark | linux.bypass_mark)
        {
            return Err(invalid(
                "invalid managed Linux table, priority, or mark reservation",
            ));
        }
        let spec = Self {
            name: name.to_owned(),
            addresses: tun.addresses.clone(),
            mtu: tun.mtu,
            offload: tun.segmentation_offload,
            routes,
            excludes: tun.route_exclude_address.clone(),
            bootstrap_dns: tun.bootstrap_dns.clone(),
            redirect: tun.auto_redirect,
            auto_dns: tun.auto_dns.unwrap_or(true),
            dns_hijack: tun.dns_hijack.unwrap_or(true),
            icmp: tun.icmp_enabled,
            linux,
        };
        if spec.auto_dns && !spec.dns_hijack {
            return Err(invalid("auto_dns requires dns_hijack"));
        }
        if spec.auto_dns || spec.redirect {
            spec.dns_addresses()?;
        }
        Ok(spec)
    }

    pub(super) fn redirect_gateway(&self, ipv6: bool) -> Option<IpAddr> {
        self.addresses
            .iter()
            .find(|network| self.redirect && network.is_ipv6() == ipv6)
            .and_then(|network| next_ip_address(network.ip()))
    }

    pub(super) fn dns_addresses(&self) -> io::Result<Vec<IpAddr>> {
        self.addresses
            .iter()
            .map(|network| {
                let ip = next_ip_address(network.ip())
                    .ok_or_else(|| invalid("TUN address has no adjacent DNS address"))?;
                if !network.contains(ip)
                    || matches!(network, IpNetwork::V4(v4) if IpAddr::V4(v4.broadcast()) == ip)
                {
                    return Err(invalid(
                        "auto_dns/auto_redirect requires space after each TUN address for a virtual peer",
                    ));
                }
                Ok(ip)
            })
            .collect()
    }
}
