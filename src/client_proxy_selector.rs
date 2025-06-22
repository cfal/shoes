use log::{debug, error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::address::{Address, NetLocation};
use crate::address::{AddressMask, NetLocationMask};
use crate::option_util::OneOrSome;
use crate::resolver::{resolve_single_address, Resolver};

// If a hostname is provided in a rule, it won't be resolved,
// and the netmask field will be ignored.
// This is useful when a huge blocklist or rule list is provided.
// However, this means that the user needs to make sure DNS
// resolutions are not done manually before hitting the server.
// TODO: make this configurable.
// TODO: when this is enabled, it would be much faster to use a
// hash map to do a single lookup rather than traversing the rules
// Vec.
const DONT_RESOLVE_RULE_HOSTNAMES: bool = true;

#[derive(Debug)]
pub struct ConnectRule<T> {
    pub masks: Vec<NetLocationMask>,
    pub action: ConnectAction<T>,
}

impl<T> ConnectRule<T> {
    pub fn new(masks: Vec<NetLocationMask>, action: ConnectAction<T>) -> Self {
        Self { masks, action }
    }
}

#[derive(Debug)]
pub enum ConnectAction<T> {
    Allow {
        override_address: Option<NetLocation>,
        client_proxies: OneOrSome<T>,
        next_proxy_index: AtomicU32,
    },
    Block,
}

impl<T> ConnectAction<T> {
    pub fn new_allow(override_address: Option<NetLocation>, client_proxies: OneOrSome<T>) -> Self {
        ConnectAction::Allow {
            override_address,
            client_proxies,
            next_proxy_index: AtomicU32::new(0),
        }
    }

    pub fn new_block() -> Self {
        ConnectAction::Block
    }

    pub fn to_decision(&self, target_location: NetLocation) -> ConnectDecision<T> {
        match self {
            ConnectAction::Allow {
                override_address,
                client_proxies,
                next_proxy_index,
            } => {
                let client_proxy = match client_proxies {
                    OneOrSome::One(item) => item,
                    OneOrSome::Some(v) => select_proxy(v, next_proxy_index),
                };

                ConnectDecision::Allow {
                    client_proxy,
                    remote_location: match override_address {
                        Some(l) => {
                            if l.port() > 0 {
                                l.clone()
                            } else {
                                // If port of 0 is specified for the replacement location,
                                // take the requested port.
                                NetLocation::new(l.address().clone(), target_location.port())
                            }
                        }
                        None => target_location,
                    },
                }
            }
            ConnectAction::Block => ConnectDecision::Block,
        }
    }
}

#[derive(Debug)]
pub struct ClientProxySelector<T> {
    rules: Vec<ConnectRule<T>>,
    default_rule_index: Option<usize>,
}

unsafe impl<T: Send> Send for ClientProxySelector<T> {}

#[derive(Debug)]
pub enum ConnectDecision<'a, T> {
    Allow {
        client_proxy: &'a T,
        remote_location: NetLocation,
    },
    Block,
}

impl<T> ClientProxySelector<T> {
    pub fn new(rules: Vec<ConnectRule<T>>) -> Self {
        let mut default_rule_index: Option<usize> = None;
        // find a default rule which we'll use for multidirectional forwarding..
        // TODO: ideally, we'd check the rule for each target during multidirectional forwarding
        // and use the right one instead.
        for (i, rule) in rules.iter().enumerate() {
            // if it allows forwarding only to a single address, we don't want to use that as
            // the default decision.
            if let ConnectAction::Allow {
                ref override_address,
                ..
            } = rule.action
            {
                if override_address.is_some() {
                    continue;
                }
            }
            let is_cover_rule = rule.masks.iter().any(|mask| mask.address_mask.netmask == 0);
            if is_cover_rule {
                default_rule_index = Some(i);
                break;
            }
        }
        Self {
            rules,
            default_rule_index,
        }
    }

    pub fn default_decision(&self) -> ConnectDecision<'_, T> {
        match self.default_rule_index {
            Some(i) => {
                let rule = &self.rules[i];
                // the remote location is unused because we don't choose a default rule with
                // an override_address, so just pass a port of 0.
                rule.action.to_decision(NetLocation::UNSPECIFIED)
            }
            None => ConnectDecision::Block,
        }
    }

    pub async fn judge<'a>(
        &'a self,
        location: NetLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a, T>> {
        match match_rule(&self.rules, &location, resolver).await? {
            Some(rule) => Ok(rule.action.to_decision(location)),
            None => Ok(ConnectDecision::Block),
        }
    }
}

#[inline]
fn select_proxy<'a, T>(proxy_list: &'a [T], index: &'a AtomicU32) -> &'a T {
    match proxy_list.len() {
        0 => {
            panic!("Empty proxy list");
        }
        1 => &proxy_list[0],
        _ => {
            let proxy_index = index.fetch_add(1, Ordering::Relaxed) as usize;
            &proxy_list[proxy_index % proxy_list.len()]
        }
    }
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => ipv4_to_u128(addr),
        IpAddr::V6(addr) => ipv6_to_u128(addr),
    }
}

#[inline]
fn ipv4_to_u128(ip: Ipv4Addr) -> u128 {
    ipv6_to_u128(ip.to_ipv6_mapped())
}

#[inline]
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

#[inline]
fn matches_domain(base_domain: &str, hostname: &str) -> bool {
    if hostname.ends_with(base_domain) {
        let hostname_len = hostname.len();
        let base_domain_len = base_domain.len();
        if hostname_len == base_domain_len {
            true
        } else {
            // hostname_len > base_domain_len since hostname ends with base_domain.
            hostname.as_bytes()[hostname_len - base_domain_len - 1] == b'.'
        }
    } else {
        false
    }
}

#[inline]
async fn match_rule<'a, T>(
    rules: &'a [ConnectRule<T>],
    location: &NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Option<&'a ConnectRule<T>>> {
    // We only resolve when necessary.
    let mut resolved_ip: Option<u128> = None;

    for rule in rules.iter() {
        for mask in rule.masks.iter() {
            match match_mask(mask, location, &mut resolved_ip, resolver).await {
                Ok(is_match) => {
                    if is_match {
                        debug!("Found matching mask for {} -> {:?}", location, mask);
                        return Ok(Some(rule));
                    }
                }
                Err(MatchMaskError::Fatal(e)) => {
                    return Err(std::io::Error::other(
                        format!("fatal error while matching mask for {}: {}", location, e),
                    ));
                }
                Err(MatchMaskError::NonFatal(e)) => {
                    error!(
                        "Non-fatal error while trying to match mask for {}: {}",
                        location, e
                    );
                }
            }
        }
    }
    Ok(None)
}

enum MatchMaskError {
    NonFatal(std::io::Error),
    Fatal(std::io::Error),
}

#[inline]
async fn match_mask(
    location_mask: &NetLocationMask,
    location: &NetLocation,
    resolved_ip: &mut Option<u128>,
    resolver: &Arc<dyn Resolver>,
) -> std::result::Result<bool, MatchMaskError> {
    let NetLocationMask {
        address_mask: AddressMask { address, netmask },
        port,
    } = location_mask;

    let netmask = *netmask;
    let port = *port;

    if port > 0 && port != location.port() {
        return Ok(false);
    }

    if netmask == 0 {
        return Ok(true);
    }

    if let Some(hostname) = address.hostname() {
        if let Some(remote_hostname) = location.address().hostname() {
            return Ok(matches_domain(hostname, remote_hostname));
        }

        // We don't care about netmasks when hostnames are provided, so we can do direct matching
        // without resolving when both the remote location and the provided rule address are hostnames,
        // and simploy return if it doesn't match.
        if DONT_RESOLVE_RULE_HOSTNAMES {
            return Ok(false);
        }
    }

    let masked_ip = match resolved_ip {
        Some(ip) => *ip,
        None => {
            // fatal error if the destination we are trying to get to cannot be resolved.
            let socket_addr = resolve_single_address(resolver, location)
                .await
                .map_err(MatchMaskError::Fatal)?;
            let ip = ip_to_u128(socket_addr.ip());
            resolved_ip.replace(ip);
            ip
        }
    } & netmask;

    match address {
        Address::Ipv4(ip_addr) => {
            let mask = ipv4_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Ipv6(ip_addr) => {
            let mask = ipv6_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Hostname(_) => {
            // non-fatal error when the rule address cannot be resolved.
            // TODO: could this be cached?
            let socket_addrs = resolver
                .resolve_location(&NetLocation::new(address.clone(), port))
                .await
                .map_err(MatchMaskError::NonFatal)?;
            for socket_addr in socket_addrs {
                let mask = ip_to_u128(socket_addr.ip()) & netmask;
                if mask == masked_ip {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
