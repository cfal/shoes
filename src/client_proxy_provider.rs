use log::{debug, error};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::address::{Address, Location};
use crate::address::{AddressMask, LocationMask};
use crate::async_tls::AsyncTlsFactory;
use crate::client_proxy::ClientProxy;
use crate::config::{ClientConfig, Rule, RuleAction};
use crate::resolver::Resolver;

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

struct ProcessedRule {
    masks: Vec<LocationMask>,
    action: ProcessedAction,
}

enum ProcessedAction {
    Allow {
        replacement_location: Option<Location>,
        proxies: Vec<ClientProxy>,
        next_proxy_index: AtomicU32,
    },
    Block,
}

pub struct ClientProxyProvider {
    default_proxies: Vec<ClientProxy>,
    next_default_proxy_index: AtomicU32,
    rules: Vec<ProcessedRule>,
}

unsafe impl Send for ClientProxyProvider {}

pub enum ProxyAction<'a> {
    Connect {
        client_proxy: Option<&'a ClientProxy>,
        remote_location: Location,
    },
    Block,
}

impl ClientProxyProvider {
    pub fn new(
        default_proxy_configs: Vec<ClientConfig>,
        rules: Vec<Rule>,
        tls_factory: &Arc<dyn AsyncTlsFactory>,
    ) -> Self {
        let rules = rules
            .into_iter()
            .map(|rule| {
                let Rule { masks, action } = rule;

                let action = match action {
                    RuleAction::Allow {
                        replacement_location,
                        proxies,
                    } => ProcessedAction::Allow {
                        replacement_location,
                        proxies: ClientProxy::from_configs(proxies, tls_factory),
                        next_proxy_index: AtomicU32::new(0),
                    },
                    RuleAction::Block => ProcessedAction::Block,
                };

                ProcessedRule { masks, action }
            })
            .collect();

        Self {
            default_proxies: ClientProxy::from_configs(default_proxy_configs, tls_factory),
            next_default_proxy_index: AtomicU32::new(0),
            rules,
        }
    }

    pub async fn get_action<'a>(
        &'a self,
        location: Location,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ProxyAction<'a>> {
        let (address, port) = location.components();

        // We only resolve when necessary.
        let mut resolved_ip: Option<u128> = None;

        for rule in self.rules.iter() {
            let mut matches = false;
            for mask in rule.masks.iter() {
                match match_mask(mask, address, port, &mut resolved_ip, resolver).await {
                    Ok(is_match) => {
                        if is_match {
                            debug!(
                                "Found matching mask for {:?}:{} -> {:?}",
                                address, port, mask
                            );
                            matches = true;
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to match mask for {:?}:{}: {}", address, port, e);
                    }
                }
            }
            if !matches {
                continue;
            }

            match &rule.action {
                ProcessedAction::Allow {
                    replacement_location,
                    proxies,
                    next_proxy_index,
                } => {
                    let client_proxy = if proxies.len() == 0 {
                        None
                    } else {
                        let proxy_index = next_proxy_index.fetch_add(1, Ordering::Relaxed) as usize;
                        Some(&proxies[proxy_index % proxies.len()])
                    };

                    return Ok(ProxyAction::Connect {
                        client_proxy,
                        remote_location: match replacement_location {
                            Some(l) => {
                                if l.port() > 0 {
                                    l.clone()
                                } else {
                                    // If port of 0 is specified for the replacement location,
                                    // take the requested port.
                                    Location::new(l.address().clone(), port)
                                }
                            }
                            None => location,
                        },
                    });
                }
                ProcessedAction::Block => {
                    return Ok(ProxyAction::Block);
                }
            }
        }

        let client_proxy = if self.default_proxies.len() == 0 {
            None
        } else {
            let proxy_index = self
                .next_default_proxy_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            Some(&self.default_proxies[proxy_index % self.default_proxies.len()])
        };
        Ok(ProxyAction::Connect {
            client_proxy,
            remote_location: location,
        })
    }
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => u32::from(addr) as u128,
        IpAddr::V6(addr) => u128::from(addr),
    }
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
async fn match_mask(
    location_mask: &LocationMask,
    remote_address: &Address,
    remote_port: u16,
    resolved_ip: &mut Option<u128>,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<bool> {
    let LocationMask {
        address_mask: AddressMask { address, netmask },
        port,
    } = location_mask;

    let netmask = *netmask;
    let port = *port;

    if port > 0 && port != remote_port {
        return Ok(false);
    }

    if DONT_RESOLVE_RULE_HOSTNAMES {
        if let Some(hostname) = address.hostname() {
            match remote_address.hostname() {
                Some(remote_hostname) => {
                    return Ok(matches_domain(hostname, remote_hostname));
                }
                None => {
                    return Ok(false);
                }
            }
        }
    }

    if remote_address.is_hostname() && address.is_hostname() && netmask == u128::MAX {
        // We can do a direct hostname match without resolving.
        return Ok(matches_domain(
            address.hostname().unwrap(),
            remote_address.hostname().unwrap(),
        ));
    }

    let masked_ip = match resolved_ip {
        Some(ip) => *ip,
        None => {
            let ip = ip_to_u128(resolver.resolve_single_address(remote_address).await?);
            resolved_ip.replace(ip);
            ip
        }
    } & netmask;

    for ip_addr in resolver.resolve_address(address).await? {
        let mask = ip_to_u128(ip_addr) & netmask;
        if mask == masked_ip {
            return Ok(true);
        }
    }

    Ok(false)
}
