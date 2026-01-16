//! DNS configuration types.

use serde::{Deserialize, Serialize};

use crate::config::types::rules::ClientChain;
use crate::config::types::selection::ConfigSelection;
use crate::dns::IpStrategy;
use crate::option_util::NoneOrSome;

/// A DNS server specification in config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DnsServerSpec {
    /// Simple URL string: "system", "udp://8.8.8.8", etc.
    /// Must be IP-based (no hostnames). Cannot have bootstrap_url.
    Simple(String),
    /// Object with URL and optional client_chain, bootstrap_url, server_name, ip_strategy.
    WithOptions {
        url: String,
        #[serde(default)]
        client_chain: NoneOrSome<ConfigSelection<ClientChain>>,
        /// Bootstrap resolver for hostname resolution.
        /// Can be a URL string (e.g., "udp://8.8.8.8") or a dns_group name.
        #[serde(default)]
        bootstrap_url: Option<String>,
        /// SNI server name override for TLS/HTTPS. Defaults to hostname from URL.
        #[serde(default)]
        server_name: Option<String>,
        /// IP lookup strategy for DNS resolution. Defaults to ipv4_then_ipv6.
        #[serde(default)]
        ip_strategy: IpStrategy,
    },
}

impl DnsServerSpec {
    /// Check if a string looks like a DNS URL (has known scheme) vs a group reference.
    fn is_url_string(s: &str) -> bool {
        s == "system" || s.contains("://")
    }

    /// Get the group name if this is a group reference.
    pub fn as_group_ref(&self) -> Option<&str> {
        if let Self::Simple(s) = self {
            if !Self::is_url_string(s) {
                return Some(s);
            }
        }
        None
    }

    /// Get the URL string from this spec.
    /// Panics if called on a group reference - use as_group_ref() to check first.
    pub fn url(&self) -> &str {
        match self {
            Self::Simple(s) => {
                debug_assert!(Self::is_url_string(s), "called url() on group reference");
                s
            }
            Self::WithOptions { url, .. } => url,
        }
    }

    /// Get the client_chain.
    pub fn client_chains(&self) -> &NoneOrSome<ConfigSelection<ClientChain>> {
        static NONE: NoneOrSome<ConfigSelection<ClientChain>> = NoneOrSome::None;
        if let Self::WithOptions { client_chain, .. } = self {
            client_chain
        } else {
            &NONE
        }
    }

    /// Get the bootstrap_url if present.
    pub fn bootstrap_url(&self) -> Option<&str> {
        if let Self::WithOptions { bootstrap_url, .. } = self {
            bootstrap_url.as_deref()
        } else {
            None
        }
    }

    /// Get the server_name override if present.
    pub fn server_name(&self) -> Option<&str> {
        if let Self::WithOptions { server_name, .. } = self {
            server_name.as_deref()
        } else {
            None
        }
    }

    /// Get the ip_strategy (defaults to Ipv4ThenIpv6 for Simple variant).
    pub fn ip_strategy(&self) -> IpStrategy {
        if let Self::WithOptions { ip_strategy, .. } = self {
            *ip_strategy
        } else {
            IpStrategy::default()
        }
    }
}

/// DNS group configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfigGroup {
    pub dns_group: String,
    #[serde(alias = "dns_server")]
    pub dns_servers: NoneOrSome<DnsServerSpec>,
}

/// DNS configuration for servers.
/// The `servers` field can be a group name, inline specs, or None (use default).
/// After validation, `servers` is mutated to a single group name reference.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(alias = "server")]
    pub servers: NoneOrSome<DnsServerSpec>,
}

impl DnsConfig {
    /// Get the resolved group name after validation.
    /// Returns None if servers was None/Unspecified (use default system resolver).
    /// Panics if called before validation or if servers wasn't resolved properly.
    pub fn resolved_group(&self) -> Option<&str> {
        match &self.servers {
            NoneOrSome::Unspecified | NoneOrSome::None => None,
            NoneOrSome::One(spec) => Some(
                spec.as_group_ref()
                    .expect("DnsConfig.servers should be a single group name after validation"),
            ),
            NoneOrSome::Some(_) => {
                panic!("DnsConfig.servers should be a single group name after validation")
            }
        }
    }
}

/// A DNS server spec with all group references expanded.
/// Client chains contain actual ClientConfig objects, not group names.
#[derive(Debug, Clone)]
pub struct ExpandedDnsSpec {
    pub url: String,
    pub server_name: Option<String>,
    /// Client chains with all group refs resolved to configs.
    pub client_chains: Vec<ClientChain>,
    /// Bootstrap resolver URL or group name. Groups are resolved at runtime.
    pub bootstrap_url: Option<String>,
    pub ip_strategy: IpStrategy,
}

/// A DNS group with all specs expanded.
#[derive(Debug, Clone)]
pub struct ExpandedDnsGroup {
    pub name: String,
    pub specs: Vec<ExpandedDnsSpec>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_server_spec_simple() {
        let yaml = r#"system"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(spec, DnsServerSpec::Simple(ref s) if s == "system"));
        assert_eq!(spec.url(), "system");
        assert!(spec.client_chains().is_empty());
    }

    #[test]
    fn test_dns_server_spec_url() {
        let yaml = r#"udp://8.8.8.8"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "udp://8.8.8.8");
    }

    #[test]
    fn test_dns_server_spec_with_chain() {
        let yaml = r#"
url: https://1.1.1.1/dns-query
client_chain: my-proxy
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "https://1.1.1.1/dns-query");
        assert!(!spec.client_chains().is_empty());
        assert!(spec.bootstrap_url().is_none());
        assert!(spec.server_name().is_none());
    }

    #[test]
    fn test_dns_server_spec_with_bootstrap() {
        let yaml = r#"
url: tls://dns.google
bootstrap_url: udp://8.8.8.8
server_name: dns.google
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "tls://dns.google");
        assert!(spec.client_chains().is_empty());
        assert_eq!(spec.bootstrap_url(), Some("udp://8.8.8.8"));
        assert_eq!(spec.server_name(), Some("dns.google"));
    }

    #[test]
    fn test_dns_server_spec_with_bootstrap_group_ref() {
        let yaml = r#"
url: https://cloudflare-dns.com/dns-query
client_chain: privacy-proxy
bootstrap_url: fast-dns
"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.url(), "https://cloudflare-dns.com/dns-query");
        assert!(!spec.client_chains().is_empty());
        assert_eq!(spec.bootstrap_url(), Some("fast-dns"));
    }

    #[test]
    fn test_dns_config_group() {
        let yaml = r#"
dns_group: my-dns
dns_servers:
  - system
  - udp://8.8.8.8
  - url: https://1.1.1.1/dns-query
    client_chain: proxy-group
"#;
        let group: DnsConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(group.dns_group, "my-dns");
        let servers = group.dns_servers.into_vec();
        assert_eq!(servers.len(), 3);
    }

    #[test]
    fn test_dns_config_bare_group_name_rejected() {
        // Bare group names are not allowed - must use servers field
        let yaml = r#"my-dns-group"#;
        let result: Result<DnsConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "bare group name should be rejected");
    }

    #[test]
    fn test_dns_config_with_servers() {
        let yaml = r#"
servers:
  - system
  - udp://8.8.8.8
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        let servers = config.servers.into_vec();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_dns_config_with_servers_group_ref() {
        // Group reference inside servers field is allowed
        let yaml = r#"
servers: my-dns-group
"#;
        let config: DnsConfig = serde_yaml::from_str(yaml).unwrap();
        let servers = config.servers.into_vec();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].as_group_ref().is_some());
        assert_eq!(servers[0].as_group_ref(), Some("my-dns-group"));
    }

    #[test]
    fn test_dns_config_resolved_group() {
        // After validation, servers should be a single group name
        let config = DnsConfig {
            servers: NoneOrSome::One(DnsServerSpec::Simple("my-resolved-group".to_string())),
        };
        assert_eq!(config.resolved_group(), Some("my-resolved-group"));
    }

    #[test]
    fn test_dns_server_spec_group_ref() {
        // Group reference (no URL scheme)
        let yaml = r#"base-dns"#;
        let spec: DnsServerSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(spec.as_group_ref().is_some());
        assert_eq!(spec.as_group_ref(), Some("base-dns"));
    }

    #[test]
    fn test_dns_server_spec_url_not_group_ref() {
        // URLs should not be detected as group refs
        for url in [
            "system",
            "udp://8.8.8.8",
            "tcp://1.1.1.1",
            "tls://dns.google",
            "https://cloudflare.com/dns-query",
            "h3://cloudflare.com/dns-query",
        ] {
            let spec = DnsServerSpec::Simple(url.to_string());
            assert!(
                !spec.as_group_ref().is_some(),
                "{} should not be a group ref",
                url
            );
            assert!(spec.as_group_ref().is_none());
        }
    }

    #[test]
    fn test_dns_server_spec_with_options_not_group_ref() {
        // WithOptions is never a group ref
        let spec = DnsServerSpec::WithOptions {
            url: "tls://dns.google".to_string(),
            client_chain: NoneOrSome::None,
            bootstrap_url: None,
            server_name: None,
            ip_strategy: IpStrategy::default(),
        };
        assert!(!spec.as_group_ref().is_some());
        assert!(spec.as_group_ref().is_none());
    }

    #[test]
    fn test_dns_group_with_composition() {
        let yaml = r#"
dns_group: full-dns
dns_servers:
  - base-dns
  - fast-dns
  - tls://1.1.1.1
"#;
        let group: DnsConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(group.dns_group, "full-dns");
        let servers = group.dns_servers.into_vec();
        assert_eq!(servers.len(), 3);
        assert!(servers[0].as_group_ref().is_some());
        assert_eq!(servers[0].as_group_ref(), Some("base-dns"));
        assert!(servers[1].as_group_ref().is_some());
        assert_eq!(servers[1].as_group_ref(), Some("fast-dns"));
        assert!(!servers[2].as_group_ref().is_some());
    }
}
