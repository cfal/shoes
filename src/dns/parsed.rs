//! Parsed and validated DNS server configuration types.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::config::LookupIpStrategy;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;

/// IP lookup strategy for DNS resolution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    /// Only query A records (IPv4).
    Ipv4Only,
    /// Only query AAAA records (IPv6).
    Ipv6Only,
    /// Query A and AAAA in parallel.
    Ipv4AndIpv6,
    /// Query A first, fall back to AAAA (default).
    #[default]
    Ipv4ThenIpv6,
    /// Query AAAA first, fall back to A.
    Ipv6ThenIpv4,
}

impl IpStrategy {
    /// Convert to hickory's LookupIpStrategy.
    pub fn to_hickory(self) -> LookupIpStrategy {
        match self {
            Self::Ipv4Only => LookupIpStrategy::Ipv4Only,
            Self::Ipv6Only => LookupIpStrategy::Ipv6Only,
            Self::Ipv4AndIpv6 => LookupIpStrategy::Ipv4AndIpv6,
            Self::Ipv4ThenIpv6 => LookupIpStrategy::Ipv4thenIpv6,
            Self::Ipv6ThenIpv4 => LookupIpStrategy::Ipv6thenIpv4,
        }
    }
}

/// Parsed DNS server with chain group, bootstrap resolver, and IP strategy.
#[derive(Debug)]
pub struct ParsedDnsServerEntry {
    pub server: ParsedDnsServer,
    /// Always present - direct chain if no client_chain configured.
    pub client_chain: Arc<ClientChainGroup>,
    /// Bootstrap resolver for proxy hostname resolution at runtime.
    pub bootstrap_resolver: Arc<dyn Resolver>,
    /// IP lookup strategy (IPv4/IPv6 selection).
    pub ip_strategy: IpStrategy,
}

impl ParsedDnsServerEntry {
    /// Create entry with the given chain group, bootstrap resolver, and IP strategy.
    pub fn new(
        server: ParsedDnsServer,
        chain: Arc<ClientChainGroup>,
        bootstrap: Arc<dyn Resolver>,
        ip_strategy: IpStrategy,
    ) -> Self {
        Self {
            server,
            client_chain: chain,
            bootstrap_resolver: bootstrap,
            ip_strategy,
        }
    }
}

/// Parsed and validated DNS server configuration.
/// The addr field is always a resolved IP address.
#[derive(Debug, Clone)]
pub enum ParsedDnsServer {
    /// System resolver (NativeResolver).
    System,

    /// UDP DNS server.
    Udp { addr: SocketAddr },

    /// TCP DNS server.
    Tcp { addr: SocketAddr },

    /// DNS-over-TLS.
    Tls {
        addr: SocketAddr,
        server_name: Arc<str>,
    },

    /// DNS-over-HTTPS.
    Https {
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    },

    /// DNS-over-HTTP/3.
    H3 {
        addr: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    },
}

/// Host parsed from a DNS URL - can be IP or hostname.
#[derive(Debug, Clone)]
pub enum DnsHost {
    Ip(IpAddr),
    Hostname(String),
}

impl DnsHost {
    /// Get the hostname string if this is a hostname, None if IP.
    pub fn as_hostname(&self) -> Option<&str> {
        match self {
            Self::Hostname(s) => Some(s),
            Self::Ip(_) => None,
        }
    }
}

/// Intermediate parsed DNS URL that might have a hostname (not yet resolved).
#[derive(Debug, Clone)]
pub enum ParsedDnsUrl {
    /// System resolver.
    System,

    /// UDP DNS server.
    Udp { host: DnsHost, port: u16 },

    /// TCP DNS server.
    Tcp { host: DnsHost, port: u16 },

    /// DNS-over-TLS.
    Tls {
        host: DnsHost,
        port: u16,
        server_name: String,
    },

    /// DNS-over-HTTPS.
    Https {
        host: DnsHost,
        port: u16,
        server_name: String,
        path: String,
    },

    /// DNS-over-HTTP/3.
    H3 {
        host: DnsHost,
        port: u16,
        server_name: String,
        path: String,
    },
}

impl ParsedDnsUrl {
    /// Parse a DNS server URL string. Host can be IP or hostname.
    pub fn parse(url_str: &str) -> Result<Self, DnsConfigError> {
        Self::parse_with_server_name(url_str, None)
    }

    /// Parse a DNS server URL string with optional server_name override.
    pub fn parse_with_server_name(
        url_str: &str,
        server_name_override: Option<&str>,
    ) -> Result<Self, DnsConfigError> {
        if url_str == "system" {
            return Ok(Self::System);
        }

        let url = Url::parse(url_str)
            .map_err(|e| DnsConfigError::InvalidUrl(url_str.to_string(), e.to_string()))?;

        let scheme = url.scheme();
        let host_str = url
            .host_str()
            .ok_or_else(|| DnsConfigError::MissingHost(url_str.to_string()))?;

        // Parse host as IP or keep as hostname
        let host = match host_str.parse::<IpAddr>() {
            Ok(ip) => DnsHost::Ip(ip),
            Err(_) => DnsHost::Hostname(host_str.to_string()),
        };

        // server_name defaults to the host string from URL
        let server_name = server_name_override
            .map(String::from)
            .unwrap_or_else(|| host_str.to_string());

        match scheme {
            "udp" => {
                let port = url.port().unwrap_or(53);
                Ok(Self::Udp { host, port })
            }
            "tcp" => {
                let port = url.port().unwrap_or(53);
                Ok(Self::Tcp { host, port })
            }
            "tls" => {
                let port = url.port().unwrap_or(853);
                Ok(Self::Tls {
                    host,
                    port,
                    server_name,
                })
            }
            "https" => {
                let port = url.port().unwrap_or(443);
                let path = url.path().to_string();
                Ok(Self::Https {
                    host,
                    port,
                    server_name,
                    path,
                })
            }
            "h3" => {
                let port = url.port().unwrap_or(443);
                let path = url.path().to_string();
                Ok(Self::H3 {
                    host,
                    port,
                    server_name,
                    path,
                })
            }
            _ => Err(DnsConfigError::UnsupportedScheme(scheme.to_string())),
        }
    }

    /// Returns true if this URL contains a hostname (needs resolution).
    pub fn has_hostname(&self) -> bool {
        self.hostname().is_some()
    }

    /// Returns the hostname if this URL contains one, None if IP or system.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::System => None,
            Self::Udp { host, .. }
            | Self::Tcp { host, .. }
            | Self::Tls { host, .. }
            | Self::Https { host, .. }
            | Self::H3 { host, .. } => host.as_hostname(),
        }
    }

    /// Convert to ParsedDnsServer with a resolved IP address.
    pub fn to_parsed_server(&self, resolved_ip: Option<IpAddr>) -> Result<ParsedDnsServer, DnsConfigError> {
        match self {
            Self::System => Ok(ParsedDnsServer::System),
            Self::Udp { host, port } => {
                let ip = Self::get_ip(host, resolved_ip)?;
                Ok(ParsedDnsServer::Udp {
                    addr: SocketAddr::new(ip, *port),
                })
            }
            Self::Tcp { host, port } => {
                let ip = Self::get_ip(host, resolved_ip)?;
                Ok(ParsedDnsServer::Tcp {
                    addr: SocketAddr::new(ip, *port),
                })
            }
            Self::Tls {
                host,
                port,
                server_name,
            } => {
                let ip = Self::get_ip(host, resolved_ip)?;
                Ok(ParsedDnsServer::Tls {
                    addr: SocketAddr::new(ip, *port),
                    server_name: Arc::from(server_name.as_str()),
                })
            }
            Self::Https {
                host,
                port,
                server_name,
                path,
            } => {
                let ip = Self::get_ip(host, resolved_ip)?;
                Ok(ParsedDnsServer::Https {
                    addr: SocketAddr::new(ip, *port),
                    server_name: Arc::from(server_name.as_str()),
                    path: Arc::from(path.as_str()),
                })
            }
            Self::H3 {
                host,
                port,
                server_name,
                path,
            } => {
                let ip = Self::get_ip(host, resolved_ip)?;
                Ok(ParsedDnsServer::H3 {
                    addr: SocketAddr::new(ip, *port),
                    server_name: Arc::from(server_name.as_str()),
                    path: Arc::from(path.as_str()),
                })
            }
        }
    }

    fn get_ip(host: &DnsHost, resolved_ip: Option<IpAddr>) -> Result<IpAddr, DnsConfigError> {
        match host {
            DnsHost::Ip(ip) => Ok(*ip),
            DnsHost::Hostname(hostname) => resolved_ip
                .ok_or_else(|| DnsConfigError::HostnameNotResolved(hostname.clone())),
        }
    }
}

/// Errors that can occur when parsing DNS configuration.
#[derive(Debug)]
pub enum DnsConfigError {
    InvalidUrl(String, String),
    MissingHost(String),
    HostnameNotResolved(String),
    UnsupportedScheme(String),
}

impl std::fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url, err) => write!(f, "invalid DNS URL '{}': {}", url, err),
            Self::MissingHost(url) => write!(f, "DNS URL missing host: {}", url),
            Self::HostnameNotResolved(host) => {
                write!(f, "hostname not resolved: {}", host)
            }
            Self::UnsupportedScheme(scheme) => write!(f, "unsupported DNS scheme: {}", scheme),
        }
    }
}

impl std::error::Error for DnsConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_system() {
        let url = ParsedDnsUrl::parse("system").unwrap();
        assert!(matches!(url, ParsedDnsUrl::System));
        let server = url.to_parsed_server(None).unwrap();
        assert!(matches!(server, ParsedDnsServer::System));
    }

    #[test]
    fn test_parse_udp_ip() {
        let url = ParsedDnsUrl::parse("udp://8.8.8.8").unwrap();
        match &url {
            ParsedDnsUrl::Udp { host, port } => {
                assert!(matches!(host, DnsHost::Ip(_)));
                assert_eq!(*port, 53);
            }
            _ => panic!("expected Udp"),
        }
        assert!(!url.has_hostname());

        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Udp { addr } => {
                assert_eq!(addr.ip().to_string(), "8.8.8.8");
                assert_eq!(addr.port(), 53);
            }
            _ => panic!("expected Udp"),
        }
    }

    #[test]
    fn test_parse_udp_custom_port() {
        let url = ParsedDnsUrl::parse("udp://8.8.8.8:5353").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Udp { addr } => {
                assert_eq!(addr.port(), 5353);
            }
            _ => panic!("expected Udp"),
        }
    }

    #[test]
    fn test_parse_tcp_ip() {
        let url = ParsedDnsUrl::parse("tcp://1.1.1.1").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Tcp { addr } => {
                assert_eq!(addr.ip().to_string(), "1.1.1.1");
                assert_eq!(addr.port(), 53);
            }
            _ => panic!("expected Tcp"),
        }
    }

    #[test]
    fn test_parse_tls_ip() {
        let url = ParsedDnsUrl::parse("tls://1.1.1.1").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Tls { addr, server_name } => {
                assert_eq!(addr.ip().to_string(), "1.1.1.1");
                assert_eq!(addr.port(), 853);
                assert_eq!(&*server_name, "1.1.1.1");
            }
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_https_ip() {
        let url = ParsedDnsUrl::parse("https://1.1.1.1/dns-query").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Https {
                addr,
                server_name,
                path,
            } => {
                assert_eq!(addr.ip().to_string(), "1.1.1.1");
                assert_eq!(addr.port(), 443);
                assert_eq!(&*server_name, "1.1.1.1");
                assert_eq!(&*path, "/dns-query");
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_parse_https_root_path() {
        // URL parser returns "/" when no path is specified
        let url = ParsedDnsUrl::parse("https://8.8.8.8").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::Https { path, .. } => {
                assert_eq!(&*path, "/");
            }
            _ => panic!("expected Https"),
        }
    }

    #[test]
    fn test_parse_h3_ip() {
        let url = ParsedDnsUrl::parse("h3://1.1.1.1/dns-query").unwrap();
        let server = url.to_parsed_server(None).unwrap();
        match server {
            ParsedDnsServer::H3 {
                addr,
                server_name,
                path,
            } => {
                assert_eq!(addr.ip().to_string(), "1.1.1.1");
                assert_eq!(addr.port(), 443);
                assert_eq!(&*server_name, "1.1.1.1");
                assert_eq!(&*path, "/dns-query");
            }
            _ => panic!("expected H3"),
        }
    }

    #[test]
    fn test_parse_h3_hostname() {
        let url = ParsedDnsUrl::parse("h3://cloudflare-dns.com/dns-query").unwrap();
        assert!(url.has_hostname());
        match &url {
            ParsedDnsUrl::H3 {
                host,
                port,
                server_name,
                path,
            } => {
                assert!(matches!(host, DnsHost::Hostname(h) if h == "cloudflare-dns.com"));
                assert_eq!(*port, 443);
                assert_eq!(server_name, "cloudflare-dns.com");
                assert_eq!(path, "/dns-query");
            }
            _ => panic!("expected H3"),
        }
    }

    #[test]
    fn test_parse_hostname() {
        let url = ParsedDnsUrl::parse("tls://dns.google").unwrap();
        assert!(url.has_hostname());
        match &url {
            ParsedDnsUrl::Tls {
                host, server_name, ..
            } => {
                assert!(matches!(host, DnsHost::Hostname(h) if h == "dns.google"));
                assert_eq!(server_name, "dns.google");
            }
            _ => panic!("expected Tls"),
        }

        // Without resolved IP, should error
        let result = url.to_parsed_server(None);
        assert!(result.is_err());

        // With resolved IP, should succeed
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let server = url.to_parsed_server(Some(ip)).unwrap();
        match server {
            ParsedDnsServer::Tls { addr, server_name } => {
                assert_eq!(addr.ip().to_string(), "8.8.8.8");
                assert_eq!(&*server_name, "dns.google");
            }
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_with_server_name_override() {
        let url =
            ParsedDnsUrl::parse_with_server_name("tls://1.2.3.4", Some("dns.example.com")).unwrap();
        match url {
            ParsedDnsUrl::Tls { server_name, .. } => {
                assert_eq!(server_name, "dns.example.com");
            }
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = ParsedDnsUrl::parse("quic://8.8.8.8");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DnsConfigError::UnsupportedScheme(_)
        ));
    }

    #[test]
    fn test_ip_strategy_serde() {
        // Test deserialization
        assert_eq!(serde_yaml::from_str::<IpStrategy>("ipv4_only").unwrap(), IpStrategy::Ipv4Only);
        assert_eq!(serde_yaml::from_str::<IpStrategy>("ipv6_only").unwrap(), IpStrategy::Ipv6Only);
        assert_eq!(serde_yaml::from_str::<IpStrategy>("ipv4_and_ipv6").unwrap(), IpStrategy::Ipv4AndIpv6);
        assert_eq!(serde_yaml::from_str::<IpStrategy>("ipv4_then_ipv6").unwrap(), IpStrategy::Ipv4ThenIpv6);
        assert_eq!(serde_yaml::from_str::<IpStrategy>("ipv6_then_ipv4").unwrap(), IpStrategy::Ipv6ThenIpv4);
    }

    #[test]
    fn test_ip_strategy_serde_invalid() {
        let result = serde_yaml::from_str::<IpStrategy>("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_strategy_default() {
        assert_eq!(IpStrategy::default(), IpStrategy::Ipv4ThenIpv6);
    }

    #[test]
    fn test_ip_strategy_to_hickory() {
        assert!(matches!(
            IpStrategy::Ipv4Only.to_hickory(),
            LookupIpStrategy::Ipv4Only
        ));
        assert!(matches!(
            IpStrategy::Ipv6Only.to_hickory(),
            LookupIpStrategy::Ipv6Only
        ));
        assert!(matches!(
            IpStrategy::Ipv4AndIpv6.to_hickory(),
            LookupIpStrategy::Ipv4AndIpv6
        ));
        assert!(matches!(
            IpStrategy::Ipv4ThenIpv6.to_hickory(),
            LookupIpStrategy::Ipv4thenIpv6
        ));
        assert!(matches!(
            IpStrategy::Ipv6ThenIpv4.to_hickory(),
            LookupIpStrategy::Ipv6thenIpv4
        ));
    }
}
