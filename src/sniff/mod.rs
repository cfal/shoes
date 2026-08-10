//! Recovering a destination hostname from the first bytes of a connection.
//!
//! Each sniffer is a pure function over a slice. It never reads, never
//! allocates beyond the name it returns, and answers one of three things: it
//! found the protocol, it needs more bytes, or this is definitely not its
//! protocol. The peek loop in [`peek`] is the only part that touches a stream.

pub mod http;
pub mod peek;
pub mod tls;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::address::{Address, NetLocation, ResolvedLocation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffedProtocol {
    Tls,
    Http,
}

impl SniffedProtocol {
    pub(crate) fn sniff(self, buf: &[u8]) -> SniffOutcome {
        match self {
            SniffedProtocol::Tls => tls::sniff(buf),
            SniffedProtocol::Http => http::sniff(buf),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    pub protocol: SniffedProtocol,
    /// `None` when the protocol was recognised but carries no name: a
    /// ClientHello without SNI, an HTTP/1.0 request without `Host`.
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffOutcome {
    Found(Sniffed),
    /// The bytes so far are consistent with this protocol. Read more and ask
    /// again.
    NeedMore,
    /// Definitively not this protocol. Stop asking.
    NotThisOne,
}

/// Resolved sniffing settings for one listener.
#[derive(Debug, Clone)]
pub struct SniffSettings {
    pub protocols: Vec<SniffedProtocol>,
    pub timeout: Duration,
}

/// Ports where the server speaks first. Reading there learns nothing and
/// stalls the connection for the whole timeout. The list is sing-box's
/// `common/sniff/sniff.go` unchanged: SMTP, IMAP and POP3.
const SERVER_FIRST_PORTS: [u16; 7] = [25, 110, 143, 465, 587, 993, 995];

/// The address to fall back to if sniffing finds nothing, or `None` when this
/// connection should not be sniffed at all.
///
/// A destination that is already a hostname has nothing to recover.
pub fn sniff_target(location: &NetLocation) -> Option<SocketAddr> {
    if SERVER_FIRST_PORTS.contains(&location.port()) {
        return None;
    }
    match location.address() {
        Address::Ipv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), location.port())),
        Address::Ipv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), location.port())),
        Address::Hostname(_) => None,
    }
}

/// The location a sniffed connection is judged by: the recovered name, with
/// the original address kept alongside it.
///
/// Rules match the name; CIDR masks match `addr` without a DNS lookup; a
/// direct connection dials `addr`; a proxied connection sends the name
/// upstream for the exit to resolve.
pub fn judged_location(name: &str, addr: SocketAddr) -> ResolvedLocation {
    ResolvedLocation::with_resolved(
        NetLocation::new(Address::Hostname(name.to_string()), addr.port()),
        addr,
    )
}

/// A name that reaches routing and the log must be a plain hostname. Anything
/// else is discarded rather than cleaned up: a rule matching a half-sanitised
/// name is worse than no name at all.
pub(crate) fn normalize_host(raw: &[u8]) -> Option<String> {
    let raw = raw.trim_ascii();

    // A bracketed IPv6 literal is not a name and there is nothing to route on.
    if raw.first() == Some(&b'[') {
        return None;
    }

    // A hostname cannot contain a colon, so the first one starts the port.
    let host = match raw.iter().position(|&b| b == b':') {
        Some(i) => &raw[..i],
        None => raw,
    };

    let host = host.strip_suffix(b".").unwrap_or(host);

    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return None;
    }

    String::from_utf8(host.to_ascii_lowercase()).ok()
}

/// A minimal but well-formed ClientHello record carrying `name` as its SNI.
///
/// Shared by every test that needs one so the length fields are computed in a
/// single place; hand-written fixtures get them wrong.
#[cfg(test)]
pub(crate) fn test_client_hello(name: &str) -> Vec<u8> {
    let name = name.as_bytes();

    let mut entry = vec![0x00]; // host_name
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name);

    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);

    let mut extensions = vec![0x00, 0x00]; // server_name
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);

    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
    body.extend_from_slice(&[0x01, 0x00]); // compression methods
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let len = body.len() as u32;
    let mut handshake = vec![0x01, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn normalize_lowercases_and_strips_the_root_dot() {
        assert_eq!(normalize_host(b"Example.COM."), Some("example.com".into()));
    }

    #[test]
    fn normalize_strips_a_port() {
        assert_eq!(
            normalize_host(b"example.com:8443"),
            Some("example.com".into())
        );
    }

    #[test]
    fn normalize_trims_surrounding_space() {
        assert_eq!(
            normalize_host(b"  example.com \t"),
            Some("example.com".into())
        );
    }

    #[test]
    fn normalize_keeps_punycode() {
        assert_eq!(
            normalize_host(b"xn--80ak6aa92e.com"),
            Some("xn--80ak6aa92e.com".into())
        );
    }

    #[test]
    fn normalize_rejects_empty_and_bracketed_and_odd_bytes() {
        assert_eq!(normalize_host(b""), None);
        assert_eq!(normalize_host(b"."), None);
        assert_eq!(normalize_host(b"[::1]:443"), None);
        assert_eq!(normalize_host(b"exa mple.com"), None);
        assert_eq!(normalize_host(b"exa\nmple.com"), None);
        assert_eq!(normalize_host(&vec![b'a'; 254]), None);
    }

    #[test]
    fn sniff_target_skips_hostnames_and_server_first_ports() {
        let by_name = NetLocation::new(Address::Hostname("example.com".into()), 443);
        assert_eq!(sniff_target(&by_name), None);

        let smtp = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 25);
        assert_eq!(sniff_target(&smtp), None);

        let https = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        assert_eq!(
            sniff_target(&https),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443))
        );

        let v6 = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(
            sniff_target(&v6),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443))
        );
    }

    #[test]
    fn the_shared_client_hello_fixture_is_well_formed() {
        assert_eq!(
            SniffedProtocol::Tls.sniff(&test_client_hello("ex.com")),
            SniffOutcome::Found(Sniffed {
                protocol: SniffedProtocol::Tls,
                domain: Some("ex.com".into()),
            })
        );
    }

    #[test]
    fn judged_location_keeps_the_original_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let location = judged_location("example.com", addr);
        assert_eq!(
            location.location(),
            &NetLocation::new(Address::Hostname("example.com".into()), 443)
        );
        assert_eq!(location.resolved_addr(), Some(addr));
    }
}
