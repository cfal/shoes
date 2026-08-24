use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Hostname(String),
}

impl Address {
    pub const UNSPECIFIED: Self = Address::Ipv4(Ipv4Addr::UNSPECIFIED);

    pub fn from(s: &str) -> std::io::Result<Self> {
        // RFC 3986 wraps an IPv6 literal in brackets so that its colons cannot
        // be mistaken for the port separator, and that is the form clients and
        // configs actually use: `[::1]:443`. Without this the leading '[' falls
        // through to the hostname branch below, and the address is handed to
        // the resolver as a name no DNS server will ever know.
        //
        // Brackets mean an IP literal and nothing else - a hostname cannot
        // contain them - so a bracketed string that is not an IPv6 address is
        // an error rather than something to look up.
        if let Some(inner) = s.strip_prefix('[') {
            let inner = inner.strip_suffix(']').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Address starts with '[' but has no closing ']': {s}"),
                )
            })?;
            return inner.parse::<Ipv6Addr>().map(Address::Ipv6).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse bracketed address as IPv6: {s}: {e}"),
                )
            });
        }

        let mut dots = 0;
        let mut possible_ipv4 = true;
        let mut possible_ipv6 = true;
        let mut possible_hostname = true;
        for b in s.as_bytes().iter() {
            let c = *b;
            if c == b':' {
                possible_ipv4 = false;
                possible_hostname = false;
                break;
            } else if c == b'.' {
                possible_ipv6 = false;
                dots += 1;
                if dots > 3 {
                    // can only be a hostname.
                    break;
                }
            } else if (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c) {
                possible_ipv4 = false;
            } else if !c.is_ascii_digit() {
                possible_ipv4 = false;
                possible_ipv6 = false;
                break;
            }
        }

        if possible_ipv4
            && dots == 3
            && let Ok(addr) = s.parse::<Ipv4Addr>()
        {
            return Ok(Address::Ipv4(addr));
        }

        if possible_ipv6 && let Ok(addr) = s.parse::<Ipv6Addr>() {
            return Ok(Address::Ipv6(addr));
        }

        if possible_hostname {
            return Ok(Address::Hostname(s.to_string()));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse address: {s}"),
        ))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            Address::Hostname(hostname) => Some(hostname),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(i) => write!(f, "{i}"),
            Address::Ipv6(i) => write!(f, "{i}"),
            Address::Hostname(h) => write!(f, "{h}"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NetLocation {
    address: Address,
    port: u16,
}

impl NetLocation {
    pub const UNSPECIFIED: Self = NetLocation::new(Address::UNSPECIFIED, 0);

    pub const fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn is_unspecified(&self) -> bool {
        self == &Self::UNSPECIFIED
    }

    pub fn from_str(s: &str, default_port: Option<u16>) -> std::io::Result<Self> {
        let (address_str, port, expect_ipv6) = match s.rfind(':') {
            Some(i) => {
                // The ':' could be from an ipv6 address.
                match s[i + 1..].parse::<u16>() {
                    Ok(port) => (&s[0..i], Some(port), false),
                    Err(_) => (s, default_port, true),
                }
            }
            None => (s, default_port, false),
        };

        let address = Address::from(address_str)?;
        if expect_ipv6 && !address.is_ipv6() {
            return Err(std::io::Error::other("Invalid location"));
        }

        let port = port.ok_or_else(|| std::io::Error::other("No port"))?;

        Ok(Self { address, port })
    }

    #[cfg(test)]
    pub fn from_ip_addr(ip: IpAddr, port: u16) -> Self {
        let address = match ip {
            IpAddr::V4(addr) => Address::Ipv4(addr),
            IpAddr::V6(addr) => Address::Ipv6(addr),
        };
        Self { address, port }
    }

    pub fn components(&self) -> (&Address, u16) {
        (&self.address, self.port)
    }

    pub fn unwrap_components(self) -> (Address, u16) {
        (self.address, self.port)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address as a peer expects to receive it, per RFC 3986: an IPv6
    /// literal in brackets, so its colons cannot be read as the port
    /// separator.
    ///
    /// `Display` does not do this and must not start: it is what logs and
    /// error messages use throughout the tree. This is the form for anything
    /// that leaves the process. Go's `net.SplitHostPort`, which is what the
    /// Hysteria2 reference feeds a received address to, rejects the
    /// unbracketed form outright — and our own parser accepts it, because it
    /// splits at the last colon, so the two agreed and no test failed.
    pub fn to_wire_string(&self) -> String {
        match self.address {
            Address::Ipv6(ref addr) => format!("[{addr}]:{}", self.port),
            _ => format!("{}:{}", self.address, self.port),
        }
    }

    pub fn to_socket_addr_nonblocking(&self) -> Option<SocketAddr> {
        match self.address {
            Address::Ipv6(ref addr) => Some(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Some(SocketAddr::new(IpAddr::V4(*addr), self.port)),
            Address::Hostname(ref _d) => None,
        }
    }
}

impl std::fmt::Display for NetLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl serde::ser::Serialize for NetLocation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

/// A network location with optional pre-resolved socket address.
///
/// When `resolved_addr` is `Some`, consumers should use it directly
/// instead of performing DNS resolution. This avoids duplicate DNS
/// lookups when the same hostname is resolved multiple times in the
/// connection pipeline (rule matching, socket connection, protocol setup).
#[derive(Debug, Clone)]
pub struct ResolvedLocation {
    location: NetLocation,
    resolved_addr: Option<SocketAddr>,
}

impl ResolvedLocation {
    /// Create an unresolved location.
    pub fn new(location: NetLocation) -> Self {
        Self {
            location,
            resolved_addr: None,
        }
    }

    /// Create a location with a pre-resolved address.
    pub fn with_resolved(location: NetLocation, addr: SocketAddr) -> Self {
        Self {
            location,
            resolved_addr: Some(addr),
        }
    }

    /// Get the underlying NetLocation.
    pub fn location(&self) -> &NetLocation {
        &self.location
    }

    /// Consume self and return the underlying NetLocation.
    pub fn into_location(self) -> NetLocation {
        self.location
    }

    /// Get the pre-resolved address, if available.
    pub fn resolved_addr(&self) -> Option<SocketAddr> {
        self.resolved_addr
    }

    /// Get the port.
    #[cfg(test)]
    pub fn port(&self) -> u16 {
        self.location.port()
    }

    /// Get the address.
    pub fn address(&self) -> &Address {
        self.location.address()
    }

    /// Set the resolved address directly.
    /// Used by the resolver when performing lazy resolution.
    pub fn set_resolved(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }
}

impl std::fmt::Display for ResolvedLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.resolved_addr {
            Some(addr) => write!(f, "{} (resolved: {})", self.location, addr),
            None => write!(f, "{}", self.location),
        }
    }
}

impl From<NetLocation> for ResolvedLocation {
    fn from(location: NetLocation) -> Self {
        Self::new(location)
    }
}

impl From<&NetLocation> for ResolvedLocation {
    fn from(location: &NetLocation) -> Self {
        Self::new(location.clone())
    }
}

/// Parse a comma-separated union of ports and inclusive ranges: `443`,
/// `80,443`, `20000-50000`, or `1234,5000-6000,7044`.
///
/// The result is sorted and deduplicated, so a port listed twice is one
/// candidate rather than two.
///
/// This is the notation used both for a listener's port range and for
/// Hysteria2's port hopping
/// (<https://v2.hysteria.network/docs/advanced/Port-Hopping/>). They are the
/// same syntax and must stay the same syntax, which is why there is one
/// parser.
pub fn parse_port_union(s: &str) -> std::io::Result<Vec<u16>> {
    let invalid = |detail: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, detail);

    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(invalid(format!("Empty port in port union: {s:?}")));
        }
        match part.split_once('-') {
            Some((start, end)) => {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|e| invalid(format!("Invalid port number in {part:?}: {e}")))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|e| invalid(format!("Invalid port number in {part:?}: {e}")))?;
                if start > end {
                    return Err(invalid(format!(
                        "Port range {part:?} ends before it starts"
                    )));
                }
                ports.extend(start..=end);
            }
            None => {
                ports.push(
                    part.parse::<u16>()
                        .map_err(|e| invalid(format!("Invalid port number in {part:?}: {e}")))?,
                );
            }
        }
    }

    if ports.is_empty() {
        return Err(invalid(format!("No ports in port union: {s:?}")));
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetLocationPortRange {
    address: Address,
    ports: Vec<u16>,
}

impl From<NetLocation> for NetLocationPortRange {
    fn from(location: NetLocation) -> Self {
        Self {
            address: location.address,
            ports: vec![location.port],
        }
    }
}

impl NetLocationPortRange {
    pub fn new(address: Address, mut ports: Vec<u16>) -> std::io::Result<Self> {
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "No valid ports specified",
            ));
        }
        Ok(Self { address, ports })
    }

    pub fn from_str(s: &str) -> std::io::Result<Self> {
        // Split address and port specification
        let (address_str, port_str) = match s.rfind(':') {
            Some(i) => (&s[0..i], &s[i + 1..]),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing port specification",
                ));
            }
        };

        // Parse the address
        let address = Address::from(address_str)?;

        let ports = parse_port_union(port_str)?;

        Self::new(address, ports)
    }

    pub fn to_socket_addrs(&self) -> std::io::Result<Vec<SocketAddr>> {
        let mut socket_addrs = Vec::with_capacity(self.ports.len());

        match &self.address {
            Address::Ipv4(addr) => {
                let ip = IpAddr::V4(*addr);
                for &port in &self.ports {
                    socket_addrs.push(SocketAddr::new(ip, port));
                }
                Ok(socket_addrs)
            }
            Address::Ipv6(addr) => {
                let ip = IpAddr::V6(*addr);
                for &port in &self.ports {
                    socket_addrs.push(SocketAddr::new(ip, port));
                }
                Ok(socket_addrs)
            }
            Address::Hostname(hostname) => {
                let mut result = Vec::new();
                for &port in &self.ports {
                    let addr_iter = format!("{hostname}:{port}").to_socket_addrs()?;
                    for addr in addr_iter {
                        result.push(addr);
                    }
                }
                if result.is_empty() {
                    return Err(std::io::Error::other(
                        "Hostname lookup failed for all ports",
                    ));
                }
                Ok(result)
            }
        }
    }
}

impl std::fmt::Display for NetLocationPortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:", self.address)?;

        // It shouldn't be possible to create an instance with empty ports.
        assert!(!self.ports.is_empty());

        let mut start_idx = 0;
        let mut idx = 0;

        while idx < self.ports.len() {
            // Find consecutive sequences
            let start_port = self.ports[start_idx];

            while idx + 1 < self.ports.len() && self.ports[idx] + 1 == self.ports[idx + 1] {
                idx += 1;
            }

            // Now idx points to the end of a consecutive sequence
            let end_port = self.ports[idx];

            // Print it properly
            if start_idx > 0 {
                write!(f, ",")?;
            }

            if start_port == end_port {
                // Single port
                write!(f, "{start_port}")?;
            } else if end_port - start_port == 1 {
                // Just two consecutive ports, write as comma-separated
                write!(f, "{start_port},{end_port}")?;
            } else {
                // Range of ports
                write!(f, "{start_port}-{end_port}")?;
            }

            idx += 1;
            start_idx = idx;
        }

        Ok(())
    }
}

impl serde::ser::Serialize for NetLocationPortRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressMask {
    pub address: Address,
    pub netmask: u128,
}

impl AddressMask {
    pub const ANY: Self = AddressMask {
        address: Address::UNSPECIFIED,
        netmask: 0,
    };

    pub fn from(s: &str) -> std::io::Result<Self> {
        let (address_str, num_bits) = match s.rfind('/') {
            Some(i) => {
                let num_bits = s[i + 1..]
                    .parse::<u8>()
                    .map_err(|e| std::io::Error::other(format!("Failed to parse netmask: {e}")))?;
                (&s[0..i], Some(num_bits))
            }
            None => (s, None),
        };
        let address = Address::from(address_str)?;
        let keep_bits = match address {
            Address::Ipv4(_) => {
                let num_bits = num_bits.unwrap_or(32);
                if num_bits > 32 {
                    return Err(std::io::Error::other(format!(
                        "Invalid number of bits for ipv4 address: {num_bits}"
                    )));
                }
                if num_bits == 0 {
                    // We make an exception when 0 is specified, because even if it's IPv6, we
                    // want this rule to match it.
                    0
                } else {
                    96 + num_bits
                }
            }
            Address::Ipv6(_) => {
                let num_bits = num_bits.unwrap_or(128);
                if num_bits > 128 {
                    return Err(std::io::Error::other(format!(
                        "Invalid number of bits for ipv4 address: {num_bits}"
                    )));
                }
                num_bits
            }
            Address::Hostname(ref hostname) => {
                if num_bits.is_some() {
                    return Err(std::io::Error::other(format!(
                        "Cannot specify number of number of netmask bits for hostnames: {hostname}"
                    )));
                }
                128
            }
        };
        let clear_bits = 128 - keep_bits;

        // rust complains if you shift away all the bits.
        let netmask = if clear_bits == 128 {
            0
        } else {
            (u128::MAX >> clear_bits) << clear_bits
        };

        Ok(Self { address, netmask })
    }
}

impl std::fmt::Display for AddressMask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Convert the 128-bit netmask back to number of bits
        let bits = if self.netmask == 0 {
            0
        } else {
            128 - self.netmask.trailing_zeros() as u8
        };

        // Determine if this is IPv4 or IPv6 based on address
        let display_bits = match &self.address {
            Address::Ipv4(_) => {
                // For IPv4, we need to subtract the IPv6 prefix (96 bits)
                if bits > 96 {
                    bits - 96
                } else if bits == 0 {
                    0
                } else {
                    bits
                }
            }
            Address::Ipv6(_) => bits,
            Address::Hostname(_) => bits,
        };

        write!(f, "{}/{}", self.address, display_bits)
    }
}

#[derive(Debug, Clone)]
pub struct NetLocationMask {
    pub address_mask: AddressMask,
    pub port: u16,
}

impl NetLocationMask {
    pub const ANY: Self = NetLocationMask {
        address_mask: AddressMask::ANY,
        port: 0,
    };

    pub fn from(s: &str) -> std::io::Result<Self> {
        // Handle IPv6 with port: [::1/128]:80
        if s.starts_with('[')
            && let Some(bracket_end) = s.find(']')
        {
            let address_mask_str = &s[1..bracket_end];
            let port = if s.len() > bracket_end + 1 && s.as_bytes()[bracket_end + 1] == b':' {
                s[bracket_end + 2..]
                    .parse::<u16>()
                    .map_err(|e| std::io::Error::other(format!("Failed to parse port: {e}")))?
            } else {
                0
            };
            return Ok(Self {
                address_mask: AddressMask::from(address_mask_str)?,
                port,
            });
        }

        // For addresses without brackets, we need to distinguish IPv6 from port notation.
        // IPv6 addresses contain multiple colons. If there's a `/` (CIDR), the port must come
        // after it. If no `/`, use rfind(':') and check if what follows looks like a port.
        let (address_mask_str, port) = if let Some(slash_pos) = s.rfind('/') {
            // Has CIDR notation. Port (if any) must come after the slash.
            // Format: addr/bits:port or addr/bits
            let after_slash = &s[slash_pos + 1..];
            if let Some(colon_in_suffix) = after_slash.find(':') {
                // There's a port after the CIDR
                let bits_str = &after_slash[..colon_in_suffix];
                let port_str = &after_slash[colon_in_suffix + 1..];
                // Validate bits is a number
                bits_str.parse::<u8>().map_err(|e| {
                    std::io::Error::other(format!("Failed to parse netmask bits: {e}"))
                })?;
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| std::io::Error::other(format!("Failed to parse port: {e}")))?;
                (&s[..slash_pos + 1 + colon_in_suffix], port)
            } else {
                // No port, just addr/bits
                (s, 0)
            }
        } else {
            // No CIDR notation. Could be:
            // - hostname:port (example.com:80)
            // - IPv4:port (1.2.3.4:80)
            // - IPv6 (::1, fe80::1)
            // - hostname (example.com)
            // - IPv4 (1.2.3.4)
            //
            // IPv6 addresses have multiple colons, so if there's more than one colon,
            // it's IPv6 and has no port. If there's exactly one colon, use it as port separator.
            let colon_count = s.chars().filter(|&c| c == ':').count();
            if colon_count == 1 {
                // Single colon - treat as port separator
                let colon_pos = s.find(':').unwrap();
                let port = s[colon_pos + 1..]
                    .parse::<u16>()
                    .map_err(|e| std::io::Error::other(format!("Failed to parse port: {e}")))?;
                (&s[..colon_pos], port)
            } else {
                // Zero or multiple colons - no port (IPv6 or plain hostname/IPv4)
                (s, 0)
            }
        };

        Ok(Self {
            address_mask: AddressMask::from(address_mask_str)?,
            port,
        })
    }
}

impl std::fmt::Display for NetLocationMask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.port == 0 {
            write!(f, "{}", self.address_mask)
        } else {
            write!(f, "{}:{}", self.address_mask, self.port)
        }
    }
}

impl serde::ser::Serialize for NetLocationMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// The bracketed form is how RFC 3986 writes an IPv6 literal, and it is
    /// what both configs and HTTP clients use. Parsing it as a hostname sends
    /// it to the resolver, which fails with "Name or service not known" and
    /// makes an IPv6 server unreachable for a reason the message does not
    /// explain.
    #[test]
    fn test_bracketed_ipv6_is_an_address_not_a_hostname() {
        for (input, expected) in [
            ("[::1]", Ipv6Addr::LOCALHOST),
            ("[2001:db8::1]", "2001:db8::1".parse().unwrap()),
            // A full eight-group address, with no "::" to shorten it.
            (
                "[2001:db8:1:2:3:4:5:6]",
                "2001:db8:1:2:3:4:5:6".parse().unwrap(),
            ),
            ("[::ffff:1.2.3.4]", "::ffff:1.2.3.4".parse().unwrap()),
        ] {
            assert_eq!(
                Address::from(input).unwrap(),
                Address::Ipv6(expected),
                "{input} must parse as an address"
            );
        }
    }

    /// Brackets denote an IP literal and nothing else, so a bracketed string
    /// that is not one must not quietly become a hostname to look up.
    #[test]
    fn test_a_bracketed_non_address_is_refused() {
        for input in [
            "[]",
            "[example.com]",
            "[1.2.3.4]",
            "[::1",
            "[not an address]",
        ] {
            assert!(
                Address::from(input).is_err(),
                "{input} must not parse as an address"
            );
        }
    }

    /// The unbracketed forms have to keep working exactly as before.
    #[test]
    fn test_unbracketed_addresses_are_unchanged() {
        assert_eq!(
            Address::from("::1").unwrap(),
            Address::Ipv6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            Address::from("1.2.3.4").unwrap(),
            Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            Address::from("example.com").unwrap(),
            Address::Hostname("example.com".to_string())
        );
    }

    /// The whole point of the brackets: the colons inside them are part of the
    /// address, and the one after them separates the port.
    #[test]
    fn test_a_bracketed_location_separates_the_port() {
        let location = NetLocation::from_str("[2001:db8::1]:2096", None).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv6("2001:db8::1".parse().unwrap())
        );
        assert_eq!(location.port(), 2096);

        // And without a port, the default applies.
        let location = NetLocation::from_str("[2001:db8::1]", Some(443)).unwrap();
        assert_eq!(
            location.address(),
            &Address::Ipv6("2001:db8::1".parse().unwrap())
        );
        assert_eq!(location.port(), 443);

        // A bracketed address with no port and no default is still an error.
        assert!(NetLocation::from_str("[2001:db8::1]", None).is_err());
    }

    /// Port ranges take the same notation.
    #[test]
    fn test_a_bracketed_port_range_parses() {
        let range = NetLocationPortRange::from_str("[2001:db8::1]:80,443").unwrap();
        assert_eq!(range.address, Address::Ipv6("2001:db8::1".parse().unwrap()));
        assert_eq!(range.ports, vec![80, 443]);
    }

    /// One notation, two callers: the listen-address parser and Hysteria2
    /// port hopping. Extracted so they cannot drift apart.
    #[test]
    fn test_port_union_accepts_the_documented_forms() {
        assert_eq!(parse_port_union("443").unwrap(), vec![443]);
        assert_eq!(parse_port_union("80,443").unwrap(), vec![80, 443]);
        assert_eq!(
            parse_port_union("1000-1003").unwrap(),
            vec![1000, 1001, 1002, 1003]
        );
        assert_eq!(
            parse_port_union("7044,5000-5002,80").unwrap(),
            vec![80, 5000, 5001, 5002, 7044],
            "the result is sorted and deduplicated"
        );
        assert_eq!(
            parse_port_union("80,80,80").unwrap(),
            vec![80],
            "a repeated port is one port, not three chances of picking it"
        );
    }

    #[test]
    fn test_port_union_rejects_nonsense() {
        for input in [
            "", "  ", "0-", "-100", "80-70", "70000", "80,", "a-b", "1-2-3",
        ] {
            assert!(
                parse_port_union(input).is_err(),
                "{input:?} must not parse as a port union"
            );
        }
    }

    /// The form that goes on a wire is not the form that goes in a log. Go's
    /// net.SplitHostPort - which is what a Hysteria2 server feeds a received
    /// address to - rejects an unbracketed IPv6 literal with "too many
    /// colons".
    ///
    /// Our own parser accepts the unbracketed form because it splits at the
    /// last colon, so a round-trip through our own code cannot catch this. The
    /// expected values below are what Go accepts, not what we parse.
    #[test]
    fn test_the_wire_form_brackets_an_ipv6_literal() {
        let v6 = NetLocation::from_str("[2001:db8::1]:443", None).unwrap();
        assert_eq!(v6.to_wire_string(), "[2001:db8::1]:443");

        let v4 = NetLocation::from_str("1.2.3.4:443", None).unwrap();
        assert_eq!(v4.to_wire_string(), "1.2.3.4:443");

        let host = NetLocation::from_str("example.com:443", None).unwrap();
        assert_eq!(host.to_wire_string(), "example.com:443");
    }

    /// Display is deliberately left alone: it is what logs and error messages
    /// use all over the tree. This pins the difference so nobody "unifies"
    /// them and quietly changes every log line in the process.
    #[test]
    fn test_display_is_not_the_wire_form() {
        let v6 = NetLocation::from_str("[2001:db8::1]:443", None).unwrap();
        assert_eq!(v6.to_string(), "2001:db8::1:443");
        assert_ne!(v6.to_string(), v6.to_wire_string());
    }

    #[test]
    fn test_netlocation_serialization() {
        let net_loc = NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let yaml_str = serde_yaml::to_string(&net_loc).expect("Failed to serialize NetLocation");
        println!("NetLocation YAML: {yaml_str}");

        let deserialized: NetLocation =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize NetLocation");
        assert_eq!(deserialized.port(), 8080);
    }

    #[test]
    fn test_address_mask_serialization() {
        let address_mask =
            AddressMask::from("192.168.0.0/16").expect("Failed to create AddressMask");
        let yaml_str =
            serde_yaml::to_string(&address_mask).expect("Failed to serialize AddressMask");
        println!("AddressMask YAML: {yaml_str}");

        let deserialized: AddressMask =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize AddressMask");

        assert_eq!(address_mask.to_string(), deserialized.to_string());
    }

    #[test]
    fn test_netlocationmask_serialization() {
        let net_location_mask =
            NetLocationMask::from("192.168.0.0/16:80").expect("Failed to create NetLocationMask");
        let yaml_str =
            serde_yaml::to_string(&net_location_mask).expect("Failed to serialize NetLocationMask");
        println!("NetLocationMask YAML: {yaml_str}");

        let deserialized: NetLocationMask =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize NetLocationMask");

        assert_eq!(net_location_mask.to_string(), deserialized.to_string());
    }
}
