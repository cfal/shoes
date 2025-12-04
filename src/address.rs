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

        // Parse the port ranges
        let mut ports = Vec::new();
        for part in port_str.split(',') {
            if part.contains('-') {
                // Handle range like "1-5"
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port range format: {part}"),
                    ));
                }

                let start = range_parts[0].parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port number: {e}"),
                    )
                })?;

                let end = range_parts[1].parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port number: {e}"),
                    )
                })?;

                if start > end {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port range (start > end): {start}-{end}"),
                    ));
                }

                for port in start..=end {
                    ports.push(port);
                }
            } else {
                // Handle single port like "8"
                let port = part.parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port number: {e}"),
                    )
                })?;

                ports.push(port);
            }
        }

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
