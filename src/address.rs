use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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

        if possible_ipv4 && dots == 3 {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                return Ok(Address::Ipv4(addr));
            }
        }

        if possible_ipv6 {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                return Ok(Address::Ipv6(addr));
            }
        }

        if possible_hostname {
            return Ok(Address::Hostname(s.to_string()));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse address: {}", s),
        ))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    pub fn is_hostname(&self) -> bool {
        matches!(self, Address::Hostname(_))
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            Address::Hostname(ref hostname) => Some(hostname),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(i) => write!(f, "{}", i),
            Address::Ipv6(i) => write!(f, "{}", i),
            Address::Hostname(h) => write!(f, "{}", h),
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

    pub fn _is_unspecified(&self) -> bool {
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid location",
            ));
        }

        let port = port.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No port"))?;

        Ok(Self { address, port })
    }

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

    pub fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        match self.address {
            Address::Ipv6(ref addr) => Ok(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Ok(SocketAddr::new(IpAddr::V4(*addr), self.port)),
            // TODO: Consider adding a resolver/resolve cache to allow using a custom provided DNS.
            // TODO: this should return an error if the address is invalid
            Address::Hostname(ref d) => format!("{}:{}", d, self.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Lookup failed")),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetLocationPortRange {
    address: Address,
    ports: Vec<u16>,
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
                ))
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
                        format!("Invalid port range format: {}", part),
                    ));
                }

                let start = range_parts[0].parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port number: {}", e),
                    )
                })?;

                let end = range_parts[1].parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port number: {}", e),
                    )
                })?;

                if start > end {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid port range (start > end): {}-{}", start, end),
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
                        format!("Invalid port number: {}", e),
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
                    let addr_iter = format!("{}:{}", hostname, port).to_socket_addrs()?;
                    for addr in addr_iter {
                        result.push(addr);
                    }
                }
                if result.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
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
                write!(f, "{}", start_port)?;
            } else if end_port - start_port == 1 {
                // Just two consecutive ports, write as comma-separated
                write!(f, "{},{}", start_port, end_port)?;
            } else {
                // Range of ports
                write!(f, "{}-{}", start_port, end_port)?;
            }

            idx += 1;
            start_idx = idx;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
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
                let num_bits = s[i + 1..].parse::<u8>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to parse netmask: {}", e),
                    )
                })?;
                (&s[0..i], Some(num_bits))
            }
            None => (s, None),
        };
        let address = Address::from(address_str)?;
        let keep_bits = match address {
            Address::Ipv4(_) => {
                let num_bits = num_bits.unwrap_or(32);
                if num_bits > 32 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Invalid number of bits for ipv4 address: {}", num_bits),
                    ));
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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Invalid number of bits for ipv4 address: {}", num_bits),
                    ));
                }
                num_bits
            }
            Address::Hostname(ref hostname) => {
                if num_bits.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Cannot specify number of number of netmask bits for hostnames: {}",
                            hostname
                        ),
                    ));
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
        let (address_mask_str, port) = match s.find(':') {
            Some(i) => {
                let port = s[i + 1..].parse::<u16>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to parse port: {}", e),
                    )
                })?;
                (&s[0..i], port)
            }
            None => (s, 0),
        };

        Ok(Self {
            address_mask: AddressMask::from(address_mask_str)?,
            port,
        })
    }
}
