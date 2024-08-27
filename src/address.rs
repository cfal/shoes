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
            } else if (c >= b'A' && c <= b'F') || (c >= b'a' && c <= b'f') {
                possible_ipv4 = false;
            } else if c < b'0' || c > b'9' {
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
