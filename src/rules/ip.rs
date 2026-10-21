use std::io;
use std::net::{IpAddr, Ipv6Addr};

use super::{contains_sorted, invalid};
use crate::address::{Address, AddressMask};

const MAPPED_START: u128 = 0xffff_0000_0000;
const MAPPED_END: u128 = MAPPED_START + u32::MAX as u128;

#[derive(Clone, Debug, Default)]
pub struct IpRanges {
    pub(crate) v4: Vec<(u32, u32)>,
    pub(crate) v6: Vec<(u128, u128)>,
}

impl IpRanges {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn add_v4(&mut self, start: u32, end: u32) -> io::Result<()> {
        if start > end {
            return Err(invalid("reversed IPv4 range"));
        }
        self.v4.push((start, end));
        Ok(())
    }

    pub fn add_v6(&mut self, start: u128, end: u128) -> io::Result<()> {
        if start > end {
            return Err(invalid("reversed IPv6 range"));
        }
        if start >= MAPPED_START && end <= MAPPED_END {
            return Err(invalid(
                "explicit mapped IPv6 predicate: use its IPv4 spelling",
            ));
        }
        self.v6.push((start, end));
        Ok(())
    }

    pub fn add_cidr(&mut self, cidr: &str) -> io::Result<()> {
        let network: ipnetwork::IpNetwork = cidr
            .parse()
            .map_err(|e| invalid(format!("invalid CIDR {cidr:?}: {e}")))?;
        match network {
            ipnetwork::IpNetwork::V4(n) => self.add_v4(n.network().into(), n.broadcast().into()),
            ipnetwork::IpNetwork::V6(n) => self.add_v6(n.network().into(), n.broadcast().into()),
        }
    }

    pub fn add_legacy(&mut self, mask: &AddressMask) -> io::Result<()> {
        match mask.address {
            Address::Ipv4(ip) => {
                let bits = mask.netmask as u32;
                let start = u32::from(ip) & bits;
                self.add_v4(start, start | !bits)
            }
            Address::Ipv6(ip) => {
                let start = u128::from(ip) & mask.netmask;
                let end = start | !mask.netmask;
                if start >= MAPPED_START && end <= MAPPED_END {
                    log::warn!(
                        "legacy mapped IPv6 mask is normalized to IPv4; prefer an IPv4 CIDR"
                    );
                    self.add_v4(start as u32, end as u32)
                } else {
                    if start <= MAPPED_START && end >= MAPPED_END {
                        log::warn!(
                            "legacy IPv6 mask now matches IPv6 only; add an IPv4 predicate when needed"
                        );
                    }
                    self.add_v6(start, end)
                }
            }
            Address::Hostname(_) => Err(invalid("hostname is not an IP predicate")),
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.v4.append(&mut other.v4);
        self.v6.append(&mut other.v6);
    }

    pub fn finish(mut self) -> Self {
        macro_rules! merge {
            ($ranges:expr) => {{
                $ranges.sort_unstable();
                let mut len = 0;
                for i in 0..$ranges.len() {
                    let (start, end) = $ranges[i];
                    if len > 0 && start <= $ranges[len - 1].1.saturating_add(1) {
                        $ranges[len - 1].1 = $ranges[len - 1].1.max(end);
                    } else {
                        $ranges[len] = (start, end);
                        len += 1;
                    }
                }
                $ranges.truncate(len);
                $ranges.shrink_to_fit();
            }};
        }
        merge!(self.v4);
        merge!(self.v6);
        self
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => contains_sorted(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => contains_sorted(&self.v6, u128::from(ip)),
        }
    }

    pub fn add_encoded(&mut self, from: &[u8], to: &[u8], mapped_encoding: bool) -> io::Result<()> {
        match (from.len(), to.len()) {
            (4, 4) => self.add_v4(
                u32::from_be_bytes(from.try_into().unwrap()),
                u32::from_be_bytes(to.try_into().unwrap()),
            ),
            (16, 16) => {
                let from = Ipv6Addr::from(<[u8; 16]>::try_from(from).unwrap());
                let to = Ipv6Addr::from(<[u8; 16]>::try_from(to).unwrap());
                if mapped_encoding {
                    match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
                        (Some(a), Some(b)) => return self.add_v4(a.into(), b.into()),
                        (None, None) => {}
                        _ => return Err(invalid("mixed-family range endpoints")),
                    }
                }
                self.add_v6(from.into(), to.into())
            }
            _ => Err(invalid(
                "IP range endpoints must have equal length, 4 or 16 bytes",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_and_families() {
        let mut ranges = IpRanges::default();
        ranges.add_cidr("10.1.0.0/16").unwrap();
        ranges.add_cidr("10.0.0.0/8").unwrap();
        ranges.add_cidr("::/0").unwrap();
        let ranges = ranges.finish();
        assert_eq!(ranges.v4.len(), 1);
        for ip in [
            "10.0.0.0",
            "10.255.255.255",
            "::ffff:10.1.2.3",
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(ranges.contains(ip.parse().unwrap()));
        }
        assert!(!ranges.contains("11.0.0.0".parse().unwrap()));
        let mut ranges = IpRanges::default();
        assert!(ranges.add_cidr("::ffff:10.0.0.0/104").is_err());
        ranges
            .add_legacy(&AddressMask::from("::ffff:10.0.0.0/104").unwrap())
            .unwrap();
        assert!(ranges.finish().contains("10.0.0.1".parse().unwrap()));
    }
}
