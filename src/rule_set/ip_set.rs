//! Sorted, disjoint, inclusive IP ranges, as `.srs` stores them.
//!
//! Addresses are held as IPv4-mapped `u128`, matching `ip_to_u128` in
//! client_proxy_selector.rs so both matchers agree on representation.

/// A set of inclusive `[from, to]` ranges, sorted and disjoint.
#[derive(Debug, Clone, Default)]
pub struct IpSet {
    ranges: Vec<(u128, u128)>,
}

impl IpSet {
    /// Ranges arrive already sorted and merged from `netipx.IPSet`. Verifying
    /// that once at load is cheaper than a matcher that is silently wrong.
    pub fn new(ranges: Vec<(u128, u128)>) -> std::io::Result<Self> {
        for &(from, to) in &ranges {
            if to < from {
                return Err(std::io::Error::other(
                    "ip set: a range has its bounds inverted",
                ));
            }
        }
        for pair in ranges.windows(2) {
            if pair[1].0 <= pair[0].1 {
                return Err(std::io::Error::other(
                    "ip set: ranges are not sorted and disjoint",
                ));
            }
        }
        Ok(Self { ranges })
    }

    pub fn contains(&self, ip: u128) -> bool {
        let index = self.ranges.partition_point(|&(from, _)| from <= ip);
        index > 0 && self.ranges[index - 1].1 >= ip
    }

    /// Test-only: production code only ever asks `contains`.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> u128 {
        u128::from(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    #[test]
    fn contains_checks_inclusive_bounds() {
        let set = IpSet::new(vec![
            (v4(10, 0, 0, 0), v4(10, 0, 0, 255)),
            (v4(192, 168, 1, 0), v4(192, 168, 1, 10)),
        ])
        .unwrap();

        assert!(set.contains(v4(10, 0, 0, 0)));
        assert!(set.contains(v4(10, 0, 0, 255)));
        assert!(set.contains(v4(192, 168, 1, 10)));
        assert!(!set.contains(v4(10, 0, 1, 0)));
        assert!(!set.contains(v4(192, 168, 1, 11)));
        assert!(!set.contains(v4(9, 255, 255, 255)));
    }

    #[test]
    fn an_empty_set_contains_nothing() {
        let set = IpSet::new(Vec::new()).unwrap();
        assert!(!set.contains(v4(1, 1, 1, 1)));
    }

    #[test]
    fn unsorted_ranges_are_rejected() {
        let err = IpSet::new(vec![
            (v4(192, 168, 0, 0), v4(192, 168, 0, 1)),
            (v4(10, 0, 0, 0), v4(10, 0, 0, 1)),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("sorted"), "{err}");
    }

    #[test]
    fn inverted_bounds_are_rejected() {
        let err = IpSet::new(vec![(v4(10, 0, 0, 5), v4(10, 0, 0, 1))]).unwrap_err();
        assert!(err.to_string().contains("inverted"), "{err}");
    }
}
