//! A UDP socket that moves: Hysteria2 client port hopping.
//!
//! The mechanism is not a performance feature. Rotating the port changes the
//! connection's 4-tuple on a timer, so a middlebox tracking the flow loses it,
//! and a server published as a port range becomes reachable at all.
//!
//! Modelled on `extras/transport/udphop/conn.go` in the reference
//! implementation, including the parts that are counter-intuitive: a new
//! socket is bound on every hop rather than the destination being rewritten on
//! one, and two sockets stay live at a time.

// Nothing reaches this module from the binary until the QUIC outbound is
// taught to use it. `lib.rs` allows dead code crate-wide but `main.rs` does
// not, so without this the tree does not build between the commit that adds
// the socket and the commit that wires it in. Removed by the wiring commit,
// which is what proves every item here is actually reachable.
#![allow(dead_code)]

use std::time::Duration;

use rand::RngExt;

use crate::address::parse_port_union;

/// The candidate ports a hopping socket draws from.
///
/// Upstream picks uniformly at random rather than cycling; a predictable cycle
/// would be a pattern, and hiding the pattern is the entire point.
#[derive(Debug, Clone)]
pub struct PortSet {
    ports: Vec<u16>,
}

impl PortSet {
    pub fn parse(s: &str) -> std::io::Result<Self> {
        Ok(Self {
            ports: parse_port_union(s)?,
        })
    }

    pub fn pick(&self) -> u16 {
        // parse_port_union rejects an empty union, so this cannot be empty.
        self.ports[rand::rng().random_range(0..self.ports.len())]
    }
}

/// How long to wait before the next hop.
#[derive(Debug, Clone, Copy)]
pub enum HopSchedule {
    Fixed(Duration),
    Range { min: Duration, max: Duration },
}

impl HopSchedule {
    pub fn next(&self) -> Duration {
        match *self {
            HopSchedule::Fixed(interval) => interval,
            HopSchedule::Range { min, max } => {
                if min >= max {
                    return min;
                }
                let span = (max - min).as_millis() as u64;
                min + Duration::from_millis(rand::rng().random_range(0..=span))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_set_only_yields_configured_ports() {
        let set = PortSet::parse("5000-5002,7044").unwrap();
        for _ in 0..200 {
            let port = set.pick();
            assert!(
                [5000, 5001, 5002, 7044].contains(&port),
                "picked {port}, which is not in the set"
            );
        }
    }

    /// A set of one is legal and must not loop forever or panic.
    #[test]
    fn test_a_single_port_set_is_constant() {
        let set = PortSet::parse("443").unwrap();
        assert_eq!(set.pick(), 443);
    }

    /// Every port has to be reachable, or a range is a lie: a picker that only
    /// ever returned the first port would pass a weaker test.
    #[test]
    fn test_every_port_is_reachable() {
        let set = PortSet::parse("100-103").unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            seen.insert(set.pick());
        }
        assert_eq!(seen.len(), 4, "only saw {seen:?}");
    }

    #[test]
    fn test_a_fixed_schedule_returns_its_interval() {
        let schedule = HopSchedule::Fixed(Duration::from_millis(250));
        for _ in 0..10 {
            assert_eq!(schedule.next(), Duration::from_millis(250));
        }
    }

    #[test]
    fn test_a_ranged_schedule_stays_within_its_bounds() {
        let schedule = HopSchedule::Range {
            min: Duration::from_millis(100),
            max: Duration::from_millis(200),
        };
        for _ in 0..200 {
            let interval = schedule.next();
            assert!(
                interval >= Duration::from_millis(100) && interval <= Duration::from_millis(200),
                "{interval:?} is outside the configured range"
            );
        }
    }
}
