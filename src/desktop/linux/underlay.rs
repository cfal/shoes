use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use parking_lot::Mutex;
use rtnetlink::packet_route::{
    RouteNetlinkMessage,
    address::{AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage},
    link::{LinkAttribute, LinkFlags},
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteVia},
};
use rtnetlink::{Handle, RouteMessageBuilder};

use super::routes;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Path {
    index: u32,
    name: String,
    gateway: Option<IpAddr>,
    source: Option<IpAddr>,
    preferred_source: Option<IpAddr>,
    nexthop: Option<u32>,
    metric: u32,
    addresses: BTreeSet<IpAddr>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Snapshot([Option<Path>; 2]);

impl Snapshot {
    pub fn available(&self) -> bool {
        self.0.iter().any(Option::is_some)
    }

    fn changed_from(&self, previous: &Self) -> bool {
        self.0
            .iter()
            .zip(&previous.0)
            .any(|(new, old)| match (new, old) {
                (Some(new), Some(old)) => {
                    new.index != old.index
                        || new.name != old.name
                        || new.gateway != old.gateway
                        || new.preferred_source != old.preferred_source
                        // A new privacy address can become preferred while the old source is valid.
                        || old
                            .source
                            .is_some_and(|source| !new.addresses.contains(&source))
                }
                (None, None) => false,
                _ => true,
            })
    }
}

#[derive(Default)]
struct State {
    snapshot: Snapshot,
    disrupted: bool,
}

#[derive(Default)]
pub(super) struct Monitor(Mutex<State>);

impl Monitor {
    pub fn initialize(&self, snapshot: Snapshot) {
        *self.0.lock() = State {
            snapshot,
            disrupted: false,
        };
    }

    pub fn update(&self, snapshot: Snapshot) -> bool {
        let mut state = self.0.lock();
        let changed = snapshot.changed_from(&state.snapshot) || state.disrupted;
        state.snapshot = snapshot;
        state.disrupted = false;
        changed
    }

    pub fn available(&self) -> bool {
        self.0.lock().snapshot.available()
    }

    // Retains losses even when a down/up burst finishes before the next dump.
    pub fn event(&self, message: &RouteNetlinkMessage) {
        let mut state = self.0.lock();
        let lost = state.snapshot.0.iter().flatten().any(|path| match message {
            RouteNetlinkMessage::DelLink(link) => link.header.index == path.index,
            RouteNetlinkMessage::NewLink(link) => {
                link.header.index == path.index
                    && !link
                        .header
                        .flags
                        .contains(LinkFlags::Up | LinkFlags::LowerUp)
            }
            RouteNetlinkMessage::DelAddress(address) => {
                address.header.index == path.index && address.attributes.iter().any(|attribute| {
                    matches!(attribute, AddressAttribute::Local(ip) | AddressAttribute::Address(ip)
                            if Some(*ip) == path.source)
                })
            }
            RouteNetlinkMessage::DelRoute(route) => {
                routes::native_default(route)
                    && matches_path(route, path.index, path.gateway, path.nexthop)
                    && metric(route) == path.metric
            }
            _ => false,
        });
        state.disrupted |= lost;
    }
}

fn metric(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
        .unwrap_or(0)
}

fn preferred_source(route: &RouteMessage) -> Option<IpAddr> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::PrefSource(RouteAddress::Inet(ip)) => Some(IpAddr::V4(*ip)),
            RouteAttribute::PrefSource(RouteAddress::Inet6(ip)) => Some(IpAddr::V6(*ip)),
            _ => None,
        })
}

fn route_gateway(attributes: &[RouteAttribute]) -> Option<IpAddr> {
    attributes.iter().find_map(|attribute| match attribute {
        RouteAttribute::Gateway(RouteAddress::Inet(ip))
        | RouteAttribute::Via(RouteVia::Inet(ip)) => Some(IpAddr::V4(*ip)),
        RouteAttribute::Gateway(RouteAddress::Inet6(ip))
        | RouteAttribute::Via(RouteVia::Inet6(ip)) => Some(IpAddr::V6(*ip)),
        _ => None,
    })
}

fn nexthop(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::NhId(id) => Some(*id),
            _ => None,
        })
}

fn matches_path(
    route: &RouteMessage,
    index: u32,
    gateway: Option<IpAddr>,
    nh: Option<u32>,
) -> bool {
    (route.attributes.contains(&RouteAttribute::Oif(index))
        && route_gateway(&route.attributes) == gateway)
        || nh.is_some_and(|id| nexthop(route) == Some(id))
        || route.attributes.iter().any(|attribute| match attribute {
            RouteAttribute::MultiPath(hops) => hops.iter().any(|hop| {
                hop.interface_index == index && route_gateway(&hop.attributes) == gateway
            }),
            _ => false,
        })
}

fn usable_addresses(addresses: &[AddressMessage], index: u32, ipv6: bool) -> BTreeSet<IpAddr> {
    let mut usable = BTreeSet::new();
    for address in addresses {
        if address.header.index != index
            || address
                .header
                .flags
                .intersects(AddressHeaderFlags::Tentative | AddressHeaderFlags::Dadfailed)
        {
            continue;
        }
        if address.attributes.iter().any(|attribute| {
            matches!(attribute, AddressAttribute::Flags(flags)
                if flags.intersects(AddressFlags::Tentative | AddressFlags::Dadfailed))
        }) {
            continue;
        }
        let local = address
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(ip) => Some(*ip),
                _ => None,
            });
        let ip = local.or_else(|| {
            address
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Address(ip) => Some(*ip),
                    _ => None,
                })
        });
        if let Some(ip) = ip
            && ip.is_ipv6() == ipv6
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            usable.insert(ip);
        }
    }
    usable
}

pub(super) async fn snapshot(handle: &Handle, owned_index: u32, mark: u32) -> io::Result<Snapshot> {
    let links = routes::request(handle.link().get().execute().try_collect::<Vec<_>>()).await?;
    let addresses =
        routes::request(handle.address().get().execute().try_collect::<Vec<_>>()).await?;
    let mut snapshot = Snapshot::default();
    for ipv6 in [false, true] {
        let defaults = routes::dump(handle, ipv6).await?;
        if !defaults.iter().any(routes::native_default) {
            continue;
        }
        // Read-only lookups select the kernel's actual next hop and source. No probe is sent.
        let mut query = if ipv6 {
            RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix("2606:4700:4700::1111".parse().unwrap(), 128)
                .mark(mark)
                .build()
        } else {
            RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::new(1, 1, 1, 1), 32)
                .mark(mark)
                .build()
        };
        // IPv4 otherwise reports table 254 even when policy routing selects another table.
        query.header.flags.insert(RouteFlags::LookupTable);
        let mut response = handle.route().get(query).execute();
        let lookup = response.try_next();
        let route = match tokio::time::timeout(std::time::Duration::from_secs(10), lookup).await {
            Ok(Ok(Some(route))) => route,
            Ok(Ok(None)) => continue,
            Ok(Err(rtnetlink::Error::NetlinkError(_))) => continue,
            Ok(Err(error)) => return Err(io::Error::other(error)),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "underlay lookup timed out",
                ));
            }
        };
        let Some(index) = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            })
        else {
            continue;
        };
        if index == owned_index || routes::table(&route) != 254 {
            continue;
        }
        let gateway = route_gateway(&route.attributes);
        let nexthop = nexthop(&route);
        let Some(default) = defaults
            .iter()
            .filter(|route| {
                routes::native_default(route) && matches_path(route, index, gateway, nexthop)
            })
            .min_by_key(|route| metric(route))
        else {
            continue;
        };
        let Some(link) = links.iter().find(|link| link.header.index == index) else {
            continue;
        };
        if !link
            .header
            .flags
            .contains(LinkFlags::Up | LinkFlags::LowerUp)
        {
            continue;
        }
        let Some(name) = link
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            })
        else {
            continue;
        };
        let addresses = usable_addresses(&addresses, index, ipv6);
        if addresses.is_empty() {
            continue;
        }
        snapshot.0[usize::from(ipv6)] = Some(Path {
            index,
            name,
            gateway,
            source: preferred_source(&route),
            preferred_source: preferred_source(default),
            nexthop,
            metric: metric(default),
            addresses,
        });
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_addresses_use_the_first_supported_attribute_of_each_kind() {
        for (source, gateway, via) in [
            (
                "192.0.2.1",
                "192.0.2.2",
                RouteVia::Inet("192.0.2.3".parse().unwrap()),
            ),
            (
                "2001:db8::1",
                "2001:db8::2",
                RouteVia::Inet6("2001:db8::3".parse().unwrap()),
            ),
        ] {
            let source: IpAddr = source.parse().unwrap();
            let gateway: IpAddr = gateway.parse().unwrap();
            let via_ip = match via {
                RouteVia::Inet(ip) => IpAddr::V4(ip),
                RouteVia::Inet6(ip) => IpAddr::V6(ip),
                _ => unreachable!(),
            };
            let mut route = RouteMessage::default();
            assert_eq!(preferred_source(&route), None);
            assert_eq!(route_gateway(&route.attributes), None);
            route.attributes = vec![
                RouteAttribute::PrefSource(RouteAddress::Other(vec![])),
                RouteAttribute::Gateway(RouteAddress::Other(vec![])),
                RouteAttribute::PrefSource(source.into()),
                RouteAttribute::Gateway(gateway.into()),
                RouteAttribute::Via(via),
                RouteAttribute::PrefSource(gateway.into()),
            ];
            assert_eq!(preferred_source(&route), Some(source));
            assert_eq!(route_gateway(&route.attributes), Some(gateway));
            route.attributes.reverse();
            assert_eq!(preferred_source(&route), Some(gateway));
            assert_eq!(route_gateway(&route.attributes), Some(via_ip));
        }
    }

    fn sample(ipv6: bool) -> Snapshot {
        let mut snapshot = Snapshot::default();
        let source: IpAddr = if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
            .parse()
            .unwrap();
        snapshot.0[usize::from(ipv6)] = Some(Path {
            index: 2,
            name: "native0".into(),
            gateway: Some(
                if ipv6 { "2001:db8::2" } else { "192.0.2.2" }
                    .parse()
                    .unwrap(),
            ),
            source: Some(source),
            preferred_source: None,
            nexthop: None,
            metric: 100,
            addresses: [source].into(),
        });
        snapshot
    }

    #[test]
    fn identity_source_gateway_and_availability_changes_reset() {
        for ipv6 in [false, true] {
            let initial = sample(ipv6);
            let monitor = Monitor::default();
            monitor.initialize(initial.clone());
            assert!(!monitor.update(initial.clone()));
            for mutation in 0..4 {
                let mut changed = initial.clone();
                let path = changed.0[usize::from(ipv6)].as_mut().unwrap();
                match mutation {
                    0 => path.index += 1,
                    1 => path.name = "native1".into(),
                    2 => {
                        path.gateway = Some(
                            if ipv6 { "2001:db8::3" } else { "192.0.2.3" }
                                .parse()
                                .unwrap(),
                        )
                    }
                    _ => {
                        path.source = Some(
                            if ipv6 { "2001:db8::4" } else { "192.0.2.4" }
                                .parse()
                                .unwrap(),
                        );
                        path.addresses = [path.source.unwrap()].into();
                    }
                }
                monitor.initialize(initial.clone());
                assert!(monitor.update(changed.clone()));
                assert!(!monitor.update(changed));
            }
            monitor.initialize(initial.clone());
            assert!(monitor.update(Snapshot::default()));
            assert!(!monitor.available());
            assert!(!monitor.update(Snapshot::default()));
            assert!(monitor.update(initial));
            assert!(monitor.available());
        }
    }

    #[test]
    fn metadata_and_unused_addresses_do_not_reset_but_source_removal_does() {
        let monitor = Monitor::default();
        let initial = sample(false);
        monitor.initialize(initial.clone());
        let mut changed = initial;
        let path = changed.0[0].as_mut().unwrap();
        path.metric = 200;
        path.addresses.insert("192.0.2.4".parse().unwrap());
        assert!(!monitor.update(changed.clone()));
        changed.0[0]
            .as_mut()
            .unwrap()
            .addresses
            .remove(&"192.0.2.1".parse().unwrap());
        assert!(monitor.update(changed));
    }

    #[test]
    fn privacy_rotation_keeps_old_flows_but_explicit_source_changes_reset() {
        let monitor = Monitor::default();
        let initial = sample(true);
        monitor.initialize(initial.clone());
        let mut rotated = initial.clone();
        let path = rotated.0[1].as_mut().unwrap();
        path.source = Some("2001:db8::9".parse().unwrap());
        path.addresses.insert(path.source.unwrap());
        assert!(!monitor.update(rotated.clone()));
        rotated.0[1]
            .as_mut()
            .unwrap()
            .addresses
            .remove(&"2001:db8::1".parse().unwrap());
        assert!(!monitor.update(rotated.clone()));
        rotated.0[1].as_mut().unwrap().preferred_source = Some("2001:db8::9".parse().unwrap());
        assert!(monitor.update(rotated));
    }

    #[test]
    fn multipath_defaults_match_the_selected_hop_and_preserve_loss_events() {
        use rtnetlink::packet_route::route::{RouteNextHop, RouteType};
        let initial = sample(false);
        let path = initial.0[0].as_ref().unwrap();
        let mut route = RouteMessage::default();
        route.header.table = 254;
        route.header.kind = RouteType::Unicast;
        let mut hop = RouteNextHop::default();
        hop.interface_index = path.index;
        hop.attributes
            .push(RouteAttribute::Gateway(RouteAddress::Inet(
                "192.0.2.2".parse().unwrap(),
            )));
        route.attributes = vec![
            RouteAttribute::MultiPath(vec![hop]),
            RouteAttribute::Priority(100),
        ];
        assert!(matches_path(&route, path.index, path.gateway, None));
        assert!(!matches_path(&route, 99, path.gateway, None));
        let monitor = Monitor::default();
        monitor.initialize(initial.clone());
        monitor.event(&RouteNetlinkMessage::DelRoute(route));
        assert!(monitor.update(initial));
    }

    #[test]
    fn short_outages_survive_event_coalescing_without_tracking_unrelated_links() {
        let monitor = Monitor::default();
        let initial = sample(false);
        monitor.initialize(initial.clone());
        let mut link = rtnetlink::packet_route::link::LinkMessage::default();
        link.header.index = 3;
        monitor.event(&RouteNetlinkMessage::DelLink(link.clone()));
        assert!(!monitor.update(initial.clone()));
        link.header.index = 2;
        monitor.event(&RouteNetlinkMessage::NewLink(link.clone()));
        link.header.flags = LinkFlags::Up | LinkFlags::LowerUp;
        monitor.event(&RouteNetlinkMessage::NewLink(link));
        assert!(monitor.update(initial.clone()));
        assert!(!monitor.update(initial));
    }

    #[test]
    fn unusable_addresses_and_lifetime_countdowns_are_ignored() {
        let mut address = AddressMessage::default();
        address.header.index = 2;
        address
            .attributes
            .push(AddressAttribute::Address("2001:db8::1".parse().unwrap()));
        assert_eq!(usable_addresses(&[address.clone()], 2, true).len(), 1);
        assert!(usable_addresses(&[address.clone()], 3, true).is_empty());
        address.header.flags = AddressHeaderFlags::Tentative;
        assert!(usable_addresses(&[address.clone()], 2, true).is_empty());
        address.header.flags = AddressHeaderFlags::empty();
        address
            .attributes
            .push(AddressAttribute::Flags(AddressFlags::Dadfailed));
        assert!(usable_addresses(&[address], 2, true).is_empty());
    }

    #[test]
    fn local_address_takes_precedence_even_when_unusable() {
        let local = "192.0.2.1".parse().unwrap();
        let mut address = AddressMessage::default();
        address.header.index = 2;
        address.attributes = vec![
            AddressAttribute::Address("192.0.2.2".parse().unwrap()),
            AddressAttribute::Local(local),
        ];
        assert_eq!(
            usable_addresses(&[address.clone()], 2, false),
            [local].into()
        );
        assert!(usable_addresses(&[address.clone()], 2, true).is_empty());
        address.attributes.reverse();
        assert_eq!(
            usable_addresses(&[address.clone()], 2, false),
            [local].into()
        );
        for ip in ["0.0.0.0", "127.0.0.1", "::", "::1", "2001:db8::1"] {
            address.attributes[0] = AddressAttribute::Local(ip.parse().unwrap());
            assert!(
                usable_addresses(&[address.clone()], 2, false).is_empty(),
                "{ip}"
            );
        }
    }
}
