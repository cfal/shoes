use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::packet_route::{
    AddressFamily,
    address::{AddressAttribute, AddressFlags, AddressHeaderFlags},
    link::{LinkAttribute, LinkFlags, LinkMessage},
    route::{
        RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RoutePreference, RouteProtocol,
        RouteScope, RouteType, RouteVia,
    },
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use rtnetlink::{Handle, IpVersion, LinkUnspec, RouteMessageBuilder};

use super::spec::{Spec, invalid};

const PROTOCOL: RouteProtocol = RouteProtocol::Other(233);

pub(super) async fn request<T>(
    future: impl std::future::Future<Output = Result<T, rtnetlink::Error>>,
) -> io::Result<T> {
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "netlink request timed out; completion requires reconciliation",
            )
        })?
        .map_err(io::Error::other)
}

pub(super) fn families(spec: &Spec) -> impl Iterator<Item = bool> + '_ {
    [false, true].into_iter().filter(|ipv6| {
        spec.addresses
            .iter()
            .any(|address| address.is_ipv6() == *ipv6)
    })
}

pub(super) async fn link(handle: &Handle, name: &str) -> io::Result<Option<LinkMessage>> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute()
            .try_next(),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "netlink link lookup timed out"))?
    {
        Ok(link) => Ok(link),
        Err(rtnetlink::Error::NetlinkError(error)) if error.raw_code() == -libc::ENODEV => Ok(None),
        Err(error) => Err(io::Error::other(error)),
    }
}

pub(super) fn owned_link(link: &LinkMessage, index: u32, name: &str, alias: &str) -> bool {
    link.header.index == index
        && link
            .attributes
            .contains(&LinkAttribute::IfName(name.to_owned()))
        && link
            .attributes
            .contains(&LinkAttribute::IfAlias(alias.to_owned()))
}

fn table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
}

async fn dump(handle: &Handle, ipv6: bool) -> io::Result<Vec<RouteMessage>> {
    let family = if ipv6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let mut query = RouteMessage::default();
    query.header.address_family = family;
    let mut routes = request(handle.route().get(query).execute().try_collect::<Vec<_>>()).await?;
    // Unsupported families can fall back to an all-family kernel dump.
    routes.retain(|route| route.header.address_family == family);
    Ok(routes)
}

pub(super) async fn rules(handle: &Handle, ipv6: bool) -> io::Result<Vec<RuleMessage>> {
    request(
        handle
            .rule()
            .get(if ipv6 { IpVersion::V6 } else { IpVersion::V4 })
            .execute()
            .try_collect(),
    )
    .await
}

pub(super) fn rule(spec: &Spec, ipv6: bool) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = if ipv6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    message.header.action = RuleAction::ToTable;
    message.attributes = vec![
        RuleAttribute::Table(spec.linux.table),
        RuleAttribute::Priority(spec.linux.rule_priority),
        RuleAttribute::FwMark(spec.linux.capture_mark),
        RuleAttribute::FwMask(spec.linux.mark_mask),
        RuleAttribute::Protocol(PROTOCOL),
    ];
    message
}

pub(super) fn same_rule(actual: &RuleMessage, expected: &RuleMessage) -> bool {
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    for message in [&mut actual, &mut expected] {
        // FRA_TABLE takes precedence; kernels differ in the compatibility header value.
        if message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RuleAttribute::Table(_)))
        {
            message.header.table = 0;
        }
    }
    // The kernel includes its default suppression value in dumps.
    actual
        .attributes
        .retain(|attribute| !matches!(attribute, RuleAttribute::SuppressPrefixLen(u32::MAX)));
    actual.header == expected.header
        && actual.attributes.len() == expected.attributes.len()
        && expected
            .attributes
            .iter()
            .all(|attribute| actual.attributes.contains(attribute))
}

pub(super) async fn preflight(handle: &Handle, spec: &Spec) -> io::Result<()> {
    if link(handle, &spec.name).await?.is_some() {
        return Err(invalid(
            "managed TUN refuses to attach to an existing interface",
        ));
    }
    for ipv6 in [false, true] {
        let configured = families(spec).any(|family| family == ipv6);
        for rule in rules(handle, ipv6).await? {
            if configured {
                check_precedence(&rule, spec)?;
                if references_reservation(&rule, spec) {
                    return Err(invalid(
                        "managed TUN rule priority or routing table is already referenced",
                    ));
                }
            }
            check_mark_reservation(&rule, spec)?;
        }
        let routes = dump(handle, ipv6).await?;
        if configured {
            check_redirect_gateways(&routes, spec)?;
        }
        for route in &routes {
            if route.header.destination_prefix_length == 0 {
                continue;
            }
            for existing in destinations(route) {
                let existing = existing?;
                if spec
                    .addresses
                    .iter()
                    .any(|owned| owned.contains(existing.ip()) || existing.contains(owned.ip()))
                {
                    return Err(invalid(format!(
                        "managed TUN subnet overlaps existing route {existing}"
                    )));
                }
            }
        }
        if configured && routes.iter().any(|route| table(route) == spec.linux.table) {
            return Err(invalid("managed TUN routing table is not empty"));
        }
        if configured && !routes.iter().any(native_default) {
            return Err(invalid(
                "managed TUN requires an underlying main-table default route without source or TOS constraints for each configured IP family",
            ));
        }
    }
    Ok(())
}

pub(super) fn native_default(route: &RouteMessage) -> bool {
    table(route) == 254
        && route.header.kind == RouteType::Unicast
        && route.header.destination_prefix_length == 0
        && route.header.source_prefix_length == 0
        && route.header.tos == 0
        && !route.attributes.iter().any(|attribute| {
            matches!(
                attribute,
                RouteAttribute::Source(_) | RouteAttribute::Iif(_) | RouteAttribute::Mark(_)
            )
        })
}

pub(super) fn check_mark_reservation(rule: &RuleMessage, spec: &Spec) -> io::Result<()> {
    let mark = rule
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::FwMark(mark) => Some(*mark),
            _ => None,
        })
        .unwrap_or(0);
    let mask = rule
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::FwMask(mask) => Some(*mask),
            _ => None,
        })
        .unwrap_or(if mark == 0 { 0 } else { u32::MAX });
    // Dumps omit zero-valued marks, but their masks still select reserved bits, even when inverted.
    if mask & spec.linux.mark_mask != 0 {
        return Err(invalid(
            "managed TUN mark reservation conflicts with an existing rule",
        ));
    }
    Ok(())
}

fn references_reservation(rule: &RuleMessage, spec: &Spec) -> bool {
    rule.attributes
        .contains(&RuleAttribute::Priority(spec.linux.rule_priority))
        || rule
            .attributes
            .contains(&RuleAttribute::Table(spec.linux.table))
        || u32::from(rule.header.table) == spec.linux.table
}

fn destinations(route: &RouteMessage) -> impl Iterator<Item = io::Result<IpNetwork>> + '_ {
    route.attributes.iter().filter_map(|attribute| {
        let address = match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(ip)) => IpAddr::V4(*ip),
            RouteAttribute::Destination(RouteAddress::Inet6(ip)) => IpAddr::V6(*ip),
            _ => return None,
        };
        Some(
            IpNetwork::new(address, route.header.destination_prefix_length)
                .map_err(io::Error::other),
        )
    })
}

fn has_next_hop(route: &RouteMessage) -> bool {
    route.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            RouteAttribute::Gateway(_)
                | RouteAttribute::Via(_)
                | RouteAttribute::MultiPath(_)
                | RouteAttribute::NhId(_)
        )
    })
}

pub(super) fn check_redirect_gateways(routes: &[RouteMessage], spec: &Spec) -> io::Result<()> {
    fn conflicts(attributes: &[RouteAttribute], spec: &Spec) -> bool {
        attributes.iter().any(|attribute| {
            let gateway = match attribute {
                RouteAttribute::Gateway(RouteAddress::Inet(ip))
                | RouteAttribute::Via(RouteVia::Inet(ip)) => IpAddr::V4(*ip),
                RouteAttribute::Gateway(RouteAddress::Inet6(ip))
                | RouteAttribute::Via(RouteVia::Inet6(ip)) => IpAddr::V6(*ip),
                RouteAttribute::MultiPath(hops) => {
                    return hops.iter().any(|hop| conflicts(&hop.attributes, spec));
                }
                // Opaque nexthop objects cannot establish exclusive ownership of the route marker.
                RouteAttribute::NhId(_) => return true,
                _ => return false,
            };
            spec.redirect_gateway(gateway.is_ipv6()) == Some(gateway)
        })
    }
    if spec.redirect
        && routes
            .iter()
            .any(|route| table(route) != spec.linux.table && conflicts(&route.attributes, spec))
    {
        return Err(invalid(
            "auto_redirect requires exclusive virtual peer gateways and does not support nexthop-object routes",
        ));
    }
    Ok(())
}

fn check_precedence(rule: &RuleMessage, spec: &Spec) -> io::Result<()> {
    let priority = rule
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(priority) => Some(*priority),
            _ => None,
        })
        .unwrap_or(0);
    let local = rule.header.action == RuleAction::ToTable
        && rule.header.src_len == 0
        && rule.header.dst_len == 0
        && rule.header.tos == 0
        && rule.header.flags.is_empty()
        && priority == 0
        && (rule.header.table == 255 || rule.attributes.contains(&RuleAttribute::Table(255)))
        && rule.attributes.iter().all(|attribute| {
            matches!(
                attribute,
                RuleAttribute::Table(255)
                    | RuleAttribute::Priority(0)
                    | RuleAttribute::SuppressPrefixLen(u32::MAX)
                    | RuleAttribute::Protocol(RouteProtocol::Kernel)
            )
        });
    if priority < spec.linux.rule_priority && !local {
        return Err(invalid(
            "managed capture does not support preceding foreign policy rules; configure an explicit nonconflicting rule_priority",
        ));
    }
    Ok(())
}

pub(super) fn default_route(spec: &Spec, index: u32, ipv6: bool) -> RouteMessage {
    let mut route = if ipv6 {
        RouteMessageBuilder::<Ipv6Addr>::new()
            .table_id(spec.linux.table)
            .output_interface(index)
            .scope(RouteScope::Universe)
            .protocol(PROTOCOL)
            .build()
    } else {
        RouteMessageBuilder::<Ipv4Addr>::new()
            .table_id(spec.linux.table)
            .output_interface(index)
            .scope(RouteScope::Link)
            .protocol(PROTOCOL)
            .build()
    };
    if let Some(gateway) = spec.redirect_gateway(ipv6) {
        route
            .attributes
            .push(RouteAttribute::Gateway(match gateway {
                IpAddr::V4(ip) => RouteAddress::Inet(ip),
                IpAddr::V6(ip) => RouteAddress::Inet6(ip),
            }));
        route.header.scope = RouteScope::Universe;
        route.header.flags.insert(RouteFlags::Onlink);
    }
    route
}

pub(super) fn same_route(actual: &RouteMessage, expected: &RouteMessage) -> bool {
    if table(actual) != table(expected) {
        return false;
    }
    let mut actual = actual.clone();
    let mut expected = expected.clone();
    for route in [&mut actual, &mut expected] {
        route.header.table = 0;
        let ipv6 = route.header.address_family == AddressFamily::Inet6;
        // Dumps include table encoding, IPv6 defaults and dynamic cache statistics.
        route.attributes.retain(|attribute| match attribute {
            RouteAttribute::Table(_) => false,
            RouteAttribute::Priority(1024)
            | RouteAttribute::Preference(RoutePreference::Medium)
                if ipv6 =>
            {
                false
            }
            RouteAttribute::CacheInfo(info) if info.expires == 0 && info.error == 0 => false,
            _ => true,
        });
    }
    actual.header == expected.header
        && actual.attributes.len() == expected.attributes.len()
        && expected
            .attributes
            .iter()
            .all(|attribute| actual.attributes.contains(attribute))
}

pub(super) async fn check_cleanup_routes(
    handle: &Handle,
    spec: &Spec,
    index: Option<u32>,
) -> io::Result<()> {
    for ipv6 in families(spec) {
        for route in dump(handle, ipv6).await? {
            if table(&route) == spec.linux.table
                && !index.is_some_and(|index| same_route(&route, &default_route(spec, index, ipv6)))
            {
                return Err(io::Error::other(
                    "managed TUN routing table was changed externally; refusing to forget it",
                ));
            }
        }
    }
    Ok(())
}

pub(super) async fn configure(
    handle: &Handle,
    spec: &Spec,
    index: u32,
    alias: &str,
) -> io::Result<()> {
    request(
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .alias(alias)
                    .mtu(u32::from(spec.mtu))
                    .up()
                    .build(),
            )
            .execute(),
    )
    .await?;
    for network in &spec.addresses {
        let mut add = handle.address().add(index, network.ip(), network.prefix());
        if network.is_ipv6() {
            add.message_mut()
                .header
                .flags
                .insert(AddressHeaderFlags::Nodad);
            add.message_mut()
                .attributes
                .push(AddressAttribute::Flags(AddressFlags::Nodad));
        }
        request(add.execute()).await?;
    }
    if spec.addresses.iter().any(IpNetwork::is_ipv4) {
        std::fs::write(
            format!("/proc/sys/net/ipv4/conf/{}/rp_filter", spec.name),
            "2",
        )?;
    }
    for ipv6 in families(spec) {
        request(
            handle
                .route()
                .add(default_route(spec, index, ipv6))
                .execute(),
        )
        .await?;
        let mut add = handle.rule().add();
        *add.message_mut() = rule(spec, ipv6);
        request(add.execute()).await?;
    }
    Ok(())
}

pub(super) async fn remove_rules(handle: &Handle, spec: &Spec) -> io::Result<()> {
    for ipv6 in families(spec) {
        let expected = rule(spec, ipv6);
        for actual in rules(handle, ipv6).await? {
            if same_rule(&actual, &expected) {
                request(handle.rule().del(actual).execute()).await?;
            } else if references_reservation(&actual, spec) {
                return Err(io::Error::other(
                    "managed TUN rule was changed externally; refusing to remove it",
                ));
            }
        }
    }
    Ok(())
}

pub(super) async fn check(handle: &Handle, spec: &Spec, index: u32, alias: &str) -> io::Result<()> {
    if !link(handle, &spec.name).await?.is_some_and(|link| {
        owned_link(&link, index, &spec.name, alias)
            && link.header.flags.contains(LinkFlags::Up)
            && link
                .attributes
                .contains(&LinkAttribute::Mtu(u32::from(spec.mtu)))
    }) {
        return Err(io::Error::other(
            "managed TUN interface disappeared or changed ownership/state",
        ));
    }
    let addresses = request(
        handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute()
            .try_collect::<Vec<_>>(),
    )
    .await?;
    for network in &spec.addresses {
        if !addresses.iter().any(|address| {
            address.header.prefix_len == network.prefix()
                && address.attributes.iter().any(|attribute| {
                    matches!(attribute,
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) if *ip == network.ip())
                })
        }) {
            return Err(io::Error::other("managed TUN address disappeared"));
        }
    }
    for ipv6 in [false, true] {
        let configured = families(spec).any(|family| family == ipv6);
        let rules = rules(handle, ipv6).await?;
        let expected = rule(spec, ipv6);
        for actual in &rules {
            if configured {
                check_precedence(actual, spec)?;
            }
            if !configured || !same_rule(actual, &expected) {
                check_mark_reservation(actual, spec)?;
            }
        }
        if !configured {
            continue;
        }
        let reserved: Vec<_> = rules
            .iter()
            .filter(|rule| references_reservation(rule, spec))
            .collect();
        if reserved.len() != 1 || !same_rule(reserved[0], &expected) {
            return Err(io::Error::other(
                "managed TUN policy rule disappeared or changed",
            ));
        }
        let routes = dump(handle, ipv6).await?;
        check_redirect_gateways(&routes, spec)?;
        let owned: Vec<_> = routes
            .iter()
            .filter(|route| table(route) == spec.linux.table)
            .collect();
        let expected = default_route(spec, index, ipv6);
        if owned.len() != 1 || !same_route(owned[0], &expected) {
            return Err(io::Error::other(
                "managed TUN routing table disappeared or changed",
            ));
        }
    }
    Ok(())
}

pub(super) async fn on_link(handle: &Handle, index: u32) -> io::Result<Vec<IpNetwork>> {
    let mut networks = Vec::new();
    for ipv6 in [false, true] {
        for route in dump(handle, ipv6).await? {
            if table(&route) != 254
                || route.header.kind != RouteType::Unicast
                || route.header.destination_prefix_length == 0
                || route.attributes.contains(&RouteAttribute::Oif(index))
                || has_next_hop(&route)
            {
                continue;
            }
            for network in destinations(&route) {
                networks.push(network?);
            }
        }
    }
    networks.sort();
    networks.dedup();
    Ok(networks)
}
