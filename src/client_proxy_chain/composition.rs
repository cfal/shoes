use super::*;
use crate::config::{ClientChainHop, ConfigSelection, GlobalLimits, GroupType};
use crate::control::selection::{Choices, SelectionView};
use crate::option_util::OneOrSome;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use std::io;

struct Leaf {
    origin: Option<MemberOrigin>,
    direct: bool,
    initial: Option<Arc<InitialHopEntry>>,
    proxy: Option<Arc<dyn ProxyConnector>>,
    udp: bool,
}

enum Node {
    Client(Leaf),
    Sequence(Vec<Node>),
    Choice {
        name: String,
        kind: GroupType,
        labels: Vec<String>,
        members: Vec<Node>,
        next: [AtomicU32; 2],
        static_members: Option<[Vec<usize>; 2]>,
    },
}

pub(crate) struct Composition {
    root: Node,
    selection: Option<Arc<SelectionView>>,
}

struct Selection<'a> {
    choices: &'a Choices,
    view: Option<&'a SelectionView>,
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "fallback has no healthy or unknown eligible member",
    )
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "selected branch cannot carry this flow",
    )
}

impl Composition {
    pub(super) fn selection(&self) -> Option<&Arc<SelectionView>> {
        self.selection.as_ref()
    }
    pub(super) fn build(
        hops: OneOrSome<ClientChainHop>,
        resolver: Arc<dyn Resolver>,
        limits: GlobalLimits,
    ) -> io::Result<Arc<Self>> {
        crate::config::composition::validate(&hops)?;
        let selection = hops
            .iter()
            .flat_map(crate::config::composition::clients)
            .find_map(|client| {
                client
                    .control
                    .as_ref()
                    .map(|origin| origin.selection.clone())
            });
        let root = sequence(hops, true, &resolver, limits)?;
        Ok(Arc::new(Self { root, selection }))
    }

    pub(super) fn select(&self, udp: bool) -> io::Result<ClientProxyChain> {
        let choices = self
            .selection
            .as_ref()
            .map(|view| view.snapshot())
            .unwrap_or_default();
        let selection = Selection {
            choices: &choices,
            view: self.selection.as_deref(),
        };
        let mut leaves = Vec::new();
        self.root.select(udp, &selection, &mut leaves)?;
        Ok(pinned(&leaves))
    }

    pub(super) fn supports_udp(&self) -> bool {
        self.root.supports_udp()
    }
    pub(super) fn num_hops(&self) -> usize {
        self.root.num_hops()
    }
    pub(super) fn direct_only(&self) -> bool {
        self.root.direct_only()
    }
    pub(super) fn may_connect_directly(&self) -> bool {
        self.root.may_connect_directly()
    }
    pub(super) fn record_demand(&self) {
        if crate::control::url_test::is_background() {
            return;
        }
        self.root.record_demand(self.selection.as_deref());
    }
}

#[cfg(test)]
impl Composition {
    fn test_pools(&self) -> Vec<Vec<&Leaf>> {
        fn collect<'a>(node: &'a Node, start: usize, pools: &mut Vec<Vec<&'a Leaf>>) -> usize {
            match node {
                Node::Client(leaf) => {
                    pools.resize_with(pools.len().max(start + 1), Vec::new);
                    pools[start].push(leaf);
                    start + 1
                }
                Node::Sequence(nodes) => nodes
                    .iter()
                    .fold(start, |offset, node| collect(node, offset, pools)),
                Node::Choice { members, .. } => members
                    .iter()
                    .map(|member| collect(member, start, pools))
                    .max()
                    .unwrap(),
            }
        }
        let mut pools = Vec::new();
        collect(&self.root, 0, &mut pools);
        pools
    }

    pub(super) fn test_select_indices(&self, udp: bool) -> io::Result<Vec<usize>> {
        let selected = self.select(udp)?;
        let pools = self.test_pools();
        let mut indices = vec![
            pools[0]
                .iter()
                .position(|leaf| {
                    Arc::ptr_eq(leaf.initial.as_ref().unwrap(), &selected.initial_hop[0])
                })
                .unwrap(),
        ];
        for (index, hop) in selected.subsequent_hops.iter().enumerate() {
            indices.push(
                pools[index + 1]
                    .iter()
                    .position(|leaf| {
                        leaf.proxy
                            .as_ref()
                            .is_some_and(|proxy| Arc::ptr_eq(proxy, &hop[0]))
                    })
                    .unwrap(),
            );
        }
        Ok(indices)
    }
}

fn sequence(
    hops: OneOrSome<ClientChainHop>,
    first: bool,
    resolver: &Arc<dyn Resolver>,
    limits: GlobalLimits,
) -> io::Result<Node> {
    let mut nodes = Vec::new();
    for (index, hop) in hops.into_vec().into_iter().enumerate() {
        nodes.push(node(hop, first && index == 0, resolver, limits)?);
    }
    if nodes.is_empty() {
        return Err(crate::config::composition::invalid("chain cannot be empty"));
    }
    Ok(if nodes.len() == 1 {
        nodes.remove(0)
    } else {
        Node::Sequence(nodes)
    })
}

fn node(
    hop: ClientChainHop,
    first: bool,
    resolver: &Arc<dyn Resolver>,
    limits: GlobalLimits,
) -> io::Result<Node> {
    match hop {
        ClientChainHop::Single(ConfigSelection::GroupName(name)) => Err(
            crate::config::composition::invalid(format!("unresolved client group: {name}")),
        ),
        ClientChainHop::Single(ConfigSelection::Config(mut config)) => {
            let origin = config.control.clone();
            let direct = config.protocol.is_direct();
            let (initial, proxy, udp) = if first {
                config.control = None;
                let chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
                    OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(config))),
                    resolver.clone(),
                    limits,
                )?;
                let entry = chain.initial_hop[0].clone();
                let udp = entry.supports_udp();
                (Some(entry), None, udp)
            } else {
                let proxy: Arc<dyn ProxyConnector> = Arc::new(
                    ProxyConnectorImpl::from_config(config, resolver.clone())?
                        .ok_or_else(unsupported)?,
                );
                let udp = proxy.supports_udp_over_tcp();
                (None, Some(proxy), udp)
            };
            Ok(Node::Client(Leaf {
                origin,
                direct,
                initial,
                proxy,
                udp,
            }))
        }
        ClientChainHop::Pool(pool) => node(
            crate::config::composition::pool_choice(
                pool.into_vec()
                    .into_iter()
                    .map(|selection| crate::config::ClientChain {
                        hops: OneOrSome::One(ClientChainHop::Single(selection)),
                    })
                    .collect(),
            ),
            first,
            resolver,
            limits,
        ),
        ClientChainHop::Choice(choice) => {
            let mut members = Vec::new();
            for member in choice.members {
                members.push(sequence(member.hops, first, resolver, limits)?);
            }
            let static_members = (choice.group_type == GroupType::RoundRobin
                && !members.iter().any(Node::has_dynamic_policy))
            .then(|| {
                [
                    (0..members.len()).collect(),
                    members
                        .iter()
                        .enumerate()
                        .filter_map(|(index, member)| member.supports_udp().then_some(index))
                        .collect(),
                ]
            });
            Ok(Node::Choice {
                name: choice.name,
                kind: choice.group_type,
                labels: choice.labels,
                members,
                next: [AtomicU32::new(0), AtomicU32::new(0)],
                static_members,
            })
        }
    }
}

fn pinned(leaves: &[&Leaf]) -> ClientProxyChain {
    let origins = leaves
        .iter()
        .map(|leaf| vec![leaf.origin.clone()])
        .collect();
    let udp = leaves.last().unwrap().udp;
    let subsequent_hops: Vec<_> = leaves
        .iter()
        .skip(1)
        .map(|leaf| vec![leaf.proxy.as_ref().unwrap().clone()])
        .collect();
    ClientProxyChain {
        composition: None,
        origins,
        selection: leaves
            .iter()
            .find_map(|leaf| leaf.origin.as_ref().map(|origin| origin.selection.clone())),
        selector_hops: vec![false; leaves.len()],
        initial_hop: vec![leaves[0].initial.as_ref().unwrap().clone()],
        initial_hop_next_index: AtomicU32::new(0),
        subsequent_next_indices: subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect(),
        subsequent_hops,
        udp_final_hop_indices: if udp { vec![0] } else { Vec::new() },
        udp_final_hop_next_index: AtomicU32::new(0),
        udp_uses_initial_hop: leaves.len() == 1,
    }
}

impl Node {
    fn num_hops(&self) -> usize {
        match self {
            Self::Client(_) => 1,
            Self::Sequence(nodes) => nodes.iter().map(Self::num_hops).sum(),
            Self::Choice { members, .. } => members.iter().map(Self::num_hops).max().unwrap_or(0),
        }
    }
    fn has_dynamic_policy(&self) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Sequence(nodes) => nodes.iter().any(Self::has_dynamic_policy),
            Self::Choice { kind, members, .. } => {
                matches!(kind, GroupType::Selector | GroupType::Fallback { .. })
                    || members.iter().any(Self::has_dynamic_policy)
            }
        }
    }
    fn supports_udp(&self) -> bool {
        match self {
            Self::Client(leaf) => leaf.udp,
            Self::Sequence(nodes) => nodes.last().unwrap().supports_udp(),
            Self::Choice { members, .. } => members.iter().any(Self::supports_udp),
        }
    }
    fn direct_only(&self) -> bool {
        match self {
            Self::Client(leaf) => leaf.direct,
            Self::Sequence(_) => false,
            Self::Choice { members, .. } => members.iter().all(Self::direct_only),
        }
    }
    fn may_connect_directly(&self) -> bool {
        match self {
            Self::Client(leaf) => leaf.direct,
            Self::Sequence(_) => false,
            Self::Choice { members, .. } => members.iter().any(Self::may_connect_directly),
        }
    }
    fn eligible(&self, udp: bool, choices: &Choices) -> bool {
        match self {
            Self::Client(leaf) => !udp || leaf.udp,
            Self::Sequence(nodes) => nodes
                .iter()
                .enumerate()
                .all(|(index, node)| node.eligible(udp && index + 1 == nodes.len(), choices)),
            Self::Choice {
                name,
                kind,
                labels,
                members,
                ..
            } => members.iter().enumerate().any(|(index, member)| {
                (*kind != GroupType::Selector || choices.get(name) == Some(&labels[index]))
                    && member.eligible(udp, choices)
            }),
        }
    }
    fn available(&self, udp: bool, selection: &Selection<'_>) -> bool {
        match self {
            Self::Client(leaf) => !udp || leaf.udp,
            Self::Sequence(nodes) => nodes
                .iter()
                .enumerate()
                .all(|(index, node)| node.available(udp && index + 1 == nodes.len(), selection)),
            Self::Choice {
                name,
                kind,
                labels,
                members,
                ..
            } => members.iter().enumerate().any(|(index, member)| {
                (*kind != GroupType::Selector
                    || selection.choices.get(name) == Some(&labels[index]))
                    && (!matches!(kind, GroupType::Fallback { .. })
                        || selection.view.is_some_and(|view| {
                            matches!(
                                view.health
                                    .member_health(name, &labels[index], selection.choices),
                                crate::control::health::Health::Healthy
                                    | crate::control::health::Health::Unknown
                            )
                        }))
                    && member.available(udp, selection)
            }),
        }
    }
    fn record_demand(&self, selection: Option<&SelectionView>) {
        match self {
            Self::Client(leaf) => {
                if let Some(entry) = &leaf.initial {
                    entry.socket().record_demand();
                }
            }
            Self::Sequence(nodes) => {
                for node in nodes {
                    node.record_demand(selection);
                }
            }
            Self::Choice { name, members, .. } => {
                if let Some(selection) = selection {
                    selection.automatic.touch(name, false);
                }
                for member in members {
                    member.record_demand(selection);
                }
            }
        }
    }
    fn select<'a>(
        &'a self,
        udp: bool,
        selection: &Selection<'_>,
        leaves: &mut Vec<&'a Leaf>,
    ) -> io::Result<()> {
        match self {
            Self::Client(leaf) => {
                if udp && !leaf.udp {
                    return Err(unsupported());
                }
                leaves.push(leaf);
            }
            Self::Sequence(nodes) => {
                // Capability errors precede health failures, without enumerating paths.
                if !self.eligible(udp, selection.choices) {
                    return Err(unsupported());
                }
                for (index, node) in nodes.iter().enumerate() {
                    node.select(udp && index + 1 == nodes.len(), selection, leaves)?;
                }
            }
            Self::Choice {
                name,
                kind,
                labels,
                members,
                next,
                static_members,
            } => {
                if let Some(eligible) = static_members {
                    let eligible = &eligible[usize::from(udp)];
                    if eligible.is_empty() {
                        return Err(unsupported());
                    }
                    let selected = eligible[next[usize::from(udp)].fetch_add(1, Ordering::Relaxed)
                        as usize
                        % eligible.len()];
                    return members[selected].select(udp, selection, leaves);
                }
                let mut eligible: Vec<_> = members
                    .iter()
                    .enumerate()
                    .filter_map(|(index, member)| {
                        ((*kind != GroupType::Selector
                            || selection.choices.get(name) == Some(&labels[index]))
                            && member.eligible(udp, selection.choices))
                        .then_some(index)
                    })
                    .collect();
                if eligible.is_empty() {
                    return Err(unsupported());
                }
                eligible.retain(|index| members[*index].available(udp, selection));
                if eligible.is_empty() {
                    return Err(unavailable());
                }
                let selected = match kind {
                    GroupType::UrlTest(_) | GroupType::Fallback { .. } => {
                        let view = selection.view.ok_or_else(unsupported)?;
                        let names = eligible
                            .iter()
                            .map(|index| labels[*index].as_str())
                            .collect();
                        let selected = if matches!(kind, GroupType::UrlTest(_)) {
                            view.automatic
                                .0
                                .get(name)
                                .ok_or_else(unsupported)?
                                .choose(&names, udp)
                        } else {
                            view.health.choose(name, &names, selection.choices)
                        }
                        .ok_or_else(unavailable)?;
                        eligible
                            .into_iter()
                            .find(|index| labels[*index] == selected)
                            .unwrap()
                    }
                    _ => {
                        eligible[next[usize::from(udp)].fetch_add(1, Ordering::Relaxed) as usize
                            % eligible.len()]
                    }
                };
                members[selected].select(udp, selection, leaves)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (ClientProxyChain, crate::control::catalog::Catalog) {
        super::super::health_tests::build(
            json!([
                {"client_group":"entry","client_chains":[{"name":"entrance","address":"192.0.2.1:80","protocol":{"type":"http"}}]},
                {"client_group":"exit","client_chains":[{"name":"exit-leaf","address":"192.0.2.2:80","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}}]},
                {"client_group":"out","type":"selector","client_chains":[{"chain": ["entry"]},{"name":"via-exit","chain":["entry","exit"]},{"chain": ["direct"]}]}
            ]),
            json!("out"),
        )
    }

    #[test]
    fn mixed_length_selection_pins_the_whole_path_and_fails_udp_closed() {
        let (chain, catalog) = fixture();
        let tree = chain.composition.as_ref().unwrap();
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        let single = tree.select(false).unwrap();
        assert_eq!(single.num_hops(), 1);
        assert_eq!(
            tree.select(true).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        owner.select("out", "via-exit").unwrap();
        let two = tree.select(true).unwrap();
        assert_eq!(two.num_hops(), 2);
        assert!(two.supports_udp());
        assert_eq!(two.origin(0, 0).unwrap().name.as_ref(), "entrance");
        assert_eq!(two.origin(1, 0).unwrap().name.as_ref(), "exit-leaf");
        for hop in 0..2 {
            let origin = two.origin(hop, 0).unwrap();
            assert_eq!(origin.path[0], ("out".into(), "via-exit".into()));
            assert!(Arc::ptr_eq(&origin.selection, &catalog.selection));
        }
        owner.select("out", "DIRECT").unwrap();
        let direct = tree.select(true).unwrap();
        assert!(direct.is_direct_only());
        assert_eq!(direct.origin(0, 0).unwrap().name.as_ref(), "DIRECT");
        assert_eq!(two.num_hops(), 2);
        assert!(!single.is_direct_only());
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let target: ResolvedLocation = crate::address::NetLocation::from_str("192.0.2.2:80", None)
            .unwrap()
            .into();
        let before = two
            .selected_route(&resolver, &[0, 0])
            .prefix(target.clone());
        owner.select("out", "via-exit").unwrap();
        let again = tree.select(false).unwrap();
        let after = again.selected_route(&resolver, &[0, 0]).prefix(target);
        assert_eq!(
            before.route_key(),
            after.route_key(),
            "reselecting a path must retain its carrier identities"
        );
    }

    #[test]
    fn same_length_alternatives_never_mix_their_hops() {
        let (chain, _) = super::super::health_tests::build(
            json!([
                {"client_group":"out","type":"selector","client_chains":[
                    {"name":"left","chain":[{"address":"192.0.2.1:80","protocol":{"type":"http"}},{"address":"192.0.2.2:80","protocol":{"type":"http"}}]},
                    {"name":"right","chain":[{"address":"192.0.2.3:80","protocol":{"type":"http"}},{"address":"192.0.2.4:80","protocol":{"type":"http"}}]}
                ]}
            ]),
            json!("out"),
        );
        let tree = chain.composition.as_ref().unwrap();
        for _ in 0..20 {
            let pinned = tree.select(false).unwrap();
            let InitialHopEntry::Proxy { proxy, .. } = pinned.initial_hop[0].as_ref() else {
                panic!()
            };
            assert_eq!(proxy.proxy_location().to_string(), "192.0.2.1:80");
            assert_eq!(
                pinned.subsequent_hops[0][0].proxy_location().to_string(),
                "192.0.2.2:80"
            );
        }
    }

    #[tokio::test]
    async fn pinned_chain_keeps_connectors_after_composition_is_dropped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let (chain, _) = super::super::health_tests::build(
                json!([{"client_group":"out", "type":"selector", "client_chains":[
                    {"chain":[{"name":"local", "protocol":{"type":"direct"}}]},
                    {"chain":["direct"]}
                ]}]),
                json!("out"),
            );
            let composition = chain.composition.as_ref().unwrap();
            let weak = Arc::downgrade(composition);
            let pinned = composition.select(false).unwrap();
            drop(chain);
            assert!(weak.upgrade().is_none());
            assert_eq!(pinned.origin(0, 0).unwrap().name.as_ref(), "local");

            let target = crate::address::NetLocation::from_str(
                &format!("127.0.0.1:{}", listener.local_addr().unwrap().port()),
                None,
            )
            .unwrap();
            let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
            let mut connection = pinned.connect_tcp(target.into(), &resolver).await.unwrap();
            connection.client_stream.write_all(b"pinned").await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut received = [0; 6];
            peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"pinned");
        })
        .await
        .unwrap();
    }

    #[test]
    fn probe_connectors_do_not_advance_forwarding_counters_or_reselect_pinned_flows() {
        let (chain, catalog) = super::super::health_tests::build(
            json!([
                {"client_group":"pool","client_chains":[
                    {"chain": [{"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}}]},
                    {"chain": [{"name":"b","address":"192.0.2.2:80","protocol":{"type":"http"}}]}
                ]},
                {"client_group":"auto","type":"url-test","url":"http://192.0.2.3/",
                 "client_chains":[{"chain": ["pool"]},{"chain": ["direct"]}]}
            ]),
            json!("auto"),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let probe = crate::tcp::chain_builder::try_build_client_proxy_chain(
            catalog.route("pool").unwrap().hops,
            resolver,
        )
        .unwrap();
        for _ in 0..3 {
            probe.composition.as_ref().unwrap().select(false).unwrap();
        }
        let pinned = chain.composition.as_ref().unwrap().select(false).unwrap();
        let InitialHopEntry::Proxy { proxy, .. } = pinned.initial_hop[0].as_ref() else {
            panic!()
        };
        assert_eq!(proxy.proxy_location().to_string(), "192.0.2.1:80");
        catalog
            .selection
            .automatic
            .record("DIRECT", "http://192.0.2.3/", Some(1));
        assert!(
            chain
                .composition
                .as_ref()
                .unwrap()
                .select(false)
                .unwrap()
                .is_direct_only()
        );
        assert!(!pinned.is_direct_only());
        assert_eq!(proxy.proxy_location().to_string(), "192.0.2.1:80");
    }
}
