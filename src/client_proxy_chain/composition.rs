use super::*;
use crate::config::{GlobalLimits, GroupType, ResolvedClientHop};
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
        static_eligible_indices: Option<[Vec<usize>; 2]>,
    },
}

pub(crate) struct Composition {
    root: Node,
    selection: Option<Arc<SelectionView>>,
}

struct Selection<'a> {
    choices: &'a Choices,
    view: Option<&'a SelectionView>,
    udp_flow: bool,
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "selected branch cannot carry this flow",
    )
}

impl Composition {
    #[cfg(unix)]
    pub(super) fn tcp_selection_indices(&self) -> Vec<u32> {
        let mut indices = Vec::new();
        self.root.visit_tcp_counters(&mut |counter| {
            indices.push(counter.load(Ordering::Relaxed));
        });
        indices
    }

    #[cfg(unix)]
    pub(super) fn restore_tcp_selection_indices(&self, indices: &[u32]) {
        let mut count = 0;
        self.root.visit_tcp_counters(&mut |_| count += 1);
        assert_eq!(indices.len(), count);
        let mut indices = indices.iter();
        self.root.visit_tcp_counters(&mut |counter| {
            counter.store(*indices.next().unwrap(), Ordering::Relaxed);
        });
    }

    #[cfg(test)]
    pub(super) fn from_connectors(
        initial: Vec<InitialHopEntry>,
        subsequent: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Arc<Self> {
        let mut nodes = vec![Node::pool(
            initial
                .into_iter()
                .map(|entry| {
                    Node::Client(Leaf {
                        origin: None,
                        direct: matches!(entry, InitialHopEntry::Direct(_)),
                        udp: entry.supports_udp(),
                        initial: Some(Arc::new(entry)),
                        proxy: None,
                    })
                })
                .collect(),
        )];
        nodes.extend(subsequent.into_iter().map(|pool| {
            Node::pool(
                pool.into_iter()
                    .map(|proxy| {
                        Node::Client(Leaf {
                            origin: None,
                            direct: false,
                            udp: proxy.supports_udp(),
                            initial: None,
                            proxy: Some(Arc::from(proxy)),
                        })
                    })
                    .collect(),
            )
        }));
        Arc::new(Self {
            root: Node::sequence(nodes),
            selection: None,
        })
    }
    pub(super) fn build(
        hops: OneOrSome<ResolvedClientHop>,
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

    pub(super) fn select(&self, udp: bool) -> io::Result<SelectedPath> {
        let choices = self
            .selection
            .as_ref()
            .map(|view| view.snapshot())
            .unwrap_or_default();
        let selection = Selection {
            choices: &choices,
            view: self.selection.as_deref(),
            udp_flow: udp,
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
                .position(|leaf| Arc::ptr_eq(leaf.initial.as_ref().unwrap(), &selected.initial))
                .unwrap(),
        ];
        for (index, hop) in selected.subsequent.iter().enumerate() {
            indices.push(
                pools[index + 1]
                    .iter()
                    .position(|leaf| {
                        leaf.proxy
                            .as_ref()
                            .is_some_and(|proxy| Arc::ptr_eq(proxy, hop))
                    })
                    .unwrap(),
            );
        }
        Ok(indices)
    }
}

fn sequence(
    hops: OneOrSome<ResolvedClientHop>,
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
    Ok(Node::sequence(nodes))
}

fn node(
    hop: ResolvedClientHop,
    first: bool,
    resolver: &Arc<dyn Resolver>,
    limits: GlobalLimits,
) -> io::Result<Node> {
    match hop {
        ResolvedClientHop::Single(mut config) => {
            let origin = config.control.clone();
            let direct = config.protocol.is_direct();
            let (initial, proxy, udp) = if first {
                config.control = None;
                let chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
                    OneOrSome::One(ResolvedClientHop::Single(config)),
                    resolver.clone(),
                    limits,
                )?;
                let ChainPlan::Fixed(path) = chain.plan else {
                    unreachable!("single leaf builds a fixed path")
                };
                let entry = path.initial;
                let udp = entry.supports_udp();
                (Some(entry), None, udp)
            } else {
                let proxy: Arc<dyn ProxyConnector> = Arc::new(
                    ProxyConnectorImpl::from_config(config, resolver.clone())?
                        .ok_or_else(unsupported)?,
                );
                let udp = proxy.supports_udp();
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
        ResolvedClientHop::Choice(choice) => {
            let mut members = Vec::new();
            for member in choice.members {
                members.push(sequence(member.hops, first, resolver, limits)?);
            }
            let static_eligible_indices = (choice.group_type == GroupType::RoundRobin
                && !members.iter().any(Node::contains_selector))
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
                static_eligible_indices,
            })
        }
    }
}

fn pinned(leaves: &[&Leaf]) -> SelectedPath {
    let origins = leaves.iter().map(|leaf| leaf.origin.clone()).collect();
    let subsequent_hops: Vec<_> = leaves
        .iter()
        .skip(1)
        .map(|leaf| leaf.proxy.as_ref().unwrap().clone())
        .collect();
    SelectedPath {
        origins,
        initial: leaves[0].initial.as_ref().unwrap().clone(),
        subsequent: subsequent_hops,
    }
}

impl Node {
    fn sequence(mut nodes: Vec<Self>) -> Self {
        if nodes.len() == 1 {
            nodes.pop().unwrap()
        } else {
            Self::Sequence(nodes)
        }
    }

    #[cfg(test)]
    fn pool(mut members: Vec<Self>) -> Self {
        if members.len() == 1 {
            return members.pop().unwrap();
        }
        let eligible = [
            (0..members.len()).collect(),
            members
                .iter()
                .enumerate()
                .filter_map(|(index, member)| member.supports_udp().then_some(index))
                .collect(),
        ];
        Self::Choice {
            name: String::new(),
            kind: GroupType::RoundRobin,
            labels: Vec::new(),
            members,
            next: [AtomicU32::new(0), AtomicU32::new(0)],
            static_eligible_indices: Some(eligible),
        }
    }
    #[cfg(unix)]
    fn visit_tcp_counters(&self, visitor: &mut impl FnMut(&AtomicU32)) {
        match self {
            Self::Client(_) => {}
            Self::Sequence(nodes) => {
                for node in nodes {
                    node.visit_tcp_counters(visitor);
                }
            }
            Self::Choice { next, members, .. } => {
                visitor(&next[0]);
                for member in members {
                    member.visit_tcp_counters(visitor);
                }
            }
        }
    }

    fn num_hops(&self) -> usize {
        match self {
            Self::Client(_) => 1,
            Self::Sequence(nodes) => nodes.iter().map(Self::num_hops).sum(),
            Self::Choice { members, .. } => members.iter().map(Self::num_hops).max().unwrap_or(0),
        }
    }
    fn contains_selector(&self) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Sequence(nodes) => nodes.iter().any(Self::contains_selector),
            Self::Choice { kind, members, .. } => {
                matches!(kind, GroupType::Selector) || members.iter().any(Self::contains_selector)
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
        require_udp: bool,
        selection: &Selection<'_>,
        leaves: &mut Vec<&'a Leaf>,
    ) -> io::Result<()> {
        match self {
            Self::Client(leaf) => {
                if require_udp && !leaf.udp {
                    return Err(unsupported());
                }
                leaves.push(leaf);
            }
            Self::Sequence(nodes) => {
                if !self.eligible(require_udp, selection.choices) {
                    return Err(unsupported());
                }
                for (index, node) in nodes.iter().enumerate() {
                    node.select(require_udp && index + 1 == nodes.len(), selection, leaves)?;
                }
            }
            Self::Choice {
                name,
                kind,
                labels,
                members,
                next,
                static_eligible_indices,
            } => {
                if let Some(eligible) = static_eligible_indices {
                    let eligible = &eligible[usize::from(require_udp)];
                    if eligible.is_empty() {
                        return Err(unsupported());
                    }
                    let selected = eligible[next[usize::from(selection.udp_flow)]
                        .fetch_add(1, Ordering::Relaxed)
                        as usize
                        % eligible.len()];
                    return members[selected].select(require_udp, selection, leaves);
                }
                let eligible: Vec<_> = members
                    .iter()
                    .enumerate()
                    .filter_map(|(index, member)| {
                        ((*kind != GroupType::Selector
                            || selection.choices.get(name) == Some(&labels[index]))
                            && member.eligible(require_udp, selection.choices))
                        .then_some(index)
                    })
                    .collect();
                if eligible.is_empty() {
                    return Err(unsupported());
                }
                let selected = match kind {
                    GroupType::UrlTest(_) => {
                        let view = selection.view.ok_or_else(unsupported)?;
                        let names = eligible
                            .iter()
                            .map(|index| labels[*index].as_str())
                            .collect();
                        let selected = view
                            .automatic
                            .0
                            .get(name)
                            .ok_or_else(unsupported)?
                            .choose(&names, selection.udp_flow)
                            .ok_or_else(unsupported)?;
                        eligible
                            .into_iter()
                            .find(|index| labels[*index] == selected)
                            .unwrap()
                    }
                    _ => {
                        eligible[next[usize::from(selection.udp_flow)]
                            .fetch_add(1, Ordering::Relaxed)
                            as usize
                            % eligible.len()]
                    }
                };
                members[selected].select(require_udp, selection, leaves)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build(
        mut config: serde_json::Value,
        chain: serde_json::Value,
    ) -> (ClientProxyChain, crate::control::catalog::Catalog) {
        use crate::config::{ResolvedConfig, ResolvedRuleActionConfig};
        config.as_array_mut().unwrap().push(json!({
            "address":"127.0.0.1:0", "protocol":{"type":"socks"},
            "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":chain}]
        }));
        let mut validated =
            crate::config::create_server_configs(serde_json::from_value(config).unwrap()).unwrap();
        let ResolvedConfig::Server(server) = &validated.configs[0] else {
            panic!()
        };
        let ResolvedRuleActionConfig::Allow { client_chains, .. } =
            &server.rules.iter().next().unwrap().action
        else {
            panic!()
        };
        let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            client_chains.iter().next().unwrap().hops.clone(),
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap();
        (chain, validated.catalog.take().unwrap())
    }

    fn fixture() -> (ClientProxyChain, crate::control::catalog::Catalog) {
        build(
            json!([
                {"client_group":"entry","client_chains":[{"name":"entrance","address":"192.0.2.1:80","protocol":{"type":"http"}}]},
                {"client_group":"exit","client_chains":[{"name":"exit-leaf","address":"192.0.2.2:80","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}}]},
                {"client_group":"out","type":"selector","client_chains":[{"chain": ["entry"]},{"name":"via-exit","chain":["entry","exit"]},{"chain": ["direct"]}]}
            ]),
            json!("out"),
        )
    }

    #[test]
    fn forwarding_and_probe_routes_select_the_same_paths() {
        let (forwarding, catalog) = build(
            json!([
                {"client_group":"left","client_chain":{"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}}},
                {"client_group":"right","client_chain":{"name":"b","address":"192.0.2.2:80","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}}},
                {"client_group":"alias","client_chain":"left"},
                {"client_group":"manual","type":"selector","client_chains":[{"chain":["alias"]},{"chain":["right"]}]},
                {"client_group":"auto","type":"url-test","url":"http://probe.invalid/","client_chains":[{"chain":["left"]},{"chain":["right"]}]},
                {"client_group":"out","client_chains":[
                    {"name":"via","chain":["manual","right"]},
                    {"chain":["right"]},
                    {"name":"pooled","chain":[{"pool":["manual","auto"]}]}
                ]}
            ]),
            json!(["out", "out"]),
        );
        let hops = catalog.route("out").unwrap().hops.into_vec();
        let probe = crate::tcp::chain_builder::try_build_client_proxy_chain(
            OneOrSome::Some(hops.iter().chain(&hops).cloned().collect()),
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap();
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        let selected = |chain: &ClientProxyChain, udp| {
            chain
                .select(udp)
                .map(|path| {
                    let initial = match path.initial.as_ref() {
                        InitialHopEntry::Proxy { proxy, .. } => proxy.proxy_location().clone(),
                        _ => panic!("fixture contains only proxy clients"),
                    };
                    let endpoints = std::iter::once(initial)
                        .chain(
                            path.subsequent
                                .iter()
                                .map(|proxy| proxy.proxy_location().clone()),
                        )
                        .collect::<Vec<_>>();
                    let origins = path
                        .origins
                        .iter()
                        .map(|origin| {
                            let origin = origin.as_ref().unwrap();
                            (origin.name.clone(), origin.path.clone())
                        })
                        .collect::<Vec<_>>();
                    (endpoints, origins)
                })
                .unwrap()
        };
        for member in ["alias", "right", "alias"] {
            owner.select("manual", member).unwrap();
            catalog
                .selection
                .automatic
                .record("left", "http://probe.invalid/", Some(10));
            catalog
                .selection
                .automatic
                .record("right", "http://probe.invalid/", Some(100));
            for _ in 0..12 {
                for udp in [false, true] {
                    assert_eq!(selected(&forwarding, udp), selected(&probe, udp));
                }
            }
        }
    }

    #[test]
    fn mixed_length_selection_pins_the_whole_path_and_fails_udp_closed() {
        let (chain, catalog) = fixture();
        let tree = chain.composition().unwrap();
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
        assert_eq!(two.origin(0).unwrap().name.as_ref(), "entrance");
        assert_eq!(two.origin(1).unwrap().name.as_ref(), "exit-leaf");
        for hop in 0..2 {
            let origin = two.origin(hop).unwrap();
            assert_eq!(origin.path[0], ("out".into(), "via-exit".into()));
            assert!(Arc::ptr_eq(&origin.selection, &catalog.selection));
        }
        owner.select("out", "DIRECT").unwrap();
        let direct = tree.select(true).unwrap();
        assert!(direct.is_direct_only());
        assert_eq!(direct.origin(0).unwrap().name.as_ref(), "DIRECT");
        assert_eq!(two.num_hops(), 2);
        assert!(!single.is_direct_only());
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let target: ResolvedLocation = crate::address::NetLocation::from_str("192.0.2.2:80", None)
            .unwrap()
            .into();
        let before = two.selected_route(&resolver).prefix(target.clone());
        owner.select("out", "via-exit").unwrap();
        let again = tree.select(false).unwrap();
        let after = again.selected_route(&resolver).prefix(target);
        assert_eq!(
            before.route_key(),
            after.route_key(),
            "reselecting a path must retain its carrier identities"
        );
    }

    #[test]
    fn same_length_alternatives_never_mix_their_hops() {
        for kind in ["selector", "round-robin"] {
            let (chain, catalog) = build(
                json!([
                    {"clash_api_address":"127.0.0.1:0","secret":"test"},
                    {"client_group":"out","type":kind,"client_chains":[
                        {"name":"left","chain":[{"address":"192.0.2.1:80","protocol":{"type":"http"}},{"address":"192.0.2.2:80","protocol":{"type":"http"}}]},
                        {"name":"right","chain":[{"address":"192.0.2.3:80","protocol":{"type":"http"}},{"address":"192.0.2.4:80","protocol":{"type":"http"}}]}
                    ]}
                ]),
                json!("out"),
            );
            let tree = chain.composition().unwrap();
            let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
            owner.activate(catalog.selection.clone()).unwrap();
            for index in 0..20 {
                let left = index % 2 == 0;
                if kind == "selector" {
                    owner
                        .select("out", if left { "left" } else { "right" })
                        .unwrap();
                }
                let pinned = tree.select(false).unwrap();
                let InitialHopEntry::Proxy { proxy, .. } = pinned.initial.as_ref() else {
                    panic!()
                };
                assert_eq!(
                    proxy.proxy_location().to_string(),
                    if left { "192.0.2.1:80" } else { "192.0.2.3:80" }
                );
                assert_eq!(
                    pinned.subsequent[0].proxy_location().to_string(),
                    if left { "192.0.2.2:80" } else { "192.0.2.4:80" }
                );
            }
        }
    }

    #[test]
    fn config_round_robin_precomputes_transport_indices() {
        const MEMBERS: usize = 2048;
        let members: Vec<_> = (0..MEMBERS)
            .map(|index| {
                json!({"chain":[{
                    "name":format!("member-{index}"),"address":"192.0.2.1:80",
                    "protocol":{"type":if index % 2 == 0 { "http" } else { "direct" }}
                }]})
            })
            .collect();
        let (chain, _) = build(
            json!([
                {"clash_api_address":"127.0.0.1:0","secret":"test"},
                {"client_group":"out","client_chains":members}
            ]),
            json!("out"),
        );
        let tree = chain.composition().unwrap();
        let Node::Choice {
            static_eligible_indices: Some(indices),
            ..
        } = &tree.root
        else {
            panic!("policy-free round-robin must use precomputed indices")
        };
        assert_eq!(indices[0], (0..MEMBERS).collect::<Vec<_>>());
        assert_eq!(indices[1], (1..MEMBERS).step_by(2).collect::<Vec<_>>());
        for index in 0..MEMBERS + 2 {
            for (udp, expected) in [(false, index % MEMBERS), (true, (2 * index + 1) % MEMBERS)] {
                let pinned = tree.select(udp).unwrap();
                assert_eq!(
                    pinned.origin(0).unwrap().name.as_ref(),
                    format!("member-{expected}")
                );
            }
        }

        for kind in ["selector", "url-test"] {
            let mut dynamic = json!({"client_group":"dynamic","type":kind,"client_chain":"direct"});
            if kind == "url-test" {
                dynamic["url"] = json!("http://192.0.2.1/");
            }
            let (chain, _) = build(
                json!([dynamic, {"client_group":"out","client_chains":[{"chain":["dynamic"]},{"chain":["direct"]}]}]),
                json!("out"),
            );
            let Node::Choice {
                static_eligible_indices,
                ..
            } = &chain.composition().unwrap().root
            else {
                panic!()
            };
            assert_eq!(
                static_eligible_indices.is_some(),
                kind == "url-test",
                "{kind}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn download_rotation_resumes_nested_and_repeated_choices() {
        let config = json!([
            {"clash_api_address":"127.0.0.1:0","secret":"test"},
            {"client_group":"inner","client_chains":[
                {"chain":[{"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}}]},
                {"chain":[{"name":"b","address":"192.0.2.2:80","protocol":{"type":"http"}}]}
            ]},
            {"client_group":"out","client_chains":[
                {"name":"short","chain":["inner"]},
                {"name":"long","chain":["inner","inner"]}
            ]}
        ]);
        let route = json!(["out", "out"]);
        let select = |chain: &ClientProxyChain| {
            chain
                .composition()
                .unwrap()
                .select(false)
                .unwrap()
                .origins
                .into_iter()
                .map(|pool| {
                    let origin = pool.unwrap();
                    (origin.name, origin.path)
                })
                .collect::<Vec<_>>()
        };
        let (original, _) = build(config.clone(), route.clone());
        for _ in 0..7 {
            select(&original);
        }
        let state = original.tcp_selection_indices();
        assert_eq!(state.len(), 8);
        let (mut resumed, _) = build(config, route);
        resumed.restore_tcp_selection_indices(&state);
        for _ in 0..32 {
            assert_eq!(select(&original), select(&resumed));
            assert_eq!(
                original.tcp_selection_indices(),
                resumed.tcp_selection_indices()
            );
        }
    }

    #[test]
    fn nonterminal_choices_rotate_tcp_and_udp_independently() {
        for nested_selector in [false, true] {
            let (chain, _) = build(
                json!([
                    {"client_group":"entry","client_chain":{"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}}},
                    {"client_group":"inner","type":"selector","client_chain":"entry"},
                    {"client_group":"out","client_chains":[
                        {"chain":[if nested_selector { "inner" } else { "entry" }]},
                        {"chain":[{"name":"b","address":"192.0.2.2:80","protocol":{"type":"http"}}]}
                    ]}
                ]),
                json!(["out", {"pool":[
                    {"name":"c","address":"192.0.2.3:80","protocol":{"type":"http"}},
                    {"name":"d","address":"192.0.2.4:80","protocol":{"type":"http"}}
                ]}, {"address":"192.0.2.5:80","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}}]),
            );
            let tree = chain.composition().unwrap();
            for index in 0..8 {
                let expected = if index % 2 == 0 {
                    ["a", "c"]
                } else {
                    ["b", "d"]
                };
                for udp in [false, true] {
                    #[cfg(unix)]
                    let before = tree.tcp_selection_indices();
                    let pinned = tree.select(udp).unwrap();
                    for (hop, name) in expected.into_iter().enumerate() {
                        assert_eq!(pinned.origin(hop).unwrap().name.as_ref(), name);
                    }
                    #[cfg(unix)]
                    if udp {
                        assert_eq!(tree.tcp_selection_indices(), before);
                    }
                }
            }
        }
    }

    #[test]
    fn nonterminal_url_test_keeps_tcp_and_udp_incumbents_separate() {
        let (chain, catalog) = build(
            json!([{"client_group":"out","type":"url-test","url":"http://192.0.2.1/","tolerance":50,"client_chains":[
                {"chain":[{"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}}]},
                {"chain":[{"name":"b","address":"192.0.2.2:80","protocol":{"type":"http"}}]}
            ]}]),
            json!(["out", {"address":"192.0.2.3:80","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}}]),
        );
        let tree = chain.composition().unwrap();
        let automatic = &catalog.selection.automatic;
        automatic.record("a", "http://192.0.2.1/", Some(100));
        automatic.record("b", "http://192.0.2.1/", Some(120));
        assert_eq!(
            tree.select(false).unwrap().origin(0).unwrap().name.as_ref(),
            "a"
        );
        automatic.record("a", "http://192.0.2.1/", Some(120));
        automatic.record("b", "http://192.0.2.1/", Some(100));
        assert_eq!(
            tree.select(true).unwrap().origin(0).unwrap().name.as_ref(),
            "b"
        );
        assert_eq!(
            tree.select(false).unwrap().origin(0).unwrap().name.as_ref(),
            "a"
        );
    }

    #[test]
    fn url_test_uses_group_samples_across_callers_without_overriding_round_robin() {
        let (chain, catalog) = build(
            json!([{"client_group":"out","type":"url-test","url":"http://192.0.2.1/","client_chains":[
                {"chain":[{"name":"primary","address":"192.0.2.10:80","protocol":{"type":"http"}}]},
                {"chain":[{"name":"backup","address":"192.0.2.11:80","protocol":{"type":"http"}}]}
            ]}]),
            json!([{"pool":[
                {"address":"192.0.2.50:80","protocol":{"type":"http"}},
                {"address":"192.0.2.51:80","protocol":{"type":"http"}}
            ]}, "out", "out"]),
        );
        let other = crate::tcp::chain_builder::try_build_client_proxy_chain(
            catalog.route("out").unwrap().hops,
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap();
        catalog
            .selection
            .automatic
            .record("primary", "http://192.0.2.1/", Some(100));
        catalog
            .selection
            .automatic
            .record("backup", "http://192.0.2.1/", Some(1));
        assert_eq!(chain.select_indices(false).unwrap(), [0, 1, 1]);
        assert_eq!(chain.select_indices(false).unwrap(), [1, 1, 1]);
        assert_eq!(other.select_indices(false).unwrap(), [1]);
        assert_eq!(catalog.selection.automatic.0.len(), 1);
    }

    #[tokio::test]
    async fn pinned_chain_keeps_connectors_after_composition_is_dropped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let (chain, _) = build(
                json!([{"client_group":"out", "type":"selector", "client_chains":[
                    {"chain":[{"name":"local", "protocol":{"type":"direct"}}]},
                    {"chain":["direct"]}
                ]}]),
                json!("out"),
            );
            let composition = chain.composition().unwrap();
            let weak = Arc::downgrade(composition);
            let pinned = composition.select(false).unwrap();
            drop(chain);
            assert!(weak.upgrade().is_none());
            assert_eq!(pinned.origin(0).unwrap().name.as_ref(), "local");

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
        let (chain, catalog) = build(
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
            probe.composition().unwrap().select(false).unwrap();
        }
        let pinned = chain.composition().unwrap().select(false).unwrap();
        let InitialHopEntry::Proxy { proxy, .. } = pinned.initial.as_ref() else {
            panic!()
        };
        assert_eq!(proxy.proxy_location().to_string(), "192.0.2.1:80");
        catalog
            .selection
            .automatic
            .record("DIRECT", "http://192.0.2.3/", Some(1));
        assert!(
            chain
                .composition()
                .unwrap()
                .select(false)
                .unwrap()
                .is_direct_only()
        );
        assert!(!pinned.is_direct_only());
        assert_eq!(proxy.proxy_location().to_string(), "192.0.2.1:80");
    }
}
