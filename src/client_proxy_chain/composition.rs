use super::*;
use crate::config::{ClientChainHop, ClientConfig, ConfigSelection, GlobalLimits, GroupType};
use crate::control::health::{Health, ProbeJob};
use crate::control::selection::{Choices, SelectionView};
use crate::control::url_test::context::{Context, Definition};
use crate::option_util::OneOrSome;
use crate::tcp::proxy_connector_impl::ProxyConnectorImpl;
use rand::{RngExt, rngs::SmallRng};
use std::collections::HashMap;
use std::io;

struct Leaf {
    config: ClientConfig,
    initial: Option<Arc<InitialHopEntry>>,
    proxy: Option<Arc<dyn ProxyConnector>>,
    udp: bool,
}

enum Node {
    Client(Arc<Leaf>),
    Sequence(Vec<Node>),
    Choice {
        id: usize,
        name: String,
        kind: GroupType,
        labels: Vec<String>,
        members: Vec<Node>,
        next: [AtomicU32; 2],
        static_members: Option<[Vec<usize>; 2]>,
    },
}

struct CheckedPath {
    leaves: Vec<Arc<Leaf>>,
    decisions: Vec<(usize, usize)>,
    checks: Vec<Arc<ProbeJob>>,
}

type ConcretePath = (Vec<Arc<Leaf>>, Vec<(usize, usize)>);

pub(crate) struct Composition {
    root: Node,
    selection: Option<Arc<SelectionView>>,
    checked: Vec<CheckedPath>,
    contexts: HashMap<usize, Arc<Context>>,
    standalone: bool,
}

struct Selection<'a> {
    choices: &'a Choices,
    contexts: &'a HashMap<usize, Arc<Context>>,
    standalone: Option<&'a crate::control::url_test::AutomaticGroups>,
    paths: &'a [CheckedPath],
    candidates: Vec<(usize, bool)>,
    forced: &'a [(usize, usize)],
    sampler: Option<&'a mut SmallRng>,
    touched: Vec<Arc<Context>>,
    now: tokio::time::Instant,
}

impl Selection<'_> {
    fn next(&mut self, counter: &AtomicU32, len: usize) -> usize {
        if let Some(sampler) = &mut self.sampler {
            sampler.random_range(0..len)
        } else {
            counter.fetch_add(1, Ordering::Relaxed) as usize % len
        }
    }
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
        standalone: bool,
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
        let mut ordinal = 0;
        let root = sequence(hops, true, &resolver, limits, &mut ordinal)?;
        let mut checked = Vec::new();
        if root.has_fallback() {
            if selection.is_none() {
                return Err(crate::config::composition::invalid(
                    "fallback requires a prepared selection view",
                ));
            }
            let paths = root.paths()?;
            for (leaves, decisions) in paths {
                let configs: Vec<Vec<_>> = leaves
                    .iter()
                    .map(|leaf| vec![leaf.config.clone()])
                    .collect();
                let chain = pinned(&leaves).with_health(&configs, 1, resolver.clone())?;
                let checks = chain
                    .health_paths
                    .into_iter()
                    .flat_map(|path| path.checks)
                    .collect();
                checked.push(CheckedPath {
                    leaves,
                    decisions,
                    checks,
                });
            }
        }
        let mut definitions = Vec::new();
        if !standalone && selection.is_some() {
            root.context_definitions(&[], &[], &mut definitions);
        }
        let mut registered = Vec::new();
        let result = Arc::new_cyclic(|owner| {
            let mut contexts = HashMap::new();
            for definition in definitions {
                let id = definition.occurrence;
                let context = Context::new(definition, owner.clone(), resolver.clone());
                // Definitions follow occurrence order, which breaks admission ties.
                registered.push(context.clone());
                contexts.insert(id, context);
            }
            Self {
                root,
                selection,
                checked,
                contexts,
                standalone,
            }
        });
        if let Some(view) = &result.selection {
            view.register_contexts(&registered)?;
        }
        Ok(result)
    }

    pub(super) fn select(&self, udp: bool) -> io::Result<ClientProxyChain> {
        let choices = self
            .selection
            .as_ref()
            .map(|view| view.snapshot())
            .unwrap_or_default();
        self.select_with(udp, &choices, &[], None)
    }

    pub(crate) fn sample_probe(
        &self,
        choices: &Choices,
        forced: &[(usize, usize)],
        sampler: &mut SmallRng,
    ) -> io::Result<ClientProxyChain> {
        let mut selected = self.select_with(false, choices, forced, Some(sampler))?;
        selected.selection = None;
        selected.automatic_contexts.clear();
        Ok(selected)
    }

    fn select_with(
        &self,
        udp: bool,
        choices: &Choices,
        forced: &[(usize, usize)],
        sampler: Option<&mut SmallRng>,
    ) -> io::Result<ClientProxyChain> {
        let mut candidates = Vec::new();
        if !self.checked.is_empty() {
            let now = self.selection.as_ref().unwrap().health.sample_time();
            let mut samples = HashMap::new();
            let mut compatible = false;
            for (index, path) in self.checked.iter().enumerate() {
                if !forced
                    .iter()
                    .all(|decision| path.decisions.contains(decision))
                {
                    continue;
                }
                if udp && !path.leaves.last().unwrap().udp {
                    continue;
                }
                if !path.leaves.iter().all(|leaf| {
                    leaf.config
                        .control
                        .as_ref()
                        .is_none_or(|origin| origin.allowed(choices))
                }) {
                    continue;
                }
                compatible = true;
                let mut healthy = true;
                let mut failed = false;
                for check in &path.checks {
                    match *samples
                        .entry(Arc::as_ptr(check))
                        .or_insert_with(|| check.health(choices, now))
                    {
                        Health::Healthy => {}
                        Health::Unknown => healthy = false,
                        Health::Failed | Health::Stale => {
                            failed = true;
                            break;
                        }
                    }
                }
                if !failed {
                    candidates.push((index, healthy));
                }
            }
            if !compatible {
                return Err(unsupported());
            }
            if candidates.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "fallback has no healthy or unknown eligible path",
                ));
            }
            self.root.prefer_fallbacks(&self.checked, &mut candidates);
        }
        let mut leaves = Vec::new();
        let mut context = Selection {
            choices,
            contexts: &self.contexts,
            standalone: self
                .selection
                .as_ref()
                .filter(|_| self.standalone)
                .map(|view| &view.automatic),
            paths: &self.checked,
            candidates,
            forced,
            sampler,
            touched: Vec::new(),
            now: tokio::time::Instant::now(),
        };
        self.root.select(udp, &mut context, &mut leaves)?;
        let mut chain = pinned(&leaves);
        chain.automatic_contexts = context.touched;
        Ok(chain)
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
        for context in self.contexts.values() {
            context.touch(false);
        }
        self.root.record_demand(self.selection.as_deref());
    }
}

#[cfg(test)]
impl Composition {
    pub(super) fn test_contexts(&self) -> Vec<Arc<Context>> {
        self.contexts.values().cloned().collect()
    }
    fn test_pools(&self) -> Vec<Vec<Arc<Leaf>>> {
        fn collect(node: &Node, start: usize, pools: &mut Vec<Vec<Arc<Leaf>>>) -> usize {
            match node {
                Node::Client(leaf) => {
                    pools.resize_with(pools.len().max(start + 1), Vec::new);
                    pools[start].push(leaf.clone());
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

    pub(super) fn test_health_paths(&self) -> Vec<HealthPath> {
        self.checked
            .iter()
            .map(|path| HealthPath {
                indices: Vec::new(),
                checks: path.checks.clone(),
            })
            .collect()
    }

    pub(super) fn test_initial_hops(&self) -> Vec<Arc<InitialHopEntry>> {
        self.test_pools()[0]
            .iter()
            .map(|leaf| leaf.initial.as_ref().unwrap().clone())
            .collect()
    }
}

fn sequence(
    hops: OneOrSome<ClientChainHop>,
    first: bool,
    resolver: &Arc<dyn Resolver>,
    limits: GlobalLimits,
    ordinal: &mut usize,
) -> io::Result<Node> {
    let mut nodes = Vec::new();
    for (index, hop) in hops.into_vec().into_iter().enumerate() {
        nodes.push(node(hop, first && index == 0, resolver, limits, ordinal)?);
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
    ordinal: &mut usize,
) -> io::Result<Node> {
    match hop {
        ClientChainHop::Single(ConfigSelection::GroupName(name)) => Err(
            crate::config::composition::invalid(format!("unresolved client group: {name}")),
        ),
        ClientChainHop::Single(ConfigSelection::Config(config)) => {
            let (initial, proxy, udp) = if first {
                let mut initial_config = config.clone();
                initial_config.control = None;
                let chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
                    OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                        initial_config,
                    ))),
                    resolver.clone(),
                    limits,
                )?;
                let entry = chain.initial_hop[0].clone();
                let udp = entry.supports_udp();
                (Some(entry), None, udp)
            } else {
                let proxy: Arc<dyn ProxyConnector> = Arc::new(
                    ProxyConnectorImpl::from_config(config.clone(), resolver.clone())?
                        .ok_or_else(unsupported)?,
                );
                let udp = proxy.supports_udp_over_tcp();
                (None, Some(proxy), udp)
            };
            Ok(Node::Client(Arc::new(Leaf {
                config,
                initial,
                proxy,
                udp,
            })))
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
            ordinal,
        ),
        ClientChainHop::Choice(choice) => {
            let id = *ordinal;
            *ordinal += 1;
            let mut members = Vec::new();
            for member in choice.members {
                members.push(sequence(member.hops, first, resolver, limits, ordinal)?);
            }
            let static_members = (choice.group_type == GroupType::RoundRobin
                && !members.iter().any(Node::has_manual))
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
                id,
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

fn pinned(leaves: &[Arc<Leaf>]) -> ClientProxyChain {
    let origins = leaves
        .iter()
        .map(|leaf| vec![leaf.config.control.clone()])
        .collect();
    let udp = leaves.last().unwrap().udp;
    let subsequent_hops: Vec<_> = leaves
        .iter()
        .skip(1)
        .map(|leaf| vec![leaf.proxy.as_ref().unwrap().clone()])
        .collect();
    ClientProxyChain {
        composition: None,
        automatic_contexts: Vec::new(),
        origins,
        selection: leaves.iter().find_map(|leaf| {
            leaf.config
                .control
                .as_ref()
                .map(|origin| origin.selection.clone())
        }),
        selector_hops: vec![false; leaves.len()],
        health_paths: Vec::new(),
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
    fn has_manual(&self) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Sequence(nodes) => nodes.iter().any(Self::has_manual),
            Self::Choice { kind, members, .. } => {
                *kind == GroupType::Selector || members.iter().any(Self::has_manual)
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
            Self::Client(leaf) => leaf.config.protocol.is_direct(),
            Self::Sequence(_) => false,
            Self::Choice { members, .. } => members.iter().all(Self::direct_only),
        }
    }
    fn may_connect_directly(&self) -> bool {
        match self {
            Self::Client(leaf) => leaf.config.protocol.is_direct(),
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
    fn has_fallback(&self) -> bool {
        match self {
            Self::Client(_) => false,
            Self::Sequence(nodes) => nodes.iter().any(Self::has_fallback),
            Self::Choice { kind, members, .. } => {
                matches!(kind, GroupType::Fallback { .. }) || members.iter().any(Self::has_fallback)
            }
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
    fn select(
        &self,
        udp: bool,
        context: &mut Selection<'_>,
        leaves: &mut Vec<Arc<Leaf>>,
    ) -> io::Result<()> {
        match self {
            Self::Client(leaf) => {
                if udp && !leaf.udp {
                    return Err(unsupported());
                }
                leaves.push(leaf.clone());
            }
            Self::Sequence(nodes) => {
                for (index, node) in nodes.iter().enumerate() {
                    node.select(udp && index + 1 == nodes.len(), context, leaves)?;
                }
            }
            Self::Choice {
                id,
                name,
                kind,
                labels,
                members,
                next,
                static_members,
            } => {
                let forced = context
                    .forced
                    .iter()
                    .find(|(node, _)| node == id)
                    .map(|(_, branch)| *branch);
                if forced.is_none()
                    && context.paths.is_empty()
                    && let Some(eligible) = static_members
                {
                    let eligible = &eligible[usize::from(udp)];
                    if eligible.is_empty() {
                        return Err(unsupported());
                    }
                    let selected = eligible[context.next(&next[usize::from(udp)], eligible.len())];
                    return members[selected].select(udp, context, leaves);
                }
                let eligible: Vec<_> = members
                    .iter()
                    .enumerate()
                    .filter_map(|(index, member)| {
                        let selected = *kind != GroupType::Selector
                            || context.choices.get(name) == Some(&labels[index]);
                        let checked = context.paths.is_empty()
                            || context.candidates.iter().any(|(path, _)| {
                                context.paths[*path].decisions.contains(&(*id, index))
                            });
                        (selected
                            && checked
                            && forced.is_none_or(|forced| forced == index)
                            && member.eligible(udp, context.choices))
                        .then_some(index)
                    })
                    .collect();
                if eligible.is_empty() {
                    return Err(unsupported());
                }
                let selected = if let Some(forced) = forced {
                    forced
                } else if let GroupType::UrlTest(_) = kind {
                    let names = eligible
                        .iter()
                        .map(|index| labels[*index].as_str())
                        .collect();
                    let selected = if let Some(groups) = context.standalone {
                        groups
                            .0
                            .get(name)
                            .ok_or_else(unsupported)?
                            .choose(&names, udp)
                    } else {
                        let group = context.contexts.get(id).ok_or_else(unsupported)?;
                        context.touched.push(group.clone());
                        group.choose(&names, udp, context.choices, context.now)
                    }
                    .ok_or_else(unsupported)?;
                    eligible
                        .into_iter()
                        .find(|index| labels[*index] == selected)
                        .unwrap()
                } else {
                    eligible[context.next(&next[usize::from(udp)], eligible.len())]
                };
                context
                    .candidates
                    .retain(|(path, _)| context.paths[*path].decisions.contains(&(*id, selected)));
                members[selected].select(udp, context, leaves)?;
            }
        }
        Ok(())
    }

    fn context_definitions(
        &self,
        ancestors: &[(usize, usize)],
        required: &[(String, String)],
        result: &mut Vec<Definition>,
    ) {
        match self {
            Self::Client(_) => {}
            Self::Sequence(nodes) => {
                for node in nodes {
                    node.context_definitions(ancestors, required, result);
                }
            }
            Self::Choice {
                id,
                name,
                kind,
                labels,
                members,
                ..
            } => {
                if let GroupType::UrlTest(config) = kind {
                    result.push(Definition {
                        name: name.clone(),
                        config: config.clone(),
                        labels: labels.clone(),
                        occurrence: *id,
                        ancestors: ancestors.to_vec(),
                        required: required.to_vec(),
                    });
                }
                for (index, member) in members.iter().enumerate() {
                    let mut ancestors = ancestors.to_vec();
                    ancestors.push((*id, index));
                    let mut required = required.to_vec();
                    if *kind == GroupType::Selector {
                        required.push((name.clone(), labels[index].clone()));
                    }
                    member.context_definitions(&ancestors, &required, result);
                }
            }
        }
    }

    fn prefer_fallbacks(&self, paths: &[CheckedPath], candidates: &mut Vec<(usize, bool)>) {
        match self {
            Self::Client(_) => {}
            Self::Sequence(nodes) => {
                for node in nodes {
                    node.prefer_fallbacks(paths, candidates);
                }
            }
            Self::Choice {
                id, kind, members, ..
            } => {
                if matches!(kind, GroupType::Fallback { .. }) {
                    let preferred = [true, false].into_iter().find_map(|healthy| {
                        (0..members.len())
                            .find(|member| {
                                candidates.iter().any(|(path, state)| {
                                    *state == healthy
                                        && paths[*path].decisions.contains(&(*id, *member))
                                })
                            })
                            .map(|member| (member, healthy))
                    });
                    if let Some((member, healthy)) = preferred {
                        candidates.retain(|(path, state)| {
                            paths[*path]
                                .decisions
                                .iter()
                                .find(|(node, _)| node == id)
                                .is_none_or(|(_, branch)| *branch == member && (!healthy || *state))
                        });
                    }
                }
                for member in members {
                    member.prefer_fallbacks(paths, candidates);
                }
            }
        }
    }
    fn paths(&self) -> io::Result<Vec<ConcretePath>> {
        let limit = crate::control::health::MAX_PATHS;
        let capacity = || {
            crate::control::health::capacity_error(
                "fallback exceeds 256 concrete chain paths".into(),
            )
        };
        match self {
            Self::Client(leaf) => Ok(vec![(vec![leaf.clone()], Vec::new())]),
            Self::Choice { id, members, .. } => {
                let mut paths = Vec::new();
                for (index, member) in members.iter().enumerate() {
                    for (leaves, mut decisions) in member.paths()? {
                        if paths.len() == limit {
                            return Err(capacity());
                        }
                        decisions.insert(0, (*id, index));
                        paths.push((leaves, decisions));
                    }
                }
                Ok(paths)
            }
            Self::Sequence(nodes) => {
                let mut paths = vec![(Vec::new(), Vec::new())];
                for node in nodes {
                    let suffixes = node.paths()?;
                    if paths
                        .len()
                        .checked_mul(suffixes.len())
                        .is_none_or(|count| count > limit)
                    {
                        return Err(capacity());
                    }
                    let mut joined = Vec::new();
                    for (prefix, decisions) in paths {
                        for (suffix, following) in &suffixes {
                            let mut leaves = prefix.clone();
                            leaves.extend(suffix.iter().cloned());
                            let mut choices = decisions.clone();
                            choices.extend(following);
                            joined.push((leaves, choices));
                        }
                    }
                    paths = joined;
                }
                Ok(paths)
            }
        }
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
                {"client_group":"out","type":"selector","client_chains":["entry",{"name":"via-exit","chain":["entry","exit"]},"direct"]}
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
        owner.select("out", "DIRECT").unwrap();
        let direct = tree.select(true).unwrap();
        assert!(direct.is_direct_only());
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

    #[test]
    fn fallback_prioritizes_healthy_complete_paths_of_different_lengths() {
        let (chain, catalog) = super::super::health_tests::build(
            json!([{"client_group":"out","type":"fallback",
            "health_check":{"url":"http://probe.invalid/","interval_secs":10},
            "client_chains":[
                {"name":"long","chain":[
                    {"address":"192.0.2.1:80","protocol":{"type":"http"}},
                    {"address":"192.0.2.2:80","protocol":{"type":"http"}}
                ]},
                {"name":"short","address":"192.0.2.3:80","protocol":{"type":"http"}}
            ]}]),
            json!("out"),
        );
        let tree = chain.composition.as_ref().unwrap();
        let choices = catalog.selection.snapshot();
        assert_eq!(tree.select(false).unwrap().num_hops(), 2);
        let record = |path: usize, healthy| {
            for check in &tree.checked[path].checks {
                check.record(
                    Ok((1, healthy)),
                    choices.clone(),
                    tokio::time::Instant::now(),
                );
            }
        };
        record(1, true);
        assert_eq!(addresses(&tree.select(false).unwrap()), ["192.0.2.3:80"]);
        record(0, true);
        assert_eq!(tree.select(false).unwrap().num_hops(), 2);
        record(0, false);
        assert_eq!(tree.select(false).unwrap().num_hops(), 1);
        record(1, false);
        assert_eq!(
            tree.select(false).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    fn automatic_config() -> serde_json::Value {
        json!([
            {"client_group":"auto","type":"url-test","url":"http://probe.invalid/","client_chains":[
                {"name":"a","address":"192.0.2.1:80","protocol":{"type":"http"}},
                {"name":"b","address":"192.0.2.2:80","protocol":{"type":"http"}}
            ]},
            {"client_group":"prefix","client_chains":[
                {"name":"p1","address":"192.0.2.3:80","protocol":{"type":"http"}},
                {"name":"p2","address":"192.0.2.4:80","protocol":{"type":"http"}}
            ]},
            {"client_group":"suffix","client_chains":[{"name":"end","address":"192.0.2.5:80","protocol":{"type":"http"}}]}
        ])
    }

    fn addresses(chain: &ClientProxyChain) -> Vec<String> {
        let mut addresses = Vec::new();
        if let InitialHopEntry::Proxy { proxy, .. } = chain.initial_hop[0].as_ref() {
            addresses.push(proxy.proxy_location().to_string());
        }
        addresses.extend(
            chain
                .subsequent_hops
                .iter()
                .map(|hop| hop[0].proxy_location().to_string()),
        );
        addresses
    }

    #[test]
    fn automatic_probes_include_prefix_and_suffix_without_advancing_flow_counters() {
        let (chain, catalog) = super::super::health_tests::build(
            automatic_config(),
            json!(["prefix", "auto", "suffix"]),
        );
        let tree = chain.composition.as_ref().unwrap();
        let context = tree.test_contexts().pop().unwrap();
        let mut prefixes: [std::collections::HashSet<String>; 2] = Default::default();
        for _ in 0..64 {
            for (member, seen) in prefixes.iter_mut().enumerate() {
                let sample = context
                    .sample(member, &catalog.selection.snapshot())
                    .unwrap()
                    .unwrap();
                let addresses = addresses(&sample.chains[0]);
                assert!(["192.0.2.3:80", "192.0.2.4:80"].contains(&addresses[0].as_str()));
                seen.insert(addresses[0].clone());
                assert_eq!(
                    addresses[1..],
                    [format!("192.0.2.{}:80", member + 1), "192.0.2.5:80".into()]
                );
                assert!(sample.chains[0].composition.is_none());
                assert!(sample.chains[0].automatic_contexts.is_empty());
            }
        }
        assert!(prefixes.iter().all(|seen| seen.len() == 2));
        // An odd probe count exposes accidental advancement of the two-member prefix.
        context
            .sample(0, &catalog.selection.snapshot())
            .unwrap()
            .unwrap();
        assert_eq!(
            addresses(&tree.select(false).unwrap()),
            ["192.0.2.3:80", "192.0.2.1:80", "192.0.2.5:80"]
        );
        assert_eq!(
            addresses(&tree.select(false).unwrap()),
            ["192.0.2.4:80", "192.0.2.1:80", "192.0.2.5:80"]
        );
    }

    #[test]
    fn automatic_contexts_register_in_occurrence_order() {
        let (chain, catalog) =
            super::super::health_tests::build(automatic_config(), json!(vec!["auto"; 8]));
        let tree = chain.composition.as_ref().unwrap();
        let mut contexts: Vec<_> = tree.contexts.iter().collect();
        contexts.sort_by_key(|(id, _)| **id);
        let registered = catalog.selection.contexts.snapshot();
        assert_eq!(registered.len(), 8);
        assert_eq!(registered.len(), contexts.len());
        for (registered, (_, context)) in registered.iter().zip(&contexts) {
            assert!(Arc::ptr_eq(registered, context));
        }
    }

    #[test]
    fn repeated_automatic_occurrences_and_standalone_samples_are_isolated() {
        let (chain, catalog) =
            super::super::health_tests::build(automatic_config(), json!(["auto", "auto"]));
        let tree = chain.composition.as_ref().unwrap();
        let mut contexts: Vec<_> = tree.contexts.iter().collect();
        contexts.sort_by_key(|(id, _)| **id);
        contexts[0].1.record(1, 0, Some(1));
        contexts[1].1.record(0, 0, Some(1));
        catalog
            .selection
            .automatic
            .record("b", "http://probe.invalid/", Some(1));
        assert_eq!(tree.test_select_indices(false).unwrap(), [1, 0]);
        assert_eq!(contexts[1].1.group.health("b"), "unprobed");
        let snapshot = crate::control::runtime::Generation {
            id: 1,
            leaf_udp_support: crate::clash_api::dto::leaf_udp_support(&catalog).unwrap(),
            catalog,
            rules: Vec::new(),
            probes: crate::control::probes::ProbeState::new(
                Arc::new(crate::resolver::NativeResolver::new()),
                Vec::new(),
            ),
        };
        crate::clash_api::dto::proxies(&snapshot);
        assert_eq!(tree.test_select_indices(false).unwrap(), [1, 0]);
    }

    #[test]
    fn automatic_context_budget_spans_roots_and_reclaims_dropped_routes() {
        let limit = crate::control::url_test::context::MAX_CONTEXTS;
        let (first, catalog) = super::super::health_tests::build(
            json!([
                {"client_group":"auto","type":"url-test","url":"http://probe.invalid/","client_chains":["direct"]},
                {"client_group":"wide","client_chains":vec!["auto"; limit / 2]}
            ]),
            json!("wide"),
        );
        let build = |name| {
            crate::tcp::chain_builder::try_build_client_proxy_chain(
                catalog.route(name).unwrap().hops,
                Arc::new(crate::resolver::NativeResolver::new()),
            )
        };
        let second = build("wide").unwrap();
        assert_eq!(catalog.selection.contexts.snapshot().len(), limit);
        let error = build("auto").unwrap_err();
        assert!(
            error.to_string().contains("1024 active route contexts"),
            "{error}"
        );
        assert_eq!(catalog.selection.contexts.snapshot().len(), limit);
        drop(first);
        let replacement = build("wide").unwrap();
        assert_eq!(catalog.selection.contexts.snapshot().len(), limit);
        drop((second, replacement));
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }

    #[test]
    fn simplification_contextual_samples_are_fenced_by_all_selector_changes() {
        let mut config = automatic_config();
        config.as_array_mut().unwrap().push(
            json!({"client_group":"manual","type":"selector","client_chains":["prefix","suffix"]}),
        );
        config.as_array_mut().unwrap().push(json!({"client_group":"unrelated","type":"selector","client_chains":["prefix","suffix"]}));
        let (chain, catalog) = super::super::health_tests::build(config, json!(["manual", "auto"]));
        let context = chain
            .composition
            .as_ref()
            .unwrap()
            .test_contexts()
            .pop()
            .unwrap();
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        let old_choices = catalog.selection.snapshot();
        let revision = context.revision();
        context.record(1, revision, Some(1));
        catalog
            .selection
            .automatic
            .record("b", "http://probe.invalid/", Some(1));
        owner.select("unrelated", "prefix").unwrap();
        assert_eq!(context.revision(), revision);
        assert!(Arc::ptr_eq(&old_choices, &catalog.selection.snapshot()));
        owner.select("unrelated", "suffix").unwrap();
        assert_ne!(context.revision(), revision);
        assert_eq!(catalog.selection.automatic.0["auto"].health("b"), "healthy");
        assert_eq!(context.group.health("b"), "unprobed");
        owner.select("unrelated", "prefix").unwrap();
        assert_eq!(*old_choices, *catalog.selection.snapshot());
        context.record(1, revision, Some(1));
        assert_eq!(context.group.health("b"), "unprobed");
        context.record(1, context.revision(), Some(1));
        let eligible = ["a", "b"].into_iter().collect();
        assert_eq!(
            context
                .choose(&eligible, false, &old_choices, tokio::time::Instant::now())
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            context
                .choose(
                    &eligible,
                    false,
                    &catalog.selection.snapshot(),
                    tokio::time::Instant::now()
                )
                .as_deref(),
            Some("b")
        );
        owner.select("manual", "suffix").unwrap();
        context.record(1, revision, Some(1));
        assert_eq!(context.group.health("b"), "unprobed");
    }

    #[test]
    fn probe_ancestors_are_forced_without_bypassing_manual_guards_or_retaining_roots() {
        let mut config = automatic_config();
        config.as_array_mut().unwrap().push(
            json!({"client_group":"guard","type":"selector","client_chains":["auto","prefix"]}),
        );
        config
            .as_array_mut()
            .unwrap()
            .push(json!({"client_group":"outer","client_chains":["suffix","guard"]}));
        let (chain, catalog) = super::super::health_tests::build(config, json!("outer"));
        let tree = chain.composition.as_ref().unwrap();
        let context = tree.test_contexts().pop().unwrap();
        let sampled = context
            .sample(1, &catalog.selection.snapshot())
            .unwrap()
            .unwrap();
        assert_eq!(addresses(&sampled.chains[0]), ["192.0.2.2:80"]);
        assert_eq!(addresses(&tree.select(false).unwrap()), ["192.0.2.5:80"]);
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        owner.select("guard", "prefix").unwrap();
        assert!(
            context
                .sample(1, &catalog.selection.snapshot())
                .unwrap()
                .is_none()
        );
        let weak = Arc::downgrade(tree);
        drop(chain);
        assert!(weak.upgrade().is_none());
        assert!(!context.active(&catalog.selection.snapshot()));
        drop(context);
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }
}
