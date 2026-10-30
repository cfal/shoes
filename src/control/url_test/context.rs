use super::*;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_chain::composition::Composition;
use crate::control::selection::{Choices, ManualSelectorPath};
use crate::resolver::Resolver;
use rand::{SeedableRng, rngs::SmallRng};
use std::sync::{Arc, Weak};
use tokio::sync::Notify;

pub(crate) const MAX_CONTEXTS: usize = 1024;

#[derive(Default)]
pub(crate) struct Contexts {
    live: Mutex<Vec<Weak<Context>>>,
    pub changed: Notify,
}

impl std::fmt::Debug for Contexts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutomaticContexts").finish_non_exhaustive()
    }
}

impl Contexts {
    pub(crate) fn register(
        &self,
        contexts: &[Arc<Context>],
        choices: &Arc<Choices>,
    ) -> io::Result<()> {
        let mut live = self.live.lock();
        live.retain(|context| context.strong_count() != 0);
        if live.len() + contexts.len() > MAX_CONTEXTS {
            return Err(crate::control::health::capacity_error(
                "URL-test exceeds 1024 active route contexts".into(),
            ));
        }
        for context in contexts {
            // The caller holds the selection read lock until registration completes.
            context.gate.lock().choices = choices.clone();
            live.push(Arc::downgrade(context));
        }
        self.changed.notify_one();
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Vec<Arc<Context>> {
        self.live.lock().iter().filter_map(Weak::upgrade).collect()
    }

    pub(crate) fn choices_changed(&self, previous: &Arc<Choices>, current: &Arc<Choices>) {
        if Arc::ptr_eq(previous, current) {
            return;
        }
        for context in self.snapshot() {
            let mut gate = context.gate.lock();
            gate.revision = gate.revision.wrapping_add(1);
            gate.choices = current.clone();
            let mut state = context.group.state.lock();
            state.samples.clear();
            state.incumbent = [None, None];
            state.last_check = None;
        }
        self.changed.notify_one();
    }
}

#[derive(Default)]
struct Gate {
    revision: u64,
    choices: Arc<Choices>,
}

pub(crate) struct Context {
    pub name: String,
    pub group: AutomaticGroup,
    pub resolver: Arc<dyn Resolver>,
    owner: Weak<Composition>,
    occurrence: usize,
    ancestors: Vec<(usize, usize)>,
    required: ManualSelectorPath,
    gate: Mutex<Gate>,
    samplers: Mutex<Vec<SmallRng>>,
    attempts: Mutex<Vec<Option<Instant>>>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutomaticContext")
            .field("group", &self.name)
            .field("occurrence", &self.occurrence)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Definition {
    pub name: String,
    pub config: UrlTestConfig,
    pub labels: Vec<String>,
    pub occurrence: usize,
    pub ancestors: Vec<(usize, usize)>,
    pub required: ManualSelectorPath,
}

impl Context {
    pub(crate) fn new(
        definition: Definition,
        owner: Weak<Composition>,
        resolver: Arc<dyn Resolver>,
    ) -> Arc<Self> {
        let members = definition.labels;
        Arc::new(Self {
            name: definition.name,
            attempts: Mutex::new(vec![None; members.len()]),
            samplers: Mutex::new(
                (0..members.len())
                    .map(|member| SmallRng::seed_from_u64(member as u64))
                    .collect(),
            ),
            group: AutomaticGroup {
                config: definition.config,
                members,
                state: Mutex::default(),
                dependencies: Mutex::default(),
            },
            resolver,
            owner,
            occurrence: definition.occurrence,
            ancestors: definition.ancestors,
            required: definition.required,
            gate: Mutex::default(),
        })
    }

    pub(crate) fn active(&self, choices: &Choices) -> bool {
        self.owner.strong_count() != 0
            && self
                .required
                .iter()
                .all(|(group, member)| choices.get(group) == Some(member))
    }

    pub(crate) fn sample(
        &self,
        member: usize,
        choices: &Choices,
    ) -> io::Result<Option<ClientChainGroup>> {
        if !self.active(choices) {
            return Ok(None);
        }
        let Some(owner) = self.owner.upgrade() else {
            return Ok(None);
        };
        let mut forced = self.ancestors.clone();
        forced.push((self.occurrence, member));
        let chain = owner.sample_probe(choices, &forced, &mut self.samplers.lock()[member])?;
        Ok(Some(ClientChainGroup::new(vec![chain])))
    }

    pub(crate) fn choose(
        &self,
        names: &HashSet<&str>,
        udp: bool,
        choices: &Choices,
        now: Instant,
    ) -> Option<String> {
        let gate = self.gate.lock();
        // Old snapshots must not consume measurements made after a selector change.
        if !std::ptr::eq(gate.choices.as_ref(), choices) {
            return self
                .group
                .members
                .iter()
                .find(|name| names.contains(name.as_str()))
                .cloned();
        }
        self.group.choose_at(names, udp, now)
    }

    pub(crate) fn revision(&self) -> u64 {
        self.gate.lock().revision
    }

    pub(crate) fn record(&self, member: usize, revision: u64, delay: Option<u16>) {
        let gate = self.gate.lock();
        if gate.revision == revision {
            self.group.state.lock().samples.insert(
                self.group.members[member].clone(),
                Sample {
                    at: Instant::now(),
                    delay,
                },
            );
        }
    }

    pub(crate) fn cancel(&self, revision: u64) {
        if self.gate.lock().revision == revision {
            self.group.cancel_check();
        }
    }

    pub(crate) fn touch(&self, failed: bool) {
        if !is_background() {
            let mut state = self.group.state.lock();
            state.last_touch = Some(Instant::now());
            state.recheck |= failed;
        }
    }

    pub(crate) fn order(&self, members: &mut [usize]) {
        let attempts = self.attempts.lock();
        members.sort_by_key(|index| attempts[*index]);
    }

    pub(crate) fn attempted(&self, member: usize) {
        self.attempts.lock()[member] = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn simplification_probe_sampler_storage_is_linear_in_members() {
        let mut configs = vec![
            json!({"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/",
                "client_chains":(0..64).map(|member| json!({"name":format!("m{member}"),
                    "address":"192.0.2.1:80", "protocol":{"type":"http"}})).collect::<Vec<_>>()}),
            json!({"client_group":"tail0", "client_chains":[
                {"address":"192.0.2.2:80", "protocol":{"type":"http"}},
                {"address":"192.0.2.3:80", "protocol":{"type":"http"}}
            ]}),
        ];
        for level in 1..6 {
            configs.push(json!({"client_group":format!("tail{level}"),
                "client_chains":vec![format!("tail{}", level - 1); 2]}));
        }
        configs
            .push(json!({"client_group":"route", "client_chains":[{"chain":["auto", "tail5"]}]}));
        let catalog =
            crate::config::create_server_configs(serde_json::from_value(json!(configs)).unwrap())
                .unwrap()
                .catalog
                .unwrap();
        let _chain =
            build_route(&catalog, Arc::new(crate::resolver::NativeResolver::new())).unwrap();
        let context = catalog.selection.contexts.snapshot().pop().unwrap();
        let choices = catalog.selection.snapshot();
        let original = context.samplers.lock().clone();
        context.sample(0, &choices).unwrap().unwrap();
        assert_ne!(context.samplers.lock()[0], original[0]);
        assert_eq!(context.samplers.lock()[1..], original[1..]);
        for _ in 0..64 {
            for member in 0..64 {
                context.sample(member, &choices).unwrap().unwrap();
            }
        }
        let samplers = context.samplers.lock();
        assert_eq!(samplers.len(), 64);
        assert!(std::mem::size_of_val(samplers.as_slice()) <= 64 * 32);
    }

    fn dependency_catalog(
        occurrences: usize,
        members: usize,
        depth: usize,
    ) -> crate::control::catalog::Catalog {
        let mut configs = vec![
            json!({"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/",
                "client_chains":[{"address":"192.0.2.1:80", "protocol":{"type":"http"}}]}),
            json!({"client_group":"wide", "client_chains":vec!["auto"; occurrences]}),
            json!({"client_group":"s0", "type":"selector", "client_chains":
                (0..members).map(|index| json!({"name":format!("leaf-{index}"),
                    "address":"192.0.2.2:80", "protocol":{"type":"http"}})).collect::<Vec<_>>()
            }),
        ];
        for index in 1..depth {
            configs.push(
                json!({"client_group":format!("s{index}"), "type":"selector",
                "client_chains":[format!("s{}", index - 1)]}),
            );
        }
        configs.push(json!({"client_group":"route",
            "client_chains":[{"chain":["wide", format!("s{}", depth - 1)]}]}));
        crate::config::create_server_configs(serde_json::from_value(json!(configs)).unwrap())
            .unwrap()
            .catalog
            .unwrap()
    }

    fn build_route(
        catalog: &crate::control::catalog::Catalog,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<crate::client_proxy_chain::ClientProxyChain> {
        crate::tcp::chain_builder::try_build_client_proxy_chain(
            catalog.route("route").unwrap().hops,
            resolver,
        )
    }

    #[test]
    fn simplification_contexts_share_one_snapshot_despite_many_selector_paths() {
        let catalog = dependency_catalog(64, 256, 9);
        let chain =
            build_route(&catalog, Arc::new(crate::resolver::NativeResolver::new())).unwrap();
        let contexts = catalog.selection.contexts.snapshot();
        assert_eq!(contexts.len(), 64);
        let previous = catalog.selection.snapshot();
        let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
        owner.activate(catalog.selection.clone()).unwrap();
        for context in &contexts {
            context.record(0, context.revision(), Some(1));
        }
        owner.select("s0", "leaf-1").unwrap();
        let current = catalog.selection.snapshot();
        assert!(!Arc::ptr_eq(&previous, &current));
        for context in &contexts {
            assert!(Arc::ptr_eq(&context.gate.lock().choices, &current));
            assert_eq!(context.group.health(&context.group.members[0]), "unprobed");
        }
        drop((contexts, chain));
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }

    #[derive(Debug)]
    struct SelectorResolver;

    impl Resolver for SelectorResolver {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            unreachable!()
        }

        fn manual_selector_paths(&self) -> Vec<ManualSelectorPath> {
            panic!("contextual probes must not enumerate resolver dependencies")
        }
    }

    #[test]
    fn simplification_contexts_do_not_enumerate_resolver_dependencies() {
        let catalog = dependency_catalog(16, 1, 1);
        let _chain = build_route(&catalog, Arc::new(SelectorResolver)).unwrap();
        assert_eq!(catalog.selection.contexts.snapshot().len(), 16);
    }

    #[test]
    fn standalone_selector_dependencies_store_only_distinct_paths() {
        let configs = serde_json::from_value(serde_json::json!([
            {"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/",
             "client_chains":[
                {"name":"a", "address":"192.0.2.1:80", "protocol":{"type":"http"}},
                {"name":"b", "address":"192.0.2.2:80", "protocol":{"type":"http"}}
             ]},
            {"client_group":"wide", "client_chains":vec!["auto"; 8]},
            {"client_group":"left", "type":"selector", "client_chains":["wide"]},
            {"client_group":"right", "type":"selector", "client_chains":["wide"]},
            {"client_group":"route", "client_chains":[{"chain":["left", "right"]}]},
            {"client_group":"outer", "type":"url-test", "url":"http://probe.invalid/",
             "client_chains":["route"]}
        ]))
        .unwrap();
        let catalog = crate::config::create_server_configs(configs)
            .unwrap()
            .catalog
            .unwrap();
        let expected = vec![
            vec![("left".into(), "wide".into())],
            vec![("right".into(), "wide".into())],
        ];
        assert_eq!(
            *catalog.selection.automatic.0["outer"].dependencies.lock(),
            expected
        );
    }
}
