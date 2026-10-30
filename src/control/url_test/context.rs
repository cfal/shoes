use super::*;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_chain::composition::Composition;
use crate::control::selection::{Choices, ManualSelectorPath, manual_choices_changed};
use crate::resolver::Resolver;
use std::sync::{Arc, Weak};
use tokio::sync::Notify;

pub(crate) const MAX_CONTEXTS: usize = 1024;
const MAX_DEPENDENCY_ENTRIES: usize = 65_536;

pub(crate) fn check_dependency_capacity(entries: usize) -> io::Result<()> {
    if entries > MAX_DEPENDENCY_ENTRIES {
        return Err(crate::control::health::capacity_error(format!(
            "URL-test exceeds {MAX_DEPENDENCY_ENTRIES} selector dependency entries"
        )));
    }
    Ok(())
}

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
    pub(crate) fn register(&self, contexts: &[Arc<Context>], choices: &Choices) -> io::Result<()> {
        let mut live = self.live.lock();
        live.retain(|context| context.strong_count() != 0);
        if live.len() + contexts.len() > MAX_CONTEXTS {
            return Err(crate::control::health::capacity_error(
                "URL-test exceeds 1024 active route contexts".into(),
            ));
        }
        let retained_entries: usize = live
            .iter()
            .filter_map(Weak::upgrade)
            .map(|context| context.dependency_entries())
            .sum();
        let added_entries: usize = contexts
            .iter()
            .map(|context| context.dependency_entries())
            .sum();
        check_dependency_capacity(retained_entries + added_entries)?;
        for context in contexts {
            // The caller holds the selection read lock until registration completes.
            context.gate.lock().choices = relevant_choices(&context.dependencies, choices);
            live.push(Arc::downgrade(context));
        }
        self.changed.notify_one();
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Vec<Arc<Context>> {
        self.live.lock().iter().filter_map(Weak::upgrade).collect()
    }

    pub(crate) fn choices_changed(&self, previous: &Choices, current: &Choices) {
        for context in self.snapshot() {
            if manual_choices_changed(&context.dependencies, previous, current) {
                let mut gate = context.gate.lock();
                gate.revision = gate.revision.wrapping_add(1);
                gate.choices = relevant_choices(&context.dependencies, current);
                let mut state = context.group.state.lock();
                state.samples.clear();
                state.incumbent = [None, None];
                state.last_check = None;
            }
        }
        self.changed.notify_one();
    }
}

fn relevant_choices(paths: &[ManualSelectorPath], choices: &Choices) -> Choices {
    paths
        .iter()
        .flatten()
        .filter_map(|(group, _)| {
            choices
                .get(group)
                .map(|member| (group.clone(), member.clone()))
        })
        .collect()
}

#[derive(Default)]
struct Gate {
    revision: u64,
    choices: Choices,
}

pub(crate) struct Context {
    pub name: String,
    pub group: AutomaticGroup,
    pub resolver: Arc<dyn Resolver>,
    owner: Weak<Composition>,
    occurrence: usize,
    ancestors: Vec<(usize, usize)>,
    required: ManualSelectorPath,
    dependencies: Vec<ManualSelectorPath>,
    gate: Mutex<Gate>,
    samplers: Mutex<Vec<HashMap<usize, u32>>>,
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
    pub dependencies: Vec<ManualSelectorPath>,
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
            samplers: Mutex::new(vec![HashMap::new(); members.len()]),
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
            dependencies: definition.dependencies,
            gate: Mutex::default(),
        })
    }

    fn dependency_entries(&self) -> usize {
        self.dependencies.iter().map(|path| path.len().max(1)).sum()
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
        if manual_choices_changed(&self.dependencies, &gate.choices, choices) {
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
    fn dependency_budget_rejects_distinct_paths_multiplied_across_contexts() {
        let catalog = dependency_catalog(64, 256, 9);
        let error =
            build_route(&catalog, Arc::new(crate::resolver::NativeResolver::new())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("65536 selector dependency entries"),
            "{error}"
        );
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }

    #[test]
    fn dependency_budget_spans_roots_and_reclaims_dropped_routes() {
        let catalog = dependency_catalog(16, 256, 8);
        let build = || build_route(&catalog, Arc::new(crate::resolver::NativeResolver::new()));
        let first = build().unwrap();
        let second = build().unwrap();
        assert_eq!(catalog.selection.contexts.snapshot().len(), 32);
        let error = build().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("65536 selector dependency entries"),
            "{error}"
        );
        assert_eq!(catalog.selection.contexts.snapshot().len(), 32);
        drop(first);
        let replacement = build().unwrap();
        assert_eq!(catalog.selection.contexts.snapshot().len(), 32);
        drop((second, replacement));
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }

    #[derive(Debug)]
    struct SelectorResolver(Vec<ManualSelectorPath>);

    impl Resolver for SelectorResolver {
        fn resolve_location(
            &self,
            _: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            unreachable!()
        }

        fn manual_selector_paths(&self) -> Vec<ManualSelectorPath> {
            self.0.clone()
        }
    }

    #[test]
    fn dependency_budget_includes_resolver_paths_and_path_depth() {
        let catalog = dependency_catalog(16, 1, 1);
        let paths = (0..64)
            .map(|path| {
                (0..64)
                    .map(|pair| (format!("dns-{path}-{pair}"), "member".into()))
                    .collect()
            })
            .collect();
        let error = build_route(&catalog, Arc::new(SelectorResolver(paths))).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("65536 selector dependency entries"),
            "{error}"
        );
        assert!(catalog.selection.contexts.snapshot().is_empty());
    }

    #[test]
    fn review_selector_dependencies_store_only_distinct_paths() {
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
        let _chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
            catalog.route("route").unwrap().hops,
            Arc::new(crate::resolver::NativeResolver::new()),
        )
        .unwrap();
        let expected = vec![
            vec![("left".into(), "wide".into())],
            vec![("right".into(), "wide".into())],
        ];
        let contexts = catalog.selection.contexts.snapshot();
        assert_eq!(contexts.len(), 16);
        for context in contexts {
            assert_eq!(context.dependencies, expected);
        }
        assert_eq!(
            *catalog.selection.automatic.0["outer"].dependencies.lock(),
            expected
        );
    }
}
