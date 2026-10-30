use super::*;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_chain::composition::Composition;
use crate::control::selection::{Choices, ManualSelectorPath, manual_choices_changed};
use crate::resolver::Resolver;
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
    pub(crate) fn register(&self, contexts: &[Arc<Context>], choices: &Choices) -> io::Result<()> {
        let mut live = self.live.lock();
        live.retain(|context| context.strong_count() != 0);
        if live.len() + contexts.len() > MAX_CONTEXTS {
            return Err(crate::control::health::capacity_error(
                "URL-test exceeds 1024 active route contexts".into(),
            ));
        }
        for context in contexts {
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
        choices: &Choices,
    ) -> Arc<Self> {
        let mut dependencies = definition.dependencies;
        dependencies.extend(resolver.manual_selector_paths());
        let members = definition.labels;
        let choices = relevant_choices(&dependencies, choices);
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
            dependencies,
            gate: Mutex::new(Gate {
                revision: 0,
                choices,
            }),
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
