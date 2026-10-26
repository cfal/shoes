use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use super::catalog::Catalog;
use super::flows::FlowRegistry;
use super::selection::{SelectionOwner, SelectionView};
use crate::config::{ControlConfig, ValidatedConfigs};

pub struct Generation {
    pub id: u64,
    pub catalog: Catalog,
    pub rules: Vec<serde_json::Value>,
    pub probes: super::probes::ProbeState,
    pub leaf_udp_support: std::collections::HashMap<String, bool>,
}

pub struct ControlRuntime {
    pub config: ControlConfig,
    pub flows: Arc<FlowRegistry>,
    pub shutdown: CancellationToken,
    pub activating: AtomicBool,
    pub connections: Arc<tokio::sync::Semaphore>,
    pub subscribers: Arc<tokio::sync::Semaphore>,
    pub probes: Arc<tokio::sync::Semaphore>,
    pub logs: Arc<super::logs::LogHub>,
    active: RwLock<Option<Arc<Generation>>>,
    probe_epoch: RwLock<CancellationToken>,
    next_generation: AtomicU64,
    commands: mpsc::Sender<Command>,
    selections: Arc<tokio::sync::Semaphore>,
}

type Reply = oneshot::Sender<io::Result<()>>;

struct SelectionCommand {
    generation: u64,
    group: String,
    member: String,
    reply: Reply,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

enum Command {
    Prepare(Arc<SelectionView>, Reply),
    Begin(Arc<SelectionView>, Reply),
    Publish(Arc<Generation>, Reply),
    Resume(Reply),
    Select(SelectionCommand),
}

pub struct ControlService {
    pub runtime: Arc<ControlRuntime>,
    owner: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ControlService {
    fn drop(&mut self) {
        self.runtime.shutdown.cancel();
        self.runtime.flows.cancel_all();
        if let Some(owner) = &self.owner {
            owner.abort();
        }
    }
}

fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "controller is busy or stopped")
}

impl ControlService {
    pub fn new(config: ControlConfig) -> io::Result<Self> {
        let owner = SelectionOwner::new(config.cache_file_path.as_deref())?;
        let (commands, receiver) = mpsc::channel(64);
        let connection_notes = config
            .listeners
            .iter()
            .any(|listener| listener.connection_notes);
        let runtime = Arc::new(ControlRuntime {
            config,
            flows: Arc::new(FlowRegistry::new(connection_notes)),
            shutdown: CancellationToken::new(),
            activating: AtomicBool::new(true),
            connections: Arc::new(tokio::sync::Semaphore::new(64)),
            subscribers: Arc::new(tokio::sync::Semaphore::new(16)),
            probes: Arc::new(tokio::sync::Semaphore::new(
                super::probes::PROBE_CONCURRENCY,
            )),
            logs: Arc::new(super::logs::LogHub::new()),
            active: RwLock::new(None),
            probe_epoch: RwLock::new(CancellationToken::new()),
            next_generation: AtomicU64::new(1),
            commands,
            selections: Arc::new(tokio::sync::Semaphore::new(64)),
        });
        let weak = Arc::downgrade(&runtime);
        let task = tokio::spawn(run_owner(owner, receiver, weak, runtime.shutdown.clone()));
        Ok(Self {
            runtime,
            owner: Some(task),
        })
    }

    pub async fn shutdown(&mut self) {
        self.runtime.shutdown.cancel();
        self.runtime.flows.cancel_all();
        if let Some(owner) = self.owner.take() {
            let _ = owner.await;
        }
    }
}

impl ControlRuntime {
    pub(crate) fn probe_epoch(&self) -> CancellationToken {
        self.probe_epoch.read().clone()
    }

    fn cancel_probes(&self) {
        let mut epoch = self.probe_epoch.write();
        epoch.cancel();
        *epoch = CancellationToken::new();
    }

    pub(crate) fn with_probe_generation<T>(
        &self,
        generation: u64,
        apply: impl FnOnce() -> T,
    ) -> io::Result<T> {
        let active = self.active.read();
        if self.shutdown.is_cancelled()
            || self.activating.load(Ordering::Acquire)
            || active.as_ref().is_none_or(|active| active.id != generation)
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "probe generation is no longer active",
            ));
        }
        Ok(apply())
    }

    async fn request(&self, make: impl FnOnce(Reply) -> Command) -> io::Result<()> {
        let (reply, received) = oneshot::channel();
        tokio::select! {
            result = self.commands.send(make(reply)) => result.map_err(|_| unavailable())?,
            _ = self.shutdown.cancelled() => return Err(unavailable()),
        }
        tokio::select! {
            result = received => result.map_err(|_| unavailable())?,
            _ = self.shutdown.cancelled() => Err(unavailable()),
        }
    }

    pub fn generation(&self) -> io::Result<Arc<Generation>> {
        self.active.read().clone().ok_or_else(unavailable)
    }
    pub async fn select(&self, generation: u64, group: String, member: String) -> io::Result<()> {
        let permit = self
            .selections
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())?;
        self.request(|reply| {
            Command::Select(SelectionCommand {
                generation,
                group,
                member,
                reply,
                _permit: permit,
            })
        })
        .await
    }
    pub async fn begin_activation(&self, generation: &Arc<Generation>) -> io::Result<()> {
        self.request(|reply| Command::Begin(generation.catalog.selection.clone(), reply))
            .await
    }
    pub async fn publish(&self, generation: Arc<Generation>) -> io::Result<()> {
        self.request(|reply| Command::Publish(generation, reply))
            .await
    }
    pub async fn resume(&self) -> io::Result<()> {
        self.request(Command::Resume).await
    }

    pub async fn prepare(
        &self,
        validated: &mut ValidatedConfigs,
    ) -> io::Result<(u64, Vec<serde_json::Value>)> {
        if validated.control != self.config {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controller listeners, credentials, origins, and cache_file_path require a restart",
            ));
        }
        // Removing the last managed group still needs an empty publication to
        // retire the previous generation's automatic checks.
        let catalog = validated.catalog.get_or_insert_with(|| Catalog {
            nodes: Default::default(),
            selection: Default::default(),
        });
        self.request(|reply| Command::Prepare(catalog.selection.clone(), reply))
            .await?;
        let id = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let rules = super::rules::attach(
            validated,
            id,
            (!self.config.listeners.is_empty()).then(|| self.flows.clone()),
        )?;
        Ok((id, rules))
    }
}

async fn stop_automatic(task: Option<AbortOnDropHandle<()>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
}

async fn stop_health(service: Option<super::health::HealthService>) {
    if let Some(service) = service {
        service.shutdown().await;
    }
}

async fn run_owner(
    mut owner: SelectionOwner,
    mut receiver: mpsc::Receiver<Command>,
    runtime: Weak<ControlRuntime>,
    shutdown: CancellationToken,
) {
    let mut paused = false;
    let mut health: Option<super::health::HealthService> = None;
    let mut pending: VecDeque<SelectionCommand> = VecDeque::new();
    let mut automatic: Option<AbortOnDropHandle<()>> = None;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let command = if !paused && let Some(mut selection) = pending.pop_front() {
            selection.generation = runtime
                .upgrade()
                .and_then(|runtime| runtime.generation().ok())
                .map(|generation| generation.id)
                .unwrap_or(0);
            Command::Select(selection)
        } else {
            let command = tokio::select! {
                _ = shutdown.cancelled() => break,
                command = receiver.recv() => command,
                result = async { automatic.as_mut().unwrap().await }, if automatic.is_some() => {
                    automatic = None;
                    if let Err(error) = result {
                        log::error!("Automatic group probe supervisor stopped: {error}");
                    }
                    continue;
                }
            };
            let Some(command) = command else {
                break;
            };
            command
        };
        match command {
            Command::Prepare(view, reply) => {
                let _ = reply.send(owner.reconcile(&view));
            }
            Command::Begin(view, reply) => {
                let result = owner.reconcile(&view);
                if result.is_ok() {
                    stop_health(health.take()).await;
                    paused = true;
                    if let Some(runtime) = runtime.upgrade() {
                        let _active = runtime.active.write();
                        runtime.activating.store(true, Ordering::Release);
                        runtime.cancel_probes();
                    }
                    stop_automatic(automatic.take()).await;
                }
                let _ = reply.send(result);
            }
            Command::Publish(generation, reply) => {
                stop_health(health.take()).await;
                let result = owner.activate(generation.catalog.selection.clone());
                if result.is_ok()
                    && let Some(runtime) = runtime.upgrade()
                {
                    let mut active = runtime.active.write();
                    runtime.cancel_probes();
                    *active = Some(generation);
                }
                let _ = reply.send(result);
            }
            Command::Resume(reply) => {
                paused = false;
                stop_automatic(automatic.take()).await;
                if let Some(runtime) = runtime.upgrade() {
                    let generation = runtime.generation();
                    if health.is_none()
                        && let Ok(generation) = &generation
                        && !generation.catalog.selection.health.definitions.is_empty()
                    {
                        health = Some(super::health::HealthService::start(
                            generation.catalog.selection.clone(),
                            runtime.probes.clone(),
                            generation.probes.forbidden_ranges(),
                        ));
                    }
                    runtime.activating.store(false, Ordering::Release);
                    if let Ok(generation) = generation
                        && !generation.catalog.selection.automatic.0.is_empty()
                    {
                        automatic = Some(AbortOnDropHandle::new(tokio::spawn(
                            super::probes::run_automatic(
                                Arc::downgrade(&runtime),
                                generation,
                                runtime.probe_epoch(),
                            ),
                        )));
                    }
                }
                let _ = reply.send(Ok(()));
            }
            Command::Select(selection) if paused => {
                pending.push_back(selection);
            }
            Command::Select(SelectionCommand {
                generation,
                group,
                member,
                reply,
                _permit,
            }) => {
                if !runtime.upgrade().is_some_and(|runtime| {
                    runtime
                        .generation()
                        .is_ok_and(|active| active.id == generation)
                }) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "generation changed; refetch before selecting",
                    )));
                    continue;
                }
                // File sync must not block a Tokio worker or the forwarding tasks on it.
                let result = tokio::task::spawn_blocking(move || {
                    let result = owner.select(&group, &member);
                    (owner, result)
                })
                .await;
                let Ok((next_owner, result)) = result else {
                    break;
                };
                owner = next_owner;
                let _ = reply.send(result);
            }
        }
    }
    stop_automatic(automatic).await;
    stop_health(health).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::selection::SelectorDefinition;

    #[tokio::test]
    async fn connection_notes_budget_survives_reload_without_retaining_generation() {
        use crate::control::connection_notes::MAX_FLOWS;
        let config = ControlConfig {
            listeners: vec![
                serde_yaml::from_str(
                    "clash_api_address: '127.0.0.1:0'\nsecret: test\nconnection_notes: true",
                )
                .unwrap(),
            ],
            ..Default::default()
        };
        let mut service = ControlService::new(config).unwrap();
        let registry = service.runtime.flows.clone();
        let old = generation(1);
        let weak = Arc::downgrade(&old);
        service.runtime.publish(old).await.unwrap();
        let buffers: Vec<_> = (0..MAX_FLOWS)
            .map(|_| registry.start_notes().unwrap())
            .collect();
        service.runtime.publish(generation(2)).await.unwrap();
        assert!(weak.upgrade().is_none());
        assert!(Arc::ptr_eq(&registry, &service.runtime.flows));
        assert!(registry.start_notes().is_none());
        drop(buffers);
        assert!(registry.start_notes().is_some());
        let mut changed = crate::config::create_server_configs(
            serde_yaml::from_str("- clash_api_address: '127.0.0.1:0'\n  secret: test").unwrap(),
        )
        .unwrap();
        assert!(
            service.runtime.prepare(&mut changed).await.is_err(),
            "changing opt-in requires restart"
        );
        service.shutdown().await;
    }

    fn generation(id: u64) -> Arc<Generation> {
        let selection = SelectionOwner::new(None)
            .unwrap()
            .prepare(std::collections::BTreeMap::from([(
                "outbound".into(),
                SelectorDefinition {
                    members: vec!["east".into(), "west".into()],
                    default: Some("east".into()),
                },
            )]))
            .unwrap();
        Arc::new(Generation {
            id,
            catalog: Catalog {
                nodes: Default::default(),
                selection,
            },
            rules: Vec::new(),
            probes: crate::clash_api::probes::ProbeState::new(
                Arc::new(crate::resolver::NativeResolver::new()),
                Vec::new(),
            ),
            leaf_udp_support: Default::default(),
        })
    }

    #[tokio::test]
    async fn preparation_only_attaches_flow_tracking_when_a_listener_is_configured() {
        for mode in ["selector", "cache", "listener"] {
            let directory = tempfile::tempdir().unwrap();
            let cache = directory.path().join("cache.db");
            let mut configs = serde_json::json!([
                {"client_group":"outbound", "type":if mode == "selector" { "selector" } else { "round-robin" }, "client_proxies":[
                    {"name":"proxy", "address":"proxy.invalid:8080", "protocol":{"type":"http"}}
                ]},
                {"name":"entry", "address":"127.0.0.1:0", "protocol":{"type":"socks"}, "rules":[
                    {"mask":"0.0.0.0/0", "action":"allow", "client_chain":"outbound"}
                ]}
            ]);
            if mode == "cache" {
                configs
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"cache_file_path":cache}));
            } else if mode == "listener" {
                configs
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"clash_api_address":"127.0.0.1:0", "secret":"test"}));
            }
            let mut validated =
                crate::config::create_server_configs(serde_json::from_value(configs).unwrap())
                    .unwrap();
            assert!(validated.catalog.is_some(), "{mode}");
            let mut service = ControlService::new(validated.control.clone()).unwrap();
            let (id, rules) = service.runtime.prepare(&mut validated).await.unwrap();
            assert_eq!(rules.len(), 1, "{mode}");
            assert_eq!(rules[0]["proxy"], "outbound", "{mode}");
            let crate::config::Config::Server(server) = &validated.configs[0] else {
                panic!("{mode}")
            };
            let crate::config::ConfigSelection::Config(rule) = server.rules.iter().next().unwrap()
            else {
                panic!("{mode}")
            };
            let description = rule.criteria.description.as_ref().unwrap();
            assert_eq!(description.proxy, "outbound", "{mode}");
            if mode == "listener" {
                let context = description.context.as_ref().unwrap();
                assert_eq!(context.generation, id);
                assert_eq!(context.inbound, "entry");
                assert_eq!(context.scope, "root");
                assert_eq!(context.protocol, "Socks5");
                assert!(Arc::ptr_eq(&context.registry, &service.runtime.flows));
            } else {
                assert!(description.context.is_none(), "{mode}");
            }
            service.shutdown().await;
        }
    }

    #[tokio::test]
    async fn activation_reconciles_latest_selection_and_saturation_cannot_block_publication() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut service = ControlService::new(ControlConfig::default()).unwrap();
            let runtime = service.runtime.clone();
            let first = generation(1);
            runtime.publish(first).await.unwrap();
            runtime.resume().await.unwrap();
            let candidate = generation(2);
            runtime
                .request(|reply| Command::Prepare(candidate.catalog.selection.clone(), reply))
                .await
                .unwrap();
            runtime
                .select(1, "outbound".into(), "west".into())
                .await
                .unwrap();
            runtime.begin_activation(&candidate).await.unwrap();
            assert_eq!(candidate.catalog.selection.snapshot()["outbound"], "west");
            let mut requests = tokio::task::JoinSet::new();
            for _ in 0..64 {
                let runtime = runtime.clone();
                requests.spawn(
                    async move { runtime.select(1, "outbound".into(), "east".into()).await },
                );
            }
            while runtime.selections.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                runtime
                    .select(1, "outbound".into(), "east".into())
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            runtime.publish(candidate.clone()).await.unwrap();
            runtime.resume().await.unwrap();
            while let Some(result) = requests.join_next().await {
                assert!(result.unwrap().is_ok());
            }
            assert_eq!(candidate.catalog.selection.snapshot()["outbound"], "east");
            assert_eq!(runtime.selections.available_permits(), 64);
            service.shutdown().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_completes_owned_saves_and_releases_cache_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let mut service = ControlService::new(ControlConfig {
            cache_file_path: Some(path.clone()),
            ..Default::default()
        })
        .unwrap();
        service.runtime.publish(generation(1)).await.unwrap();
        service.runtime.resume().await.unwrap();
        service
            .runtime
            .select(1, "outbound".into(), "west".into())
            .await
            .unwrap();
        assert!(super::super::store::SelectionStore::open(&path).is_err());
        service.shutdown().await;
        let (_, restored) = super::super::store::SelectionStore::open(&path).unwrap();
        assert_eq!(restored["outbound"], "west");
    }
}
