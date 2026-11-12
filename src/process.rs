use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::RecommendedWatcher;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::config::ResolvedConfig;
use crate::config::{self, BindLocation, Config, ValidatedConfigs};
use crate::dns::{self, DnsRegistry};
use crate::option_util::OneOrSome;
use crate::resources;
use crate::tcp::tcp_server::TcpListeners;

#[cfg(unix)]
use crate::rule_updater::CacheLease;
#[cfg(not(unix))]
type CacheLease = std::fs::File;

const RELOAD_DEBOUNCE: Duration = Duration::from_secs(5);

type DiscoverDependencies<'a> = dyn FnMut(&[PathBuf], &[PathBuf], Option<&Path>) + Send + 'a;

async fn validate_configs(
    paths: &[String],
    configs: Vec<Config>,
    discovered: &mut DiscoverDependencies<'_>,
) -> io::Result<ValidatedConfigs> {
    load_candidate(paths, configs, discovered, false, None, &mut None, &[])
        .await
        .map(|(validated, _, _)| validated)
}

async fn load_candidate(
    paths: &[String],
    mut configs: Vec<Config>,
    discovered: &mut DiscoverDependencies<'_>,
    for_runtime: bool,
    previous_servers: Option<&PreparedServers>,
    cache_lease: &mut Option<std::sync::Arc<CacheLease>>,
    retained_ranges: &[ipnetwork::IpNetwork],
) -> io::Result<(
    ValidatedConfigs,
    Vec<Config>,
    crate::rule_set::MemorySources,
)> {
    async {
        let expected_cache_dir =
            previous_servers.map(|previous| &previous.validated.rule_cache_dir);
        let cache_dir = crate::rule_set::cache_directory(&configs)?;
        let mut dependencies = crate::rule_set::dependencies(&mut configs)?;
        let mut recovery_dependencies = config::pem_candidate_dependencies(&mut configs)?;
        dependencies.extend(config::pem_reload_dependencies(&mut configs)?);
        recovery_dependencies.retain(|path| !dependencies.contains(path));
        discovered(
            &dependencies,
            &recovery_dependencies,
            expected_cache_dir.unwrap_or(&cache_dir).as_deref(),
        );
        let config_files: Vec<_> = paths.iter().map(PathBuf::from).collect();
        crate::rule_set::validate_remote_paths(&mut configs, &config_files)?;
        if let Some(expected) = expected_cache_dir
            && &cache_dir != expected
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "changing rule_cache_dir requires a restart",
            ));
        }
        #[cfg(unix)]
        if for_runtime
            && cache_lease.is_none()
            && let Some(directory) = cache_dir
        {
            *cache_lease = Some(std::sync::Arc::new(
                tokio::task::spawn_blocking(move || {
                    crate::rule_updater::create_cache_directory(&directory)?;
                    crate::rule_updater::cache_lease(&directory)
                })
                .await
                .map_err(io::Error::other)??,
            ));
        }
        #[cfg(not(unix))]
        let _ = (cache_lease, retained_ranges);
        let (mut configs, _) = config::convert_cert_paths(configs).await?;
        let mut memory = crate::rule_set::MemorySources::new();
        #[cfg(unix)]
        if for_runtime {
            (configs, memory) = crate::rule_updater::bootstrap(
                configs,
                retained_ranges,
                previous_servers
                    .map(|previous| previous.remote_rules.memory.clone())
                    .unwrap_or_default(),
                cache_lease.clone(),
            )
            .await?;
        }
        let snapshot = if memory.is_empty() {
            Vec::new()
        } else {
            configs.clone()
        };
        let mut validated =
            config::compile_configs_with_memory(configs, for_runtime.then(|| memory.clone()))
                .await?;
        validated.reload_files = dependencies;
        tokio::task::spawn_blocking(move || {
            if validated.catalog.is_some() {
                crate::control::validation::validate_resources(&validated)?;
            }
            Ok((validated, snapshot, memory))
        })
        .await
        .map_err(io::Error::other)?
    }
    .await
    .map_err(|error: io::Error| {
        io::Error::new(
            error.kind(),
            format!("Could not validate config files {paths:?}: {error}"),
        )
    })
}

struct PreparedServers {
    ntp: crate::ntp::Prepared,
    #[cfg(target_os = "linux")]
    managed: Option<std::sync::Arc<crate::desktop::Ingress>>,
    cache_lease: Option<std::sync::Arc<CacheLease>>,
    #[cfg(unix)]
    remote_rules: crate::rule_updater::Refresh,
    generation: Option<std::sync::Arc<crate::control::runtime::Generation>>,
    certificates: crate::certificates::Registry,
    validated: ValidatedConfigs,
    dns: DnsRegistry,
    tcp: TcpListeners,
    #[cfg(unix)]
    wireguard: crate::wireguard::Prepared,
    #[cfg(unix)]
    tun_fds: std::collections::HashMap<std::os::fd::RawFd, std::sync::Arc<std::os::fd::OwnedFd>>,
}

#[cfg(test)]
async fn prepare(paths: &[String], previous: Option<&DnsRegistry>) -> io::Result<PreparedServers> {
    prepare_tracking(
        paths,
        config::load_config_files(paths).await?,
        previous,
        None,
        &mut |_, _, _| {},
        &mut None,
        &crate::desktop::NetworkSession::default().topology(),
    )
    .await
}

async fn build_runtime_dns(
    validated: &ValidatedConfigs,
    previous: Option<&DnsRegistry>,
) -> io::Result<DnsRegistry> {
    let endpoints: Vec<_> = config::tun_endpoint_ips(&validated.configs).collect();
    dns::build_dns_registry_for_runtime(
        validated.dns_groups.clone(),
        validated.global_limits,
        previous,
        &endpoints,
        config::protects_tun_endpoints(&validated.configs),
    )
    .await
}

async fn prepare_tracking(
    paths: &[String],
    configs: Vec<Config>,
    previous: Option<&DnsRegistry>,
    previous_servers: Option<&PreparedServers>,
    discovered: &mut DiscoverDependencies<'_>,
    control: &mut Option<crate::control::runtime::ControlService>,
    network: &crate::desktop::NetworkTopology,
) -> io::Result<PreparedServers> {
    let mut cache_lease = previous_servers.and_then(|previous| previous.cache_lease.clone());
    let (mut validated, snapshot, memory) = load_candidate(
        paths,
        configs,
        discovered,
        true,
        previous_servers,
        &mut cache_lease,
        previous.map_or(&[], DnsRegistry::forbidden_ranges),
    )
    .await?;
    network.validate(&validated.configs)?;
    for config in &mut validated.configs {
        if let ResolvedConfig::TunServer(tun) = config
            && tun.auto_route
            && tun.dns_hijack.is_none()
        {
            tun.dns_hijack = Some(true);
        }
    }
    if control.is_none() && validated.catalog.is_some() {
        if previous.is_some()
            && (!validated.control.listeners.is_empty()
                || validated.control.cache_file_path.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "enabling controller or cache_file_path requires a restart",
            ));
        }
        *control = Some(crate::control::runtime::ControlService::new(
            validated.control.clone(),
        )?);
    }
    let control_generation = match control {
        Some(control) => Some(control.runtime.prepare(&mut validated).await?),
        None => None,
    };
    if let Some(previous) = previous {
        validated
            .validate_network_endpoints(previous.forbidden_ranges())
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("{error}; guard retained from the running configuration until restart"),
                )
            })?;
    }
    #[cfg(unix)]
    let wireguard = if let Some(previous) = previous {
        crate::wireguard::Prepared::with_forbidden(&mut validated, previous.forbidden_ranges())
            .await?
    } else {
        crate::wireguard::Prepared::new(&mut validated).await?
    };
    for config in &mut validated.configs {
        let ResolvedConfig::Server(server) = config else {
            continue;
        };
        let BindLocation::Address(addresses) = &server.bind_location else {
            continue;
        };
        let addresses = addresses.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            let mut resolved = Vec::new();
            for address in addresses.iter() {
                let socket_addrs = address.to_socket_addrs()?;
                // NetLocation has no scope ID; retain scoped literals in their original form.
                if socket_addrs.iter().any(
                    |addr| matches!(addr, std::net::SocketAddr::V6(addr) if addr.scope_id() != 0),
                ) {
                    resolved.push(address.clone());
                    continue;
                }
                for socket_addr in socket_addrs {
                    resolved.push(
                        NetLocation::from_ip_addr(socket_addr.ip(), socket_addr.port()).into(),
                    );
                }
            }
            Ok::<_, io::Error>(resolved)
        })
        .await
        .map_err(io::Error::other)??;
        if resolved.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "listener address resolved to no addresses",
            ));
        }
        server.bind_location = BindLocation::Address(OneOrSome::Some(resolved));
    }
    validated.refresh_catalog()?;
    dns::check_interception(&validated.configs, &validated.dns_groups).await?;
    let mut dns = build_runtime_dns(&validated, previous)
        .await
        .map_err(|error| {
            let live = resources::limits().quic_memory_bytes;
            let candidate = validated.global_limits.quic_memory_bytes;
            if live == candidate {
                error
            } else {
                io::Error::new(error.kind(), format!(
                    "{error}; DNS preparation uses the live QUIC cap {live:?}, not the candidate cap {candidate:?}"
                ))
            }
        })?;
    let certificates = match previous_servers {
        Some(previous) => {
            crate::certificates::Registry::prepare_with_retiring(
                &mut validated,
                Some(&previous.certificates),
                &previous.validated.configs,
            )
            .await?
        }
        None => crate::certificates::Registry::prepare(&mut validated, None).await?,
    };
    let generation = if let (Some((id, rules)), Some(catalog)) =
        (control_generation, validated.catalog.take())
    {
        let leaf_udp_support = crate::clash_api::dto::leaf_udp_support(&catalog)?;
        let generation = std::sync::Arc::new(crate::control::runtime::Generation {
            id,
            catalog,
            rules,
            leaf_udp_support,
            probes: crate::control::probes::ProbeState::new(
                dns.get_or_create_default(),
                dns.forbidden_ranges().to_vec(),
            ),
        });
        crate::clash_api::json_bytes(&crate::clash_api::dto::proxies(&generation))?;
        Some(generation)
    } else {
        None
    };
    #[cfg(unix)]
    let tun_fds = validated
        .configs
        .iter()
        .filter_map(|config| {
            let ResolvedConfig::TunServer(tun) = config else {
                return None;
            };
            let fd = tun.device_fd?;
            Some((fd, previous_servers?.tun_fds.get(&fd)?.clone()))
        })
        .collect();
    Ok(PreparedServers {
        ntp: crate::ntp::Prepared::new(
            validated.ntp.clone(),
            previous_servers.map(|previous| &previous.ntp),
        ),
        #[cfg(target_os = "linux")]
        managed: network.ingress(),
        cache_lease: cache_lease.clone(),
        #[cfg(unix)]
        remote_rules: crate::rule_updater::Refresh::new(
            snapshot,
            &validated.remote_rules,
            memory,
            previous_servers.map(|servers| &servers.remote_rules),
            cache_lease,
        )?,
        generation,
        certificates,
        validated,
        dns,
        tcp: TcpListeners::default(),
        #[cfg(unix)]
        wireguard,
        #[cfg(unix)]
        tun_fds,
    })
}

#[derive(Default)]
struct RunningServers {
    ntp: Option<crate::ntp::Running>,
    listeners: Vec<JoinHandle<()>>,
    #[cfg(unix)]
    tun: Vec<JoinHandle<io::Result<()>>>,
    reporter: Option<resources::ResourceReporter>,
    dns_snapshots: Option<dns::DnsSnapshotTask>,
    quic_retirements: crate::listener_tasks::QuicRetirements,
    #[cfg(unix)]
    wireguard: crate::wireguard::Running,
}

impl RunningServers {
    async fn pause_network(
        &mut self,
        prepared: &mut PreparedServers,
        control: Option<&crate::control::runtime::ControlService>,
        lifetime: &crate::network_tasks::NetworkTasks,
    ) -> io::Result<()> {
        if let (Some(control), Some(generation)) = (control, &prepared.generation) {
            control.runtime.begin_activation(generation).await?;
        }
        #[cfg(unix)]
        self.wireguard.cancel();
        lifetime.cancel();
        self.stop().await;
        lifetime.wait().await;
        prepared.tcp.defer_admission();
        prepared.dns.retire_network();
        self.quic_retirements.wait().await
    }

    async fn refresh_network(
        &mut self,
        prepared: &mut PreparedServers,
        network: &crate::desktop::NetworkSession,
    ) -> io::Result<()> {
        // Rejected activation may have published candidate limits and clock.
        self.configure_runtime(prepared).await?;
        network.refresh_bootstrap()?;
        prepared.dns = build_runtime_dns(&prepared.validated, Some(&prepared.dns)).await?;
        #[cfg(unix)]
        match tokio::time::timeout(Duration::from_secs(3), prepared.wireguard.refresh_peers()).await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::warn!(
                    "WireGuard peer refresh incomplete; retaining unresolved peer endpoints: {error}"
                )
            }
            Err(_) => {
                log::warn!("WireGuard peer refresh timed out; retaining unresolved peer endpoints")
            }
        }
        if let Some(generation) = &prepared.generation {
            generation.probes.reset_network(
                prepared.dns.get_or_create_default(),
                prepared.dns.forbidden_ranges().to_vec(),
            );
            generation.catalog.selection.automatic.choices_changed();
        }
        Ok(())
    }

    async fn shutdown_network(
        &mut self,
        registries: &[&PreparedServers],
        network: &mut crate::desktop::NetworkSession,
    ) -> io::Result<()> {
        if let Some(ntp) = &mut self.ntp {
            ntp.stop().await;
        }
        let network_result = network.deactivate().await;
        let worker_result = self.shutdown(registries).await;
        match (network_result, worker_result) {
            (Ok(()), result) => result,
            (Err(error), result) => Err(io::Error::other(format!(
                "network cleanup failed: {error}; worker cleanup: {result:?}"
            ))),
        }
    }
    async fn tun_failure(&mut self) -> io::Error {
        #[cfg(unix)]
        if !self.tun.is_empty() {
            let (result, index, _) = futures::future::select_all(self.tun.iter_mut()).await;
            drop(self.tun.swap_remove(index));
            return match result {
                Ok(Err(error)) => error,
                Ok(Ok(())) => io::Error::other("TUN service stopped unexpectedly"),
                Err(error) => io::Error::other(error),
            };
        }
        std::future::pending().await
    }

    async fn shutdown(&mut self, registries: &[&PreparedServers]) -> io::Result<()> {
        self.stop().await;
        self.ntp = None;
        let mut result = Ok(());
        for registry in registries {
            registry.certificates.stop().await;
            if let Err(error) = registry.dns.shutdown_checkpoint().await {
                log::warn!("Final Fake DNS checkpoint failed: {error}");
                if result.is_ok() {
                    result = Err(error);
                }
            }
        }
        result
    }

    async fn stop(&mut self) {
        if let Some(ntp) = &mut self.ntp {
            ntp.stop().await;
        }
        #[cfg(unix)]
        {
            for task in &self.tun {
                task.abort();
            }
            for task in self.tun.drain(..) {
                let _ = task.await;
            }
        }
        for task in &self.listeners {
            task.abort();
        }
        for task in self.listeners.drain(..) {
            let _ = task.await;
        }
        #[cfg(unix)]
        self.wireguard.stop().await;
        self.reporter = None;
        self.dns_snapshots = None;
    }

    async fn configure_runtime(&mut self, prepared: &PreparedServers) -> io::Result<()> {
        resources::configure(prepared.validated.global_limits)?;
        self.ntp = Some(
            prepared
                .ntp
                .start(prepared.dns.forbidden_ranges().to_vec().into())
                .await,
        );
        Ok(())
    }

    async fn start(&mut self, prepared: &mut PreparedServers) -> io::Result<()> {
        // Synchronize before retryable binds, including deferred HTTP-01 listeners.
        self.configure_runtime(prepared).await?;
        prepared.certificates.bind_pending().await?;
        self.reporter = Some(resources::ResourceReporter::start());
        self.dns_snapshots = Some(prepared.dns.snapshot_task());
        #[cfg(unix)]
        if let Err(error) = prepared
            .wireguard
            .start(&mut prepared.dns, &mut self.wireguard)
            .await
        {
            self.stop().await;
            return Err(error);
        }
        for config in &prepared.validated.configs {
            let dns_ref = match config {
                ResolvedConfig::Server(server) => server.dns.as_ref(),
                ResolvedConfig::TunServer(tun) => tun.dns.as_ref(),
            };
            let resolver = prepared.dns.get_for_server(dns_ref);
            #[cfg(unix)]
            if let ResolvedConfig::TunServer(config) = config {
                #[cfg(target_os = "linux")]
                if config.auto_route {
                    let ingress = prepared
                        .managed
                        .as_ref()
                        .ok_or_else(|| io::Error::other("managed TUN ingress is missing"))?;
                    let admission = crate::desktop::Ingress::tcp_admission(config);
                    ingress
                        .start(config, resolver, admission, &mut self.tun)
                        .await?;
                    continue;
                }
                if let Some(fd) = config.device_fd {
                    use std::os::fd::FromRawFd;
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        prepared.tun_fds.entry(fd)
                    {
                        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        entry.insert(std::sync::Arc::new(unsafe {
                            std::os::fd::OwnedFd::from_raw_fd(fd)
                        }));
                    }
                }
                // The registry retains the descriptor through rollback; each stack borrows a duplicate.
                match crate::tun::start_tun_server_with_fd_ownership(
                    config.clone(),
                    resolver,
                    false,
                )
                .await
                {
                    Ok(task) => self.tun.push(task),
                    Err(error) => {
                        self.stop().await;
                        return Err(error);
                    }
                }
                continue;
            }
            let startup = crate::tcp::tcp_server::start_servers_with_listeners(
                config.clone(),
                resolver,
                &mut prepared.tcp,
            );
            match self.quic_retirements.track(startup).await {
                Ok(tasks) => self.listeners.extend(tasks),
                Err(error) => {
                    self.stop().await;
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    async fn start_retry(&mut self, prepared: &mut PreparedServers) -> io::Result<()> {
        // Initial synchronization must not consume the listener rebind budget.
        let mut deadline = None;
        loop {
            let error = match self.start(prepared).await {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            self.stop().await;
            if error.kind() != io::ErrorKind::AddrInUse {
                return Err(error);
            }
            let now = tokio::time::Instant::now();
            let retry_deadline = *deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_secs(3));
            if now >= retry_deadline {
                return Err(error);
            }
            self.quic_retirements.wait().await?;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn commit_activation(
        &self,
        prepared: &PreparedServers,
        control: Option<&crate::control::runtime::ControlService>,
    ) -> io::Result<()> {
        if let (Some(control), Some(generation)) = (control, &prepared.generation) {
            control.runtime.publish(generation.clone()).await?;
        }
        self.finish_activation(prepared, control).await
    }

    async fn finish_activation(
        &self,
        prepared: &PreparedServers,
        control: Option<&crate::control::runtime::ControlService>,
    ) -> io::Result<()> {
        if let Some(control) = control {
            control.runtime.resume().await?;
        }
        // Workers can update durable ACME state, so activation starts them last.
        prepared.certificates.start().await;
        prepared.tcp.activate();
        Ok(())
    }

    async fn discard_candidate(
        &mut self,
        previous: &mut PreparedServers,
        candidate: &mut PreparedServers,
    ) -> io::Result<()> {
        self.stop().await;
        candidate
            .certificates
            .retire_unused(&previous.certificates)
            .await;
        candidate.certificates.shutdown().await;
        // Candidate-only sockets can overlap addresses the previous listeners rebind.
        candidate.tcp = TcpListeners::default();
        // Rejected reloads retain inherited descriptors for a corrected configuration.
        #[cfg(unix)]
        for (fd, descriptor) in candidate.tun_fds.drain() {
            previous.tun_fds.entry(fd).or_insert(descriptor);
        }
        self.quic_retirements.wait().await?;
        // Pools may be shared with the live registry: rejection is not terminal shutdown.
        if let Err(error) = candidate.dns.checkpoint().await {
            log::warn!("Rejected candidate Fake DNS checkpoint failed: {error}");
        }
        previous.tcp.defer_admission();
        Ok(())
    }
}

impl Drop for RunningServers {
    fn drop(&mut self) {
        #[cfg(unix)]
        for task in &self.tun {
            task.abort();
        }
        for task in &self.listeners {
            task.abort();
        }
    }
}

struct ConfigWatches {
    cache_dir: Option<PathBuf>,
    configs: Vec<PathBuf>,
    active: Vec<PathBuf>,
    candidate: Vec<PathBuf>,
    recovery: Vec<PathBuf>,
    watcher: Option<RecommendedWatcher>,
    recovery_watcher: Option<RecommendedWatcher>,
    events: crate::file_watcher::EventFilter,
    recovery_events: crate::file_watcher::EventFilter,
    tx: mpsc::Sender<()>,
    recovery_tx: mpsc::Sender<()>,
    recovery_changes: mpsc::Receiver<()>,
    disabled: bool,
}

impl ConfigWatches {
    fn new(paths: &[String], tx: mpsc::Sender<()>, disabled: bool) -> io::Result<Self> {
        let (recovery_tx, recovery_changes) = mpsc::channel(1);
        let mut state = Self {
            cache_dir: None,
            configs: paths.iter().map(PathBuf::from).collect(),
            active: Vec::new(),
            candidate: Vec::new(),
            recovery: Vec::new(),
            watcher: None,
            recovery_watcher: None,
            events: crate::file_watcher::EventFilter::default(),
            recovery_events: crate::file_watcher::EventFilter::default(),
            tx,
            recovery_tx,
            recovery_changes,
            disabled,
        };
        state.refresh()?;
        Ok(state)
    }

    fn refresh(&mut self) -> io::Result<()> {
        if !self.disabled {
            let paths: Vec<_> = self
                .configs
                .iter()
                .chain(&self.active)
                .chain(&self.candidate)
                .collect();
            // Construct the replacement before dropping the old watches.
            self.watcher = Some(crate::file_watcher::watch_excluding(
                &paths,
                self.tx.clone(),
                self.cache_dir.as_deref(),
                cfg!(target_os = "macos").then_some(&self.events),
            )?);
            self.recovery_watcher = if self.recovery.is_empty() {
                None
            } else {
                Some(crate::file_watcher::watch_excluding(
                    &self.recovery,
                    self.recovery_tx.clone(),
                    self.cache_dir.as_deref(),
                    cfg!(target_os = "macos").then_some(&self.recovery_events),
                )?)
            };
        }
        Ok(())
    }

    fn discovered(&mut self, paths: &[PathBuf], recovery: &[PathBuf], cache_dir: Option<&Path>) {
        self.cache_dir = cache_dir.map(Path::to_path_buf);
        self.candidate = paths.to_vec();
        self.recovery = recovery.to_vec();
        if let Err(error) = self.refresh() {
            log::warn!("Could not refresh config dependency watches: {error}");
        }
    }

    fn activated(&mut self, paths: &[PathBuf]) {
        self.active = paths.to_vec();
        self.candidate.clear();
        self.recovery.clear();
        self.recovery_watcher = None;
        // Late callbacks and queued identity-only events belong to the candidate,
        // not the active generation. Preserve the separate config/reload queue.
        (self.recovery_tx, self.recovery_changes) = mpsc::channel(1);
        self.recovery_events = crate::file_watcher::EventFilter::default();
        if let Err(error) = self.refresh() {
            log::warn!("Could not refresh config dependency watches: {error}");
        }
    }

    async fn changed(&mut self, changes: &mut mpsc::Receiver<()>) {
        tokio::select! {
            _ = changes.recv() => {},
            _ = self.recovery_changes.recv() => {},
        }
    }

    async fn debounce(&mut self, changes: &mut mpsc::Receiver<()>) {
        loop {
            tokio::select! {
                biased;
                _ = self.changed(changes) => {},
                _ = tokio::time::sleep(RELOAD_DEBOUNCE) => return,
            }
        }
    }
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
    }
}

#[cfg(windows)]
struct ShutdownSignals(tokio::signal::windows::CtrlC);

#[cfg(windows)]
impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        tokio::signal::windows::ctrl_c().map(Self)
    }
    async fn recv(&mut self) {
        self.0.recv().await;
    }
}

struct ReloadSignal {
    #[cfg(unix)]
    signal: tokio::signal::unix::Signal,
}

impl ReloadSignal {
    fn new() -> io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            signal: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            self.signal.recv().await;
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    }
}

pub async fn run(paths: Vec<String>, dry_run: bool, no_reload: bool) -> io::Result<()> {
    if dry_run {
        let configs = config::load_config_files(&paths).await?;
        validate_configs(&paths, configs, &mut |_, _, _| {}).await?;
        println!("Configuration valid");
        return Ok(());
    }
    let mut shutdown = ShutdownSignals::new()?;
    let mut reload = ReloadSignal::new()?;
    let mut network = crate::desktop::NetworkSession::default();
    let mut control = None;
    let mut api = None;
    let result = run_inner(
        paths,
        no_reload,
        &mut control,
        &mut api,
        &mut network,
        &mut shutdown,
        &mut reload,
    )
    .await;
    let cleanup = network.close().await;
    if let Some(api) = &mut api {
        api.shutdown().await;
    }
    drop(api);
    if let Some(control) = &mut control {
        control.shutdown().await;
    }
    drop(control);
    match (result, cleanup) {
        (result, Ok(())) => result,
        (result, Err(error)) => Err(io::Error::other(format!(
            "managed TUN cleanup failed: {error}; process: {result:?}"
        ))),
    }
}

async fn run_inner(
    paths: Vec<String>,
    no_reload: bool,
    control: &mut Option<crate::control::runtime::ControlService>,
    api: &mut Option<crate::clash_api::ApiService>,
    network: &mut crate::desktop::NetworkSession,
    shutdown: &mut ShutdownSignals,
    reload: &mut ReloadSignal,
) -> io::Result<()> {
    let (change_tx, mut changes) = mpsc::channel(1);
    let mut watches = ConfigWatches::new(&paths, change_tx, no_reload)?;
    let configs = tokio::select! {
        biased;
        _ = shutdown.recv() => return Ok(()),
        result = config::load_config_files(&paths) => result?,
    };
    let mut lifetime = crate::network_tasks::NetworkLifetime::default();
    *network = lifetime
        .scope(crate::desktop::NetworkSession::prepare(&configs))
        .await?;
    if !network.monitors_underlay() {
        lifetime = crate::network_tasks::NetworkLifetime::untracked();
    }
    let mut discovered = |paths: &[PathBuf], recovery: &[PathBuf], root: Option<&Path>| {
        watches.discovered(paths, recovery, root)
    };
    let topology = network.topology();
    let mut prepared = tokio::select! {
        biased;
        _ = shutdown.recv() => return Ok(()),
        result = lifetime.scope(prepare_tracking(&paths, configs, None, None, &mut discovered, control, &topology)) => result?,
    };
    network.prepare_network().await?;
    #[cfg(target_os = "linux")]
    {
        prepared.managed = network.ingress();
    }
    prepared.tcp =
        TcpListeners::prepare(&prepared.validated.configs, &TcpListeners::default(), &[])?;
    watches.activated(&prepared.validated.reload_files);
    let mut running = RunningServers::default();
    if let (Some(control), Some(generation)) = (control.as_ref(), prepared.generation.as_ref()) {
        control.runtime.begin_activation(generation).await?;
        control.runtime.publish(generation.clone()).await?;
        if !control.runtime.config.listeners.is_empty() {
            *api = Some(crate::clash_api::ApiService::start(control.runtime.clone()).await?);
        }
    }
    tokio::select! {
        biased;
        _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
        result = lifetime.scope(running.start(&mut prepared)) => if let Err(error) = result {
            let _ = running.shutdown_network(&[&prepared], network).await;
            return Err(error);
        },
    }
    tokio::select! {
        biased;
        _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
        result = lifetime.scope(running.finish_activation(&prepared, control.as_ref())) => if let Err(error) = result {
            let cleanup = running.shutdown_network(&[&prepared], network).await;
            return Err(io::Error::other(format!(
                "controller activation failed: {error}; shutdown: {cleanup:?}"
            )));
        },
    }
    if let Err(error) = network.activate().await {
        let cleanup = running.shutdown_network(&[&prepared], network).await;
        return Err(io::Error::other(format!(
            "managed network activation failed: {error}; shutdown: {cleanup:?}"
        )));
    }
    println!("Servers ready");
    let mut reconnecting = false;
    let mut pending_reload = false;
    let mut force_network_reset = false;
    let mut retry_at = tokio::time::Instant::now();
    loop {
        let can_retry = reconnecting && network.available();
        enum Change {
            Shutdown,
            TunFailure(io::Error),
            Reload { debounce: bool },
            Reconnect,
        }
        let change = wait_with_reconciliation(
            async {
                tokio::select! {
                    biased;
                    _ = shutdown.recv() => Change::Shutdown,
                    error = running.tun_failure() => Change::TunFailure(error),
                    _ = std::future::ready(()), if force_network_reset => Change::Reconnect,
                    _ = reload.recv() => Change::Reload { debounce: false },
                    _ = lifetime.scope(remote_rule_change(&mut prepared)), if !reconnecting => Change::Reload { debounce: false },
                    _ = watches.changed(&mut changes) => Change::Reload { debounce: true },
                    _ = tokio::time::sleep_until(retry_at), if can_retry => Change::Reconnect,
                }
            },
            network,
        )
        .await;
        let debounce = match change {
            Ok(Some(Change::Shutdown)) => {
                return running.shutdown_network(&[&prepared], network).await;
            }
            Ok(Some(Change::TunFailure(error))) => {
                let _ = running.shutdown_network(&[&prepared], network).await;
                return Err(error);
            }
            Ok(Some(Change::Reload { debounce })) => {
                if reconnecting {
                    pending_reload = true;
                    force_network_reset = network.available();
                    continue;
                }
                debounce
            }
            Ok(None) | Ok(Some(Change::Reconnect)) => {
                force_network_reset = false;
                if !reconnecting {
                    log::info!("Underlay changed; retiring network workers");
                }
                // Rejected repair preparation can leave work in the current lifetime.
                if let Err(error) = running
                    .pause_network(&mut prepared, control.as_ref(), &lifetime)
                    .await
                {
                    let _ = running.shutdown_network(&[&prepared], network).await;
                    return Err(error);
                }
                if !reconnecting && !network.available() {
                    println!("Network unavailable; waiting for underlay");
                }
                reconnecting = true;
                if !network.available() {
                    continue;
                }
                lifetime = crate::network_tasks::NetworkLifetime::default();
                let mut result = tokio::select! {
                    biased;
                    _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
                    result = lifetime.scope(async {
                        if pending_reload {
                            // Repair must not depend on the accepted DNS configuration recovering.
                            running.configure_runtime(&prepared).await?;
                            network.refresh_bootstrap()
                        } else {
                            running.refresh_network(&mut prepared, network).await?;
                            running.start_retry(&mut prepared).await
                        }
                    }) => result,
                };
                // Ownership failures remain terminal, unlike transient worker startup errors.
                match network.reconcile().await {
                    Err(error) => {
                        let _ = running.shutdown_network(&[&prepared], network).await;
                        return Err(error);
                    }
                    Ok(changed) if changed || !network.available() => {
                        result = Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "underlay changed during recovery",
                        ));
                    }
                    Ok(_) => {}
                }
                match result {
                    Ok(()) if pending_reload => {
                        pending_reload = false;
                        false
                    }
                    Ok(()) => {
                        tokio::select! {
                            biased;
                            _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
                            result = lifetime.scope(running.finish_activation(&prepared, control.as_ref())) => if let Err(error) = result {
                                let _ = running.shutdown_network(&[&prepared], network).await;
                                return Err(error);
                            },
                        }
                        reconnecting = false;
                        println!("Network reconnected");
                        continue;
                    }
                    Err(error) => {
                        log::warn!("Network recovery deferred: {error}");
                        if let Err(error) = running
                            .pause_network(&mut prepared, control.as_ref(), &lifetime)
                            .await
                        {
                            let _ = running.shutdown_network(&[&prepared], network).await;
                            return Err(error);
                        }
                        retry_at = tokio::time::Instant::now() + Duration::from_secs(2);
                        continue;
                    }
                }
            }
            Err(error) => {
                let cleanup = running.shutdown_network(&[&prepared], network).await;
                return Err(io::Error::other(format!(
                    "managed network changed: {error}; shutdown: {cleanup:?}"
                )));
            }
        };
        if debounce {
            let settled = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
                error = running.tun_failure() => {
                    let _ = running.shutdown_network(&[&prepared], network).await;
                    return Err(error);
                },
                result = wait_with_reconciliation(async {
                    tokio::select! {
                        _ = reload.recv() => {},
                        _ = watches.debounce(&mut changes) => {},
                    }
                }, network) => result,
            };
            match settled {
                Ok(Some(())) => {}
                Ok(None) => {
                    pending_reload = true;
                    force_network_reset = true;
                    continue;
                }
                Err(error) => {
                    let _ = running.shutdown_network(&[&prepared], network).await;
                    return Err(error);
                }
            }
        }
        while changes.try_recv().is_ok() {}
        while watches.recovery_changes.try_recv().is_ok() {}
        // Refresh symlink targets even when the candidate's YAML is invalid.
        if let Err(error) = watches.refresh() {
            log::warn!("Could not refresh config watches: {error}");
        }
        let mut discovered = |paths: &[PathBuf], recovery: &[PathBuf], root: Option<&Path>| {
            watches.discovered(paths, recovery, root)
        };
        let topology = network.topology();
        let candidate = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown_network(&[&prepared], network).await,
            error = running.tun_failure() => {
                let _ = running.shutdown_network(&[&prepared], network).await;
                return Err(error);
            },
            result = wait_with_reconciliation(async {
                let configs = config::load_config_files(&paths).await?;
                lifetime.scope(prepare_tracking(&paths, configs, Some(&prepared.dns), Some(&prepared), &mut discovered, control, &topology)).await
            }, network) => result,
        };
        let mut candidate = match candidate {
            Ok(Some(Ok(candidate))) => candidate,
            Ok(Some(Err(error))) => {
                report_reload_rejection(&error, reconnecting);
                continue;
            }
            Ok(None) => {
                pending_reload = true;
                force_network_reset = true;
                continue;
            }
            Err(error) => {
                let _ = running.shutdown_network(&[&prepared], network).await;
                return Err(error);
            }
        };
        candidate.tcp = match TcpListeners::prepare(
            &candidate.validated.configs,
            &prepared.tcp,
            &prepared.certificates.listener_addresses(),
        ) {
            Ok(listeners) => listeners,
            Err(error) => {
                report_reload_rejection(&error, reconnecting);
                continue;
            }
        };
        if let (Some(control), Some(generation)) = (control.as_ref(), candidate.generation.as_ref())
            && let Err(error) = control.runtime.begin_activation(generation).await
        {
            report_reload_rejection(&error, reconnecting);
            continue;
        }
        let retirement = async {
            running.stop().await;
            prepared.tcp.retain_shared(&candidate.tcp);
            prepared
                .certificates
                .retire_unused(&candidate.certificates)
                .await;
            if let Err(error) = prepared.dns.checkpoint().await {
                log::warn!("Reload Fake DNS checkpoint failed; continuing reload: {error}");
            }
            running.quic_retirements.wait().await
        };
        tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown_network(&[&prepared, &candidate], network).await,
            result = retirement => if let Err(error) = result {
                let _ = running.shutdown_network(&[&prepared, &candidate], network).await;
                return Err(error);
            },
        }
        let mut result = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown_network(&[&prepared, &candidate], network).await,
            result = lifetime.scope(running.start_retry(&mut candidate)) => result,
        };
        if reconnecting {
            // A repair candidate must not publish before ownership is checked again.
            match network.reconcile().await {
                Err(error) => {
                    let _ = running
                        .shutdown_network(&[&prepared, &candidate], network)
                        .await;
                    return Err(error);
                }
                Ok(changed) if changed || !network.available() => {
                    pending_reload = true;
                    result = Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "underlay changed during reload recovery",
                    ));
                }
                Ok(_) => {}
            }
        }
        if result.is_ok() {
            result = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown_network(&[&prepared, &candidate], network).await,
                result = lifetime.scope(running.commit_activation(&candidate, control.as_ref())) => result,
            };
        }
        if let Err(error) = result {
            let fallback = async {
                running
                    .discard_candidate(&mut prepared, &mut candidate)
                    .await?;
                if reconnecting {
                    running
                        .pause_network(&mut prepared, control.as_ref(), &lifetime)
                        .await
                } else {
                    running.start_retry(&mut prepared).await?;
                    running.commit_activation(&prepared, control.as_ref()).await
                }
            };
            let fallback_result = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown_network(&[&prepared, &candidate], network).await,
                result = lifetime.scope(fallback) => result,
            };
            if let Err(fallback_error) = fallback_result {
                let operation = if reconnecting {
                    "recovery cleanup"
                } else {
                    "rollback"
                };
                let cleanup = running
                    .shutdown_network(&[&prepared, &candidate], network)
                    .await;
                return Err(io::Error::other(format!(
                    "Reload activation failed: {error}; {operation} failed: {fallback_error}; shutdown: {cleanup:?}"
                )));
            }
            if reconnecting {
                if pending_reload {
                    eprintln!("Reload deferred until network recovery: {error}");
                } else {
                    eprintln!(
                        "Reload rejected; recovery will retry previous configuration: {error}"
                    );
                }
                retry_at = tokio::time::Instant::now() + Duration::from_secs(2);
            } else {
                eprintln!("Reload rejected; previous servers restored: {error}");
            }
            continue;
        }
        watches.activated(&candidate.validated.reload_files);
        let mut retired = std::mem::replace(&mut prepared, candidate);
        retired.certificates.shutdown().await;
        if reconnecting {
            reconnecting = false;
            println!("Network reconnected");
        }
        println!("Servers ready");
    }
}

fn report_reload_rejection(error: &io::Error, reconnecting: bool) {
    let status = if reconnecting {
        "workers unavailable, recovery continues"
    } else {
        "current servers retained"
    };
    eprintln!("Reload rejected; {status}: {error}");
}

async fn wait_with_reconciliation<T>(
    change: impl std::future::Future<Output = T>,
    network: &mut crate::desktop::NetworkSession,
) -> io::Result<Option<T>> {
    tokio::pin!(change);
    loop {
        tokio::select! {
            biased;
            result = &mut change => return Ok(Some(result)),
            _ = network.changed() => {
                // Retain in-flight refreshes and finish network mutations before handling reload/shutdown.
                if network.reconcile().await? {
                    return Ok(None);
                }
            }
        }
    }
}

async fn remote_rule_change(prepared: &mut PreparedServers) {
    #[cfg(unix)]
    prepared
        .remote_rules
        .changed(&prepared.dns, prepared.validated.global_limits)
        .await;
    #[cfg(not(unix))]
    {
        let _ = prepared;
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
#[path = "../tests/cases/retention/process.rs"]
mod retention_tests;

#[cfg(test)]
mod tests;
