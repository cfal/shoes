use std::io;
use std::path::PathBuf;
use std::time::Duration;

use notify::RecommendedWatcher;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::config::{self, BindLocation, Config, ValidatedConfigs};
use crate::dns::{self, DnsRegistry};
use crate::file_watcher::watch;
use crate::option_util::OneOrSome;
use crate::resources;
use crate::tcp::tcp_server::TcpListeners;

const RELOAD_DEBOUNCE: Duration = Duration::from_secs(5);

async fn load_validated(
    paths: &[String],
    discovered: &mut (dyn FnMut(&[PathBuf], &[PathBuf]) + Send),
) -> io::Result<ValidatedConfigs> {
    let mut configs = config::load_configs(&paths.to_vec()).await?;
    async {
        let mut dependencies = crate::rule_set::dependencies(&mut configs)?;
        let mut recovery_dependencies = config::pem_candidate_dependencies(&mut configs)?;
        dependencies.extend(config::pem_reload_dependencies(&mut configs)?);
        recovery_dependencies.retain(|path| !dependencies.contains(path));
        discovered(&dependencies, &recovery_dependencies);
        let (configs, _) = config::convert_cert_paths(configs).await?;
        let mut validated = config::compile_configs(configs).await?;
        validated.reload_files = dependencies;
        tokio::task::spawn_blocking(move || {
            if validated.catalog.is_some() {
                crate::control::validation::validate_resources(&validated)?;
            }
            Ok(validated)
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
    prepare_tracking(paths, previous, None, &mut |_, _| {}, &mut None).await
}

async fn prepare_tracking(
    paths: &[String],
    previous: Option<&DnsRegistry>,
    previous_servers: Option<&PreparedServers>,
    discovered: &mut (dyn FnMut(&[PathBuf], &[PathBuf]) + Send),
    control: &mut Option<crate::control::runtime::ControlService>,
) -> io::Result<PreparedServers> {
    let mut validated = load_validated(paths, discovered).await?;
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
        let Config::Server(server) = config else {
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
    let synthetic_endpoints: Vec<_> = crate::config::tun_endpoint_ips(&validated.configs).collect();
    validated.refresh_catalog()?;
    let mut dns = dns::build_dns_registry_for_runtime(
        std::mem::take(&mut validated.dns_groups),
        validated.global_limits,
        previous,
        &synthetic_endpoints,
    )
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
            let Config::TunServer(tun) = config else {
                return None;
            };
            let fd = tun.device_fd?;
            Some((fd, previous_servers?.tun_fds.get(&fd)?.clone()))
        })
        .collect();
    Ok(PreparedServers {
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

    async fn start(&mut self, prepared: &mut PreparedServers) -> io::Result<()> {
        prepared.certificates.bind_pending().await?;
        resources::configure(prepared.validated.global_limits)?;
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
                Config::Server(server) => server.dns.as_ref(),
                Config::TunServer(tun) => tun.dns.as_ref(),
                _ => None,
            };
            let resolver = prepared.dns.get_for_server(dns_ref);
            #[cfg(unix)]
            if let Config::TunServer(config) = config {
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            match self.start(prepared).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    self.stop().await;
                    if error.kind() != io::ErrorKind::AddrInUse
                        || tokio::time::Instant::now() >= deadline
                    {
                        return Err(error);
                    }
                    self.quic_retirements.wait().await?;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    async fn activate(
        &mut self,
        prepared: &mut PreparedServers,
        control: Option<&crate::control::runtime::ControlService>,
    ) -> io::Result<()> {
        self.start_retry(prepared).await?;
        if let Some(control) = control {
            if let Some(generation) = &prepared.generation {
                control.runtime.publish(generation.clone()).await?;
            }
            control.runtime.resume().await?;
        }
        // Workers can update durable ACME state, so activation starts them last.
        prepared.certificates.start().await;
        prepared.tcp.activate();
        Ok(())
    }

    async fn rollback(
        &mut self,
        previous: &mut PreparedServers,
        candidate: &mut PreparedServers,
        control: Option<&crate::control::runtime::ControlService>,
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
        self.activate(previous, control).await
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
    configs: Vec<PathBuf>,
    active: Vec<PathBuf>,
    candidate: Vec<PathBuf>,
    recovery: Vec<PathBuf>,
    watcher: Option<RecommendedWatcher>,
    recovery_watcher: Option<RecommendedWatcher>,
    tx: mpsc::Sender<()>,
    recovery_tx: mpsc::Sender<()>,
    recovery_changes: mpsc::Receiver<()>,
    disabled: bool,
}

impl ConfigWatches {
    fn new(paths: &[String], tx: mpsc::Sender<()>, disabled: bool) -> io::Result<Self> {
        let (recovery_tx, recovery_changes) = mpsc::channel(1);
        let mut state = Self {
            configs: paths.iter().map(PathBuf::from).collect(),
            active: Vec::new(),
            candidate: Vec::new(),
            recovery: Vec::new(),
            watcher: None,
            recovery_watcher: None,
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
            self.watcher = Some(watch(&paths, self.tx.clone())?);
            self.recovery_watcher = if self.recovery.is_empty() {
                None
            } else {
                Some(watch(&self.recovery, self.recovery_tx.clone())?)
            };
        }
        Ok(())
    }

    fn discovered(&mut self, paths: &[PathBuf], recovery: &[PathBuf]) {
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
    let mut control = None;
    let mut api = None;
    let result = run_inner(paths, dry_run, no_reload, &mut control, &mut api).await;
    if let Some(api) = &mut api {
        api.shutdown().await;
    }
    drop(api);
    if let Some(control) = &mut control {
        control.shutdown().await;
    }
    drop(control);
    result
}

async fn run_inner(
    paths: Vec<String>,
    dry_run: bool,
    no_reload: bool,
    control: &mut Option<crate::control::runtime::ControlService>,
    api: &mut Option<crate::clash_api::ApiService>,
) -> io::Result<()> {
    if dry_run {
        load_validated(&paths, &mut |_, _| {}).await?;
        println!("Configuration valid");
        return Ok(());
    }
    let mut shutdown = ShutdownSignals::new()?;
    let mut reload = ReloadSignal::new()?;
    let (change_tx, mut changes) = mpsc::channel(1);
    let mut watches = ConfigWatches::new(&paths, change_tx, no_reload)?;
    let mut discovered =
        |paths: &[PathBuf], recovery: &[PathBuf]| watches.discovered(paths, recovery);
    let mut prepared = tokio::select! {
        biased;
        _ = shutdown.recv() => return Ok(()),
        result = prepare_tracking(&paths, None, None, &mut discovered, control) => result?,
    };
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
        _ = shutdown.recv() => return running.shutdown(&[&prepared]).await,
        result = running.start(&mut prepared) => if let Err(error) = result {
            let _ = running.shutdown(&[&prepared]).await;
            return Err(error);
        },
    }
    if let Some(control) = control.as_ref() {
        control.runtime.resume().await?;
    }
    prepared.certificates.start().await;
    prepared.tcp.activate();
    println!("Servers ready");
    loop {
        let debounce = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared]).await,
            error = running.tun_failure() => {
                let _ = running.shutdown(&[&prepared]).await;
                return Err(error);
            },
            _ = reload.recv() => false,
            _ = watches.changed(&mut changes) => true,
        };
        if debounce {
            tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown(&[&prepared]).await,
                error = running.tun_failure() => {
                    let _ = running.shutdown(&[&prepared]).await;
                    return Err(error);
                },
                _ = reload.recv() => {}
                _ = watches.debounce(&mut changes) => {}
            }
        }
        while changes.try_recv().is_ok() {}
        while watches.recovery_changes.try_recv().is_ok() {}
        // Refresh symlink targets even when the candidate's YAML is invalid.
        if let Err(error) = watches.refresh() {
            log::warn!("Could not refresh config watches: {error}");
        }
        let mut discovered =
            |paths: &[PathBuf], recovery: &[PathBuf]| watches.discovered(paths, recovery);
        let candidate = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared]).await,
            error = running.tun_failure() => {
                let _ = running.shutdown(&[&prepared]).await;
                return Err(error);
            },
            result = prepare_tracking(&paths, Some(&prepared.dns), Some(&prepared), &mut discovered, control) => result,
        };
        let mut candidate = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("Reload rejected; current servers retained: {error}");
                continue;
            }
        };
        candidate.tcp = match TcpListeners::prepare(
            &candidate.validated.configs,
            &prepared.tcp,
            &prepared.certificates.listener_addresses(),
        ) {
            Ok(listeners) => listeners,
            Err(error) => {
                eprintln!("Reload rejected; current servers retained: {error}");
                continue;
            }
        };
        if let (Some(control), Some(generation)) = (control.as_ref(), candidate.generation.as_ref())
            && let Err(error) = control.runtime.begin_activation(generation).await
        {
            eprintln!("Reload rejected; current servers retained: {error}");
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
            _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
            result = retirement => if let Err(error) = result {
                let _ = running.shutdown(&[&prepared, &candidate]).await;
                return Err(error);
            },
        }
        let result = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
            result = running.activate(&mut candidate, control.as_ref()) => result,
        };
        if let Err(error) = result {
            let rollback = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
                result = running.rollback(&mut prepared, &mut candidate, control.as_ref()) => result,
            };
            if let Err(rollback) = rollback {
                let cleanup = running.shutdown(&[&prepared, &candidate]).await;
                return Err(io::Error::other(format!(
                    "Reload activation failed: {error}; rollback failed: {rollback}; shutdown: {cleanup:?}"
                )));
            }
            eprintln!("Reload rejected; previous servers restored: {error}");
            continue;
        }
        watches.activated(&candidate.validated.reload_files);
        let mut retired = std::mem::replace(&mut prepared, candidate);
        retired.certificates.shutdown().await;
        println!("Servers ready");
    }
}

#[cfg(test)]
#[path = "../tests/cases/retention/process.rs"]
mod retention_tests;

#[cfg(test)]
mod tests;
