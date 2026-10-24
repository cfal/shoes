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

const RELOAD_DEBOUNCE: Duration = Duration::from_secs(5);

async fn load_validated(
    paths: &[String],
    discovered: &mut (dyn FnMut(&[PathBuf], &[PathBuf]) + Send),
) -> io::Result<ValidatedConfigs> {
    let mut configs = config::load_configs(&paths.to_vec()).await?;
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

struct PreparedServers {
    generation: Option<std::sync::Arc<crate::control::runtime::Generation>>,
    certificates: crate::certificates::Registry,
    validated: ValidatedConfigs,
    dns: DnsRegistry,
    #[cfg(unix)]
    wireguard: crate::wireguard::Prepared,
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
            probes: crate::clash_api::probes::ProbeState::new(
                dns.get_or_create_default(),
                dns.forbidden_ranges().to_vec(),
            ),
        });
        crate::clash_api::json_bytes(&crate::clash_api::dto::proxies(&generation))?;
        Some(generation)
    } else {
        None
    };
    Ok(PreparedServers {
        generation,
        certificates,
        validated,
        dns,
        #[cfg(unix)]
        wireguard,
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
                match crate::tun::start_tun_server(config.clone(), resolver).await {
                    Ok(task) => self.tun.push(task),
                    Err(error) => {
                        self.stop().await;
                        return Err(error);
                    }
                }
                continue;
            }
            let startup = crate::tcp::tcp_server::start_servers(config.clone(), resolver);
            match self.quic_retirements.track(startup).await {
                Ok(tasks) => self.listeners.extend(tasks),
                Err(error) => {
                    self.stop().await;
                    return Err(error);
                }
            }
        }
        prepared.certificates.start().await;
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
        if let (Some(control), Some(generation)) = (control.as_ref(), candidate.generation.as_ref())
            && let Err(error) = control.runtime.begin_activation(generation).await
        {
            eprintln!("Reload rejected; current servers retained: {error}");
            continue;
        }
        running.stop().await;
        prepared
            .certificates
            .retire_unused(&candidate.certificates)
            .await;
        if let Err(error) = prepared.dns.checkpoint().await {
            log::warn!("Reload Fake DNS checkpoint failed; continuing reload: {error}");
        }
        tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
            result = running.quic_retirements.wait() => if let Err(error) = result {
                let _ = running.shutdown(&[&prepared, &candidate]).await;
                return Err(error);
            },
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        if let (Some(control), Some(generation)) = (control.as_ref(), candidate.generation.as_ref())
        {
            control.runtime.publish(generation.clone()).await?;
        }
        loop {
            let result = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
                result = running.start(&mut candidate) => result,
            };
            match result {
                Ok(()) => break,
                Err(error)
                    if error.kind() == io::ErrorKind::AddrInUse
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::select! {
                        biased;
                        _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
                        result = running.quic_retirements.wait() => if let Err(error) = result {
                            let _ = running.shutdown(&[&prepared, &candidate]).await;
                            return Err(error);
                        },
                    }
                    tokio::select! {
                        biased;
                        _ = shutdown.recv() => return running.shutdown(&[&prepared, &candidate]).await,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                    }
                }
                Err(error) => {
                    let _ = running.shutdown(&[&prepared, &candidate]).await;
                    return Err(error);
                }
            }
        }
        watches.activated(&candidate.validated.reload_files);
        if let Some(control) = control.as_ref() {
            control.runtime.resume().await?;
        }
        let mut retired = std::mem::replace(&mut prepared, candidate);
        retired.certificates.shutdown().await;
        println!("Servers ready");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activation_discards_candidate_identity_events_but_preserves_reload_events() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::tempdir().unwrap();
            let config = directory.path().join("config.yaml");
            let cert = directory.path().join("cert.pem");
            let key = directory.path().join("key.pem");
            let trust = directory.path().join("ca.pem");
            let pair = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            std::fs::write(&cert, pair.cert.pem()).unwrap();
            std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
            std::fs::write(&trust, pair.cert.pem()).unwrap();
            std::fs::write(&config, serde_yaml::to_string(&serde_json::json!([
                {"address": "127.0.0.1:18443", "protocol": {"type": "tls", "default_tls_target": {
                    "cert": cert, "key": key, "protocol": {"type": "socks"}
                }}}
            ])).unwrap()).unwrap();
            let paths = [config.to_str().unwrap().to_owned()];
            let (tx, mut changes) = mpsc::channel(1);
            let mut watches = ConfigWatches::new(&paths, tx, false).unwrap();
            let validated = load_validated(&paths, &mut |reload, recovery| {
                assert!(!reload.contains(&cert) && !reload.contains(&key));
                assert!(recovery.contains(&cert) && recovery.contains(&key));
                watches.discovered(reload, recovery);
            })
            .await
            .unwrap();
            // A renewal while preparation is still in progress must not leak into
            // the active reload queue, even if a notifier callback arrives late.
            let late_callback = watches.recovery_tx.clone();
            std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
            while watches.recovery_changes.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(changes.is_empty());
            watches.activated(&validated.reload_files);
            assert!(late_callback.try_send(()).is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(100), watches.changed(&mut changes))
                    .await
                    .is_err()
            );

            for changed in [&config, &trust] {
                watches.discovered(std::slice::from_ref(&trust), &[cert.clone(), key.clone()]);
                let contents = std::fs::read(changed).unwrap();
                std::fs::write(changed, contents).unwrap();
                while changes.is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                watches.activated(std::slice::from_ref(&trust));
                assert!(
                    changes.try_recv().is_ok(),
                    "activation must retain YAML and reload-only dependency events"
                );
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reload_debounce_includes_candidate_recovery_events() {
        let (tx, mut changes) = mpsc::channel(1);
        let mut watches = ConfigWatches::new(&[], tx.clone(), true).unwrap();
        let recovery = watches.recovery_tx.clone();
        let task = tokio::spawn(async move { watches.debounce(&mut changes).await });
        tokio::task::yield_now().await;
        for sender in [tx, recovery] {
            tokio::time::advance(Duration::from_secs(4)).await;
            assert!(!task.is_finished());
            sender.send(()).await.unwrap();
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_dns_rejected_reload_keeps_inherited_guards_without_freezing_live_pool() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let paths = [path.to_str().unwrap().to_owned()];
        std::fs::write(
            &path,
            r#"[{"dns_group":"fake","dns_servers":"udp://127.0.0.1:9","fake_ip":true}]"#,
        )
        .unwrap();
        let live = prepare(&paths, None).await.unwrap();
        let context = live
            .dns
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        context.allocate("before.example", false).unwrap();
        std::fs::write(
            &path,
            r#"[{"dns_group":"ordinary","dns_servers":"udp://198.18.0.5:53"}]"#,
        )
        .unwrap();
        load_validated(&paths, &mut |_, _| {}).await.unwrap();
        let error = prepare(&paths, Some(&live.dns)).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("running configuration until restart")
        );
        context.allocate("after.example", false).unwrap();
    }

    #[tokio::test]
    async fn fake_dns_removed_context_rejects_forwarding_and_override_reload_targets() {
        use serde_json::json;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let paths = [path.to_str().unwrap().to_owned()];
        std::fs::write(
            &path,
            r#"[{"dns_group":"fake","dns_servers":"udp://127.0.0.1:9","fake_ip":true}]"#,
        )
        .unwrap();
        let live = prepare(&paths, None).await.unwrap();
        std::fs::write(&path, "[]").unwrap();
        let removed = prepare(&paths, Some(&live.dns)).await.unwrap();
        assert!(!removed.dns.forbidden_ranges().is_empty());

        for server in [
            json!({"address":"127.0.0.1:1080", "protocol":{"type":"forward", "targets":["198.18.0.5:443"]}}),
            json!({"address":"127.0.0.1:1080", "protocol":{"type":"socks"}, "rules":[{
                "masks":"0.0.0.0/0", "action":"allow", "override_address":"198.18.0.5:443"
            }]}),
        ] {
            std::fs::write(&path, json!([server]).to_string()).unwrap();
            load_validated(&paths, &mut |_, _| {}).await.unwrap();
            let error = prepare(&paths, Some(&removed.dns)).await.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                error
                    .to_string()
                    .contains("running configuration until restart")
            );
        }
    }

    #[tokio::test]
    async fn fake_dns_retained_pools_reject_tun_endpoint_reload_collisions() {
        use serde_json::json;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let paths = [path.to_str().unwrap().to_owned()];
        std::fs::write(
            &path,
            json!([
                {"dns_group":"fake", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{
                    "ipv4_range":"198.18.0.0/29", "ipv6_range":"2001:2::/125", "max_entries":5
                }},
                {"device_name":"tun0", "device_fd":42, "address":"10.99.0.1"},
            ])
            .to_string(),
        )
        .unwrap();
        let live = prepare(&paths, None).await.unwrap();
        let context = live
            .dns
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        let ip = context.allocate("before.example", false).unwrap();
        for config in [
            json!([{ "dns_group":"fake", "dns_servers":"udp://127.0.0.1:9", "fake_ip":false }]),
            json!([]),
        ] {
            std::fs::write(&path, config.to_string()).unwrap();
            let retained = prepare(&paths, Some(&live.dns)).await.unwrap();
            for field in ["address", "destination"] {
                for (endpoint, allowed) in [
                    ("198.18.0.5", false),
                    ("::ffff:198.18.0.5", false),
                    ("2001:2::5", false),
                    ("198.18.0.1", true),
                    ("::ffff:198.18.0.1", true),
                    ("2001:2::1", true),
                    ("10.99.0.1", true),
                ] {
                    let mut tun = json!({"device_name":"tun0", "device_fd":42});
                    tun[field] = endpoint.into();
                    std::fs::write(&path, json!([tun]).to_string()).unwrap();
                    load_validated(&paths, &mut |_, _| {}).await.unwrap();
                    let result = prepare(&paths, Some(&retained.dns)).await;
                    if allowed {
                        result.unwrap();
                    } else {
                        let error = result.err().expect("retained TUN collision accepted");
                        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                        assert!(
                            error.to_string().contains("TUN interface/gateway"),
                            "{error}"
                        );
                    }
                }
            }
        }
        assert_eq!(
            context.restore(ip).unwrap().as_deref(),
            Some("before.example")
        );
        context.allocate("after.example", false).unwrap();
    }

    #[tokio::test]
    async fn fake_dns_terminal_shutdown_closes_all_registries_after_checkpoint_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut registries = Vec::new();
        let mut contexts = Vec::new();
        for index in 0..2 {
            let path = directory.path().join(format!("config-{index}.yaml"));
            let state = directory.path().join(format!("state-{index}.json"));
            std::fs::write(
                &path,
                serde_json::json!([
                    {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"state_file":state}}
                ])
                .to_string(),
            )
            .unwrap();
            let prepared = prepare(&[path.to_str().unwrap().to_owned()], None)
                .await
                .unwrap();
            let context = prepared
                .dns
                .get_by_name("fake")
                .unwrap()
                .fake_dns_context()
                .unwrap();
            context.allocate("before.example", false).unwrap();
            contexts.push(context);
            registries.push(prepared);
        }
        let failed_state = directory.path().join("state-0.json");
        std::fs::remove_file(&failed_state).unwrap();
        std::fs::create_dir(&failed_state).unwrap();
        let marker = std::sync::Arc::new(());
        let owned = marker.clone();
        let mut running = RunningServers::default();
        running.listeners.push(tokio::spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        }));
        assert!(
            running
                .shutdown(&[&registries[0], &registries[1]])
                .await
                .is_err()
        );
        assert_eq!(std::sync::Arc::strong_count(&marker), 1);
        for context in contexts {
            assert!(context.allocate("after.example", false).is_err());
        }
        let snapshot: serde_json::Value = serde_json::from_reader(
            std::fs::File::open(directory.path().join("state-1.json")).unwrap(),
        )
        .unwrap();
        assert!(
            snapshot["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry[0] == "before.example")
        );
    }

    #[tokio::test]
    async fn preparation_preserves_ipv6_scope_ids_and_port_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::fs::write(
            &path,
            "- address: '[fe80::1%2]:8080-8081'\n  protocol: {type: http}\n",
        )
        .unwrap();
        let prepared = prepare(&[path.to_str().unwrap().to_owned()], None)
            .await
            .unwrap();
        let Config::Server(server) = &prepared.validated.configs[0] else {
            panic!()
        };
        let BindLocation::Address(addresses) = &server.bind_location else {
            panic!()
        };
        let resolved: Vec<_> = addresses
            .iter()
            .flat_map(|address| address.to_socket_addrs().unwrap())
            .collect();
        assert_eq!(
            resolved,
            [
                "[fe80::1%2]:8080".parse().unwrap(),
                "[fe80::1%2]:8081".parse().unwrap()
            ]
        );
    }
}
