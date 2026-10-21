use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::address::NetLocation;
use crate::config::{self, BindLocation, Config, ValidatedConfigs};
use crate::dns::{self, DnsRegistry};
use crate::option_util::OneOrSome;
use crate::resources;

async fn load_validated(
    paths: &[String],
    discovered: &mut (dyn FnMut(&[PathBuf]) + Send),
) -> io::Result<ValidatedConfigs> {
    let mut configs = config::load_configs(&paths.to_vec()).await?;
    discovered(&crate::rule_set::dependencies(&mut configs)?);
    let (configs, _) = config::convert_cert_paths(configs).await?;
    config::compile_configs(configs).await
}

struct PreparedServers {
    validated: ValidatedConfigs,
    dns: DnsRegistry,
    #[cfg(unix)]
    wireguard: crate::wireguard::Prepared,
}

#[cfg(test)]
async fn prepare(paths: &[String], previous: Option<&DnsRegistry>) -> io::Result<PreparedServers> {
    prepare_tracking(paths, previous, &mut |_| {}).await
}

async fn prepare_tracking(
    paths: &[String],
    previous: Option<&DnsRegistry>,
    discovered: &mut (dyn FnMut(&[PathBuf]) + Send),
) -> io::Result<PreparedServers> {
    let mut validated = load_validated(paths, discovered).await?;
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
    let dns = dns::build_dns_registry_for_runtime(
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
    Ok(PreparedServers {
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

    async fn shutdown(&mut self, registries: &[&DnsRegistry]) -> io::Result<()> {
        self.stop().await;
        let mut result = Ok(());
        for registry in registries {
            if let Err(error) = registry.shutdown_checkpoint().await {
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
        println!("Servers ready");
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

fn watch<P: AsRef<Path>>(paths: &[P], tx: mpsc::Sender<()>) -> io::Result<RecommendedWatcher> {
    let mut files = HashSet::new();
    let mut required_directories = HashSet::new();
    for path in paths {
        let path = std::path::absolute(path)?;
        if let Some(parent) = path.parent() {
            required_directories.insert(parent.to_path_buf());
        }
        if let Ok(canonical) = std::fs::canonicalize(&path) {
            if let Some(parent) = canonical.parent() {
                required_directories.insert(parent.to_path_buf());
            }
            files.insert(canonical);
        }
        files.insert(path.clone());
        if let Err(error) = resolve_watch_path(&path, &mut files, &mut 0) {
            log::warn!(
                "Could not resolve watch path {}: {error}; retaining lexical and discovered paths for recovery",
                path.display()
            );
        }
    }
    let required_directories: HashSet<_> = required_directories
        .iter()
        .map(|path| watch_directory(path))
        .collect();
    let directories: HashSet<_> = files
        .iter()
        .filter_map(|path| path.parent()?.ancestors().find(|parent| parent.is_dir()))
        .map(watch_directory)
        .collect();
    let direct_files: HashSet<_> = files
        .iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .filter(|path| path.is_file())
        .collect();
    files.extend(direct_files.iter().cloned());
    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
            Ok(event)
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) && event.paths.iter().any(|path| files.contains(path)) =>
            {
                let _ = tx.try_send(());
            }
            Err(error) => log::warn!("Config watcher failed: {error}"),
            _ => {}
        })
        .map_err(io::Error::other)?;
    for directory in directories {
        if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
            if required_directories.contains(&directory) {
                if !matches!(&error.kind, notify::ErrorKind::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)
                {
                    return Err(io::Error::other(error));
                }
                log::warn!(
                    "Could not watch config directory {}: {error}; using file watches, atomic replacements may be missed",
                    directory.display()
                );
            } else {
                log::warn!(
                    "Could not watch intermediate config directory {}: {error}",
                    directory.display()
                );
            }
        }
    }
    for file in direct_files {
        if let Err(error) = watcher.watch(&file, RecursiveMode::NonRecursive) {
            let missing = match &error.kind {
                notify::ErrorKind::PathNotFound => true,
                notify::ErrorKind::Io(error) => error.kind() == io::ErrorKind::NotFound,
                _ => false,
            };
            if !missing {
                log::warn!("Could not watch config file {}: {error}", file.display());
            }
        }
    }
    Ok(watcher)
}

struct ConfigWatches {
    configs: Vec<PathBuf>,
    active: Vec<PathBuf>,
    candidate: Vec<PathBuf>,
    watcher: Option<RecommendedWatcher>,
    tx: mpsc::Sender<()>,
    disabled: bool,
}

impl ConfigWatches {
    fn new(paths: &[String], tx: mpsc::Sender<()>, disabled: bool) -> io::Result<Self> {
        let mut state = Self {
            configs: paths.iter().map(PathBuf::from).collect(),
            active: Vec::new(),
            candidate: Vec::new(),
            watcher: None,
            tx,
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
        }
        Ok(())
    }

    fn discovered(&mut self, paths: &[PathBuf]) {
        self.candidate = paths.to_vec();
        if let Err(error) = self.refresh() {
            log::warn!("Could not refresh rule/config watches: {error}");
        }
    }

    fn activated(&mut self, paths: &[PathBuf]) {
        self.active = paths.to_vec();
        self.candidate.clear();
        if let Err(error) = self.refresh() {
            log::warn!("Could not refresh rule/config watches: {error}");
        }
    }
}

fn watch_directory(path: &Path) -> PathBuf {
    // inotify keeps one event path per inode; register directory aliases only once.
    #[cfg(unix)]
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    path.to_path_buf()
}

fn resolve_watch_path(
    path: &Path,
    files: &mut HashSet<PathBuf>,
    symlinks: &mut usize,
) -> io::Result<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        if component == Component::ParentDir {
            resolved.pop();
            continue;
        }
        resolved.push(component);
        match std::fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                *symlinks += 1;
                if *symlinks > 40 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many config symlinks",
                    ));
                }
                let target = resolved
                    .parent()
                    .unwrap()
                    .join(std::fs::read_link(&resolved)?);
                if cfg!(target_os = "macos") && resolved.parent() == Some(Path::new("/")) {
                    // System-volume links cannot be retargeted; tracking them subscribes
                    // FSEvents to the entire filesystem even with NonRecursive watches.
                    resolved = resolve_watch_path(&target, &mut HashSet::new(), symlinks)?;
                } else {
                    files.insert(resolved.clone());
                    resolved = resolve_watch_path(&target, files, symlinks)?;
                }
            }
            // Retain missing components so creating a target or its parent triggers another reload.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                files.insert(resolved.clone());
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
    }
    files.insert(resolved.clone());
    Ok(resolved)
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
        load_validated(&paths, &mut |_| {}).await?;
        println!("Configuration valid");
        return Ok(());
    }
    let mut shutdown = ShutdownSignals::new()?;
    let mut reload = ReloadSignal::new()?;
    let (change_tx, mut changes) = mpsc::channel(1);
    let mut watches = ConfigWatches::new(&paths, change_tx, no_reload)?;
    let mut discovered = |paths: &[PathBuf]| watches.discovered(paths);
    let mut prepared = tokio::select! {
        biased;
        _ = shutdown.recv() => return Ok(()),
        result = prepare_tracking(&paths, None, &mut discovered) => result?,
    };
    watches.activated(&prepared.validated.rule_files);
    let mut running = RunningServers::default();
    tokio::select! {
        biased;
        _ = shutdown.recv() => return running.shutdown(&[&prepared.dns]).await,
        result = running.start(&mut prepared) => if let Err(error) = result {
            let _ = running.shutdown(&[&prepared.dns]).await;
            return Err(error);
        },
    }
    loop {
        let debounce = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared.dns]).await,
            error = running.tun_failure() => {
                let _ = running.shutdown(&[&prepared.dns]).await;
                return Err(error);
            },
            _ = reload.recv() => false,
            _ = changes.recv() => true,
        };
        if debounce {
            tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown(&[&prepared.dns]).await,
                error = running.tun_failure() => {
                    let _ = running.shutdown(&[&prepared.dns]).await;
                    return Err(error);
                },
                _ = reload.recv() => {}
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
        }
        while changes.try_recv().is_ok() {}
        // Refresh symlink targets even when the candidate's YAML is invalid.
        if let Err(error) = watches.refresh() {
            log::warn!("Could not refresh config watches: {error}");
        }
        let mut discovered = |paths: &[PathBuf]| watches.discovered(paths);
        let candidate = tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared.dns]).await,
            error = running.tun_failure() => {
                let _ = running.shutdown(&[&prepared.dns]).await;
                return Err(error);
            },
            result = prepare_tracking(&paths, Some(&prepared.dns), &mut discovered) => result,
        };
        let mut candidate = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("Reload rejected; current servers retained: {error}");
                continue;
            }
        };
        running.stop().await;
        if let Err(error) = prepared.dns.checkpoint().await {
            log::warn!("Reload Fake DNS checkpoint failed; continuing reload: {error}");
        }
        tokio::select! {
            biased;
            _ = shutdown.recv() => return running.shutdown(&[&prepared.dns, &candidate.dns]).await,
            result = running.quic_retirements.wait() => if let Err(error) = result {
                let _ = running.shutdown(&[&prepared.dns, &candidate.dns]).await;
                return Err(error);
            },
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let result = tokio::select! {
                biased;
                _ = shutdown.recv() => return running.shutdown(&[&prepared.dns, &candidate.dns]).await,
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
                        _ = shutdown.recv() => return running.shutdown(&[&prepared.dns, &candidate.dns]).await,
                        result = running.quic_retirements.wait() => if let Err(error) = result {
                            let _ = running.shutdown(&[&prepared.dns, &candidate.dns]).await;
                            return Err(error);
                        },
                    }
                    tokio::select! {
                        biased;
                        _ = shutdown.recv() => return running.shutdown(&[&prepared.dns, &candidate.dns]).await,
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                    }
                }
                Err(error) => {
                    let _ = running.shutdown(&[&prepared.dns, &candidate.dns]).await;
                    return Err(error);
                }
            }
        }
        watches.activated(&candidate.validated.rule_files);
        drop(std::mem::replace(&mut prepared, candidate));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        load_validated(&paths, &mut |_| {}).await.unwrap();
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
            load_validated(&paths, &mut |_| {}).await.unwrap();
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
                    load_validated(&paths, &mut |_| {}).await.unwrap();
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
                .shutdown(&[&registries[0].dns, &registries[1].dns])
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

    #[cfg(unix)]
    #[tokio::test]
    async fn directory_aliases_preserve_missing_target_notifications() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join("alias")).unwrap();
        let existing = root.join("alias/existing.yaml");
        std::fs::write(&existing, "existing").unwrap();
        let missing = target.join("missing.yaml");
        let (tx, mut events) = mpsc::channel(1);
        let _watcher = watch(
            &[
                existing.to_str().unwrap().to_owned(),
                missing.to_str().unwrap().to_owned(),
            ],
            tx,
        )
        .unwrap();
        std::fs::write(&missing, "created").unwrap();
        tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_symlinks_do_not_add_root_directory_watches() {
        let mut files = HashSet::new();
        resolve_watch_path(Path::new("/var/db/config.yaml"), &mut files, &mut 0).unwrap();
        assert!(files.contains(Path::new("/private/var/db/config.yaml")));
        assert!(!files.contains(Path::new("/var")));
        assert!(!files.contains(Path::new("/private/var")));
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

    #[cfg(unix)]
    #[test]
    fn watch_paths_include_missing_targets_and_symlinked_parents() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("targets")).unwrap();
        std::os::unix::fs::symlink("targets", root.join("alias")).unwrap();
        std::os::unix::fs::symlink("alias/missing/config.yaml", root.join("config.yaml")).unwrap();
        let mut files = HashSet::new();
        resolve_watch_path(&root.join("config.yaml"), &mut files, &mut 0).unwrap();
        for path in [
            "config.yaml",
            "alias",
            "targets/missing",
            "targets/missing/config.yaml",
        ] {
            assert!(files.contains(&root.join(path)), "missing {path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn watch_paths_reject_symlink_cycles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::os::unix::fs::symlink("config.yaml", &path).unwrap();
        assert_eq!(
            resolve_watch_path(&path, &mut HashSet::new(), &mut 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
