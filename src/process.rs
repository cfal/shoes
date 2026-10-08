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

async fn load_validated(paths: &[String]) -> io::Result<ValidatedConfigs> {
    let configs = config::load_configs(&paths.to_vec()).await?;
    let (configs, _) = config::convert_cert_paths(configs).await?;
    config::create_server_configs(configs)
}

struct PreparedServers {
    validated: ValidatedConfigs,
    dns: DnsRegistry,
}

async fn prepare(paths: &[String]) -> io::Result<PreparedServers> {
    let mut validated = load_validated(paths).await?;
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
    let dns = dns::build_dns_registry_with_limits(
        std::mem::take(&mut validated.dns_groups),
        validated.global_limits,
    )
    .await?;
    Ok(PreparedServers { validated, dns })
}

#[derive(Default)]
struct RunningServers {
    listeners: Vec<JoinHandle<()>>,
    reporter: Option<resources::ResourceReporter>,
}

impl RunningServers {
    async fn stop(&mut self) {
        for task in &self.listeners {
            task.abort();
        }
        for task in self.listeners.drain(..) {
            let _ = task.await;
        }
        self.reporter = None;
    }

    async fn start(&mut self, prepared: &mut PreparedServers) -> io::Result<()> {
        resources::configure(prepared.validated.global_limits)?;
        self.reporter = Some(resources::ResourceReporter::start());
        for config in &prepared.validated.configs {
            let dns_ref = match config {
                Config::Server(server) => server.dns.as_ref(),
                Config::TunServer(tun) => tun.dns.as_ref(),
                _ => None,
            };
            let resolver = prepared.dns.get_for_server(dns_ref);
            match crate::tcp::tcp_server::start_servers(config.clone(), resolver).await {
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
        for task in &self.listeners {
            task.abort();
        }
    }
}

fn watch(paths: &[String], tx: mpsc::Sender<()>) -> io::Result<RecommendedWatcher> {
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
        resolve_watch_path(&path, &mut files, &mut 0)?;
    }
    let directories: HashSet<_> = files
        .iter()
        .filter_map(|path| path.parent()?.ancestors().find(|parent| parent.is_dir()))
        .map(PathBuf::from)
        .collect();
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
                return Err(io::Error::other(error));
            }
            log::warn!(
                "Could not watch intermediate config directory {}: {error}",
                directory.display()
            );
        }
    }
    Ok(watcher)
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
                files.insert(resolved.clone());
                let target = resolved
                    .parent()
                    .unwrap()
                    .join(std::fs::read_link(&resolved)?);
                resolved = resolve_watch_path(&target, files, symlinks)?;
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
        load_validated(&paths).await?;
        println!("Configuration valid");
        return Ok(());
    }
    let mut shutdown = ShutdownSignals::new()?;
    let mut reload = ReloadSignal::new()?;
    let (change_tx, mut changes) = mpsc::channel(1);
    let mut _watcher = if no_reload {
        None
    } else {
        Some(watch(&paths, change_tx.clone())?)
    };
    let mut prepared = tokio::select! {
        biased;
        _ = shutdown.recv() => return Ok(()),
        result = prepare(&paths) => result?,
    };
    let mut running = RunningServers::default();
    tokio::select! {
        biased;
        _ = shutdown.recv() => { running.stop().await; return Ok(()); }
        result = running.start(&mut prepared) => result?,
    }
    loop {
        let debounce = tokio::select! {
            biased;
            _ = shutdown.recv() => { running.stop().await; return Ok(()); }
            _ = reload.recv() => false,
            _ = changes.recv() => true,
        };
        if debounce {
            tokio::select! {
                biased;
                _ = shutdown.recv() => { running.stop().await; return Ok(()); }
                _ = reload.recv() => {}
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
        }
        while changes.try_recv().is_ok() {}
        if !no_reload {
            // A symlink may now point outside the directories watched by the previous generation.
            match watch(&paths, change_tx.clone()) {
                Ok(watcher) => _watcher = Some(watcher),
                Err(error) => log::warn!("Could not refresh config watches: {error}"),
            }
        }
        let candidate = tokio::select! {
            biased;
            _ = shutdown.recv() => { running.stop().await; return Ok(()); }
            result = prepare(&paths) => result,
        };
        let mut candidate = match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("Reload rejected; current servers retained: {error}");
                continue;
            }
        };
        running.stop().await;
        // Quinn may retain its UDP socket briefly while closing old connections.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let result = tokio::select! {
                biased;
                _ = shutdown.recv() => { running.stop().await; return Ok(()); }
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
                        _ = shutdown.recv() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
        drop(std::mem::replace(&mut prepared, candidate));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preparation_preserves_ipv6_scope_ids_and_port_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::fs::write(
            &path,
            "- address: '[fe80::1%2]:8080-8081'\n  protocol: {type: http}\n",
        )
        .unwrap();
        let prepared = prepare(&[path.to_str().unwrap().to_owned()]).await.unwrap();
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
