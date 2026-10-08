use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{self, Config, ValidatedConfigs};
use crate::dns::{self, DnsRegistry};
use crate::resources;

async fn load_validated(paths: &[String]) -> io::Result<ValidatedConfigs> {
    let configs = config::load_configs(&paths.to_vec()).await?;
    let (configs, _) = config::convert_cert_paths(configs).await?;
    config::create_server_configs(configs)
}

struct Prepared {
    validated: ValidatedConfigs,
    dns: DnsRegistry,
}

async fn prepare(paths: &[String]) -> io::Result<Prepared> {
    let mut validated = load_validated(paths).await?;
    for config in &mut validated.configs {
        if let Config::Server(server) = config
            && let config::BindLocation::Address(addresses) = &server.bind_location
        {
            let addresses = addresses.clone();
            let resolved = tokio::task::spawn_blocking(move || {
                let mut resolved = Vec::new();
                for address in addresses.iter() {
                    for address in address.to_socket_addrs()? {
                        resolved.push(
                            crate::address::NetLocation::from_ip_addr(address.ip(), address.port())
                                .into(),
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
            server.bind_location =
                config::BindLocation::Address(crate::option_util::OneOrSome::Some(resolved));
        }
    }
    let dns = dns::build_dns_registry(std::mem::take(&mut validated.dns_groups)).await?;
    Ok(Prepared { validated, dns })
}

#[derive(Default)]
struct Running {
    listeners: Vec<JoinHandle<()>>,
    reporter: Option<resources::ResourceReporter>,
}

impl Running {
    async fn stop(&mut self) {
        for task in &self.listeners {
            task.abort();
        }
        for task in self.listeners.drain(..) {
            let _ = task.await;
        }
        self.reporter = None;
    }

    async fn start(&mut self, prepared: &mut Prepared) -> io::Result<()> {
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

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.listeners {
            task.abort();
        }
    }
}

fn watch(paths: &[String], tx: mpsc::Sender<()>) -> io::Result<RecommendedWatcher> {
    let files: HashSet<PathBuf> = paths
        .iter()
        .map(|path| std::path::absolute(path))
        .collect::<io::Result<_>>()?;
    let directories: HashSet<_> = files
        .iter()
        .filter_map(|path| path.parent().map(PathBuf::from))
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
        watcher
            .watch(&directory, RecursiveMode::NonRecursive)
            .map_err(io::Error::other)?;
    }
    Ok(watcher)
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

    async fn recv(&mut self) -> i32 {
        tokio::select! {
            _ = self.interrupt.recv() => 130,
            _ = self.terminate.recv() => 143,
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
    async fn recv(&mut self) -> i32 {
        self.0.recv().await;
        130
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

pub async fn run(paths: Vec<String>, dry_run: bool, no_reload: bool) -> io::Result<i32> {
    if dry_run {
        load_validated(&paths).await?;
        println!("Configuration valid");
        return Ok(0);
    }
    let mut shutdown = ShutdownSignals::new()?;
    let mut reload = ReloadSignal::new()?;
    let (change_tx, mut changes) = mpsc::channel(1);
    let _watcher = if no_reload {
        None
    } else {
        Some(watch(&paths, change_tx.clone())?)
    };
    let mut prepared = tokio::select! {
        biased;
        code = shutdown.recv() => return Ok(code),
        result = prepare(&paths) => result?,
    };
    let mut running = Running::default();
    tokio::select! {
        biased;
        code = shutdown.recv() => { running.stop().await; return Ok(code); }
        result = running.start(&mut prepared) => result?,
    }
    loop {
        let debounce = tokio::select! {
            biased;
            code = shutdown.recv() => { running.stop().await; return Ok(code); }
            _ = reload.recv() => false,
            _ = changes.recv() => true,
        };
        if debounce {
            tokio::select! {
                biased;
                code = shutdown.recv() => { running.stop().await; return Ok(code); }
                _ = reload.recv() => {}
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
        }
        while changes.try_recv().is_ok() {}
        let candidate = tokio::select! {
            biased;
            code = shutdown.recv() => { running.stop().await; return Ok(code); }
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
                code = shutdown.recv() => { running.stop().await; return Ok(code); }
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
                        code = shutdown.recv() => return Ok(code),
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                }
                Err(error) => return Err(error),
            }
        }
        drop(std::mem::replace(&mut prepared, candidate));
    }
}
