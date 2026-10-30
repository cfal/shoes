//! Delivery of immutable rules, with optional persistent caching.
mod bootstrap;
mod http;
mod install;

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::config::{Config, GlobalLimits, ValidatedConfigs};
use crate::dns::DnsRegistry;
use crate::rule_set::{MemorySource, MemorySources, RuleInputs, RuleSource};
use crate::rules::invalid;
use install::Install;
use tokio::time::{Instant, timeout};

const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Limits {
    bytes: u64,
    connect: Duration,
    idle: Duration,
    overall: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(10),
            overall: Duration::from_secs(120),
        }
    }
}

pub(crate) use bootstrap::prepare as bootstrap;
pub(crate) use install::{cache_file, cache_lease, create_cache_directory};

struct Staged {
    install: Install,
    digest: blake3::Hash,
}

async fn stage(
    source: &RuleSource,
    install: Install,
    dns: &DnsRegistry,
    global: GlobalLimits,
    limits: Limits,
    state: &mut http::DownloadState,
) -> io::Result<Staged> {
    let mut file = tokio::fs::File::from_std(install.file.try_clone()?);
    let digest = download(source, dns, global, &mut file, limits, state).await?;
    let validation_source = source.clone();
    let file = install.file.try_clone()?;
    crate::config::blocking_compile(move || {
        crate::rule_set::validate_file(&validation_source, file)
            .map_err(|_| invalid("download failed Shoes rule validation"))
    })
    .await?;
    Ok(Staged { install, digest })
}

async fn download(
    source: &RuleSource,
    dns: &DnsRegistry,
    global: GlobalLimits,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    limits: Limits,
    state: &mut http::DownloadState,
) -> io::Result<blake3::Hash> {
    crate::control::url_test::BACKGROUND
        .scope(
            (),
            timeout(
                limits.overall,
                http::download(source, dns, global, output, limits, state),
            ),
        )
        .await
        .map_err(|_| invalid("overall rule download deadline exceeded"))?
}

async fn download_memory(
    source: &RuleSource,
    previous: Option<&MemorySource>,
    dns: &DnsRegistry,
    global: GlobalLimits,
    state: &mut http::DownloadState,
) -> io::Result<Option<std::sync::Arc<MemorySource>>> {
    let mut bytes = Vec::new();
    let digest = download(source, dns, global, &mut bytes, Limits::default(), state).await?;
    if let Some(previous) = previous
        && previous.digest == digest
        && previous.matches(source)?
    {
        return Ok(None);
    }
    let source = source.clone();
    crate::config::blocking_compile(move || {
        crate::rule_set::load_memory(source, bytes, digest)
            .map(|loaded| Some(std::sync::Arc::new(loaded)))
            .map_err(|_| invalid("download failed Shoes rule validation"))
    })
    .await
}

async fn validate_staged(
    configs: Vec<Config>,
    path: &Path,
    install: &Install,
) -> io::Result<ValidatedConfigs> {
    validate_inputs(
        configs,
        RuleInputs {
            file: Some((path.to_owned(), install.file.try_clone()?)),
            ..Default::default()
        },
    )
    .await
}

async fn validate_inputs(configs: Vec<Config>, inputs: RuleInputs) -> io::Result<ValidatedConfigs> {
    let validated = crate::config::compile_configs_with_inputs(configs, inputs)
        .await
        .map_err(|error| {
            invalid(format!(
                "download rejected by whole configuration validation: {error}"
            ))
        })?;
    tokio::task::spawn_blocking(move || {
        if validated.catalog.is_some() {
            crate::control::validation::validate_resources(&validated)?;
        }
        Ok(validated)
    })
    .await
    .map_err(io::Error::other)?
}

struct Scheduled {
    identity: serde_json::Value,
    source: RuleSource,
    due: Instant,
    failures: u32,
    download: http::DownloadState,
}

async fn refresh_source(
    source: &RuleSource,
    configs: &[Config],
    dns: &DnsRegistry,
    global: GlobalLimits,
    state: &mut http::DownloadState,
) -> io::Result<bool> {
    let install = Install::open_async(&source.path).await?;
    let Staged { install, digest } =
        stage(source, install, dns, global, Limits::default(), state).await?;
    let (install, unchanged) = install.check_unchanged(digest).await?;
    if unchanged {
        return Ok(false);
    }
    validate_staged(configs.to_vec(), &source.path, &install).await?;
    Ok(install.finish_async(digest).await?.changed())
}

async fn refresh_memory(
    source: &RuleSource,
    configs: &[Config],
    memory: &mut MemorySources,
    dns: &DnsRegistry,
    global: GlobalLimits,
    state: &mut http::DownloadState,
) -> io::Result<bool> {
    let Some(loaded) = download_memory(
        source,
        memory.get(&source.path).map(AsRef::as_ref),
        dns,
        global,
        state,
    )
    .await?
    else {
        return Ok(false);
    };
    let mut candidate = memory.clone();
    candidate.insert(source.path.clone(), loaded);
    validate_inputs(
        configs.to_vec(),
        RuleInputs {
            file: None,
            memory: candidate.clone(),
        },
    )
    .await?;
    *memory = candidate;
    Ok(true)
}

/// Polled by the process select loop. Dropping that future cancels the HTTP
/// connection and removes its stage; no detached task retains a generation.
pub(crate) struct Refresh {
    configs: Vec<Config>,
    scheduled: Vec<Scheduled>,
    pub(crate) memory: MemorySources,
    persistent: bool,
}

impl Refresh {
    pub(crate) fn new(
        configs: Vec<Config>,
        sources: &[RuleSource],
        memory: MemorySources,
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        let persistent = crate::rule_set::cache_directory(&configs)?.is_some();
        let mut scheduled = Vec::new();
        for source in sources {
            let identity = serde_json::to_value(source)?;
            let prior = previous.and_then(|previous| {
                previous
                    .scheduled
                    .iter()
                    .find(|item| item.source.path == source.path && item.identity == identity)
            });
            let interval = source.interval()?;
            let due = if let Some(prior) = prior {
                prior.due
            } else if let Some(loaded) = memory.get(&source.path) {
                Instant::now() + interval.saturating_sub(loaded.updated.elapsed())
            } else {
                let remaining = std::fs::metadata(&source.path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|mtime| SystemTime::now().duration_since(mtime).ok())
                    .map_or(Duration::ZERO, |age| interval.saturating_sub(age));
                Instant::now() + remaining
            };
            scheduled.push(Scheduled {
                identity,
                source: source.clone(),
                due,
                failures: prior.map_or(0, |item| item.failures),
                download: prior
                    .map_or_else(http::DownloadState::default, |item| item.download.clone()),
            });
        }
        Ok(Self {
            configs,
            scheduled,
            memory,
            persistent,
        })
    }

    pub(crate) async fn changed(&mut self, dns: &DnsRegistry, global: GlobalLimits) {
        loop {
            let Some(item) = self.scheduled.iter_mut().min_by_key(|item| item.due) else {
                std::future::pending::<()>().await;
                return;
            };
            tokio::time::sleep_until(item.due).await;
            let result = if self.persistent {
                refresh_source(&item.source, &self.configs, dns, global, &mut item.download).await
            } else {
                refresh_memory(
                    &item.source,
                    &self.configs,
                    &mut self.memory,
                    dns,
                    global,
                    &mut item.download,
                )
                .await
            };
            let interval = item.source.interval().expect("validated interval");
            let delay = match &result {
                Ok(_) => {
                    item.failures = 0;
                    interval
                }
                Err(_) => {
                    item.failures = (item.failures + 1).min(12);
                    Duration::from_secs(5 * (1u64 << item.failures.min(10)))
                        .min(interval)
                        .min(Duration::from_secs(3600))
                }
            };
            let jitter = 0.9 + rand::random::<f64>() * 0.2;
            item.due = Instant::now() + delay.mul_f64(jitter);
            match result {
                Ok(changed) => {
                    log::info!(
                        "Remote rules {}: {}",
                        if changed { "updated" } else { "unchanged" },
                        item.source.path.display()
                    );
                    if changed {
                        return;
                    }
                }
                Err(error) => log::warn!(
                    "Remote rules retained for {}: {error}",
                    item.source.path.display()
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests;
