//! Staged delivery of immutable rule files. No updater state enters forwarding.
mod bootstrap;
mod http;
mod install;

use std::collections::HashMap;
use std::io;
use std::time::{Duration, SystemTime};

use crate::config::{Config, GlobalLimits, ValidatedConfigs};
use crate::dns::DnsRegistry;
use crate::rule_set::RuleSource;
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
    source: RuleSource,
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
    let digest = crate::control::url_test::BACKGROUND
        .scope(
            (),
            timeout(
                limits.overall,
                http::download(source, dns, global, &mut file, limits, state),
            ),
        )
        .await
        .map_err(|_| invalid("overall rule download deadline exceeded"))??;
    let validation_source = source.clone();
    let file = install.file.try_clone()?;
    crate::config::blocking_compile(move || {
        crate::rule_set::validate_file(&validation_source, file)
            .map_err(|_| invalid("download failed Shoes rule validation"))
    })
    .await?;
    Ok(Staged {
        source: source.clone(),
        install,
        digest,
    })
}

async fn validate_staged(configs: Vec<Config>, staged: &[Staged]) -> io::Result<ValidatedConfigs> {
    let inputs = staged
        .iter()
        .map(|item| Ok((item.source.path.clone(), item.install.file.try_clone()?)))
        .collect::<io::Result<HashMap<_, _>>>()?;
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
    let mut staged = stage(source, install, dns, global, Limits::default(), state).await?;
    let (install, unchanged) = staged.install.check_unchanged(staged.digest).await?;
    staged.install = install;
    if unchanged {
        return Ok(false);
    }
    validate_staged(configs.to_vec(), std::slice::from_ref(&staged)).await?;
    Ok(staged.install.finish_async(staged.digest).await?.changed())
}

/// Polled by the process select loop. Dropping that future cancels the HTTP
/// connection and removes its stage; no detached task retains a generation.
pub(crate) struct Refresh {
    configs: Vec<Config>,
    scheduled: Vec<Scheduled>,
}

impl Refresh {
    pub(crate) fn new(
        configs: Vec<Config>,
        sources: &[RuleSource],
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        let mut scheduled = Vec::new();
        for source in sources {
            let identity = serde_json::to_value(source)?;
            let prior = previous.and_then(|previous| {
                previous
                    .scheduled
                    .iter()
                    .find(|item| item.identity == identity)
            });
            let interval = source.interval()?;
            let remaining = std::fs::metadata(&source.path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mtime| SystemTime::now().duration_since(mtime).ok())
                .map_or(Duration::ZERO, |age| interval.saturating_sub(age));
            scheduled.push(Scheduled {
                identity,
                source: source.clone(),
                due: prior.map_or_else(|| Instant::now() + remaining, |item| item.due),
                failures: prior.map_or(0, |item| item.failures),
                download: prior
                    .map_or_else(http::DownloadState::default, |item| item.download.clone()),
            });
        }
        Ok(Self { configs, scheduled })
    }

    pub(crate) async fn changed(&mut self, dns: &DnsRegistry, global: GlobalLimits) {
        loop {
            let Some(item) = self.scheduled.iter_mut().min_by_key(|item| item.due) else {
                std::future::pending::<()>().await;
                return;
            };
            tokio::time::sleep_until(item.due).await;
            let result =
                refresh_source(&item.source, &self.configs, dns, global, &mut item.download).await;
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
