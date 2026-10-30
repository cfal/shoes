//! Delivery of immutable rules, with optional persistent caching.
mod bootstrap;
mod http;
mod install;

use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, GlobalLimits, ValidatedConfigs};
use crate::dns::DnsRegistry;
use crate::rule_set::{MemorySource, MemorySources, RuleInputs, RuleSource};
use crate::rules::invalid;
use install::Install;
use tokio::time::{Instant, timeout};

const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Limits {
    connect: Duration,
    idle: Duration,
    overall: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(10),
            overall: Duration::from_secs(120),
        }
    }
}

pub(crate) use bootstrap::prepare as bootstrap;
pub(crate) use install::{CacheLease, cache_file, cache_lease, create_cache_directory};

struct Downloaded {
    bytes: Vec<u8>,
    loaded: Arc<MemorySource>,
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

async fn download_source(
    source: &RuleSource,
    previous: Option<&Arc<MemorySource>>,
    dns: &DnsRegistry,
    global: GlobalLimits,
    limits: Limits,
    state: &mut http::DownloadState,
) -> io::Result<Downloaded> {
    let mut bytes = Vec::new();
    let digest = download(source, dns, global, &mut bytes, limits, state).await?;
    if let Some(previous) = previous
        && previous.digest == digest
        && previous.matches(source)?
    {
        return Ok(Downloaded {
            bytes,
            loaded: previous.clone(),
        });
    }
    let source = source.clone();
    crate::config::blocking_compile(move || {
        let loaded = crate::rule_set::load_memory(&source, &bytes, digest)
            .map_err(|_| invalid("download failed Shoes rule validation"))?;
        Ok(Downloaded {
            bytes,
            loaded: Arc::new(loaded),
        })
    })
    .await
}

fn load_cached(source: &RuleSource, lease: Option<&CacheLease>) -> io::Result<Arc<MemorySource>> {
    let file = cache_file(&source.path, lease)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_BYTES {
        return Err(invalid("rule source input exceeds 64 MiB"));
    }
    let interval = source.interval()?;
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .unwrap_or(interval);
    let mut bytes = Vec::new();
    file.take(metadata.len() + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(invalid("rule cache changed while reading"));
    }
    let mut loaded = crate::rule_set::load_memory(source, &bytes, blake3::hash(&bytes))?;
    let now = std::time::Instant::now();
    loaded.updated = now.checked_sub(age).unwrap_or(now - interval);
    Ok(Arc::new(loaded))
}

async fn save_cache(
    source: &RuleSource,
    bytes: Vec<u8>,
    digest: blake3::Hash,
    lease: Option<Arc<CacheLease>>,
) {
    if let Err(error) = Install::save(&source.path, bytes, digest, lease).await {
        log::warn!(
            "Remote rule cache not saved for {}: {error}; validated rules remain available in memory",
            source.path.display()
        );
    }
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
    memory: &mut MemorySources,
    dns: &DnsRegistry,
    global: GlobalLimits,
    state: &mut http::DownloadState,
    lease: Option<Arc<CacheLease>>,
) -> io::Result<bool> {
    let Downloaded { bytes, loaded } = download_source(
        source,
        memory.get(&source.path),
        dns,
        global,
        Limits::default(),
        state,
    )
    .await?;
    let changed = memory
        .get(&source.path)
        .is_none_or(|previous| !Arc::ptr_eq(previous, &loaded));
    if changed {
        let mut candidate = memory.clone();
        candidate.insert(source.path.clone(), loaded.clone());
        validate_inputs(
            configs.to_vec(),
            RuleInputs {
                memory: Some(candidate),
            },
        )
        .await?;
        memory.insert(source.path.clone(), loaded.clone());
    }
    if crate::rule_set::cache_directory(configs)?.is_some() {
        // Identical downloads also retry persistence after a previous cache failure.
        save_cache(source, bytes, loaded.digest, lease).await;
    }
    Ok(changed)
}

/// Polled by the process select loop. Dropping that future cancels the HTTP
/// connection and removes its stage; no detached task retains a generation.
pub(crate) struct Refresh {
    configs: Vec<Config>,
    scheduled: Vec<Scheduled>,
    pub(crate) memory: MemorySources,
    cache_lease: Option<Arc<CacheLease>>,
}

impl Refresh {
    pub(crate) fn new(
        configs: Vec<Config>,
        sources: &[RuleSource],
        memory: MemorySources,
        previous: Option<&Self>,
        cache_lease: Option<Arc<CacheLease>>,
    ) -> io::Result<Self> {
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
                return Err(invalid("remote rules unavailable in memory"));
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
            cache_lease,
        })
    }

    pub(crate) async fn changed(&mut self, dns: &DnsRegistry, global: GlobalLimits) {
        loop {
            let Some(item) = self.scheduled.iter_mut().min_by_key(|item| item.due) else {
                std::future::pending::<()>().await;
                return;
            };
            tokio::time::sleep_until(item.due).await;
            let result = refresh_source(
                &item.source,
                &self.configs,
                &mut self.memory,
                dns,
                global,
                &mut item.download,
                self.cache_lease.clone(),
            )
            .await;
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
