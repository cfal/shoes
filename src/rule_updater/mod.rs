//! Staged delivery of immutable rule files. No updater state enters forwarding.
mod http;
mod install;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
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

pub(crate) use install::cache_file;

struct Staged {
    source: RuleSource,
    install: Install,
    digest: blake3::Hash,
}

async fn stage(
    source: &RuleSource,
    dns: &DnsRegistry,
    global: GlobalLimits,
    limits: Limits,
) -> io::Result<Staged> {
    let mut install = Install::open(&source.path)?;
    let (_, digest) = crate::control::url_test::BACKGROUND
        .scope(
            (),
            timeout(
                limits.overall,
                http::download(source, dns, global, &mut install.file, limits),
            ),
        )
        .await
        .map_err(|_| invalid("overall rule download deadline exceeded"))??;
    let validation_source = source.clone();
    let file = install.file.try_clone()?;
    crate::config::blocking_compile(move || {
        let predicate = crate::rule_set::validate_file(&validation_source, file)
            .map_err(|_| invalid("download failed Shoes rule validation"))?;
        if matches!(predicate.kind, crate::rules::Kind::Constant(false)) {
            return Err(invalid("refusing an empty remote rule set"));
        }
        Ok(())
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
        .map_err(|_| invalid("download rejected by whole configuration validation"))?;
    tokio::task::spawn_blocking(move || {
        if validated.catalog.is_some() {
            crate::control::validation::validate_resources(&validated)?;
        }
        Ok(validated)
    })
    .await
    .map_err(io::Error::other)?
}

pub(crate) async fn prepare(
    mut configs: Vec<Config>,
    previous: Option<&DnsRegistry>,
    control: &mut Option<crate::control::runtime::ControlService>,
) -> io::Result<ValidatedConfigs> {
    let sources = crate::rule_set::remote_sources(&mut configs)?;
    if sources.is_empty() {
        return crate::config::compile_configs(configs).await;
    }
    let initial_error = match crate::config::compile_configs(configs.clone()).await {
        Ok(validated) => return Ok(validated),
        Err(error) => error,
    };
    let missing = crate::config::blocking_compile(move || {
        Ok(sources
            .into_iter()
            .filter(|source| {
                cache_file(&source.path)
                    .and_then(|file| crate::rule_set::validate_file(source, file))
                    .is_err()
            })
            .map(|s| s.path)
            .collect::<Vec<_>>())
    })
    .await?;
    if missing.is_empty() {
        return Err(initial_error);
    }
    let context = configs.clone();
    let mut context =
        crate::config::blocking_compile(move || crate::config::rule_download_context(context))
            .await?;
    if let Some(catalog) = &context.catalog {
        if control.is_none() {
            if previous.is_some()
                && (!context.control.listeners.is_empty()
                    || context.control.cache_file_path.is_some())
            {
                return Err(invalid(
                    "enabling controller or cache_file_path requires a restart",
                ));
            }
            *control = Some(crate::control::runtime::ControlService::new(
                context.control.clone(),
            )?);
        }
        let runtime = &control.as_ref().unwrap().runtime;
        if runtime.config != context.control {
            return Err(invalid("controller settings require a restart"));
        }
        runtime
            .prepare_rule_download_selection(catalog.selection.clone())
            .await?;
    }
    context
        .sources
        .retain(|source| missing.contains(&source.path));
    let sources = context.sources;
    let global = context.limits;
    let dns = timeout(
        Limits::default().overall,
        DnsRegistry::for_rule_downloads(context.groups, global, &sources, &configs, previous),
    )
    .await
    .map_err(|_| invalid("rule bootstrap preparation deadline exceeded"))??;
    let mut staged = Vec::new();
    let mut total = 0;
    for source in &sources {
        let item = stage(source, &dns, global, Limits::default()).await?;
        total += item.install.file.metadata()?.len();
        if total > 512 * 1024 * 1024 {
            return Err(invalid("cold rule downloads exceed 512 MiB staging budget"));
        }
        staged.push(item);
    }
    let validated = validate_staged(configs, &staged).await?;
    for mut item in staged {
        item.install.finish(item.digest)?;
        log::info!(
            "Installed initial remote rules: {}",
            item.source.path.display()
        );
    }
    Ok(validated)
}

struct Scheduled {
    identity: serde_json::Value,
    source: RuleSource,
    due: Instant,
    failures: u32,
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
            });
        }
        Ok(Self { configs, scheduled })
    }

    pub(crate) async fn changed(&mut self, dns: &DnsRegistry, global: GlobalLimits) {
        loop {
            let Some((index, next)) = self
                .scheduled
                .iter()
                .enumerate()
                .min_by_key(|(_, item)| item.due)
            else {
                std::future::pending::<()>().await;
                return;
            };
            tokio::time::sleep_until(next.due).await;
            let item = &mut self.scheduled[index];
            let result = async {
                let mut staged = stage(&item.source, dns, global, Limits::default()).await?;
                if staged.install.unchanged(staged.digest)? {
                    return Ok(false);
                }
                validate_staged(self.configs.clone(), std::slice::from_ref(&staged)).await?;
                staged
                    .install
                    .finish(staged.digest)
                    .map(|outcome| outcome.changed())
            }
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
