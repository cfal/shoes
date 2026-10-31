use super::{Limits, download_source, http, install, load_cached, save_cache};
use crate::config::Config;
use crate::dns::DnsRegistry;
use crate::rule_set::MemorySources;
use std::io;

pub(crate) async fn prepare(
    configs: Vec<Config>,
    retained_ranges: &[ipnetwork::IpNetwork],
    previous: MemorySources,
    lease: Option<std::sync::Arc<install::CacheLease>>,
) -> io::Result<(Vec<Config>, MemorySources)> {
    let cache_lease = lease.clone();
    let (configs, missing, global, persistent, mut memory, mut budget) =
        crate::config::blocking_compile(move || {
            let mut configs = configs;
            let mut missing = Vec::new();
            let persistent = crate::rule_set::cache_directory(&configs)?.is_some();
            let mut memory = MemorySources::new();
            let mut budget = crate::rules::Compiler::default();
            let sources = crate::rule_set::remote_sources(&mut configs)?;
            // All retained indexes constrain cache decoding, regardless of path order.
            for source in &sources {
                if let Some(loaded) = previous.get(&source.path)
                    && loaded.matches(source)?
                {
                    budget.charge(loaded.retained_bytes(), 0)?;
                    memory.insert(source.path.clone(), loaded.clone());
                }
            }
            for source in sources {
                if memory.contains_key(&source.path) {
                    continue;
                }
                if persistent && !previous.contains_key(&source.path) {
                    match load_cached(&source, cache_lease.as_deref(), budget.charged_bytes()) {
                        Ok(loaded) => {
                            budget.charge(loaded.retained_bytes(), 0)?;
                            memory.insert(source.path.clone(), loaded);
                            continue;
                        }
                        Err(error) => {
                            log::warn!("Remote rule cache unavailable for {}: {error}; fetching fresh rules", source.path.display());
                        }
                    }
                }
                missing.push(source);
            }
            let global = if missing.is_empty() {
                Default::default()
            } else {
                crate::config::validate_rule_bootstrap(&configs, &mut missing)?
            };
            Ok((configs, missing, global, persistent, memory, budget))
        })
        .await?;
    if missing.is_empty() {
        return Ok((configs, memory));
    }
    let dns = DnsRegistry::for_rule_bootstrap(&configs, retained_ranges, global)?;
    for source in &missing {
        let download = source.download.as_ref().expect("remote source checked");
        let result = async {
            let url = source.parsed_url()?.expect("remote source checked");
            http::validate_literal_endpoints(&url, download, &dns)?;
            dns.rule_bootstrap(&download.bootstrap_url).await?;
            Ok(())
        }
        .await;
        result.map_err(|error: io::Error| {
            io::Error::new(
                error.kind(),
                format!("rule bootstrap {}: {error}", source.path.display()),
            )
        })?;
    }
    for source in missing {
        log::info!("Bootstrapping remote rules {}", source.path.display());
        let downloaded = download_source(
            &source,
            None,
            &dns,
            global,
            Limits::default(),
            &mut http::DownloadState::default(),
            budget.charged_bytes(),
        )
        .await
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "rule bootstrap {}: {error}; no direct fallback",
                    source.path.display()
                ),
            )
        })?;
        let digest = downloaded.loaded.digest;
        let retained_bytes = downloaded.loaded.retained_bytes();
        memory.insert(source.path.clone(), downloaded.loaded);
        budget.charge(retained_bytes, 0)?;
        if persistent {
            save_cache(&source, downloaded.bytes, digest, lease.clone()).await;
        }
    }
    Ok((configs, memory))
}
