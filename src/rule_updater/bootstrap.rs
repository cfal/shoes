use super::{Limits, download_memory, http, install, stage};
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
    let (configs, missing, global, persistent, mut memory) =
        crate::config::blocking_compile(move || {
            let mut configs = configs;
            let mut missing = Vec::new();
            let persistent = crate::rule_set::cache_directory(&configs)?.is_some();
            let mut memory = MemorySources::new();
            for source in crate::rule_set::remote_sources(&mut configs)? {
                if !persistent {
                    if let Some(loaded) = previous.get(&source.path)
                        && loaded.matches(&source)?
                    {
                        memory.insert(source.path.clone(), loaded.clone());
                    } else {
                        missing.push(source);
                    }
                    continue;
                }
                match install::cache_file(&source.path, cache_lease.as_deref()) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => missing.push(source),
                    Err(error) => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("rule cache {}: {error}", source.path.display()),
                        ));
                    }
                }
            }
            let global = if missing.is_empty() {
                Default::default()
            } else {
                crate::config::validate_rule_bootstrap(&configs, &mut missing)?
            };
            Ok((configs, missing, global, persistent, memory))
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
        if !persistent {
            log::info!(
                "Bootstrapping remote rules in memory {}",
                source.path.display()
            );
            let loaded = download_memory(
                &source,
                None,
                &dns,
                global,
                &mut http::DownloadState::default(),
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
            })?
            .expect("initial download always decodes");
            memory.insert(source.path.clone(), loaded);
            let mut budget = crate::rules::Compiler::default();
            for loaded in memory.values() {
                budget.charge(loaded.retained_bytes(), 0)?;
            }
            continue;
        }
        log::info!("Bootstrapping missing rule cache {}", source.path.display());
        let result = async {
            let install = install::Install::open_async(&source.path, lease.clone()).await?;
            install.require_missing()?;
            let staged = stage(
                &source,
                install,
                &dns,
                global,
                Limits::default(),
                &mut http::DownloadState::default(),
            )
            .await?;
            staged.install.finish_async(staged.digest).await
        }
        .await;
        result.map_err(|error| io::Error::new(error.kind(), format!(
            "rule bootstrap {}: {error}; no direct fallback; earlier completed cache installs remain",
            source.path.display()
        )))?;
        log::info!(
            "Installed bootstrap cache {}; full candidate validation is still pending",
            source.path.display()
        );
    }
    Ok((configs, memory))
}
