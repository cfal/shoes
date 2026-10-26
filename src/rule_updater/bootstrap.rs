use super::{Limits, http, install, stage};
use crate::config::Config;
use crate::dns::DnsRegistry;
use std::io;

pub(crate) async fn prepare(
    configs: Vec<Config>,
    retained_ranges: &[ipnetwork::IpNetwork],
) -> io::Result<Vec<Config>> {
    let (configs, missing, global) = crate::config::blocking_compile(move || {
        let mut configs = configs;
        let mut missing = Vec::new();
        for source in crate::rule_set::remote_sources(&mut configs)? {
            match install::cache_file(&source.path) {
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
        Ok((configs, missing, global))
    })
    .await?;
    if missing.is_empty() {
        return Ok(configs);
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
        log::info!("Bootstrapping missing rule cache {}", source.path.display());
        let result = async {
            let install = install::Install::open_async(&source.path).await?;
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
    Ok(configs)
}
