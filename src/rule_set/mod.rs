mod binary;
#[cfg(test)]
mod config_tests;
mod geodata;
mod json;
mod mihomo;
mod mrs;
mod singbox;
mod srs;
mod yaml;

use std::collections::HashSet;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::{Config, rule_visit};
use crate::rules::{Compiler, Predicate, invalid};
pub use mihomo::Behavior;

/// Conservative YAML parser scratch reservation, excluding retained entries.
pub const YAML_PARSER_SCRATCH_BYTES: usize = 64 * 1024 * 1024;

const MAX_INPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Srs,
    SingboxJson,
    MihomoYaml,
    MihomoText,
    Mrs,
    GeositeDat,
    GeoipDat,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSource {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<Download>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<Behavior>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Download {
    pub client_chain: crate::config::ClientChain,
    pub bootstrap_url: String,
}

#[derive(PartialEq, Eq, Hash)]
pub(crate) struct SourceKey {
    path: PathBuf,
    format: Format,
    behavior: Option<Behavior>,
    code: Option<String>,
    attributes: Vec<String>,
}

impl SourceKey {
    fn new(path: PathBuf, format: Format, source: &RuleSource) -> Self {
        let mut attributes: Vec<_> = source
            .attributes
            .iter()
            .map(|attribute| attribute.to_ascii_lowercase())
            .collect();
        attributes.sort_unstable();
        attributes.dedup();
        Self {
            path,
            format,
            behavior: source.behavior,
            code: source.code.as_ref().map(|code| code.to_ascii_lowercase()),
            attributes,
        }
    }
}

impl RuleSource {
    pub(crate) fn from_path(path: PathBuf) -> Self {
        Self {
            path,
            url: None,
            download: None,
            update_interval: None,
            format: None,
            behavior: None,
            code: None,
            attributes: Vec::new(),
        }
    }

    pub(crate) fn format(&self, prefix: &[u8]) -> io::Result<Format> {
        if let Some(format) = self.format {
            return Ok(format);
        }
        if prefix.starts_with(b"SRS") {
            return Ok(Format::Srs);
        }
        if prefix.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            // Zstd selects the MRS decoder, which still validates the payload.
            return Ok(Format::Mrs);
        }
        fn extension(path: &Path) -> Option<Format> {
            match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
                "srs" => Some(Format::Srs),
                "mrs" => Some(Format::Mrs),
                "json" => Some(Format::SingboxJson),
                "yaml" | "yml" => Some(Format::MihomoYaml),
                "txt" => Some(Format::MihomoText),
                _ => None,
            }
        }
        self.parsed_url()?.and_then(|url| extension(Path::new(url.path())))
            .or_else(|| extension(&self.path))
            .ok_or_else(|| invalid("cannot detect rule source format; specify format explicitly (DAT requires geosite_dat or geoip_dat)"))
    }

    pub(crate) fn interval(&self) -> io::Result<std::time::Duration> {
        let value = self.update_interval.as_deref().unwrap_or("24h");
        let (number, unit) = value
            .split_at_checked(value.len().saturating_sub(1))
            .ok_or_else(|| invalid("invalid update_interval"))?;
        let factor = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => 0,
        };
        let secs = number
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(factor))
            .filter(|n| (1..=365 * 86400).contains(n))
            .ok_or_else(|| invalid("update_interval requires 1s to 365d, using s, m, h or d"))?;
        Ok(std::time::Duration::from_secs(secs))
    }

    pub(crate) fn parsed_url(&self) -> io::Result<Option<url::Url>> {
        let Some(raw) = &self.url else {
            if self.download.is_some() || self.update_interval.is_some() {
                return Err(invalid("download/update_interval requires url"));
            }
            return Ok(None);
        };
        if raw.len() > 8192 {
            return Err(invalid("rule source URL exceeds 8192 bytes"));
        }
        let url = url::Url::parse(raw).map_err(|_| invalid("invalid rule source URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "rule source requires HTTP(S) without credentials or fragment",
            ));
        }
        if self.download.is_none() {
            return Err(invalid(
                "remote rules require explicit download.client_chain and download.bootstrap_url",
            ));
        }
        self.interval()?;
        #[cfg(not(unix))]
        return Err(invalid("remote rule updates require Unix"));
        #[cfg(unix)]
        Ok(Some(url))
    }
}

pub(crate) fn visit_sources(
    configs: &mut [Config],
    visitor: &mut dyn FnMut(&mut RuleSource) -> io::Result<()>,
) -> io::Result<()> {
    for config in configs.iter_mut() {
        if let Config::RuleSourceGroup(group) = config {
            for expression in &mut group.rules {
                expression.visit_sources(visitor)?;
            }
        }
    }
    rule_visit::visit(
        configs,
        &mut |rule| rule.criteria.expression.visit_sources(visitor),
        &mut |_| Ok(()),
    )
}

pub fn dependencies(configs: &mut [Config]) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    visit_sources(configs, &mut |source| {
        source.parsed_url()?;
        paths.push(source.path.clone());
        Ok(())
    })?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(crate) fn remote_sources(configs: &mut [Config]) -> io::Result<Vec<RuleSource>> {
    let mut sources = std::collections::BTreeMap::<PathBuf, RuleSource>::new();
    visit_sources(configs, &mut |source| {
        if source.parsed_url()?.is_some() {
            if !source.path.is_absolute() {
                return Err(invalid(
                    "remote cache paths must be absolute for string configs",
                ));
            }
            if let Some(previous) = sources.get(&source.path) {
                if serde_json::to_value(previous)? != serde_json::to_value(&source)? {
                    return Err(invalid("conflicting remote sources share a cache path"));
                }
            } else {
                if sources.len() >= 1024 {
                    return Err(invalid("remote source limit exceeded (1024)"));
                }
                sources.insert(source.path.clone(), source.clone());
            }
        }
        Ok(())
    })?;
    Ok(sources.into_values().collect())
}

pub(crate) fn cache_paths(path: &Path) -> [PathBuf; 3] {
    let sidecar = |suffix| {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    };
    [
        path.into(),
        sidecar(".shoes-update.lock"),
        sidecar(".shoes-update.tmp"),
    ]
}

pub(crate) fn source_identity(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    Ok(absolute.canonicalize().unwrap_or_else(|_| {
        absolute
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .zip(absolute.file_name())
            .map_or_else(|| absolute.clone(), |(parent, name)| parent.join(name))
    }))
}

pub(crate) fn validate_remote_paths(configs: &mut [Config], extra: &[PathBuf]) -> io::Result<()> {
    use source_identity as identity;
    let remotes = remote_sources(configs)?;
    if remotes.is_empty() {
        return Ok(());
    }
    let mut owned = HashSet::new();
    let mut sidecars = HashSet::new();
    for source in &remotes {
        for (index, path) in cache_paths(&identity(&source.path)?)
            .into_iter()
            .enumerate()
        {
            if !owned.insert(path.clone()) {
                return Err(invalid("remote cache ownership paths overlap"));
            }
            if index != 0 {
                sidecars.insert(path);
            }
        }
    }
    visit_sources(configs, &mut |source| {
        if sidecars.contains(&identity(&source.path)?) {
            return Err(invalid("remote sidecar overlaps a rule source"));
        }
        Ok(())
    })?;
    let mut reserved = extra.to_vec();
    let mut state_dirs = Vec::new();
    let mut reserve_state = |path: &Path| {
        reserved.push(path.into());
        reserved.push(crate::control::store::lock_path(path));
    };
    for config in configs.iter() {
        let dns = match config {
            Config::Server(server) => {
                if let crate::config::BindLocation::Path(path) = &server.bind_location {
                    reserve_state(path);
                }
                server.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref())
            }
            Config::TunServer(tun) => tun.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref()),
            Config::DnsConfigGroup(group) => group.fake_ip.as_ref(),
            Config::CacheFile(config) => {
                reserve_state(&config.cache_file_path);
                None
            }
            Config::ClashApi(config) => {
                if let crate::config::BindLocation::Path(path) = &config.bind {
                    reserve_state(path);
                }
                None
            }
            Config::CertificateSource(source) => {
                match &source.source {
                    crate::certificates::SourceConfig::Files { cert, key } => {
                        reserve_state(cert);
                        reserve_state(key);
                    }
                    crate::certificates::SourceConfig::Acme(acme) => {
                        state_dirs.push(identity(&acme.state_dir)?);
                        if let Some(path) = &acme.ca_cert {
                            reserve_state(path);
                        }
                    }
                }
                None
            }
            _ => None,
        };
        if let Some(path) = dns
            .and_then(|policy| policy.options())
            .and_then(|options| options.state_file)
        {
            reserve_state(&path);
        }
    }
    for path in reserved {
        if owned.contains(&identity(&path)?) {
            return Err(invalid(
                "remote cache overlaps a configuration, PEM, socket, or state path",
            ));
        }
    }
    if owned
        .iter()
        .any(|path| state_dirs.iter().any(|dir| path.starts_with(dir)))
    {
        return Err(invalid("remote cache overlaps an ACME state directory"));
    }
    Ok(())
}

pub fn anchor(configs: &mut [Config], config_file: &Path) -> io::Result<()> {
    let base = std::path::absolute(config_file)?
        .parent()
        .ok_or_else(|| invalid("config path has no parent"))?
        .to_path_buf();
    visit_sources(configs, &mut |source| {
        if source.path.is_relative() {
            source.path = base.join(&source.path);
        }
        Ok(())
    })
}

pub fn load(configs: &mut [Config], compiler: &mut Compiler) -> io::Result<()> {
    compiler
        .policy_groups
        .extend(["allow-all-direct".into(), "block-all".into()]);
    let mut names: HashSet<_> = compiler.policy_groups.clone();
    for config in configs.iter() {
        let name = match config {
            Config::RuleConfigGroup(group) => {
                if group.rules.iter().next().is_none() {
                    return Err(invalid("rule group cannot be empty"));
                }
                compiler.policy_groups.insert(group.rule_group.clone());
                &group.rule_group
            }
            Config::RuleSourceGroup(group) => {
                compiler.source_groups.insert(
                    group.rule_source_group.clone(),
                    crate::rules::Expression::or(group.rules.clone()),
                );
                &group.rule_source_group
            }
            _ => continue,
        };
        if name.is_empty() || !names.insert(name.clone()) {
            return Err(invalid(format!(
                "duplicate or empty rule group name: {name}"
            )));
        }
    }
    compiler.source_group_depths =
        crate::rules::Expression::check_source_group_depths(&compiler.source_groups)?;
    rule_visit::visit(configs, &mut |_| Ok(()), &mut |name| {
        if compiler.policy_groups.contains(name) {
            Ok(())
        } else if names.contains(name) {
            Err(invalid(format!(
                "'{name}' is a rule source group; reference it with masks: {{rule_source_group: {name}}} and an action"
            )))
        } else {
            Err(invalid(format!("unknown rule group: {name}")))
        }
    })?;
    for config in configs.iter() {
        if let Config::RuleSourceGroup(group) = config {
            compiler.compile(crate::rules::Expression::RuleSourceGroup(
                group.rule_source_group.clone(),
            ))?;
        }
    }
    Ok(())
}

pub fn load_source(source: &RuleSource, compiler: &mut Compiler) -> io::Result<Arc<Predicate>> {
    read_source(source, compiler).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("rule source {}: {e}", source.path.display()),
        )
    })
}

fn read_source(source: &RuleSource, compiler: &mut Compiler) -> io::Result<Arc<Predicate>> {
    if !source.path.is_absolute() {
        return Err(invalid(
            "rule source path must be absolute for string configs; file configs anchor paths to their declaring file",
        ));
    }
    if let Some(file) = compiler.input_files.get(&source.path) {
        return read_file(source, file.try_clone()?, source.path.clone(), compiler);
    }
    if !compiler.input_files.is_empty() {
        let identity = source_identity(&source.path)?;
        if let Some(file) = compiler.input_files.get(&identity) {
            return read_file(source, file.try_clone()?, identity, compiler);
        }
    }
    #[cfg(unix)]
    if source.url.is_some() {
        return read_file(
            source,
            crate::rule_updater::cache_file(&source.path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("remote cache unavailable (offline checks never download): {e}"),
                )
            })?,
            source.path.clone(),
            compiler,
        );
    }
    let path = std::fs::canonicalize(&source.path)?;
    if let Some(file) = compiler.input_files.get(&path) {
        return read_file(source, file.try_clone()?, path, compiler);
    }
    if !std::fs::metadata(&path)?.is_file() {
        return Err(invalid("rule source must be a regular file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A concurrent replacement with a FIFO must not strand the compiler worker.
        options.custom_flags(libc::O_NONBLOCK);
    }
    read_file(source, options.open(&path)?, path, compiler)
}

pub(crate) fn validate_file(
    source: &RuleSource,
    file: std::fs::File,
) -> io::Result<Arc<Predicate>> {
    read_file(source, file, source.path.clone(), &mut Compiler::default())
}

fn read_file(
    source: &RuleSource,
    mut file: std::fs::File,
    path: PathBuf,
    compiler: &mut Compiler,
) -> io::Result<Arc<Predicate>> {
    source.parsed_url()?;
    let start = std::time::Instant::now();
    file.rewind()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("rule source must be a regular file"));
    }
    if metadata.len() > MAX_INPUT as u64 {
        return Err(invalid("rule source input exceeds 64 MiB"));
    }
    let size = metadata.len() as usize;
    let mut prefix = [0; 4];
    let prefix = &mut prefix[..size.min(4)];
    file.read_exact(prefix)?;
    file.rewind()?;
    let format = source.format(prefix)?;
    if !matches!(
        format,
        Format::MihomoYaml | Format::MihomoText | Format::Mrs
    ) && source.behavior.is_some()
    {
        return Err(invalid("behavior is only valid for Mihomo formats"));
    }
    if !matches!(format, Format::GeositeDat | Format::GeoipDat)
        && (source.code.is_some() || !source.attributes.is_empty())
    {
        return Err(invalid(
            "code and attributes are only valid for DAT formats",
        ));
    }
    let key = SourceKey::new(path, format, source);
    if let Some(predicate) = compiler.sources.get(&key) {
        if source.url.is_some() && matches!(predicate.kind, crate::rules::Kind::Constant(false)) {
            return Err(invalid("refusing an empty remote rule set"));
        }
        return Ok(predicate.clone());
    }
    if compiler.sources.len() >= 1024 {
        return Err(invalid(
            "rule source limit exceeded (1024 distinct sources)",
        ));
    }
    let predicate = compiler.source(|compiler| {
        // JSON may retain doubled escape scratch alongside an owned map key.
        let factor = if format == Format::SingboxJson { 4 } else { 2 };
        compiler.charge(size.saturating_mul(factor).saturating_add(64), 0)?;
        let mut bytes = Vec::with_capacity(size + 1);
        file.take(size as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() != size {
            return Err(invalid(
                "rule source changed while reading; retry with an atomic file replacement",
            ));
        }
        match format {
            Format::Srs => srs::decode(&bytes, compiler),
            Format::SingboxJson => singbox::decode(&bytes, compiler),
            Format::MihomoYaml | Format::MihomoText => mihomo::decode(
                &bytes,
                format == Format::MihomoYaml,
                source
                    .behavior
                    .ok_or_else(|| invalid("Mihomo YAML/text requires behavior"))?,
                compiler,
            ),
            Format::Mrs => mrs::decode(&bytes, source.behavior, compiler),
            Format::GeositeDat | Format::GeoipDat => geodata::decode(
                &bytes,
                format == Format::GeoipDat,
                source
                    .code
                    .as_deref()
                    .ok_or_else(|| invalid("DAT sources require an explicit code"))?,
                &source.attributes,
                compiler,
            ),
        }
    })?;
    if source.url.is_some() && matches!(predicate.kind, crate::rules::Kind::Constant(false)) {
        return Err(invalid("refusing an empty remote rule set"));
    }
    log::info!(
        "Loaded rule source {} ({format:?}, {size} bytes) in {:?}",
        source.path.display(),
        start.elapsed()
    );
    compiler.sources.insert(key, predicate.clone());
    Ok(predicate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_detection_prefers_overrides_then_signatures_then_suffixes() {
        for (path, prefix, expected) in [
            ("source", b"SRS\x02".as_slice(), Some(Format::Srs)),
            ("wrong.json", b"SRS\x02", Some(Format::Srs)),
            ("source", &[0x28, 0xb5, 0x2f, 0xfd], Some(Format::Mrs)),
            ("list.SRS", b"", Some(Format::Srs)),
            ("list.mrs", b"", Some(Format::Mrs)),
            ("list.json", b"{}", Some(Format::SingboxJson)),
            ("list.yaml", b"payl", Some(Format::MihomoYaml)),
            ("list.yml", b"", Some(Format::MihomoYaml)),
            ("list.txt", b"exam", Some(Format::MihomoText)),
            ("list.dat", b"", None),
            ("list", b"{}", None),
            ("list", b"SR", None),
        ] {
            let mut source = RuleSource {
                url: None,
                download: None,
                update_interval: None,
                path: path.into(),
                format: None,
                behavior: None,
                code: None,
                attributes: vec![],
            };
            assert_eq!(source.format(prefix).ok(), expected, "{path}");
            source.format = Some(Format::MihomoText);
            assert_eq!(source.format(prefix).unwrap(), Format::MihomoText);
        }
    }

    #[test]
    fn detected_binary_sources_still_require_valid_payloads() {
        let dir = tempfile::tempdir().unwrap();
        for bytes in [
            include_bytes!("../../tests/fixtures/rule_sets/singbox-v2.srs").as_slice(),
            include_bytes!("../../tests/fixtures/rule_sets/mihomo-domain.mrs").as_slice(),
        ] {
            let path = dir.path().join("source.json");
            let source = RuleSource {
                url: None,
                download: None,
                update_interval: None,
                path: path.clone(),
                format: None,
                behavior: None,
                code: None,
                attributes: vec![],
            };
            std::fs::write(&path, bytes).unwrap();
            load_source(&source, &mut Compiler::default()).unwrap();
            std::fs::write(&path, &bytes[..4]).unwrap();
            assert!(load_source(&source, &mut Compiler::default()).is_err());
        }
    }

    #[test]
    fn escaped_json_keys_reserve_scratch_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escaped.json");
        std::fs::write(&path, format!(r#"{{"{}\n":0}}"#, "a".repeat(1024 * 1024))).unwrap();
        let source = RuleSource {
            url: None,
            download: None,
            update_interval: None,
            path,
            format: Some(Format::SingboxJson),
            behavior: None,
            code: None,
            attributes: vec![],
        };
        let mut compiler = Compiler::default();
        compiler.charge(509 * 1024 * 1024, 0).unwrap();
        assert!(
            load_source(&source, &mut compiler)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        assert!(
            load_source(&source, &mut Compiler::default())
                .unwrap_err()
                .to_string()
                .contains("field name too long")
        );
    }

    #[test]
    fn source_errors_preserve_context_and_error_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("domains.json");
        let source = RuleSource {
            url: None,
            download: None,
            update_interval: None,
            path: path.clone(),
            format: Some(Format::SingboxJson),
            behavior: None,
            code: None,
            attributes: Vec::new(),
        };
        let context = format!("rule source {}: ", path.display());
        let mut compiler = Compiler::default();
        let error = load_source(&source, &mut compiler).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().starts_with(&context));
        assert!(compiler.sources.is_empty());

        std::fs::write(&path, r#"{"version":6,"rules":[]}"#).unwrap();
        let error = load_source(&source, &mut compiler).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            format!("{context}unsupported sing-box rule-set version (expected 1-5)")
        );
        assert!(compiler.sources.is_empty());
    }

    #[test]
    fn shared_sources_and_strict_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("domains.json");
        std::fs::write(
            &path,
            r#"{"version":1,"rules":[{"domain_suffix":["example.com"]}]}"#,
        )
        .unwrap();
        let mut configs: Vec<Config> = serde_yaml::from_str(
            "- rule_source_group: a\n  rules: [domains.json]\n- rule_source_group: b\n  rules: [{path: domains.json, format: singbox_json}]"
        ).unwrap();
        let mut compiler = Compiler::default();
        assert!(load(&mut configs, &mut Compiler::default()).is_err());
        anchor(&mut configs, &dir.path().join("config.yaml")).unwrap();
        load(&mut configs, &mut compiler).unwrap();
        assert!(Arc::ptr_eq(&compiler.groups["a"], &compiler.groups["b"]));
        let inline = load_source(&RuleSource::from_path(path), &mut compiler).unwrap();
        assert!(Arc::ptr_eq(&inline, &compiler.groups["a"]));
        assert!(
            load(
                &mut [configs[0].clone(), configs[0].clone()],
                &mut Compiler::default()
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<Config>(
                "rule_source_group: x\nrules: [{path: x.json, unknown: true}]"
            )
            .is_err()
        );
    }
}
