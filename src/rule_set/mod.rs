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
pub(crate) const CACHE_LOCK_SUFFIX: &str = ".shoes-update.lock";
pub(crate) const CACHE_STAGE_SUFFIX: &str = ".shoes-update.tmp";

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
    #[serde(default)]
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<Box<Download>>,
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

pub(crate) type MemorySources = std::collections::BTreeMap<PathBuf, Arc<MemorySource>>;

pub(crate) struct MemorySource {
    identity: blake3::Hash,
    format: Format,
    predicate: Arc<Predicate>,
    retained_bytes: usize,
    pub(crate) digest: blake3::Hash,
    pub(crate) updated: std::time::Instant,
}

impl MemorySource {
    pub(crate) fn matches(&self, source: &RuleSource) -> io::Result<bool> {
        Ok(self.identity == source.content_identity()?)
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
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
    fn content_identity(&self) -> io::Result<blake3::Hash> {
        let identity = serde_json::to_vec(&(
            &self.url,
            self.format,
            self.behavior,
            &self.code,
            &self.attributes,
        ))?;
        Ok(blake3::hash(&identity))
    }

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

    #[cfg(test)]
    pub(crate) fn format(&self, prefix: &[u8]) -> io::Result<Format> {
        self.format_with_hint(prefix, self.url_format()?)
    }

    fn url_format(&self) -> io::Result<Option<Format>> {
        Ok(self
            .parsed_url()?
            .and_then(|url| extension(Path::new(url.path()))))
    }

    fn format_with_hint(&self, prefix: &[u8], hint: Option<Format>) -> io::Result<Format> {
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
        if let Some(format) = hint {
            return Ok(format);
        }
        if let Some(format) = extension(&self.path) {
            return Ok(format);
        }
        Err(invalid(
            "cannot detect rule source format; specify format explicitly (DAT requires geosite_dat or geoip_dat)",
        ))
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
            if self.path.as_os_str().is_empty() {
                return Err(invalid("local rule source requires path"));
            }
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
        if source.parsed_url()?.is_none() {
            paths.push(source.path.clone());
        }
        Ok(())
    })?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub(crate) fn remote_sources(configs: &mut [Config]) -> io::Result<Vec<RuleSource>> {
    let directory = cache_directory(configs)?;
    let mut sources = std::collections::BTreeMap::<PathBuf, RuleSource>::new();
    visit_sources(configs, &mut |source| {
        if source.parsed_url()?.is_none() {
            return Ok(());
        }
        match &directory {
            None => {
                let path = PathBuf::from(format!("remote:{}.rules", source.content_identity()?));
                if !source.path.as_os_str().is_empty() && source.path != path {
                    return Err(invalid(
                        "remote path requires rule_cache_dir; omit path for memory-only sources",
                    ));
                }
                source.path = path;
            }
            Some(directory) => {
                if source.path.as_os_str().is_empty() {
                    source.path = directory.join(format!("{}.rules", source.content_identity()?));
                }
                if !source.path.is_absolute() {
                    return Err(invalid(
                        "remote cache paths must be absolute for string configs",
                    ));
                }
                source.path = std::path::absolute(&source.path)?;
            }
        }
        if let Some(previous) = sources.get(&source.path) {
            if serde_json::to_value(previous)? != serde_json::to_value(&source)? {
                return Err(invalid("conflicting remote sources share a cache path"));
            }
            return Ok(());
        }
        if sources.len() >= 1024 {
            return Err(invalid("remote source limit exceeded (1024)"));
        }
        sources.insert(source.path.clone(), source.clone());
        Ok(())
    })?;
    Ok(sources.into_values().collect())
}

pub(crate) fn normalize_sources(
    configs: &mut [Config],
    compiler: &mut Compiler,
) -> io::Result<Vec<RuleSource>> {
    let deliveries = remote_sources(configs)?;
    for source in &deliveries {
        compiler
            .remote_files
            .insert(source.path.clone(), source.url_format()?);
        // Retained remote indexes are resident before any local source decodes.
        if compiler
            .memory
            .as_ref()
            .is_some_and(|memory| memory.contains_key(&source.path))
        {
            load_source(source, compiler)?;
        }
    }
    visit_sources(configs, &mut |source| {
        source.url = None;
        source.download = None;
        source.update_interval = None;
        Ok(())
    })?;
    Ok(deliveries)
}

pub(crate) fn source_identity(path: &Path) -> io::Result<PathBuf> {
    let mut absolute = std::path::absolute(path)?;
    let mut followed = HashSet::new();
    'links: for _ in 0..40 {
        if !followed.insert(absolute.clone()) {
            break;
        }
        let mut ancestor = absolute.as_path();
        let mut suffix = Vec::new();
        loop {
            if let Ok(mut canonical) = ancestor.canonicalize() {
                canonical.extend(suffix.iter().rev());
                return Ok(canonical);
            }
            // Resolve aliases before reattaching missing descendants. Otherwise a
            // not-yet-created state directory could bypass the managed namespace.
            if let Ok(target) = std::fs::read_link(ancestor) {
                let mut target = ancestor.parent().unwrap().join(target);
                target.extend(suffix.iter().rev());
                absolute = target;
                continue 'links;
            }
            let (Some(parent), Some(name)) = (ancestor.parent(), ancestor.file_name()) else {
                return Err(invalid(format!(
                    "rule resource path {} has an unresolved parent or inaccessible root",
                    path.display()
                )));
            };
            suffix.push(name.to_os_string());
            ancestor = parent;
        }
    }
    Err(invalid(
        "rule source symlink chain exceeds 40 links or contains a loop",
    ))
}

pub(crate) fn validate_remote_paths(configs: &mut [Config], extra: &[PathBuf]) -> io::Result<()> {
    use source_identity as identity;
    let remotes = remote_sources(configs)?;
    let Some(directory) = cache_directory(configs)? else {
        return Ok(());
    };
    if !cfg!(unix) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "rule_cache_dir requires Unix",
        ));
    }
    let directory_identity = identity(&directory)?;
    #[cfg(target_os = "linux")]
    if directory_identity == identity(Path::new(crate::desktop::MANAGED_STATE_DIRECTORY))? {
        return Err(invalid(
            "rule_cache_dir overlaps the managed TUN state directory",
        ));
    }
    for source in &remotes {
        if std::path::absolute(&source.path)?.parent() != Some(directory.as_path()) {
            return Err(invalid(
                "remote caches must be direct children of rule_cache_dir",
            ));
        }
        if source
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                let name = name.to_ascii_lowercase();
                name == "owner.lock"
                    || name.ends_with(CACHE_LOCK_SUFFIX)
                    || name.ends_with(CACHE_STAGE_SUFFIX)
            })
        {
            return Err(invalid(
                "rule_cache_dir owner.lock and updater sidecar suffixes are reserved",
            ));
        }
    }
    visit_sources(configs, &mut |source| {
        if source.url.is_none()
            && (std::path::absolute(&source.path)?.starts_with(&directory)
                || identity(&source.path)?.starts_with(&directory_identity))
        {
            return Err(invalid(
                "local rule source overlaps rule_cache_dir; managed caches cannot have local aliases",
            ));
        }
        Ok(())
    })?;
    let mut reserved = extra.to_vec();
    reserved.extend(crate::config::pem_candidate_dependencies(configs)?);
    let mut state_dirs = Vec::new();
    let mut reserve_state = |path: &Path| {
        if path.file_name().is_none() {
            return Err(invalid(
                "reserved socket, PEM, or state path must name a file",
            ));
        }
        reserved.push(path.into());
        reserved.push(crate::control::store::lock_path(path));
        Ok(())
    };
    for config in configs.iter() {
        let dns = match config {
            Config::Server(server) => {
                if let crate::config::BindLocation::Path(path) = &server.bind_location {
                    reserve_state(path)?;
                }
                server.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref())
            }
            Config::TunServer(tun) => tun.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref()),
            Config::DnsConfigGroup(group) => group.fake_ip.as_ref(),
            Config::CacheFile(config) => {
                reserve_state(&config.cache_file_path)?;
                None
            }
            Config::ClashApi(config) => {
                if let crate::config::BindLocation::Path(path) = &config.bind {
                    reserve_state(path)?;
                }
                None
            }
            Config::CertificateSource(source) => {
                match &source.source {
                    crate::certificates::SourceConfig::Files { cert, key } => {
                        reserve_state(cert)?;
                        reserve_state(key)?;
                    }
                    crate::certificates::SourceConfig::Acme(acme) => {
                        state_dirs.push(identity(&acme.state_dir)?);
                        if let Some(path) = &acme.ca_cert {
                            reserve_state(path)?;
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
            reserve_state(&path)?;
        }
    }
    for path in reserved {
        if std::path::absolute(&path)?.starts_with(&directory)
            || identity(&path)?.starts_with(&directory_identity)
        {
            return Err(invalid(
                "rule_cache_dir overlaps a configuration, PEM, socket, or state path",
            ));
        }
    }
    if state_dirs
        .iter()
        .any(|dir| dir.starts_with(&directory_identity) || directory_identity.starts_with(dir))
    {
        return Err(invalid("remote cache overlaps an ACME state directory"));
    }
    Ok(())
}

pub(crate) fn cache_directory(configs: &[Config]) -> io::Result<Option<PathBuf>> {
    let mut directory = None;
    for config in configs {
        if let Config::RuleCacheDirectory(path) = config {
            if !path.is_absolute()
                || path.file_name().is_none()
                || path
                    .components()
                    .any(|component| component == std::path::Component::ParentDir)
            {
                return Err(invalid(
                    "rule_cache_dir must be an absolute directory without parent traversal",
                ));
            }
            if directory.replace(std::path::absolute(path)?).is_some() {
                return Err(invalid("rule_cache_dir may only be specified once"));
            }
        }
    }
    Ok(directory)
}

pub fn anchor(configs: &mut [Config], config_file: &Path) -> io::Result<()> {
    let base = std::path::absolute(config_file)?
        .parent()
        .ok_or_else(|| invalid("config path has no parent"))?
        .to_path_buf();
    for config in configs.iter_mut() {
        if let Config::RuleCacheDirectory(path) = config {
            if path.as_os_str().is_empty() {
                return Err(invalid("rule_cache_dir must not be empty"));
            }
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
    visit_sources(configs, &mut |source| {
        if !source.path.as_os_str().is_empty() && source.path.is_relative() {
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
                if group.rules.is_empty() {
                    return Err(invalid("rule source group cannot be empty"));
                }
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
    if compiler.remote_files.contains_key(&source.path) {
        if let Some(loaded) = compiler
            .memory
            .as_ref()
            .and_then(|memory| memory.get(&source.path))
            .cloned()
        {
            let key = SourceKey::new(source.path.clone(), loaded.format, source);
            if let Some(predicate) = compiler.sources.get(&key) {
                return Ok(predicate.clone());
            }
            if compiler.sources.len() >= 1024 {
                return Err(invalid(
                    "rule source limit exceeded (1024 distinct sources)",
                ));
            }
            compiler.charge(loaded.retained_bytes(), 0)?;
            compiler.sources.insert(key, loaded.predicate.clone());
            return Ok(loaded.predicate.clone());
        }
        if compiler.memory_only || compiler.memory.is_some() {
            return Err(invalid(
                "remote rules unavailable in memory; offline checks never download; daemon startup fetches remote sources",
            ));
        }
    }
    if !source.path.is_absolute() {
        return Err(invalid(
            "rule source path must be absolute for string configs; file configs anchor paths to their declaring file",
        ));
    }
    #[cfg(unix)]
    if source.url.is_some() || compiler.remote_files.contains_key(&source.path) {
        let file = crate::rule_updater::cache_file(&source.path, None)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "remote cache unavailable; offline checks never download; daemon startup can fetch missing caches: {error}"
                ),
            )
        })?;
        return read_file(source, file, source.path.clone(), compiler).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{error}; offline checks never download; daemon startup can refetch invalid caches"
                ),
            )
        });
    }
    let path = std::fs::canonicalize(&source.path)?;
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

fn read_file(
    source: &RuleSource,
    file: std::fs::File,
    path: PathBuf,
    compiler: &mut Compiler,
) -> io::Result<Arc<Predicate>> {
    read_data(source, path, SourceInput::File(file), compiler).map(|(_, predicate)| predicate)
}

pub(crate) fn load_memory(
    source: &RuleSource,
    bytes: &[u8],
    digest: blake3::Hash,
    retained_bytes: usize,
) -> io::Result<MemorySource> {
    let mut compiler = Compiler::default();
    compiler.charge(retained_bytes, 0)?;
    let (format, predicate) = read_data(
        source,
        source.path.clone(),
        SourceInput::Memory(bytes),
        &mut compiler,
    )?;
    Ok(MemorySource {
        identity: source.content_identity()?,
        format,
        retained_bytes: predicate.retained_bytes(),
        predicate,
        digest,
        updated: std::time::Instant::now(),
    })
}

enum SourceInput<'a> {
    File(std::fs::File),
    Memory(&'a [u8]),
}

fn read_data(
    source: &RuleSource,
    path: PathBuf,
    mut input: SourceInput<'_>,
    compiler: &mut Compiler,
) -> io::Result<(Format, Arc<Predicate>)> {
    let url_hint = source.url_format()?;
    let start = std::time::Instant::now();
    let size = match &mut input {
        SourceInput::File(file) => {
            file.rewind()?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(invalid("rule source must be a regular file"));
            }
            metadata.len()
        }
        SourceInput::Memory(bytes) => bytes.len() as u64,
    };
    if size > MAX_INPUT as u64 {
        return Err(invalid("rule source input exceeds 64 MiB"));
    }
    let size = size as usize;
    let mut prefix = [0; 4];
    let prefix = &mut prefix[..size.min(4)];
    match &mut input {
        SourceInput::File(file) => {
            file.read_exact(prefix)?;
            file.rewind()?;
        }
        SourceInput::Memory(bytes) => prefix.copy_from_slice(&bytes[..prefix.len()]),
    }
    let remote_hint = compiler.remote_files.get(&path).copied().flatten();
    let format = source.format_with_hint(prefix, url_hint.or(remote_hint))?;
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
    let remote = source.url.is_some() || compiler.remote_files.contains_key(&path);
    let key = SourceKey::new(path, format, source);
    if let Some(predicate) = compiler.sources.get(&key) {
        if remote && matches!(predicate.kind, crate::rules::Kind::Constant(false)) {
            return Err(invalid("refusing an empty remote rule set"));
        }
        return Ok((format, predicate.clone()));
    }
    if compiler.sources.len() >= 1024 {
        return Err(invalid(
            "rule source limit exceeded (1024 distinct sources)",
        ));
    }
    let predicate = compiler
        .source(|compiler| {
            // JSON may retain doubled escape scratch alongside an owned map key.
            let factor = if format == Format::SingboxJson { 4 } else { 2 };
            compiler.charge(size.saturating_mul(factor).saturating_add(64), 0)?;
            let bytes = match input {
                SourceInput::Memory(bytes) => std::borrow::Cow::Borrowed(bytes),
                SourceInput::File(file) => {
                    let mut bytes = Vec::with_capacity(size + 1);
                    file.take(size as u64 + 1).read_to_end(&mut bytes)?;
                    if bytes.len() != size {
                        return Err(invalid("rule source changed while reading; retry with an atomic file replacement"));
                    }
                    std::borrow::Cow::Owned(bytes)
                }
            };
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
        })
        .map_err(|error| {
            if remote {
                io::Error::new(
                    error.kind(),
                    "remote rule data failed validation (details redacted)",
                )
            } else {
                error
            }
        })?;
    if remote && matches!(predicate.kind, crate::rules::Kind::Constant(false)) {
        return Err(invalid("refusing an empty remote rule set"));
    }
    log::info!(
        "Loaded rule source {} ({format:?}, {size} bytes) in {:?}",
        source.path.display(),
        start.elapsed()
    );
    compiler.sources.insert(key, predicate.clone());
    Ok((format, predicate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmatic_source_groups_must_be_nonempty() {
        let config = Config::RuleSourceGroup(crate::config::RuleSourceGroup {
            rule_source_group: "empty".into(),
            rules: Vec::new(),
        });
        let error = crate::config::create_server_configs(vec![config])
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "rule source group cannot be empty");
    }

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
            let mut source = RuleSource::from_path(path.into());
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
            let source = RuleSource::from_path(path.clone());
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
            format: Some(Format::SingboxJson),
            ..RuleSource::from_path(path)
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
            format: Some(Format::SingboxJson),
            ..RuleSource::from_path(path.clone())
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
