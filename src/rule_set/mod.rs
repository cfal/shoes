mod binary;
mod geodata;
mod json;
mod mihomo;
mod mrs;
mod singbox;
mod srs;

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::rules::{Compiler, Predicate, invalid};
pub use mihomo::Behavior;

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
pub struct RuleSetConfig {
    pub rule_set: String,
    pub path: PathBuf,
    pub format: Option<Format>,
    pub behavior: Option<Behavior>,
    pub code: Option<String>,
    #[serde(default)]
    pub attributes: Vec<String>,
}

#[derive(PartialEq, Eq, Hash)]
struct SourceKey {
    path: PathBuf,
    format: Format,
    behavior: Option<Behavior>,
    code: Option<String>,
    attributes: Vec<String>,
}

impl RuleSetConfig {
    fn format(&self) -> io::Result<Format> {
        self.format
            .or_else(|| match self.path.extension().and_then(|s| s.to_str()) {
                Some("srs") => Some(Format::Srs),
                Some("mrs") => Some(Format::Mrs),
                _ => None,
            })
            .ok_or_else(|| {
                invalid("rule_set requires an explicit format (only .srs/.mrs are inferred)")
            })
    }
}

pub fn dependencies(configs: &[Config]) -> Vec<PathBuf> {
    configs
        .iter()
        .filter_map(|c| match c {
            Config::RuleSet(s) => Some(s.path.clone()),
            _ => None,
        })
        .collect()
}

pub fn anchor(configs: &mut [Config], config_file: &Path) -> io::Result<()> {
    let base = std::path::absolute(config_file)?
        .parent()
        .ok_or_else(|| invalid("config path has no parent"))?
        .to_path_buf();
    for config in configs {
        if let Config::RuleSet(source) = config
            && source.path.is_relative()
        {
            source.path = base.join(&source.path);
        }
    }
    Ok(())
}

pub fn load(configs: &[Config], compiler: &mut Compiler) -> io::Result<()> {
    let mut names = HashSet::new();
    let mut cache: HashMap<SourceKey, Arc<Predicate>> = HashMap::new();
    for config in configs {
        let Config::RuleSet(source) = config else {
            continue;
        };
        if source.rule_set.is_empty() || !names.insert(&source.rule_set) {
            return Err(invalid("duplicate or empty rule_set name"));
        }
        if names.len() > 1024 {
            return Err(invalid("rule_set source limit exceeded"));
        }
        let predicate = load_source(source, compiler, &mut cache).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "rule_set {} ({}): {e}",
                    source.rule_set,
                    source.path.display()
                ),
            )
        })?;
        compiler.sets.insert(source.rule_set.clone(), predicate);
    }
    Ok(())
}

fn load_source(
    source: &RuleSetConfig,
    compiler: &mut Compiler,
    cache: &mut HashMap<SourceKey, Arc<Predicate>>,
) -> io::Result<Arc<Predicate>> {
    if !source.path.is_absolute() {
        return Err(invalid(
            "rule_set path must be absolute for string configs; file configs anchor paths to their declaring file",
        ));
    }
    let format = source.format()?;
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
    let path = std::fs::canonicalize(&source.path)?;
    let key = SourceKey {
        path: path.clone(),
        format,
        behavior: source.behavior,
        code: source.code.clone(),
        attributes: source.attributes.clone(),
    };
    if let Some(predicate) = cache.get(&key) {
        return Ok(predicate.clone());
    }
    let start = std::time::Instant::now();
    if !std::fs::metadata(&path)?.is_file() {
        return Err(invalid("rule_set source must be a regular file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A concurrent replacement with a FIFO must not strand the compiler worker.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("rule_set source must be a regular file"));
    }
    if metadata.len() > MAX_INPUT as u64 {
        return Err(invalid("rule_set input exceeds 64 MiB"));
    }
    let size = metadata.len() as usize;
    let predicate = compiler.source(|compiler| {
        // Raw input and JSON string scratch overlap; YAML also retains parser events.
        let factor = if format == Format::MihomoYaml { 16 } else { 2 };
        compiler.charge(size.saturating_mul(factor).saturating_add(64), 0)?;
        let mut bytes = Vec::with_capacity(size);
        file.take(size as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() != size {
            return Err(invalid(
                "rule_set changed while reading; retry with an atomic file replacement",
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
    log::info!(
        "Loaded rule_set {} ({format:?}, {size} bytes) in {:?}",
        source.rule_set,
        start.elapsed()
    );
    cache.insert(key, predicate.clone());
    Ok(predicate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_errors_preserve_context_and_error_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("domains.json");
        let configs = vec![Config::RuleSet(RuleSetConfig {
            rule_set: "domains".into(),
            path: path.clone(),
            format: Some(Format::SingboxJson),
            behavior: None,
            code: None,
            attributes: Vec::new(),
        })];
        let context = format!("rule_set domains ({}): ", path.display());
        let mut compiler = Compiler::default();
        let error = load(&configs, &mut compiler).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().starts_with(&context));
        assert!(compiler.sets.is_empty());

        std::fs::write(&path, r#"{"version":6,"rules":[]}"#).unwrap();
        let error = load(&configs, &mut compiler).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            format!("{context}unsupported sing-box rule-set version (expected 1-5)")
        );
        assert!(compiler.sets.is_empty());
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
        let source = RuleSetConfig {
            rule_set: "a".into(),
            path: path.clone(),
            format: Some(Format::SingboxJson),
            behavior: None,
            code: None,
            attributes: Vec::new(),
        };
        let mut other = source.clone();
        other.rule_set = "b".into();
        let configs = vec![Config::RuleSet(source), Config::RuleSet(other)];
        let mut compiler = Compiler::default();
        load(&configs, &mut compiler).unwrap();
        assert!(Arc::ptr_eq(&compiler.sets["a"], &compiler.sets["b"]));
        assert!(
            load(
                &[configs[0].clone(), configs[0].clone()],
                &mut Compiler::default()
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<Config>(
                "rule_set: x\npath: x.json\nformat: singbox_json\nunknown: true"
            )
            .is_err()
        );
        let mut relative = vec![
            serde_yaml::from_str::<Config>("rule_set: x\npath: domains.json\nformat: singbox_json")
                .unwrap(),
        ];
        assert!(load(&relative, &mut Compiler::default()).is_err());
        anchor(&mut relative, &dir.path().join("config.yaml")).unwrap();
        load(&relative, &mut Compiler::default()).unwrap();
    }
}
