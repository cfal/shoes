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

use crate::config::{Config, RuleGroupRules, rule_visit};
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
    pub format: Option<Format>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior: Option<Behavior>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
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
            format: None,
            behavior: None,
            code: None,
            attributes: Vec::new(),
        }
    }

    fn format(&self, prefix: &[u8]) -> io::Result<Format> {
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
        let extension = self
            .path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        match extension.as_deref() {
            Some("srs") => Ok(Format::Srs),
            Some("mrs") => Ok(Format::Mrs),
            Some("json") => Ok(Format::SingboxJson),
            Some("yaml" | "yml") => Ok(Format::MihomoYaml),
            Some("txt") => Ok(Format::MihomoText),
            _ => Err(invalid(
                "cannot detect rule source format; specify format explicitly (DAT requires geosite_dat or geoip_dat)",
            )),
        }
    }
}

fn visit_sources(
    configs: &mut [Config],
    visitor: &mut dyn FnMut(&mut RuleSource) -> io::Result<()>,
) -> io::Result<()> {
    for config in configs.iter_mut() {
        if let Config::RuleConfigGroup(group) = config
            && let RuleGroupRules::Sources(sources) = &mut group.rules
        {
            for source in sources.iter_mut() {
                visitor(source)?;
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
        paths.push(source.path.clone());
        Ok(())
    })?;
    paths.sort();
    paths.dedup();
    Ok(paths)
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
        let Config::RuleConfigGroup(group) = config else {
            continue;
        };
        if group.rule_group.is_empty() || !names.insert(group.rule_group.clone()) {
            return Err(invalid(format!(
                "duplicate or empty rule group name: {}",
                group.rule_group
            )));
        }
        if matches!(group.rules, RuleGroupRules::Policies(_)) {
            compiler.policy_groups.insert(group.rule_group.clone());
        }
    }
    rule_visit::visit(configs, &mut |_| Ok(()), &mut |name| {
        if compiler.policy_groups.contains(name) {
            Ok(())
        } else if names.contains(name) {
            Err(invalid(format!(
                "rule group '{name}' contains file sources; reference it with masks: {{rule_group: {name}}} and an action"
            )))
        } else {
            Err(invalid(format!("unknown rule group: {name}")))
        }
    })?;
    for config in configs.iter() {
        if let Config::RuleConfigGroup(group) = config
            && let RuleGroupRules::Sources(sources) = &group.rules
        {
            let mut predicates = Vec::new();
            for source in sources.iter() {
                compiler.charge(128, 0)?;
                predicates.push(load_source(source, compiler).map_err(|e| {
                    io::Error::new(e.kind(), format!("rule group {}: {e}", group.rule_group))
                })?);
            }
            compiler
                .groups
                .insert(group.rule_group.clone(), Predicate::any(predicates));
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
    let start = std::time::Instant::now();
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
    let mut file = options.open(&path)?;
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
            "- rule_group: a\n  rules: [domains.json]\n- rule_group: b\n  rules: [{path: domains.json, format: singbox_json}]"
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
            serde_yaml::from_str::<Config>("rule_group: x\nrules: [{path: x.json, unknown: true}]")
                .is_err()
        );
    }
}
