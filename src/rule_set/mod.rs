mod binary;
mod singbox;
mod srs;

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::rules::{Compiler, Predicate, invalid};

const MAX_INPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Srs,
    SingboxJson,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    pub rule_set: String,
    pub path: PathBuf,
    pub format: Option<Format>,
}

impl RuleSetConfig {
    fn format(&self) -> io::Result<Format> {
        self.format
            .or_else(|| match self.path.extension().and_then(|s| s.to_str()) {
                Some("srs") => Some(Format::Srs),
                _ => None,
            })
            .ok_or_else(|| invalid("rule_set requires an explicit format (only .srs is inferred)"))
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
    let mut cache: HashMap<(PathBuf, Format), Arc<Predicate>> = HashMap::new();
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
        let result = (|| {
            if !source.path.is_absolute() { return Err(invalid("rule_set path must be absolute for string configs; file configs anchor paths to their declaring file")); }
            let format = source.format()?;
            let path = std::fs::canonicalize(&source.path)?;
            let key = (path.clone(), format);
            if let Some(predicate) = cache.get(&key) { return Ok(predicate.clone()); }
            let start = std::time::Instant::now();
            if !std::fs::metadata(&path)?.is_file() { return Err(invalid("rule_set source must be a regular file")); }
            let file = std::fs::File::open(&path)?;
            if !file.metadata()?.is_file() { return Err(invalid("rule_set source must be a regular file")); }
            let mut bytes = Vec::new();
            file.take(MAX_INPUT as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > MAX_INPUT { return Err(invalid("rule_set input exceeds 64 MiB")); }
            // Reserve a conservative parse/build charge before decoding text containers.
            compiler.charge(bytes.len().saturating_mul(16), 0)?;
            let expression = match format {
                Format::Srs => srs::decode(&bytes, compiler),
                Format::SingboxJson => singbox::decode(&bytes),
            }?;
            let input_size = bytes.len();
            drop(bytes);
            let predicate = compiler.compile(expression)?;
            log::info!("Loaded rule_set {} ({format:?}, {input_size} bytes) in {:?}", source.rule_set, start.elapsed());
            cache.insert(key, predicate.clone());
            Ok::<_, io::Error>(predicate)
        })().map_err(|e| io::Error::new(e.kind(), format!("rule_set {} ({}): {e}", source.rule_set, source.path.display())))?;
        compiler.sets.insert(source.rule_set.clone(), result);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
