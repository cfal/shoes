use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;

use super::store::{ExplicitSelections, SelectionStore, encoded, valid_name};

#[derive(Debug, Clone)]
pub struct SelectorDefinition {
    pub members: Vec<String>,
    pub default: Option<String>,
}

pub type SelectorDefinitions = BTreeMap<String, SelectorDefinition>;
pub type Choices = BTreeMap<String, String>;

#[derive(Debug, Default)]
pub struct SelectionView {
    definitions: SelectorDefinitions,
    choices: RwLock<Arc<Choices>>,
}

impl SelectionView {
    pub fn snapshot(&self) -> Arc<Choices> {
        self.choices.read().clone()
    }

    pub fn definitions(&self) -> &SelectorDefinitions {
        &self.definitions
    }
}

pub struct SelectionOwner {
    explicit: ExplicitSelections,
    store: Option<SelectionStore>,
    active: Arc<SelectionView>,
}

impl SelectionOwner {
    pub fn new(path: Option<&Path>) -> io::Result<Self> {
        let (store, explicit) = match path {
            Some(path) => {
                let (store, explicit) = SelectionStore::open(path)?;
                (Some(store), explicit)
            }
            None => (None, ExplicitSelections::new()),
        };
        Ok(Self {
            explicit,
            store,
            active: Arc::default(),
        })
    }

    pub fn prepare(&self, definitions: SelectorDefinitions) -> io::Result<Arc<SelectionView>> {
        validate(&definitions)?;
        self.check_capacity(&definitions)?;
        Ok(Arc::new(SelectionView {
            choices: RwLock::new(Arc::new(effective(&definitions, &self.explicit))),
            definitions,
        }))
    }

    pub fn activate(&mut self, candidate: Arc<SelectionView>) -> io::Result<()> {
        self.reconcile(&candidate)?;
        let stale = candidate
            .definitions
            .iter()
            .filter(|(name, definition)| {
                self.explicit
                    .get(*name)
                    .is_some_and(|member| !definition.members.contains(member))
            })
            .count();
        if stale != 0 {
            log::warn!(
                "Ignoring {stale} saved selector choices whose members are no longer configured"
            );
        }
        self.active = candidate;
        Ok(())
    }

    pub fn reconcile(&self, candidate: &SelectionView) -> io::Result<()> {
        self.check_capacity(&candidate.definitions)?;
        *candidate.choices.write() = Arc::new(effective(&candidate.definitions, &self.explicit));
        Ok(())
    }

    pub fn select(&mut self, group: &str, member: &str) -> io::Result<()> {
        let definition =
            self.active.definitions.get(group).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "selector does not exist")
            })?;
        if !definition.members.iter().any(|name| name == member) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "member does not belong to selector",
            ));
        }
        let mut explicit = self.explicit.clone();
        explicit.insert(group.to_owned(), member.to_owned());
        let choices = Arc::new(effective(&self.active.definitions, &explicit));
        if let Some(store) = &mut self.store {
            store.save(&explicit).map_err(|error| {
                log::error!("Could not persist selector choice: {error}");
                io::Error::other(format!("selection was not applied: {error}"))
            })?;
        }
        self.explicit = explicit;
        *self.active.choices.write() = choices;
        Ok(())
    }

    fn check_capacity(&self, definitions: &SelectorDefinitions) -> io::Result<()> {
        if self.store.is_none() {
            return Ok(());
        }
        let mut worst = self.explicit.clone();
        for (name, definition) in definitions {
            let value = definition
                .members
                .iter()
                .chain(self.explicit.get(name))
                .max_by_key(|value| {
                    serde_json::to_vec(value)
                        .expect("string serialization")
                        .len()
                })
                .expect("validated nonempty selector");
            worst.insert(name.clone(), value.clone());
        }
        encoded(&worst).map(|_| ())
    }
}

fn validate(definitions: &SelectorDefinitions) -> io::Result<()> {
    for (name, definition) in definitions {
        let mut members = HashSet::new();
        if !valid_name(name)
            || definition.members.is_empty()
            || definition
                .members
                .iter()
                .any(|member| !valid_name(member) || !members.insert(member))
            || definition
                .default
                .as_ref()
                .is_some_and(|value| !members.contains(value))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid selector name, membership, or default",
            ));
        }
    }
    Ok(())
}

fn effective(definitions: &SelectorDefinitions, explicit: &ExplicitSelections) -> Choices {
    definitions
        .iter()
        .map(|(name, definition)| {
            let selected = explicit
                .get(name)
                .filter(|value| definition.members.contains(value))
                .or(definition.default.as_ref())
                .unwrap_or(&definition.members[0]);
            (name.clone(), selected.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definitions(default: &str) -> SelectorDefinitions {
        BTreeMap::from([(
            "outbound".into(),
            SelectorDefinition {
                members: vec!["east".into(), "west".into()],
                default: Some(default.into()),
            },
        )])
    }

    #[test]
    fn defaults_remain_configuration_not_explicit_choices() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let mut owner = SelectionOwner::new(Some(&path)).unwrap();
        let old = owner.prepare(definitions("east")).unwrap();
        owner.activate(old.clone()).unwrap();
        let new = owner.prepare(definitions("west")).unwrap();
        owner.activate(new.clone()).unwrap();
        assert_eq!(old.snapshot()["outbound"], "east");
        assert_eq!(new.snapshot()["outbound"], "west");
        assert!(!path.exists());
        owner.select("outbound", "west").unwrap();
        drop(owner);
        let owner = SelectionOwner::new(Some(&path)).unwrap();
        let restored = owner.prepare(definitions("east")).unwrap();
        assert_eq!(restored.snapshot()["outbound"], "west");
    }

    #[test]
    fn activation_reconciles_choices_acknowledged_during_preparation() {
        let mut owner = SelectionOwner::new(None).unwrap();
        let old = owner.prepare(definitions("east")).unwrap();
        owner.activate(old.clone()).unwrap();
        let candidate = owner.prepare(definitions("east")).unwrap();
        owner.select("outbound", "west").unwrap();
        owner.activate(candidate.clone()).unwrap();
        assert_eq!(candidate.snapshot()["outbound"], "west");
        owner.select("outbound", "east").unwrap();
        assert_eq!(old.snapshot()["outbound"], "west");
        assert_eq!(candidate.snapshot()["outbound"], "east");
    }

    #[test]
    fn removed_groups_keep_explicit_choices_without_reload_writes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let mut owner = SelectionOwner::new(Some(&path)).unwrap();
        owner
            .activate(owner.prepare(definitions("east")).unwrap())
            .unwrap();
        owner.select("outbound", "west").unwrap();
        let before = std::fs::read(&path).unwrap();
        owner
            .activate(owner.prepare(BTreeMap::new()).unwrap())
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let restored = owner.prepare(definitions("east")).unwrap();
        owner.activate(restored.clone()).unwrap();
        assert_eq!(restored.snapshot()["outbound"], "west");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn invalid_members_and_defaults_are_rejected() {
        let mut owner = SelectionOwner::new(None).unwrap();
        assert!(owner.prepare(definitions("missing")).is_err());
        owner
            .activate(owner.prepare(definitions("east")).unwrap())
            .unwrap();
        assert!(owner.select("outbound", "missing").is_err());
        assert_eq!(owner.active.snapshot()["outbound"], "east");
    }

    #[test]
    fn failed_save_never_publishes_and_same_choice_retry_rewrites() {
        use super::super::store::FailPoint;
        for fault in [
            FailPoint::Write,
            FailPoint::Rename,
            FailPoint::DirectorySync,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("cache.db");
            let mut owner = SelectionOwner::new(Some(&path)).unwrap();
            owner
                .activate(owner.prepare(definitions("east")).unwrap())
                .unwrap();
            owner.select("outbound", "east").unwrap();
            owner.store.as_mut().unwrap().fail_at = Some(fault);
            let error = owner.select("outbound", "west").unwrap_err();
            assert_eq!(
                error.to_string().contains("uncertain"),
                fault == FailPoint::DirectorySync
            );
            assert_eq!(owner.active.snapshot()["outbound"], "east");
            assert_eq!(owner.explicit["outbound"], "east");
            owner.select("outbound", "east").unwrap();
            drop(owner);
            let owner = SelectionOwner::new(Some(&path)).unwrap();
            assert_eq!(owner.explicit["outbound"], "east");
        }
    }
}
