//! ConfigSelection type for referencing configs by group name or inline.

use std::collections::HashMap;

use crate::option_util::NoneOrSome;

#[derive(Debug, Clone)]
pub enum ConfigSelection<T> {
    Config(T),
    GroupName(String),
}

impl<T> ConfigSelection<T> {
    pub fn unwrap_config(self) -> T {
        match self {
            ConfigSelection::Config(config) => config,
            ConfigSelection::GroupName(_) => {
                panic!("Tried to unwrap a ConfigSelection::GroupName");
            }
        }
    }

    pub fn unwrap_config_mut(&mut self) -> &mut T {
        match self {
            ConfigSelection::Config(config) => config,
            ConfigSelection::GroupName(_) => {
                panic!("Tried to unwrap a ConfigSelection::GroupName");
            }
        }
    }

    fn replace<'a, U>(
        iter: impl Iterator<Item = &'a ConfigSelection<U>>,
        client_groups: &HashMap<String, Vec<U>>,
    ) -> std::io::Result<Vec<ConfigSelection<U>>>
    where
        U: Clone + 'a,
    {
        let mut ret = vec![];
        for selection in iter {
            match selection {
                ConfigSelection::Config(client_config) => {
                    ret.push(ConfigSelection::Config(client_config.clone()));
                }
                ConfigSelection::GroupName(client_group) => {
                    match client_groups.get(client_group.as_str()) {
                        Some(client_configs) => {
                            ret.extend(client_configs.iter().cloned().map(ConfigSelection::Config));
                        }
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("No such client group: {client_group}"),
                            ));
                        }
                    }
                }
            }
        }
        Ok(ret)
    }

    pub fn replace_none_or_some_groups(
        selections: &mut NoneOrSome<ConfigSelection<T>>,
        client_groups: &HashMap<String, Vec<T>>,
    ) -> std::io::Result<()>
    where
        T: Clone + Sync,
    {
        if selections.is_empty() {
            return Ok(());
        }

        let ret = Self::replace(selections.iter(), client_groups)?;
        let _ = std::mem::replace(selections, NoneOrSome::Some(ret));
        Ok(())
    }
}

impl<'de, T> serde::de::Deserialize<'de> for ConfigSelection<T>
where
    T: serde::de::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};
        use std::fmt;
        use std::marker::PhantomData;

        struct ConfigSelectionVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for ConfigSelectionVisitor<T>
        where
            T: serde::de::Deserialize<'de>,
        {
            type Value = ConfigSelection<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "either a string (group name reference) or an inline configuration object",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(ConfigSelection::GroupName(value.to_string()))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let config = T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map_err(|e| Error::custom(format!(
                        "Failed to parse inline configuration: {e}. \
                        Expected either a string referencing a named group or a valid configuration object"
                    )))?;
                Ok(ConfigSelection::Config(config))
            }
        }

        deserializer.deserialize_any(ConfigSelectionVisitor(PhantomData))
    }
}

impl<T> serde::ser::Serialize for ConfigSelection<T>
where
    T: serde::ser::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            ConfigSelection::Config(config) => config.serialize(serializer),
            ConfigSelection::GroupName(name) => serializer.serialize_str(name),
        }
    }
}
