use std::fmt;
use std::io;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::rules::{Compiler, MAX_DEPTH, MAX_STRING_BYTES, invalid};

pub(super) fn decode(bytes: &[u8], budget: &mut Compiler) -> io::Result<Value> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed { budget, depth: 0 }
        .deserialize(&mut decoder)
        .map_err(|e| invalid(format!("rule-set JSON: {e}")))?;
    decoder.end().map_err(|e| invalid(e.to_string()))?;
    Ok(value)
}

struct Seed<'a> {
    budget: &'a mut Compiler,
    depth: usize,
}

impl Seed<'_> {
    fn charge<E: de::Error>(&mut self, bytes: usize, entries: usize) -> Result<(), E> {
        self.budget.charge(bytes, entries).map_err(E::custom)
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(mut self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("rule-set JSON nesting exceeds 100"));
        }
        // Covers Value/vector capacity and the later typed expression while the
        // original tree is consumed. Object members are charged separately.
        self.charge(128, 0)?;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded rule-set JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("rule-set numbers must be integers"))
    }
    fn visit_str<E: de::Error>(mut self, v: &str) -> Result<Value, E> {
        if v.len() > MAX_STRING_BYTES {
            return Err(E::custom("rule string exceeds 64 KiB"));
        }
        self.charge(v.len() * 2 + 32, 1)?;
        Ok(Value::String(v.to_owned()))
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            self.charge(32, 0)?;
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        // A BTreeMap node may be allocated for a single tiny object. Charge per
        // member before allocating it, not as a multiple of serialized bytes.
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 128 {
                return Err(de::Error::custom("rule-set field name too long"));
            }
            self.charge(768, 0)?;
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate rule-set field"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_small_objects_are_charged_before_materialization() {
        let bytes = format!("[{}]", [r#"{"domain":[]}"#; 2000].join(","));
        let mut budget = Compiler::default();
        budget.charge(511 * 1024 * 1024, 0).unwrap();
        assert!(
            decode(bytes.as_bytes(), &mut budget)
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        assert!(decode(br#"{"a":[],"a":[]}"#, &mut Compiler::default()).is_err());
    }
}
