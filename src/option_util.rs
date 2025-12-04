use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum NoneOrOne<T> {
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
    None,
    One(T),
}

impl<T> NoneOrOne<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, NoneOrOne::Unspecified)
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            NoneOrOne::One(item) => Some(item),
            _ => None,
        }
    }

    // Used on non-Linux platforms (macOS, Windows, iOS) for bind_interface validation
    #[allow(dead_code)]
    pub fn is_one(&self) -> bool {
        matches!(self, NoneOrOne::One(_))
    }
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum NoneOrSome<T> {
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
    None,
    One(T),
    Some(Vec<T>),
}

impl<T> NoneOrSome<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, NoneOrSome::Unspecified)
    }

    pub fn len(&self) -> usize {
        match self {
            NoneOrSome::Unspecified => 0,
            NoneOrSome::None => 0,
            NoneOrSome::One(_) => 1,
            NoneOrSome::Some(v) => v.len(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => vec![],
            NoneOrSome::One(item) => vec![item],
            NoneOrSome::Some(v) => v,
        }
    }

    pub fn into_iter(self) -> Box<dyn Iterator<Item = T> + Send>
    where
        T: Send + 'static,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.into_iter()),
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.iter()),
        }
    }

    pub fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut T> + Send + 'a>
    where
        T: Send,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.iter_mut()),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            NoneOrSome::Unspecified => true,
            NoneOrSome::None => true,
            NoneOrSome::One(_) => false,
            NoneOrSome::Some(v) => v.is_empty(),
        }
    }

    pub fn map<F, U>(self, mut f: F) -> NoneOrSome<U>
    where
        F: FnMut(T) -> U,
    {
        match self {
            NoneOrSome::Unspecified => NoneOrSome::Unspecified,
            NoneOrSome::None => NoneOrSome::None,
            NoneOrSome::One(item) => NoneOrSome::One(f(item)),
            NoneOrSome::Some(v) => NoneOrSome::Some(v.into_iter().map(f).collect()),
        }
    }

    pub fn _filter<F>(self, f: F) -> Self
    where
        F: Fn(&T) -> bool,
    {
        match self {
            NoneOrSome::Unspecified => NoneOrSome::Unspecified,
            NoneOrSome::None => NoneOrSome::None,
            NoneOrSome::One(item) => {
                if f(&item) {
                    NoneOrSome::One(item)
                } else {
                    NoneOrSome::None
                }
            }
            NoneOrSome::Some(v) => {
                let filtered: Vec<T> = v.into_iter().filter(f).collect();
                if filtered.is_empty() {
                    NoneOrSome::None
                } else {
                    NoneOrSome::Some(filtered)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrSome<T> {
    One(T),
    #[serde(deserialize_with = "validate_non_empty")]
    Some(Vec<T>),
}

fn validate_non_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = Vec::deserialize(d)?;
    if value.is_empty() {
        return Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("empty"),
            &"need at least one element",
        ));
    }
    Ok(value)
}

impl<T> OneOrSome<T> {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        match self {
            OneOrSome::One(_) => 1,
            OneOrSome::Some(v) => v.len(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrSome::One(item) => vec![item],
            OneOrSome::Some(v) => v,
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter()),
        }
    }

    pub fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut T> + Send + 'a>
    where
        T: Send,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter_mut()),
        }
    }

    pub fn _contains(&self, x: &T) -> bool
    where
        T: PartialEq,
    {
        match self {
            OneOrSome::One(item) => item == x,
            OneOrSome::Some(v) => v.contains(x),
        }
    }
}

struct SingleItemIter<T>(Option<T>);

impl<T> Iterator for SingleItemIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take()
    }
}

impl<T> TryFrom<Vec<T>> for OneOrSome<T> {
    type Error = std::io::Error;
    fn try_from(vec: Vec<T>) -> std::io::Result<Self> {
        match vec.len() {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cannot create OneOrSome from empty vector",
            )),
            1 => Ok(OneOrSome::One(vec.into_iter().next().unwrap())),
            _ => Ok(OneOrSome::Some(vec)),
        }
    }
}
