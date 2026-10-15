use std::convert::TryFrom;
use std::fmt::{self, Display};

use super::varint::VarInt;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PushId(pub(crate) u64);

#[derive(Debug, PartialEq)]
pub struct InvalidPushId(u64);

impl TryFrom<u64> for PushId {
    type Error = InvalidPushId;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match VarInt::try_from(v) {
            Ok(id) => Ok(id.into()),
            Err(_) => Err(InvalidPushId(v)),
        }
    }
}

impl Display for InvalidPushId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid push id: {:x}", self.0)
    }
}

impl From<VarInt> for PushId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
    }
}

impl From<PushId> for VarInt {
    fn from(v: PushId) -> Self {
        Self(v.0)
    }
}

impl fmt::Display for PushId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "push {}", self.0)
    }
}
