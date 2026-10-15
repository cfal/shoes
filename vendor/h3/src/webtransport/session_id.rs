use std::convert::TryFrom;

use crate::proto::{
    coding::{Decode, Encode},
    stream::{InvalidStreamId, StreamId},
    varint::VarInt,
};

/// Identifies a WebTransport session
///
/// The session id is the same as the stream id of the CONNECT request.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SessionId(u64);
impl SessionId {
    pub(crate) fn from_varint(id: VarInt) -> SessionId {
        Self(id.0)
    }

    pub(crate) fn into_inner(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SessionId {
    type Error = InvalidStreamId;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        if v > VarInt::MAX.0 {
            return Err(InvalidStreamId(v));
        }
        Ok(Self(v))
    }
}

impl Encode for SessionId {
    fn encode<B: bytes::BufMut>(&self, buf: &mut B) {
        VarInt::from_u64(self.0).unwrap().encode(buf);
    }
}

impl Decode for SessionId {
    fn decode<B: bytes::Buf>(buf: &mut B) -> crate::proto::coding::Result<Self> {
        Ok(Self(VarInt::decode(buf)?.into_inner()))
    }
}

impl From<StreamId> for SessionId {
    fn from(value: StreamId) -> Self {
        Self(value.index())
    }
}
