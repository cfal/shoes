mod config;
mod crypto;
pub(crate) mod generator;
mod handshake;
mod keys;
mod mask;
mod session;
mod stream;

#[cfg(test)]
pub(crate) mod tests;

use std::{fmt, io, sync::Arc};

use parking_lot::Mutex;

use crate::config::vless::VlessEncryptionLimits;
use config::{Lifetime, Mode, Padding, ParsedConfig};
use keys::{ClientKey, ServerKey};
use session::{ClientSessionCache, ServerSessions};

pub(crate) use stream::EncryptionStream;

pub(crate) struct ClientEncryption {
    mode: Mode,
    padding: Padding,
    keys: Vec<ClientKey>,
    resume: bool,
    cache: Arc<ClientSessionCache>,
}

impl ClientEncryption {
    pub(crate) fn new(value: &str) -> io::Result<Self> {
        let (parsed, resume) = ParsedConfig::client(value)?;
        let keys = parsed
            .keys
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                ClientKey::new(raw).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid VLESS encryption public key {i}"),
                    )
                })
            })
            .collect::<io::Result<_>>()?;
        Ok(Self {
            mode: parsed.mode,
            padding: parsed.padding,
            keys,
            resume,
            cache: Arc::default(),
        })
    }
}

pub(crate) struct ServerEncryption {
    mode: Mode,
    padding: Padding,
    keys: Vec<ServerKey>,
    relay_len: usize,
    lifetime: Lifetime,
    sessions: Mutex<ServerSessions>,
}

impl ServerEncryption {
    pub(crate) fn new(value: &str, limits: VlessEncryptionLimits) -> io::Result<Self> {
        limits.validate()?;
        let (parsed, lifetime) = ParsedConfig::server(value)?;
        let keys = parsed
            .keys
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                ServerKey::new(raw).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid VLESS decryption private key {i}"),
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let relay_len = keys
            .iter()
            .try_fold(0usize, |total, key| total.checked_add(key.relay_len() + 32))
            .and_then(|total| total.checked_sub(32))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "VLESS key chain is too large")
            })?;
        Ok(Self {
            mode: parsed.mode,
            padding: parsed.padding,
            keys,
            relay_len,
            lifetime,
            sessions: Mutex::new(ServerSessions::new(limits)),
        })
    }
}

impl fmt::Debug for ClientEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientEncryption")
            .field("mode", &self.mode)
            .field("resume", &self.resume)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ServerEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerEncryption")
            .field("mode", &self.mode)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}
