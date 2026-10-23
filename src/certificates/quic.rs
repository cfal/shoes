use std::io;
use std::sync::Arc;

use quinn::crypto::rustls::QuicServerConfig;
use quinn::crypto::{Keys, ServerConfig, Session, UnsupportedVersion};
use quinn_proto::transport_parameters::TransportParameters;

use super::Source;

struct RotatingQuicConfig {
    base: Arc<rustls::ServerConfig>,
    initial: QuicServerConfig,
    source: Arc<Source>,
}

pub(crate) fn quic_config(
    base: Arc<rustls::ServerConfig>,
    source: Option<Arc<Source>>,
) -> io::Result<Arc<dyn ServerConfig>> {
    let initial = QuicServerConfig::try_from(base.clone()).map_err(io::Error::other)?;
    Ok(match source {
        Some(source) => Arc::new(RotatingQuicConfig {
            base,
            initial,
            source,
        }),
        None => Arc::new(initial),
    })
}

impl ServerConfig for RotatingQuicConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &quinn::ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        self.initial.initial_keys(version, dst_cid)
    }

    fn retry_tag(
        &self,
        version: u32,
        orig_dst_cid: &quinn::ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        self.initial.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        // Cipher suites and protocol versions are unchanged from the validated base.
        let config = QuicServerConfig::try_from(self.source.snapshot(&self.base))
            .expect("certificate snapshot preserves QUIC crypto policy");
        Arc::new(config).start_session(version, params)
    }
}
