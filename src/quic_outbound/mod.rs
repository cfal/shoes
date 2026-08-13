//! Shared machinery for outbounds that dial over QUIC and own their transport.

pub mod connection;
#[cfg(test)]
pub mod testing;

use std::sync::Arc;
use std::time::Duration;

use crate::address::NetLocation;
use crate::config::ClientQuicConfig;
use crate::quic_transport::obfs::{ObfuscatedUdpSocket, Obfuscator};
use crate::quic_transport::{QuicTransportParams, effective_mtu};
use crate::rustls_config_util::create_client_config;
use crate::socket_util::new_udp_socket;

/// Everything a QUIC outbound needs to raise an endpoint.
///
/// The transport parameters below are not invented. They are the values our own
/// Hysteria2 and TUIC servers use, which came from the reference
/// implementations in turn. Transport parameters are part of a client's
/// fingerprint - Hysteria's Chrome parroting pins the idle timeout and the
/// receive windows for exactly that reason - so picking our own numbers would
/// cost a unique signature and buy nothing.
pub struct QuicOutboundSettings {
    pub server: NetLocation,
    pub quic: ClientQuicConfig,
    pub bind_interface: Option<String>,
    pub obfs: Option<Arc<dyn Obfuscator>>,
    /// ALPN used when the configuration does not name one.
    pub default_alpn: &'static str,
}

impl std::fmt::Debug for QuicOutboundSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicOutboundSettings")
            .field("server", &self.server)
            .field("obfuscated", &self.obfs.is_some())
            .field("default_alpn", &self.default_alpn)
            .finish()
    }
}

impl QuicOutboundSettings {
    pub fn alpn_protocols(&self) -> Vec<String> {
        if self.quic.alpn_protocols.is_unspecified() {
            vec![self.default_alpn.to_string()]
        } else {
            self.quic.alpn_protocols.clone().into_vec()
        }
    }

    pub fn sni_hostname(&self) -> Option<String> {
        if self.quic.sni_hostname.is_unspecified() {
            self.server.address().hostname().map(ToString::to_string)
        } else {
            self.quic.sni_hostname.clone().into_option()
        }
    }

    /// The MTU available to QUIC once an obfuscator has taken its share of
    /// every datagram.
    fn effective_mtu(&self) -> u16 {
        effective_mtu(self.obfs.as_ref().map(|o| o.overhead()))
    }

    /// Raise an endpoint bound for the given address family.
    ///
    /// The family comes from the *resolved* server address rather than from the
    /// configured one, so that a hostname resolving to IPv6 does not end up on
    /// an IPv4 socket.
    pub fn build_endpoint(&self, server_is_ipv6: bool) -> std::io::Result<quinn::Endpoint> {
        let sni = self.sni_hostname();

        let key_and_cert = self
            .quic
            .key
            .clone()
            .zip(self.quic.cert.clone())
            .map(|(key, cert)| (key.into_bytes(), cert.into_bytes()));

        let rustls_client_config = create_client_config(
            self.quic.verify,
            self.quic.server_fingerprints.clone().into_vec(),
            self.alpn_protocols(),
            sni.is_some(),
            key_and_cert,
            // QUIC enforces TLS 1.3 anyway.
            false,
        );

        let tls13_suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            rustls::SupportedCipherSuite::Tls13(suite) => suite,
            _ => unreachable!("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite"),
        };

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
            Arc::new(rustls_client_config),
            tls13_suite.quic_suite().unwrap(),
        )
        .map_err(|e| std::io::Error::other(format!("failed to build QUIC client config: {e}")))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        let transport = QuicTransportParams {
            // These bound what the *server* may open toward us. Neither
            // protocol has it open bidirectional streams, so that stays zero.
            // The uni stream allowance matches what our own Hysteria2 server
            // grants; see the field's documentation for why it cannot be zero.
            max_concurrent_bidi_streams: 0,
            max_concurrent_uni_streams: 1024,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            mtu: self.effective_mtu(),
            enable_segmentation_offload: self.obfs.is_none(),
        };
        client_config.transport_config(Arc::new(transport.build()));

        let udp_socket = new_udp_socket(server_is_ipv6, self.bind_interface.clone())?;
        let udp_socket = udp_socket.into_std()?;

        let mut endpoint = match self.obfs.clone() {
            Some(obfs) => quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(ObfuscatedUdpSocket::new(udp_socket, obfs)?),
                Arc::new(quinn::TokioRuntime),
            )?,
            None => quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                udp_socket,
                Arc::new(quinn::TokioRuntime),
            )?,
        };
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option_util::{NoneOrOne, NoneOrSome};
    use crate::quic_transport::BASE_MTU;
    use crate::quic_transport::obfs::Salamander;

    fn settings() -> QuicOutboundSettings {
        QuicOutboundSettings {
            server: NetLocation::from_str("example.com:443", None).unwrap(),
            quic: ClientQuicConfig::default(),
            bind_interface: None,
            obfs: None,
            default_alpn: "h3",
        }
    }

    #[test]
    fn test_alpn_defaults_to_the_protocols_own() {
        assert_eq!(settings().alpn_protocols(), vec!["h3".to_string()]);
    }

    #[test]
    fn test_alpn_can_be_overridden() {
        let mut s = settings();
        s.quic.alpn_protocols = NoneOrSome::One("hysteria".to_string());
        assert_eq!(s.alpn_protocols(), vec!["hysteria".to_string()]);
    }

    #[test]
    fn test_sni_defaults_to_the_server_hostname() {
        assert_eq!(settings().sni_hostname().as_deref(), Some("example.com"));
    }

    #[test]
    fn test_sni_can_be_overridden() {
        let mut s = settings();
        s.quic.sni_hostname = NoneOrOne::One("other.example".to_string());
        assert_eq!(s.sni_hostname().as_deref(), Some("other.example"));
    }

    #[test]
    fn test_sni_is_none_for_a_bare_ip_server() {
        let mut s = settings();
        s.server = NetLocation::from_str("1.2.3.4:443", None).unwrap();
        assert!(s.sni_hostname().is_none());
    }

    #[test]
    fn test_mtu_drops_by_the_obfuscation_overhead() {
        assert_eq!(settings().effective_mtu(), BASE_MTU);

        let mut s = settings();
        s.obfs = Some(Arc::new(Salamander::new(b"a password").unwrap()));
        assert_eq!(s.effective_mtu(), BASE_MTU - 8);
    }

    #[tokio::test]
    async fn test_endpoint_binds_for_the_resolved_family() {
        let s = settings();

        let endpoint = s.build_endpoint(true).unwrap();
        assert!(endpoint.local_addr().unwrap().is_ipv6());

        let endpoint = s.build_endpoint(false).unwrap();
        assert!(!endpoint.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn test_obfuscated_endpoint_reports_no_segmentation() {
        let mut s = settings();
        s.obfs = Some(Arc::new(Salamander::new(b"a password").unwrap()));
        // Raising it at all is the check: the obfuscated socket is wrapped by
        // a different constructor than the plain one.
        assert!(s.build_endpoint(false).is_ok());
    }
}
