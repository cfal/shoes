//! In-process servers for the QUIC outbound tests.
//!
//! Every end-to-end test here runs the real server from this repository, so a
//! change to either side that breaks the pairing fails a test rather than
//! waiting for a user to notice.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::client_proxy_selector::ClientProxySelector;
use crate::config::{ClientQuicConfig, RuleConfig};
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_config_util::create_server_config;
use crate::tcp::tcp_client_handler_factory::create_tcp_client_proxy_selector;

/// A self-signed certificate for `localhost`, as PEM.
pub struct TestCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_certificate() -> TestCertificate {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generating a self-signed certificate");
    TestCertificate {
        cert_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
    }
}

pub fn test_resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}

/// A selector that allows everything and dials it directly.
///
/// This is the same construction the real server startup uses, so the tests
/// exercise the production routing path rather than a stand-in.
pub fn direct_selector(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
    Arc::new(create_tcp_client_proxy_selector(
        vec![RuleConfig::default()],
        resolver,
    ))
}

/// Client-side QUIC settings for the harness.
///
/// Verification is off: the certificate is self-signed, generated seconds
/// earlier by this same process, and reachable only over loopback. Pinning its
/// fingerprint would prove nothing that generating it did not already prove.
pub fn client_quic_config() -> ClientQuicConfig {
    ClientQuicConfig {
        verify: false,
        server_fingerprints: NoneOrSome::Unspecified,
        sni_hostname: NoneOrOne::One("localhost".to_string()),
        alpn_protocols: NoneOrSome::Unspecified,
        key: None,
        cert: None,
    }
}

/// Build the QUIC server config the in-process servers need.
pub fn quic_server_config(
    cert: &TestCertificate,
    alpn: &[String],
) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
    let server_config = Arc::new(create_server_config(
        cert.cert_pem.as_bytes(),
        cert.key_pem.as_bytes(),
        vec![],
        alpn,
        &[],
    ));
    let quic: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .expect("a valid QUIC server config");
    Arc::new(quic)
}

/// Reserve a loopback UDP port and release it, so a server can bind it.
///
/// Binding to port 0 inside the server is not an option: the caller needs to
/// know the address to dial, and the server does not report it back.
pub fn reserve_udp_port() -> SocketAddr {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("binding a probe socket");
    let addr = probe.local_addr().expect("probe address");
    drop(probe);
    addr
}

/// An echo server on a fresh TCP port. Returns its address.
pub async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

/// An echo server on a fresh UDP port. Returns its address.
pub async fn spawn_udp_echo() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], from).await;
        }
    });
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_echo_harness() {
        let addr = spawn_tcp_echo().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn test_udp_echo_harness() {
        let addr = spawn_udp_echo().await;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(b"ping", addr).await.unwrap();
        let mut buf = [0u8; 4];
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
    }

    #[test]
    fn test_certificate_generation() {
        let cert = generate_certificate();
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_quic_server_config_accepts_the_generated_certificate() {
        let cert = generate_certificate();
        let _ = quic_server_config(&cert, &["h3".to_string()]);
    }

    #[test]
    fn test_reserved_ports_differ() {
        assert_ne!(reserve_udp_port(), reserve_udp_port());
    }
}
