//! Handshake I/O uses the same input owner as post-handshake reads.

use futures::future::poll_fn;
use std::io;
use tokio::io::AsyncWriteExt;

use super::CryptoTlsStream;
use crate::async_stream::AsyncStream;

pub(super) async fn perform_crypto_handshake<IO: AsyncStream>(
    stream: &mut CryptoTlsStream<IO>,
) -> io::Result<()> {
    while stream.session.is_handshaking() {
        stream.flush().await?;
        if !stream.session.is_handshaking() {
            break;
        }
        if !stream.session.wants_read() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS handshake stalled: neither wants_read nor wants_write",
            ));
        }

        // Any successfully consumed record is progress, regardless of fragmentation.
        // The caller's setup deadline bounds the handshake, not a record count.
        match poll_fn(|cx| stream.poll_receive_tls(cx)).await {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF during TLS handshake",
                ));
            }
            Ok(_) => {}
            Err(error) => {
                let _ = stream.flush().await;
                return Err(error);
            }
        }
    }
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tls_deframer::TlsDeframer;
    use crate::crypto::{CryptoConnection, TlsReadMode, feed_crypto_connection};
    use std::sync::Arc;

    #[tokio::test]
    async fn fragmented_handshake_can_exceed_one_hundred_records() {
        let mut names = vec!["localhost".to_string()];
        names.extend((0..100).map(|index| format!("host-{index}.example.test")));
        let cert = rcgen::generate_simple_self_signed(names).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                )
                .unwrap();
        server_config.max_fragment_size = Some(32);
        server_config.send_tls13_tickets = 0;
        let server_config = Arc::new(server_config);
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        for framed in [false, true] {
            let mut client = CryptoConnection::new_rustls_client(
                rustls::ClientConnection::new(
                    client_config.clone(),
                    "localhost".try_into().unwrap(),
                )
                .unwrap(),
            );
            let mut server = CryptoConnection::new_rustls_server(
                rustls::ServerConnection::new(server_config.clone()).unwrap(),
            );
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            feed_crypto_connection(&mut server, &hello).unwrap();
            server.process_new_packets().unwrap();
            let mut flight = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut flight).unwrap();
            }
            let mut counter = TlsDeframer::new();
            counter.feed(&flight);
            assert!(counter.next_records().unwrap().len() > 100);

            let (io, mut peer) = tokio::io::duplex(32 * 1024);
            peer.write_all(&flight).await.unwrap();
            let mode = if framed {
                TlsReadMode::PreserveRecords
            } else {
                TlsReadMode::Stream
            };
            let stream = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                CryptoTlsStream::handshake(io, client, mode, &[]),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!stream.session.is_handshaking());
        }
    }

    #[test]
    fn test_rustls_connection_enum_exists() {
        // Compile-time test that rustls::Connection exists
        // This will fail to compile if rustls::Connection doesn't exist
        fn _assert_connection_type(_: &rustls::Connection) {}
    }

    #[test]
    fn test_connection_has_required_methods() {
        // This test ensures rustls::Connection has the methods we need
        // It won't compile if the methods don't exist
        use std::sync::Arc;

        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let server_name = rustls::pki_types::ServerName::try_from("example.com")
            .unwrap()
            .to_owned();

        let client_conn = rustls::ClientConnection::new(config, server_name).unwrap();
        let connection = rustls::Connection::Client(client_conn);

        // These method calls will fail to compile if the methods don't exist
        let _handshaking = connection.is_handshaking();
        let _wants_read = connection.wants_read();
        let _wants_write = connection.wants_write();
    }
}
