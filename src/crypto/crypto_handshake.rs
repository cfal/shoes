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
    use crate::crypto::{TlsConnection, TlsReadMode};
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
            let mut client = TlsConnection::new(
                rustls::ClientConnection::new(
                    client_config.clone(),
                    "localhost".try_into().unwrap(),
                )
                .unwrap(),
            );
            let mut server =
                TlsConnection::new(rustls::ServerConnection::new(server_config.clone()).unwrap());
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            server.feed(&hello).unwrap();
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
}
