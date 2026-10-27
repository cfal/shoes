use super::*;
use futures::task::noop_waker_ref;

struct PendingWriteIo;

impl AsyncRead for PendingWriteIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingWriteIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for PendingWriteIo {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for PendingWriteIo {}

struct ZeroWriteIo;

impl AsyncRead for ZeroWriteIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for ZeroWriteIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ZeroWriteIo {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for ZeroWriteIo {}

fn completed_reality_connection() -> TlsConnection {
    crate::reality::established_pair().1
}

#[tokio::test]
async fn reality_certificate_errors_match_across_read_modes() {
    use aws_lc_rs::agreement;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let public_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &[1; 32])
        .unwrap()
        .compute_public_key()
        .unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap(),
    );
    for (mode, preread) in [
        (TlsReadMode::Stream, false),
        (TlsReadMode::PreserveRecords, false),
        (TlsReadMode::Stream, true),
    ] {
        let mut client = crate::reality::RealityClientConfig {
            mldsa65_verify: None,
            public_key: public_key.as_ref().try_into().unwrap(),
            short_id: [0; 8],
            server_name: "localhost".try_into().unwrap(),
            cipher_suites: Vec::new(),
        }
        .create_connection()
        .unwrap();
        let mut server =
            TlsConnection::new(rustls::ServerConnection::new(server_config.clone()).unwrap());
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        server.feed(&hello).unwrap();
        let mut flight = Vec::new();
        server.write_tls(&mut flight).unwrap();
        let (io, mut peer) = tokio::io::duplex(65536);
        if !preread {
            peer.write_all(&flight).await.unwrap();
        }
        let error =
            CryptoTlsStream::handshake(io, client, mode, if preread { &flight } else { &[] })
                .await
                .err()
                .expect("a real target certificate must not authenticate REALITY");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .starts_with("reality client error processing new packets:")
        );
        let mut output = Vec::new();
        peer.read_to_end(&mut output).await.unwrap();
        // Record-preserving reads may send a compatibility CCS before the certificate arrives.
        assert!(
            output.is_empty() || output == [20, 3, 3, 0, 1, 1],
            "failed REALITY authentication must not send alerts: {output:?}"
        );
    }
}

#[tokio::test]
async fn reality_shutdown_preserves_buffered_data_before_close_notify() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = crate::reality::established_pair();
    let (io, peer) = tokio::io::duplex(16);
    let mut sender = CryptoTlsStream::new(io, client, None);
    let mut receiver = CryptoTlsStream::new(peer, server, None);
    let payload = vec![42; 40_000];
    sender.write_all(&payload).await.unwrap();
    assert!(sender.session.wants_write());
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(Pin::new(&mut sender).poll_shutdown(&mut cx).is_pending());

    let mut received = Vec::new();
    let (shutdown, read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(sender.shutdown(), receiver.read_to_end(&mut received))
    })
    .await
    .unwrap();
    shutdown.unwrap();
    read.unwrap();
    assert_eq!(received, payload);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn raw_tcp_capability_requires_drained_io_and_open_directions() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (socket, peer) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let _peer = peer.unwrap();
    let session = completed_reality_connection();
    let mut stream = CryptoTlsStream::new(socket.unwrap(), session, Some(TlsDeframer::new()));
    assert!(stream.plain_tcp().is_none());
    stream.start_raw_read().unwrap();
    assert!(stream.plain_tcp().is_none());
    stream.start_raw_write(b"").unwrap();
    assert!(stream.plain_tcp().is_none());
    stream.flush().await.unwrap();
    assert!(stream.plain_tcp().is_some());

    stream.input = TlsInput::Raw(Bytes::from_static(b"transport tail"));
    assert!(stream.plain_tcp().is_none());
    let mut tail = [0; 14];
    stream.read_exact(&mut tail[..1]).await.unwrap();
    assert!(stream.plain_tcp().is_none());
    stream.read_exact(&mut tail[1..]).await.unwrap();
    assert_eq!(&tail, b"transport tail");
    assert!(stream.plain_tcp().is_some());

    stream.need_flush = true;
    assert!(stream.plain_tcp().is_none());
    stream.flush().await.unwrap();
    // TLS responses queued after DIRECT must not be sent on the raw wire.
    stream.session.send_close_notify();
    assert!(stream.plain_tcp().is_some());

    for state in [
        TlsState::ReadShutdown,
        TlsState::WriteShutdown,
        TlsState::FullyShutdown,
    ] {
        stream.state = state;
        assert!(stream.plain_tcp().is_none());
    }
}

fn ordinary_connections() -> (TlsConnection, TlsConnection) {
    use std::sync::Arc;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server =
        TlsConnection::new(rustls::ServerConnection::new(Arc::new(server_config)).unwrap());
    let client = TlsConnection::new(
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap(),
    );
    (client, server)
}

#[tokio::test]
async fn ordinary_tls_shutdown_drains_data_and_fatal_alert_after_backpressure() {
    use std::io::Read;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for fail_server in [false, true] {
        let (mut client, mut server) = ordinary_connections();
        for _ in 0..8 {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.feed(&wire).unwrap();
            wire.clear();
            server.write_tls(&mut wire).unwrap();
            client.feed(&wire).unwrap();
            if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(!client.wants_write() && !server.wants_write());
        let (sender, mut receiver) = if fail_server {
            (server, client)
        } else {
            (client, server)
        };
        let (io, mut peer) = tokio::io::duplex(16);
        let mut stream = CryptoTlsStream::new(io, sender, None);
        let payload = [42; 1000];
        stream.write_all(&payload).await.unwrap();
        assert!(stream.session.wants_write());
        peer.write_all(&[23, 3, 3, 0, 1, 0]).await.unwrap();
        assert_eq!(
            stream.read(&mut [0]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(stream.session.wants_write());

        let mut wire = Vec::new();
        let (shutdown, read) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                async move {
                    let result = stream.shutdown().await;
                    drop(stream);
                    result
                },
                peer.read_to_end(&mut wire)
            )
        })
        .await
        .unwrap();
        assert_eq!(shutdown.unwrap_err().kind(), io::ErrorKind::InvalidData);
        read.unwrap();
        let error = receiver.feed(&wire).unwrap_err();
        assert!(error.to_string().contains("BadRecordMac"), "{error}");
        let mut received = [0; 1000];
        receiver.reader().read_exact(&mut received).unwrap();
        assert_eq!(received, payload);
    }
}

#[tokio::test]
async fn vectored_tls_roundtrip_with_partial_transport_writes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, server) = ordinary_connections();
    let (client_io, server_io) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        let mut stream = CryptoTlsStream::handshake(server_io, server, TlsReadMode::Stream, &[])
            .await
            .unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received
    });
    let mut stream = CryptoTlsStream::handshake(client_io, client, TlsReadMode::Stream, &[])
        .await
        .unwrap();
    assert!(stream.is_write_vectored());
    assert_eq!(
        stream
            .write_vectored(&[io::IoSlice::new(b"")])
            .await
            .unwrap(),
        0
    );
    let payload: Vec<u8> = (0..70000).map(|i| (i ^ (i >> 8)) as u8).collect();
    let mut slices = [
        io::IoSlice::new(b""),
        io::IoSlice::new(&payload[..9]),
        io::IoSlice::new(&payload[9..40000]),
        io::IoSlice::new(&payload[40000..]),
    ];
    let mut remaining = &mut slices[..];
    while !remaining.is_empty() {
        let written = stream.write_vectored(remaining).await.unwrap();
        assert!(written > 0);
        io::IoSlice::advance_slices(&mut remaining, written);
    }
    stream.shutdown().await.unwrap();
    assert_eq!(peer.await.unwrap(), payload);
    assert_eq!(
        stream.write_vectored(&slices).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn vectored_reality_fallback_accounts_for_accepted_plaintext_under_backpressure() {
    let mut stream = CryptoTlsStream::new(PendingWriteIo, completed_reality_connection(), None);
    assert!(!stream.is_write_vectored());
    let mut cx = Context::from_waker(noop_waker_ref());
    let data = [7; 16384];
    let slices = [
        io::IoSlice::new(b""),
        io::IoSlice::new(&data),
        io::IoSlice::new(&data),
    ];
    let mut accepted = 0;
    let mut blocked = false;
    for _ in 0..16 {
        match Pin::new(&mut stream).poll_write_vectored(&mut cx, &slices) {
            Poll::Ready(Ok(n)) => {
                assert!(n > 0);
                accepted += n;
            }
            Poll::Pending => {
                blocked = true;
                break;
            }
            Poll::Ready(Err(error)) => panic!("unexpected error: {error}"),
        }
    }
    assert!(blocked);
    assert!(accepted > 0 && accepted <= 65536);
}

#[tokio::test]
async fn raw_vectors_follow_the_entire_encrypted_prefix() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (io, mut peer) = tokio::io::duplex(8);
    let mut stream = CryptoTlsStream::new(io, completed_reality_connection(), None);
    stream.start_raw_write(b"last encrypted bytes").unwrap();
    let mut expected = stream.raw_write_prefix.as_ref().unwrap().to_vec();
    expected.extend_from_slice(b"raw bytes");
    let mut received = vec![0; expected.len()];
    let slices = [io::IoSlice::new(b"raw "), io::IoSlice::new(b"bytes")];
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(
        Pin::new(&mut stream)
            .poll_write_vectored(&mut cx, &slices)
            .is_pending()
    );
    assert!(stream.is_write_vectored());
    let send = async {
        let mut slices = slices;
        let mut remaining = &mut slices[..];
        while !remaining.is_empty() {
            let n = stream.write_vectored(remaining).await.unwrap();
            assert!(n > 0);
            io::IoSlice::advance_slices(&mut remaining, n);
        }
        stream.flush().await.unwrap();
    };
    let ((), read) = tokio::join!(send, peer.read_exact(&mut received));
    read.unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn ordinary_preread_returns_to_backend_reads_at_a_record_boundary() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let payload = vec![42; 40_000];
    for split in [0, 1, 4, 5, 10, 20_000, usize::MAX] {
        let (mut sender, receiver) = crate::reality::established_pair();
        sender.writer().write_all(&payload).unwrap();
        let mut ciphertext = Vec::new();
        sender.write_tls(&mut ciphertext).unwrap();
        let split = split.min(ciphertext.len());
        let (io, mut peer) = tokio::io::duplex(65536);
        peer.write_all(&ciphertext[split..]).await.unwrap();
        let mut stream =
            CryptoTlsStream::handshake(io, receiver, TlsReadMode::Stream, &ciphertext[..split])
                .await
                .unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
        assert!(matches!(stream.input, TlsInput::Stream));
    }
}

#[test]
fn reality_stream_stops_accepting_plaintext_when_tls_output_is_blocked() {
    let mut stream = CryptoTlsStream::new(PendingWriteIo, completed_reality_connection(), None);
    let mut cx = Context::from_waker(noop_waker_ref());
    let data = [0u8; 16 * 1024];
    let mut accepted = 0;

    for _ in 0..16 {
        match Pin::new(&mut stream).poll_write(&mut cx, &data) {
            Poll::Ready(Ok(written)) => accepted += written,
            Poll::Pending => break,
            Poll::Ready(Err(error)) => panic!("unexpected write error: {error}"),
        }
    }

    assert!(
        accepted <= 64 * 1024,
        "blocked REALITY stream accepted {accepted} plaintext bytes"
    );
}

#[test]
fn reality_stream_rejects_write_zero_without_waiting_for_a_wake() {
    let mut stream = CryptoTlsStream::new(ZeroWriteIo, completed_reality_connection(), None);
    let mut cx = Context::from_waker(noop_waker_ref());

    let result = Pin::new(&mut stream).poll_write(&mut cx, &[0; 1024]);
    assert!(matches!(
        result,
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WriteZero
    ));
}
