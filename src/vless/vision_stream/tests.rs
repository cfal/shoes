mod decisions;
mod native_decisions;
mod native_errors;
#[cfg(target_os = "linux")]
mod native_splice;
#[cfg(target_os = "linux")]
mod splice;

use super::*;
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncPing;
use crate::crypto::tls_deframer::TlsDeframer;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use crate::reality::{RealityClientConfig, RealityServerConfig};
use futures::task::noop_waker_ref;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;

struct ScriptedIo {
    reads: VecDeque<bytes::Bytes>,
}

impl AsyncRead for ScriptedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(chunk) = this.reads.front_mut() else {
            return Poll::Pending;
        };
        let len = buf.remaining().min(chunk.len());
        buf.put_slice(&chunk[..len]);
        chunk.advance(len);
        if chunk.is_empty() {
            this.reads.pop_front();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ScriptedIo {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for ScriptedIo {}

#[derive(Default)]
struct WriteGate {
    blocked: bool,
    flush_blocked: bool,
    output: Vec<u8>,
}

struct GatedIo {
    input: ScriptedIo,
    gate: Arc<std::sync::Mutex<WriteGate>>,
}

impl AsyncRead for GatedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().input).poll_read(cx, buf)
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut gate = self.gate.lock().unwrap();
        if gate.blocked {
            return Poll::Pending;
        }
        gate.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.gate.lock().unwrap().flush_blocked {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncPing for GatedIo {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for GatedIo {}

#[derive(Clone, Copy, Debug)]
enum Backend {
    Tls12,
    Tls13,
    Reality,
}

const BACKENDS: [Backend; 3] = [Backend::Tls12, Backend::Tls13, Backend::Reality];

fn new_connections(backend: Backend) -> (TlsConnection, TlsConnection) {
    let version = match backend {
        Backend::Tls12 => &rustls::version::TLS12,
        Backend::Tls13 => &rustls::version::TLS13,
        Backend::Reality => return reality_connections(),
    };
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.send_tls13_tickets = 0;
    let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = TlsConnection::new(
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap(),
    );
    let server = TlsConnection::new(rustls::ServerConnection::new(Arc::new(config)).unwrap());
    (client, server)
}

fn reality_connections() -> (TlsConnection, TlsConnection) {
    use aws_lc_rs::agreement;
    let private_key = [1; 32];
    let public_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key)
        .unwrap()
        .compute_public_key()
        .unwrap();
    let mut client = RealityClientConfig {
        mldsa65_verify: None,
        public_key: public_key.as_ref().try_into().unwrap(),
        short_id: [0; 8],
        server_name: "localhost".try_into().unwrap(),
        cipher_suites: Vec::new(),
    }
    .create_connection()
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let server = RealityServerConfig {
        mldsa65_key: None,
        private_key,
        short_ids: vec![[0; 8]],
        dest: NetLocation::new(Address::Hostname("localhost".into()), 443),
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: Vec::new(),
    }
    .authenticate_client_hello(&hello)
    .unwrap()
    .into_connection(&crate::reality::default_target_records(&hello[44..76]))
    .unwrap();
    (client, server)
}

fn connection_pair(backend: Backend) -> (TlsConnection, TlsConnection) {
    let (mut client, mut server) = new_connections(backend);
    for _ in 0..8 {
        transfer_tls(&mut client, &mut server);
        transfer_tls(&mut server, &mut client);
        if !client.is_handshaking() && !server.is_handshaking() {
            return (client, server);
        }
    }
    panic!("in-memory TLS handshake did not finish");
}

fn transfer_tls(sender: &mut TlsConnection, receiver: &mut TlsConnection) {
    let mut bytes = Vec::new();
    sender.write_tls(&mut bytes).unwrap();
    if !bytes.is_empty() {
        receiver.feed(&bytes).unwrap();
    }
}

fn encrypt(session: &mut TlsConnection, plaintext: &[u8]) -> Vec<u8> {
    session.writer().write_all(plaintext).unwrap();
    let mut ciphertext = Vec::new();
    session.write_tls(&mut ciphertext).unwrap();
    ciphertext
}

fn inner_server_hello() -> bytes::Bytes {
    let (mut client, mut server) = new_connections(Backend::Tls13);
    transfer_tls(&mut client, &mut server);
    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();
    let mut deframer = TlsDeframer::new();
    deframer.feed(&flight);
    deframer.next_record().unwrap().unwrap()
}

fn assert_buffered_reads(stream: &mut (impl AsyncRead + Unpin), expected: &[u8]) {
    let mut received = Vec::new();
    let mut cx = Context::from_waker(noop_waker_ref());
    while received.len() < expected.len() {
        let mut bytes = [0; 3];
        let mut buf = ReadBuf::new(&mut bytes);
        match Pin::new(&mut *stream).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) => {}
            result => panic!("expected buffered data: {result:?}"),
        }
        assert!(!buf.filled().is_empty());
        received.extend_from_slice(buf.filled());
    }
    assert_eq!(received, expected);

    let mut bytes = [0; 3];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(Pin::new(stream).poll_read(&mut cx, &mut buf).is_pending());
    assert!(buf.filled().is_empty());
}

#[test]
fn vision_rejects_streams_without_record_preservation() {
    let (client, server) = connection_pair(Backend::Tls13);
    for session in [client, server] {
        let is_server = session.is_server();
        let io = ScriptedIo {
            reads: VecDeque::new(),
        };
        let tls = CryptoTlsStream::new(io, session, None);
        let result = if is_server {
            VisionStream::new_server(tls, [7; 16], b"")
        } else {
            VisionStream::new_client(tls, [7; 16])
        };
        let error = result.err().expect("missing framing must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn direct_write_waits_for_pending_tls_and_transport_flush() {
    use std::io::Read;

    for backend in BACKENDS {
        let (mut peer, session) = connection_pair(backend);
        let gate = Arc::new(std::sync::Mutex::new(WriteGate {
            blocked: true,
            flush_blocked: true,
            output: Vec::new(),
        }));
        let io = GatedIo {
            input: ScriptedIo {
                reads: VecDeque::new(),
            },
            gate: gate.clone(),
        };
        let mut tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            Pin::new(&mut tls).poll_write(&mut cx, b"before handoff"),
            Poll::Ready(Ok(14))
        ));
        let mut vision = VisionStream::new_server(tls, [7; 16], b"").unwrap();
        vision.vless_response_to_send = false;
        vision.queue_padded_write(b"-final padded record");
        vision.switch_write_to_direct_mode().unwrap();
        assert!(
            Pin::new(&mut vision)
                .poll_write(&mut cx, b"raw")
                .is_pending()
        );
        assert!(gate.lock().unwrap().output.is_empty());

        gate.lock().unwrap().blocked = false;
        assert!(
            Pin::new(&mut vision)
                .poll_write(&mut cx, b"raw")
                .is_pending()
        );
        let ciphertext = gate.lock().unwrap().output.clone();
        peer.feed(&ciphertext).unwrap();
        let mut plaintext = [0; 34];
        peer.reader().read_exact(&mut plaintext).unwrap();
        assert_eq!(&plaintext, b"before handoff-final padded record");

        gate.lock().unwrap().flush_blocked = false;
        assert!(matches!(
            Pin::new(&mut vision).poll_write(&mut cx, b"raw"),
            Poll::Ready(Ok(3))
        ));
        assert!(matches!(
            Pin::new(&mut vision).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            gate.lock().unwrap().output,
            [ciphertext.as_slice(), b"raw"].concat()
        );
    }
}

#[test]
fn raw_write_direction_never_sends_tls_alerts() {
    let (_, session) = connection_pair(Backend::Tls13);
    let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
    let io = GatedIo {
        input: ScriptedIo {
            reads: VecDeque::from([bytes::Bytes::from_static(b"\x17\x03\x03\x00\x03bad")]),
        },
        gate: gate.clone(),
    };
    let mut tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
    let mut cx = Context::from_waker(noop_waker_ref());
    tls.start_raw_write(b"").unwrap();
    let mut bytes = [0; 8];
    let result = Pin::new(&mut tls).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes));
    assert!(matches!(result, Poll::Ready(Err(_))));
    assert!(gate.lock().unwrap().output.is_empty());
}

#[test]
fn direct_write_never_sends_later_tls_alerts() {
    use std::io::{BufRead, Read};

    let hello = inner_server_hello();
    let application = b"\x17\x03\x03\x00\x03app";
    let uuid = [7; 16];
    for backend in BACKENDS {
        for flush_first in [false, true] {
            for blocked in [false, true] {
                let (mut peer, session) = connection_pair(backend);
                let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
                let io = GatedIo {
                    input: ScriptedIo {
                        reads: VecDeque::from([bytes::Bytes::from_static(
                            b"\x17\x03\x03\x00\x03bad",
                        )]),
                    },
                    gate: gate.clone(),
                };
                let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
                let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
                let mut cx = Context::from_waker(noop_waker_ref());
                assert!(matches!(
                    Pin::new(&mut vision).poll_write(&mut cx, &hello),
                    Poll::Ready(Ok(n)) if n == hello.len()
                ));
                gate.lock().unwrap().blocked = blocked;
                assert!(matches!(
                    Pin::new(&mut vision).poll_write(&mut cx, application),
                    Poll::Ready(Ok(n)) if n == application.len()
                ));
                if flush_first {
                    let result = Pin::new(&mut vision).poll_flush(&mut cx);
                    if blocked {
                        assert!(result.is_pending());
                    } else {
                        assert!(matches!(result, Poll::Ready(Ok(()))));
                    }
                }
                let sent_before_read = gate.lock().unwrap().output.clone();
                let mut bytes = [0; 8];
                assert!(matches!(
                    Pin::new(&mut vision).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
                    Poll::Ready(Err(_))
                ));
                assert_eq!(gate.lock().unwrap().output, sent_before_read);

                gate.lock().unwrap().blocked = false;
                assert!(matches!(
                    Pin::new(&mut vision).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(
                    Pin::new(&mut vision).poll_shutdown(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let ciphertext = gate.lock().unwrap().output.clone();
                peer.feed(&ciphertext).unwrap();
                let mut plaintext = Vec::new();
                if let Err(error) = peer.reader().read_to_end(&mut plaintext) {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                }
                assert!(matches!(peer.reader().fill_buf(),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                assert_eq!(&plaintext[..2], &[0, 0]);
                let result = VisionUnpadder::new(uuid).unpad(&plaintext[2..]).unwrap();
                assert_eq!(result.command, Some(UnpadCommand::Direct));
                assert_eq!(result.content, [hello.as_ref(), application].concat());
            }
        }
    }
}

#[test]
fn direct_transition_keeps_reads_live_under_output_backpressure() {
    let hello = inner_server_hello();
    let application = b"\x17\x03\x03\x00\x03app";
    let uuid = [7; 16];
    for backend in BACKENDS {
        let (mut peer, session) = connection_pair(backend);
        let mut reply = uuid.to_vec();
        reply.extend_from_slice(&[COMMAND_CONTINUE, 0, 5, 0, 0]);
        reply.extend_from_slice(b"reply");
        let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
        let io = GatedIo {
            input: ScriptedIo {
                reads: VecDeque::from([encrypt(&mut peer, &reply).into()]),
            },
            gate: gate.clone(),
        };
        let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
        let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            Pin::new(&mut vision).poll_write(&mut cx, &hello),
            Poll::Ready(Ok(n)) if n == hello.len()
        ));
        gate.lock().unwrap().blocked = true;
        gate.lock().unwrap().flush_blocked = true;
        assert!(matches!(
            Pin::new(&mut vision).poll_write(&mut cx, application),
            Poll::Ready(Ok(n)) if n == application.len()
        ));
        assert!(
            Pin::new(&mut vision)
                .poll_write(&mut cx, b"raw")
                .is_pending()
        );
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut vision).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"reply");

        gate.lock().unwrap().blocked = false;
        assert!(
            Pin::new(&mut vision)
                .poll_write(&mut cx, b"raw")
                .is_pending()
        );
        let ciphertext = gate.lock().unwrap().output.clone();
        gate.lock().unwrap().flush_blocked = false;
        assert!(matches!(
            Pin::new(&mut vision).poll_write(&mut cx, b"raw"),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(
            gate.lock().unwrap().output,
            [ciphertext.as_slice(), b"raw"].concat()
        );
    }
}

#[test]
fn record_preservation_survives_pending_between_fragments() {
    for backend in BACKENDS {
        let (mut sender, session) = connection_pair(backend);
        let uuid = [7; 16];
        let mut plaintext = uuid.to_vec();
        plaintext.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
        plaintext.extend_from_slice(b"one");
        let ciphertext = encrypt(&mut sender, &plaintext);
        let (io, mut peer) = tokio::io::duplex(4096);
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, &ciphertext[..3]),
            Poll::Ready(Ok(3))
        ));
        let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
        let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
        let mut bytes = [0; 16];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut vision)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
        assert!(buf.filled().is_empty());
        let tail = [&ciphertext[3..], b"-raw"].concat();
        assert!(matches!(
            Pin::new(&mut peer).poll_write(&mut cx, &tail),
            Poll::Ready(Ok(n)) if n == tail.len()
        ));
        assert_buffered_reads(&mut vision, b"one-raw");
    }
}

#[tokio::test]
async fn vision_target_plain_udp_preserves_preread_and_following_records() {
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    use crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream;

    for backend in BACKENDS {
        for addon in [b"".as_slice(), b"\x0a\x10xtls-rprx-vision".as_slice()] {
            let (mut client, server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut request = vec![0];
            request.extend_from_slice(&uuid);
            request.push(addon.len() as u8);
            request.extend_from_slice(addon);
            request.extend_from_slice(&[2, 0, 53, 1, 127, 0, 0, 1]);
            request.extend_from_slice(&1000u16.to_be_bytes());
            request.extend_from_slice(&[42; 1000]);
            let mut first = encrypt(&mut client, &request);
            let second = encrypt(&mut client, b"\x00\x03two");
            first.extend_from_slice(&second[..3]);
            let io = ScriptedIo {
                reads: VecDeque::from([first.into(), second[3..].to_vec().into()]),
            };
            let tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let result = setup_custom_tls_vision_vless_server_stream(
                tls,
                &uuid,
                true,
                Arc::new(ClientProxySelector::new(Vec::new())),
                &resolver,
                None,
            )
            .await
            .unwrap();
            let TcpServerSetupResult::BidirectionalUdp {
                mut stream,
                need_initial_flush,
                ..
            } = result
            else {
                panic!("expected ordinary UDP on the Vision-enabled target");
            };
            assert!(!need_initial_flush);
            for expected in [vec![42; 1000], b"two".to_vec()] {
                let mut bytes = [0; 1024];
                let mut buf = ReadBuf::new(&mut bytes);
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut *stream).poll_read_message(cx, &mut buf)
                })
                .await
                .unwrap();
                assert_eq!(buf.filled(), expected);
            }
        }
    }
}

#[tokio::test]
async fn vision_target_auth_fallback_preserves_all_plaintext() {
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::resolver::{NativeResolver, Resolver};
    use crate::tcp::tcp_handler::TcpServerSetupResult;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for backend in BACKENDS {
        for invalid_version in [false, true] {
            let (mut client, server) = connection_pair(backend);
            let mut expected = vec![u8::from(invalid_version)];
            expected.extend_from_slice(&[8; 16]);
            let mut first = encrypt(&mut client, &expected);
            let suffix = vec![42; 1000];
            let second = encrypt(&mut client, &suffix);
            expected.extend_from_slice(&suffix);
            first.extend_from_slice(&second[..3]);
            let mut remaining = second[3..].to_vec();
            client.send_close_notify();
            client.write_tls(&mut remaining).unwrap();
            let io = ScriptedIo {
                reads: VecDeque::from([first.into(), remaining.into()]),
            };
            let tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let fallback = NetLocation::new(
                Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                listener.local_addr().unwrap().port(),
            );
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let result =
                super::super::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                    tls,
                    &[7; 16],
                    true,
                    Arc::new(ClientProxySelector::new(Vec::new())),
                    &resolver,
                    Some(fallback),
                )
                .await
                .unwrap();
            let TcpServerSetupResult::Session(session) = result else {
                panic!("expected authentication fallback");
            };
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(session, async {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut received = Vec::new();
                    socket.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, expected);
                    socket.shutdown().await.unwrap();
                });
            })
            .await
            .unwrap();
        }
    }
}

#[test]
fn closure_framed_tls_rejects_unclean_eof() {
    for backend in BACKENDS {
        for framed in [false, true] {
            let (_, session) = connection_pair(backend);
            let io = ScriptedIo {
                reads: VecDeque::from([bytes::Bytes::new()]),
            };
            let mut stream = CryptoTlsStream::new(io, session, framed.then(TlsDeframer::new));
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut bytes = [0; 8];
            let mut buf = ReadBuf::new(&mut bytes);
            let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
            assert!(
                matches!(result, Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof),
                "framed={framed}: {result:?}"
            );
        }
    }
}

#[test]
fn closure_vision_recognizes_close_notify_without_tcp_eof() {
    for backend in BACKENDS {
        let (mut client, server) = connection_pair(backend);
        let uuid = [7; 16];
        let mut plaintext = uuid.to_vec();
        plaintext.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
        plaintext.extend_from_slice(b"one");
        let mut ciphertext = encrypt(&mut client, &plaintext);
        client.send_close_notify();
        client.write_tls(&mut ciphertext).unwrap();
        let io = ScriptedIo {
            reads: VecDeque::from([ciphertext.into()]),
        };
        let mut stream = VisionStream::new_server(
            CryptoTlsStream::new(io, server, Some(TlsDeframer::new())),
            uuid,
            b"",
        )
        .unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut bytes = [0; 8];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"one");
        buf.clear();
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
        assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
        assert!(buf.filled().is_empty());
    }
}

#[test]
fn tls_handoff_preserves_partial_record() {
    for backend in BACKENDS {
        for split in [1, 2, 3, 4, 5, 10, 5000, usize::MAX] {
            let (mut client, server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut first = vec![0];
            first.extend_from_slice(&uuid);
            first.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
            first.extend_from_slice(b"one");
            let mut ciphertext = encrypt(&mut client, &first);
            let mut second = vec![COMMAND_CONTINUE];
            second.extend_from_slice(&10_000u16.to_be_bytes());
            second.extend_from_slice(&[0, 0]);
            second.resize(10_005, b'Z');
            let next_record = encrypt(&mut client, &second);
            let split = split.min(next_record.len() - 1);
            ciphertext.extend_from_slice(&next_record[..split]);
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext.into(), next_record[split..].to_vec().into()]),
            };
            let mut tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut header = [255];
            let mut buf = ReadBuf::new(&mut header);
            assert!(matches!(
                Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(header, [0]);

            let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
            let mut expected = b"one".to_vec();
            expected.resize(10_003, b'Z');
            assert_buffered_reads(&mut vision, &expected);
        }
    }
}

#[test]
fn direct_read_preserves_plaintext_beyond_the_read_buffer() {
    for backend in BACKENDS {
        for is_server in [false, true] {
            let (client, server) = connection_pair(backend);
            let (session, mut peer) = if is_server {
                (server, client)
            } else {
                (client, server)
            };
            let uuid = [7; 16];
            let mut plaintext = if is_server { Vec::new() } else { vec![0, 0] };
            plaintext.extend_from_slice(&uuid);
            plaintext.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
            plaintext.extend_from_slice(b"one");
            plaintext.extend_from_slice(&[b'Z'; 10_000]);
            let mut ciphertext = encrypt(&mut peer, &plaintext);
            ciphertext.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext.into()]),
            };
            let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
            let mut vision = if is_server {
                VisionStream::new_server(tls, uuid, b"").unwrap()
            } else {
                VisionStream::new_client(tls, uuid).unwrap()
            };
            let mut expected = b"one".to_vec();
            expected.extend_from_slice(&[b'Z'; 10_000]);
            expected.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
            assert_buffered_reads(&mut vision, &expected);
        }
    }
}

#[test]
fn tls_handoff_preserves_coalesced_direct_bytes() {
    for backend in BACKENDS {
        for raw_tail in [b"-three".as_slice(), b"\x17\x03\x03\x00\x03raw"] {
            let (mut client, server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut first = vec![0];
            first.extend_from_slice(&uuid);
            first.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
            first.extend_from_slice(b"one-two");
            let mut ciphertext = encrypt(&mut client, &first);
            ciphertext.extend_from_slice(raw_tail);
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext.into()]),
            };
            let mut tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut header = [255];
            let mut buf = ReadBuf::new(&mut header);
            assert!(matches!(
                Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(header, [0]);

            let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
            let mut expected = b"one-two".to_vec();
            expected.extend_from_slice(raw_tail);
            assert_buffered_reads(&mut vision, &expected);
            assert_eq!(vision.read_mode, VisionMode::Direct);
        }
    }
}

#[test]
fn client_response_preserves_coalesced_direct_bytes() {
    for backend in BACKENDS {
        for header_split in [0, 1, 3] {
            let (client, mut server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut ciphertext = Vec::new();
            let mut response = vec![0, 3, 1, 2, 3];
            if header_split != 0 {
                ciphertext.extend(encrypt(&mut server, &response[..header_split]));
                response.drain(..header_split);
            }
            response.extend_from_slice(&uuid);
            response.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
            response.extend_from_slice(b"one-two");
            ciphertext.extend(encrypt(&mut server, &response));
            ciphertext.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext.into()]),
            };
            let mut vision = VisionStream::new_client(
                CryptoTlsStream::new(io, client, Some(TlsDeframer::new())),
                uuid,
            )
            .unwrap();
            assert_buffered_reads(&mut vision, b"one-two\x17\x03\x03\x00\x03raw");
            assert_eq!(vision.read_mode, VisionMode::Direct);
        }
    }
}

#[tokio::test]
async fn handshake_handoff_preserves_partial_record() {
    for backend in [Backend::Tls13, Backend::Reality] {
        let (mut client, mut server) = new_connections(backend);
        transfer_tls(&mut client, &mut server);
        transfer_tls(&mut server, &mut client);
        assert!(!client.is_handshaking());
        assert!(server.is_handshaking());

        let mut flight = Vec::new();
        client.write_tls(&mut flight).unwrap();
        let uuid = [7; 16];
        let mut first = vec![0];
        first.extend_from_slice(&uuid);
        first.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
        first.extend_from_slice(b"one");
        flight.extend(encrypt(&mut client, &first));
        let next_record = encrypt(&mut client, b"\x00\x00\x04\x00\x00-two");
        flight.extend_from_slice(&next_record[..10]);
        let io: Box<dyn AsyncStream> = Box::new(ScriptedIo {
            reads: VecDeque::from([
                flight[3..].to_vec().into(),
                next_record[10..].to_vec().into(),
            ]),
        });
        let mut tls = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            CryptoTlsStream::handshake(io, server, TlsReadMode::PreserveRecords, &flight[..3]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut header = [255];
        let mut buf = ReadBuf::new(&mut header);
        assert!(matches!(
            Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(header, [0]);
        let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
        assert_buffered_reads(&mut vision, b"one-two");
    }
}

#[tokio::test]
async fn tls12_client_handshake_preserves_buffered_response() {
    let (mut client, mut server) = new_connections(Backend::Tls12);
    transfer_tls(&mut client, &mut server);
    transfer_tls(&mut server, &mut client);
    transfer_tls(&mut client, &mut server);
    assert!(client.is_handshaking());

    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();
    let uuid = [7; 16];
    let mut response = vec![0, 0];
    response.extend_from_slice(&uuid);
    response.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
    response.extend_from_slice(b"one");
    let application_record = encrypt(&mut server, &response);
    assert!(!application_record.is_empty());
    flight.extend(application_record);
    flight.extend_from_slice(b"-two");
    let io: Box<dyn AsyncStream> = Box::new(ScriptedIo {
        reads: VecDeque::from([flight.into()]),
    });
    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        CryptoTlsStream::handshake(io, client, TlsReadMode::PreserveRecords, &[]),
    )
    .await
    .unwrap()
    .unwrap();
    let mut vision = VisionStream::new_client(tls, uuid).unwrap();
    assert_buffered_reads(&mut vision, b"one-two");
}

#[test]
fn transferred_records_are_read_before_polling_the_socket() {
    for backend in BACKENDS {
        let (client, mut server) = connection_pair(backend);
        let uuid = [7; 16];
        let mut response = vec![0, 0];
        response.extend_from_slice(&uuid);
        response.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
        response.extend_from_slice(b"one");
        let mut deframer = TlsDeframer::new();
        deframer.feed(&encrypt(&mut server, &response));
        deframer.feed(&encrypt(&mut server, b"\x00\x00\x04\x00\x00-two"));
        let io = ScriptedIo {
            reads: VecDeque::new(),
        };
        let mut vision =
            VisionStream::new_client(CryptoTlsStream::new(io, client, Some(deframer)), uuid)
                .unwrap();
        assert_buffered_reads(&mut vision, b"one-two");
    }
}

#[test]
fn initial_direct_orders_plaintext_before_deframer_tail() {
    for backend in BACKENDS {
        let (mut client, mut server) = connection_pair(backend);
        let uuid = [7; 16];
        let mut initial = uuid.to_vec();
        initial.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
        initial.extend_from_slice(b"one");
        server.feed(&encrypt(&mut client, b"-two")).unwrap();
        let mut deframer = TlsDeframer::new();
        deframer.feed(b"-three");
        let io = ScriptedIo {
            reads: VecDeque::new(),
        };
        let mut vision = VisionStream::new_server(
            CryptoTlsStream::new(io, server, Some(deframer)),
            uuid,
            &initial,
        )
        .unwrap();
        assert_buffered_reads(&mut vision, b"one-two-three");
    }
}

#[test]
fn initial_end_preserves_queued_records_and_partial_ciphertext() {
    for backend in BACKENDS {
        let (mut client, mut server) = connection_pair(backend);
        let uuid = [7; 16];
        let mut initial = uuid.to_vec();
        initial.extend_from_slice(&[COMMAND_END, 0, 3, 0, 0]);
        initial.extend_from_slice(b"one");
        server.feed(&encrypt(&mut client, b"-two")).unwrap();
        let mut deframer = TlsDeframer::new();
        deframer.feed(&encrypt(&mut client, b"-three"));
        let last = encrypt(&mut client, b"-four");
        deframer.feed(&last[..10]);
        let io = ScriptedIo {
            reads: VecDeque::from([last[10..].to_vec().into()]),
        };
        let mut vision = VisionStream::new_server(
            CryptoTlsStream::new(io, server, Some(deframer)),
            uuid,
            &initial,
        )
        .unwrap();
        assert_buffered_reads(&mut vision, b"one-two-three-four");
    }
}

#[test]
fn framed_tls_drains_large_preread_in_both_directions() {
    let payload = vec![b'Q'; 40_000];
    for backend in BACKENDS {
        let (mut client, mut server) = connection_pair(backend);
        let request = encrypt(&mut client, &payload);
        let response = encrypt(&mut server, &payload);
        for (session, ciphertext) in [(server, request), (client, response)] {
            let mut deframer = TlsDeframer::new();
            deframer.feed(&ciphertext);
            let io = ScriptedIo {
                reads: VecDeque::new(),
            };
            let mut stream = CryptoTlsStream::new(io, session, Some(deframer));
            assert_buffered_reads(&mut stream, &payload);
        }
    }
}

#[test]
fn framed_tls_without_vision_handoff_preserves_both_directions() {
    for backend in BACKENDS {
        let (mut client, mut server) = connection_pair(backend);
        let request = [encrypt(&mut client, b"one"), encrypt(&mut client, b"-two")].concat();
        let response = [
            encrypt(&mut server, b"three"),
            encrypt(&mut server, b"-four"),
        ]
        .concat();
        for (session, ciphertext, expected) in [
            (server, request, b"one-two".as_slice()),
            (client, response, b"three-four".as_slice()),
        ] {
            let mut deframer = TlsDeframer::new();
            deframer.feed(&ciphertext[..8]);
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext[8..].to_vec().into()]),
            };
            let mut stream = CryptoTlsStream::new(io, session, Some(deframer));
            assert_buffered_reads(&mut stream, expected);
        }
    }
}

fn assert_initial_mode_transition(command: UnpadCommand, session_plaintext: &[u8]) {
    let uuid = [7; 16];
    let mut initial = uuid.to_vec();
    initial.extend_from_slice(&[command as u8, 0, 3, 0, 2]);
    initial.extend_from_slice(b"one\0\0-two");

    let (mut peer, mut session) = crate::reality::established_pair();
    if !session_plaintext.is_empty() {
        peer.writer().write_all(session_plaintext).unwrap();
        let mut ciphertext = Vec::new();
        peer.write_tls(&mut ciphertext).unwrap();
        session.feed(&ciphertext).unwrap();
    }

    let (io, _peer) = tokio::io::duplex(64);
    let mut stream = VisionStream::new_server(
        CryptoTlsStream::new(io, session, Some(TlsDeframer::new())),
        uuid,
        &initial,
    )
    .unwrap();
    let expected_mode = match command {
        UnpadCommand::End => VisionMode::Tls,
        UnpadCommand::Direct => VisionMode::Direct,
        UnpadCommand::Continue => panic!("expected a final padding command"),
    };
    assert_eq!(stream.read_mode, expected_mode);

    let mut expected = b"one-two".to_vec();
    expected.extend_from_slice(session_plaintext);
    assert_buffered_reads(&mut stream, &expected);
    assert!(stream.pending_read.is_empty());
}

#[test]
fn initial_end_preserves_session_plaintext() {
    assert_initial_mode_transition(UnpadCommand::End, b"-three");
}

#[test]
fn initial_end_accepts_empty_session() {
    assert_initial_mode_transition(UnpadCommand::End, b"");
}

#[test]
fn initial_direct_preserves_session_plaintext() {
    assert_initial_mode_transition(UnpadCommand::Direct, b"-three");
}

#[test]
fn initial_direct_accepts_empty_session() {
    assert_initial_mode_transition(UnpadCommand::Direct, b"");
}
