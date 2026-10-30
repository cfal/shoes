use super::*;
use crate::crypto::TlsConnection;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct TargetReads {
    chunks: std::collections::VecDeque<Bytes>,
    reads: usize,
}

impl AsyncRead for TargetReads {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(chunk) = self.chunks.pop_front() else {
            // An open, idle target must not make collection wait for an unseen seventh record.
            return Poll::Pending;
        };
        assert!(chunk.len() <= buffer.remaining());
        buffer.put_slice(&chunk);
        self.reads += 1;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn target_collection_respects_observed_read_boundaries() {
    use crate::reality::CipherSuite;
    use crate::reality::reality_hello::RealityGroup;
    use crate::reality::tests::reality_fixtures::{
        configs, separate_target_records, write_record_header,
    };

    for case in ["six", "seven", "split-seven", "combined-trailing"] {
        let (client_config, server_config) = configs(CipherSuite::AES_128_GCM_SHA256);
        let mut client = client_config.create_connection().unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut records = if case == "combined-trailing" {
            crate::reality::default_target_records(&hello[44..76])
        } else {
            separate_target_records(
                RealityGroup::X25519MlKem768,
                CipherSuite::AES_128_GCM_SHA256,
                &hello[44..76],
            )
        };
        if matches!(case, "seven" | "split-seven") {
            let mut trailing = write_record_header(23, 59);
            trailing.resize(64, 0);
            records.push(trailing.into());
        }
        let mut wire = records.concat();
        let remaining: &[u8] = if case == "combined-trailing" {
            &[23, 3, 3]
        } else {
            &[]
        };
        wire.extend_from_slice(remaining);
        let chunks = if case == "split-seven" {
            let split = wire.len() - 61;
            vec![
                Bytes::copy_from_slice(&wire[..split]),
                Bytes::copy_from_slice(&wire[split..]),
            ]
        } else {
            vec![Bytes::copy_from_slice(&wire)]
        };
        let expected_reads = chunks.len();
        let mut target = TargetReads {
            chunks: chunks.into(),
            reads: 0,
        };
        let flight = tokio::time::timeout(
            Duration::from_secs(1),
            read_target_flight(&mut target, &server_config.dest, true),
        )
        .await
        .expect(case)
        .unwrap();
        assert_eq!(target.reads, expected_reads, "{case}");
        assert_eq!(flight.records, records, "{case}");
        assert_eq!(flight.remaining.as_ref(), remaining, "{case}");
        assert_eq!(flight.usable, case != "combined-trailing", "{case}");
        if flight.usable {
            let mut server = server_config
                .authenticate_client_hello(&hello)
                .unwrap()
                .into_connection(&flight.records)
                .unwrap();
            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            client.feed(&wire).unwrap();
            wire.clear();
            client.write_tls(&mut wire).unwrap();
            server.feed(&wire).unwrap();
            assert!(
                !client.is_handshaking() && !server.is_handshaking(),
                "{case}"
            );
        }
    }
}

#[test]
fn synthesis_failures_only_forward_explicit_incompatibilities() {
    assert_eq!(forward_unsupported(Ok(())).unwrap(), Some(()));
    assert_eq!(
        forward_unsupported::<()>(Err(io::ErrorKind::Unsupported.into())).unwrap(),
        None
    );
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::Other,
    ] {
        let error = io::Error::new(kind, "injected synthesis failure");
        let propagated = forward_unsupported::<()>(Err(error)).unwrap_err();
        assert_eq!(propagated.kind(), kind);
        assert_eq!(propagated.to_string(), "injected synthesis failure");
    }
}

fn client_key_share_offsets(hello: &[u8]) -> Vec<usize> {
    use crate::buf_reader::BufReader;

    let mut reader = BufReader::new(hello);
    reader.skip(43).unwrap();
    let session_len = reader.read_u8().unwrap() as usize;
    reader.skip(session_len).unwrap();
    let cipher_len = reader.read_u16_be().unwrap() as usize;
    reader.skip(cipher_len).unwrap();
    let compression_len = reader.read_u8().unwrap() as usize;
    reader.skip(compression_len).unwrap();
    let extensions_len = reader.read_u16_be().unwrap() as usize;
    assert_eq!(extensions_len, reader.remaining());
    while !reader.is_consumed() {
        let id = reader.read_u16_be().unwrap();
        let len = reader.read_u16_be().unwrap() as usize;
        let start = reader.position();
        let data = reader.read_slice(len).unwrap();
        if id == 51 {
            let mut shares = BufReader::new(data);
            let len = shares.read_u16_be().unwrap() as usize;
            assert_eq!(len, shares.remaining());
            let mut offsets = Vec::new();
            while !shares.is_consumed() {
                offsets.push(start + shares.position());
                shares.skip(2).unwrap();
                let len = shares.read_u16_be().unwrap() as usize;
                shares.skip(len).unwrap();
            }
            return offsets;
        }
    }
    panic!("missing key_share extension");
}

#[tokio::test]
async fn incompatible_hellos_and_small_targets_forward_unchanged() {
    use crate::client_proxy_chain::InitialHopEntry;
    use crate::port_forward_handler::PortForwardServerHandler;
    use crate::reality::reality_hello::RealityGroup;
    use crate::reality::tests::reality_fixtures::{
        configs, separate_target_records, target_with_unknown_extension, write_record_header,
    };
    use crate::reality::{CipherSuite, mldsa65_signing_key};
    use crate::tcp::socket_connector_impl::SocketConnectorImpl;

    for case in [
        "small",
        "small-separate",
        "retry",
        "unsupported",
        "client-unknown-shares",
        "client-truncated-share",
        "client-bad-auth",
        "bad-late-record",
        "bad-ccs",
        "wrong-session",
        "unknown-extension",
        "combined-trailing",
    ] {
        let capture = crate::logging::test_capture::Capture::new();
        let (cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
        let (seed, _) = crate::reality::generate_mldsa65_keypair().unwrap();
        sc.mldsa65_key = Some(mldsa65_signing_key(&seed).unwrap());
        let mut client = cc.create_connection().unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let auth_failure = matches!(
            case,
            "client-unknown-shares" | "client-truncated-share" | "client-bad-auth"
        );
        let mut response = match case {
            "client-unknown-shares" | "client-truncated-share" | "client-bad-auth" => {
                let offsets = client_key_share_offsets(&hello);
                assert_eq!(offsets.len(), 2);
                let expected_error = match case {
                    "client-unknown-shares" => {
                        for (offset, group) in offsets.into_iter().zip([0xfe30u16, 0xfe31]) {
                            hello[offset..offset + 2].copy_from_slice(&group.to_be_bytes());
                        }
                        io::ErrorKind::InvalidData
                    }
                    "client-truncated-share" => {
                        // Keeps the TLS framing valid while overstating the last share's length.
                        let offset = offsets[1] + 2;
                        assert_eq!(&hello[offset..offset + 2], &[0, 32]);
                        hello[offset..offset + 2].copy_from_slice(&33u16.to_be_bytes());
                        io::ErrorKind::UnexpectedEof
                    }
                    _ => {
                        hello[44] ^= 1;
                        io::ErrorKind::PermissionDenied
                    }
                };
                let check = sc.clone();
                assert_eq!(
                    check.authenticate_client_hello(&hello).unwrap_err().kind(),
                    expected_error
                );
                // A valid target flight reaches the admission-error branch, not hello fallback.
                crate::reality::default_target_records(&hello[44..76]).concat()
            }
            "small" | "small-separate" => {
                let (mut records, small_record) = if case == "small" {
                    (crate::reality::default_target_records(&hello[44..76]), 2)
                } else {
                    (
                        separate_target_records(
                            RealityGroup::X25519MlKem768,
                            CipherSuite::AES_128_GCM_SHA256,
                            &hello[44..76],
                        ),
                        3,
                    )
                };
                let mut encrypted = write_record_header(23, 600);
                encrypted.resize(605, 0);
                records[small_record] = encrypted.into();
                let check = sc.clone();
                let authenticated = check.authenticate_client_hello(&hello).unwrap();
                assert_eq!(
                    authenticated
                        .into_connection(&records)
                        .unwrap_err()
                        .to_string(),
                    "Unsupported REALITY target or insufficient capacity"
                );
                records.concat()
            }
            "bad-late-record" | "bad-ccs" | "wrong-session" | "unknown-extension"
            | "combined-trailing" => {
                let mut records = crate::reality::default_target_records(&hello[44..76]);
                match case {
                    "bad-ccs" => records[1] = Bytes::from_static(&[20, 3, 3, 0, 1, 0]),
                    "wrong-session" => {
                        let mut sh = records[0].to_vec();
                        sh[44] ^= 1;
                        records[0] = sh.into();
                    }
                    "unknown-extension" => records[0] = target_with_unknown_extension(&records[0]),
                    "combined-trailing" => {}
                    "bad-late-record" => records.push(Bytes::from_static(&[255, 3, 3, 0, 0])),
                    _ => unreachable!(),
                }
                records.concat()
            }
            _ => {
                let mut message = vec![2, 0, 0, 0, 3, 3];
                if case == "retry" {
                    let retry_random =
                        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"HelloRetryRequest");
                    message.extend_from_slice(retry_random.as_ref());
                } else {
                    message.extend_from_slice(&[3; 32]);
                }
                message.push(32);
                message.extend_from_slice(&hello[44..76]);
                message.extend_from_slice(&[0x13, 1, 0]);
                let mut extensions = vec![0, 43, 0, 2, 3, 4];
                if case == "retry" {
                    extensions.extend_from_slice(&[0, 51, 0, 2, 0, 23]);
                } else {
                    extensions.extend_from_slice(&[0, 51, 0, 5, 0xfe, 0x30, 0, 1, 1]);
                }
                message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
                message.extend_from_slice(&extensions);
                let len = (message.len() - 4) as u32;
                message[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
                let mut record = write_record_header(22, message.len() as u16);
                record.extend_from_slice(&message);
                record
            }
        };
        // A partial trailing record exercises the deframer's retained bytes.
        if matches!(case, "retry" | "unsupported" | "combined-trailing") {
            response.extend_from_slice(&[23, 3, 3]);
        }

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let dest = NetLocation::new(
            crate::address::Address::Hostname("localhost".into()),
            listener.local_addr().unwrap().port(),
        );
        let selector = Arc::new(ClientProxySelector::new(Vec::new()));
        let target = RealityServerTarget {
            mldsa65_key: sc.mldsa65_key,
            private_key: sc.private_key,
            short_ids: sc.short_ids,
            dest: dest.clone(),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: sc.cipher_suites,
            effective_selector: selector.clone(),
            inner_protocol: InnerProtocol::Normal(Box::new(PortForwardServerHandler::new(
                vec![dest],
                selector,
            ))),
            dest_client_chain: ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Arc::new(
                    SocketConnectorImpl::from_config(&crate::config::ClientConfig::default(), None)
                        .unwrap(),
                ))],
                Vec::new(),
            ),
        };
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let (io, mut peer) = tokio::io::duplex(65536);
        let mut flight = hello.clone();
        flight.extend_from_slice(b"pending");
        peer.write_all(&flight).await.unwrap();
        let mut io: Box<dyn AsyncStream> = Box::new(io);
        let parsed = crate::shadow_tls::read_client_hello(&mut io).await.unwrap();
        assert!(parsed.supports_tls13);
        assert_eq!(parsed.client_reader.unparsed_data(), b"pending");
        let decoy_io = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut forwarded = vec![0; hello.len()];
            socket.read_exact(&mut forwarded).await.unwrap();
            assert_eq!(forwarded, hello);
            socket.write_all(&response).await.unwrap();
            let mut upstream = Vec::new();
            socket.read_to_end(&mut upstream).await.unwrap();
            assert_eq!(upstream, b"pending-live");
            socket.write_all(b"-reply").await.unwrap();
            socket.shutdown().await.unwrap();
        };
        let handler = async {
            let result = setup_reality_server_stream(io, &target, parsed, &resolver)
                .await
                .unwrap();
            let TcpServerSetupResult::Session(session) = result else {
                panic!("expected transparent fallback for {case}");
            };
            session.await;
        };
        let peer_io = async {
            let mut actual = vec![0; response.len()];
            peer.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, response, "{case}");
            peer.write_all(b"-live").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"-reply");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(handler, decoy_io, peer_io);
        })
        .await
        .unwrap_or_else(|_| panic!("transparent forwarding stalled for {case}"));
        let logs = capture.finish();
        if auth_failure {
            assert!(logs.contains("REALITY: Auth failed"), "{case}: {logs}");
        }
        if matches!(case, "small" | "small-separate" | "unknown-extension") {
            assert!(
                logs.contains("Auth succeeded, building response"),
                "{case}: {logs}"
            );
            assert!(
                logs.contains("REALITY: Cannot synthesize"),
                "{case}: {logs}"
            );
        }
        if case == "combined-trailing" {
            assert!(
                logs.contains("REALITY: Dest handshake failed"),
                "{case}: {logs}"
            );
        }
    }
}

#[tokio::test]
async fn authenticated_non_vision_oversized_preread_returns_error_without_panicking() {
    use crate::client_proxy_chain::InitialHopEntry;
    use crate::port_forward_handler::PortForwardServerHandler;
    use crate::reality::RealityClientConfig;
    use crate::tcp::socket_connector_impl::SocketConnectorImpl;
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let dest = NetLocation::new(
        crate::address::Address::Hostname("localhost".into()),
        address.port(),
    );
    let cert = rcgen::generate_simple_self_signed(
        (0..100)
            .map(|index| format!("host-{index}.example.test"))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let decoy_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
    let mut decoy =
        TlsConnection::new(rustls::ServerConnection::new(Arc::new(decoy_config)).unwrap());
    decoy.feed(&hello).unwrap();
    let mut response = Vec::new();
    decoy.write_tls(&mut response).unwrap();
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let target = RealityServerTarget {
        mldsa65_key: None,
        private_key,
        short_ids: vec![[0; 8]],
        dest: dest.clone(),
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: Vec::new(),
        effective_selector: selector.clone(),
        inner_protocol: InnerProtocol::Normal(Box::new(PortForwardServerHandler::new(
            vec![dest],
            selector,
        ))),
        dest_client_chain: ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(
                SocketConnectorImpl::from_config(&crate::config::ClientConfig::default(), None)
                    .unwrap(),
            ))],
            Vec::new(),
        ),
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    // A ClientHello split across records authenticates like a single-record one, while
    // dest still receives the client's records unchanged.
    for wire_hello in [hello.clone(), crate::sniff::tests::records(&hello, 100)] {
        let (io, mut peer) = tokio::io::duplex(65540);
        let mut flight = wire_hello.clone();
        flight.extend_from_slice(&[0x17, 0x03, 0x03, 0, 1, 0].repeat(6000));
        peer.write_all(&flight).await.unwrap();
        let mut io: Box<dyn AsyncStream> = Box::new(io);
        let parsed = crate::shadow_tls::read_client_hello(&mut io).await.unwrap();
        assert!(parsed.client_reader.unparsed_data().len() > 33290);

        let decoy_io = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut forwarded_hello = vec![0; wire_hello.len()];
            socket.read_exact(&mut forwarded_hello).await.unwrap();
            assert_eq!(forwarded_hello, wire_hello);
            socket.write_all(&response).await.unwrap();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                setup_reality_server_stream(io, &target, parsed, &resolver),
                decoy_io,
            )
        })
        .await
        .unwrap();
        let error = result.err().expect("invalid encrypted records must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    }
}

#[tokio::test]
async fn authenticated_vless_handoff_flushes_buffered_response() {
    use crate::async_stream::test_streams::FlushGatedStream;
    use crate::client_proxy_chain::InitialHopEntry;
    use crate::reality::CipherSuite;
    use crate::reality::tests::reality_fixtures::configs;
    use crate::tcp::socket_connector_impl::SocketConnectorImpl;
    use crate::vless::vless_server_handler::VlessTcpServerHandler;

    const USER_ID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";
    let (cc, sc) = configs(CipherSuite::AES_128_GCM_SHA256);
    let mut client = cc.create_connection().unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let response = crate::reality::default_target_records(&hello[44..76]).concat();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let dest = NetLocation::new(
        crate::address::Address::Hostname("localhost".into()),
        listener.local_addr().unwrap().port(),
    );
    let selector = Arc::new(ClientProxySelector::new(Vec::new()));
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let target = RealityServerTarget {
        mldsa65_key: None,
        private_key: sc.private_key,
        short_ids: sc.short_ids,
        dest,
        max_time_diff: None,
        min_client_version: None,
        max_client_version: None,
        cipher_suites: sc.cipher_suites,
        effective_selector: selector.clone(),
        inner_protocol: InnerProtocol::Normal(Box::new(
            VlessTcpServerHandler::new(
                USER_ID,
                false,
                selector,
                resolver.clone(),
                None,
                None,
                false,
            )
            .unwrap(),
        )),
        dest_client_chain: ClientProxyChain::new(
            vec![InitialHopEntry::Direct(Arc::new(
                SocketConnectorImpl::from_config(&crate::config::ClientConfig::default(), None)
                    .unwrap(),
            ))],
            Vec::new(),
        ),
    };
    let (io, mut peer) = tokio::io::duplex(64);
    let server = async {
        let mut io: Box<dyn AsyncStream> = Box::new(FlushGatedStream::new(io));
        let parsed = crate::shadow_tls::read_client_hello(&mut io).await.unwrap();
        let setup = setup_reality_server_stream(io, &target, parsed, &resolver)
            .await
            .unwrap();
        let TcpServerSetupResult::TcpForward {
            mut stream,
            need_initial_flush,
            connection_success_response,
            ..
        } = setup
        else {
            panic!("expected TCP forwarding");
        };
        assert!(need_initial_flush, "REALITY must flush the inner handoff");
        stream
            .write_all(&connection_success_response.unwrap())
            .await
            .unwrap();
        if need_initial_flush {
            stream.flush().await.unwrap();
        }
    };
    let decoy = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut forwarded = vec![0; hello.len()];
        socket.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, hello);
        socket.write_all(&response).await.unwrap();
    };
    let peer = async {
        peer.write_all(&hello).await.unwrap();
        let mut stream = CryptoTlsStream::handshake(peer, client, TlsReadMode::Stream, &[])
            .await
            .unwrap();
        let mut request = vec![0];
        request.extend_from_slice(&crate::uuid_util::parse_uuid(USER_ID).unwrap());
        request.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
        stream.write_all(&request).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 0]);
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, decoy, peer);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fallback_preread_backpressure_does_not_block_server_response() {
    let (client, mut client_peer) = tokio::io::duplex(64);
    let (dest, mut dest_peer) = tokio::io::duplex(64);
    let pending = vec![42; 128];
    let TcpServerSetupResult::Session(session) = start_forward_to_dest(
        Box::new(client),
        Box::new(dest),
        vec![Bytes::from_static(b"server")],
        Bytes::new(),
        Bytes::copy_from_slice(&pending),
    ) else {
        panic!("expected fallback session");
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(session, async {
            let mut response = [0; 6];
            client_peer.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"server");
            let mut received = vec![0; pending.len()];
            dest_peer.read_exact(&mut received).await.unwrap();
            assert_eq!(received, pending);
            client_peer.shutdown().await.unwrap();
            dest_peer.shutdown().await.unwrap();
        });
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fallback_preserves_preread_client_bytes() {
    let (client, mut client_peer) = tokio::io::duplex(64);
    let (dest, mut dest_peer) = tokio::io::duplex(64);
    let TcpServerSetupResult::Session(session) = start_forward_to_dest(
        Box::new(client),
        Box::new(dest),
        vec![Bytes::from_static(b"server")],
        Bytes::from_static(b"-tail"),
        Bytes::from_static(b"client"),
    ) else {
        panic!("expected fallback session");
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(session, async {
            client_peer.write_all(b"-live").await.unwrap();
            client_peer.shutdown().await.unwrap();
            let mut received = [0; 11];
            dest_peer.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"client-live");
            dest_peer.write_all(b"-reply").await.unwrap();
            dest_peer.shutdown().await.unwrap();
            let mut response = Vec::new();
            client_peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"server-tail-reply");
        });
    })
    .await
    .unwrap();
}

struct StalledShutdown {
    fail_write: bool,
    fail_flush: bool,
    _marker: Arc<()>,
}

impl AsyncRead for StalledShutdown {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for StalledShutdown {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail_write {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(bytes.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_flush {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl crate::async_stream::AsyncPing for StalledShutdown {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for StalledShutdown {}

#[tokio::test(start_paused = true)]
async fn fallback_cleanup_is_bounded_after_copy_and_early_errors() {
    let bytes = Bytes::from_static(b"handshake");
    let cases = [
        (false, false, vec![], Bytes::new(), 10),
        (true, false, vec![bytes.clone()], Bytes::new(), 5),
        (false, true, vec![bytes.clone()], Bytes::new(), 5),
        (true, false, vec![], bytes, 5),
    ];
    for (fail_write, fail_flush, records, remaining, seconds) in cases {
        let marker = Arc::new(());
        let client = StalledShutdown {
            fail_write,
            fail_flush,
            _marker: marker.clone(),
        };
        let dest = StalledShutdown {
            fail_write: false,
            fail_flush: false,
            _marker: marker.clone(),
        };
        let TcpServerSetupResult::Session(session) = start_forward_to_dest(
            Box::new(client),
            Box::new(dest),
            records,
            remaining,
            Bytes::new(),
        ) else {
            panic!("fallback must remain owned by its caller")
        };
        let started = tokio::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(11), session)
            .await
            .expect("fallback cleanup retained the streams indefinitely");
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(seconds));
        assert_eq!(Arc::strong_count(&marker), 1);
    }
}
