use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::ClientProxyChain;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::tls_deframer::TlsDeframer;
use crate::crypto::{CryptoConnection, CryptoTlsStream, TlsReadMode};
use crate::prepend_stream::PrependStream;
use crate::resolver::Resolver;
use crate::shadow_tls::{ParsedClientHello, parse_server_hello};
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerSetupResult};
use crate::tls_server_handler::InnerProtocol;
use crate::util::{allocate_vec, write_all};

use super::reality_key_exchange::extract_server_key_share;
use super::{RealityServerConfig, RealityServerConnection};

#[derive(Debug)]
pub struct RealityServerTarget {
    pub mldsa65_key: Option<Arc<aws_lc_rs::signature::PqdsaKeyPair>>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub dest: NetLocation,
    pub max_time_diff: Option<u64>, // in milliseconds
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub cipher_suites: Vec<super::CipherSuite>,
    /// The effective proxy selector for this REALITY target.
    /// For Vision mode, this is passed to the VLESS setup function.
    /// Inner handler already has this selector from construction.
    pub effective_selector: Arc<ClientProxySelector>,
    /// What to do after Reality termination - normal handler, Vision VLESS, or Naive
    pub inner_protocol: InnerProtocol,
    /// Client chain for connecting to dest server (for fallback connections).
    pub dest_client_chain: ClientProxyChain,
}

/// Set up REALITY server stream with real-time mirroring for anti-probing.
///
/// Connect to dest IMMEDIATELY before auth processing, making timing
/// indistinguishable from a real reverse proxy. This defeats active probing.
///
/// Flow:
/// - Connect to dest immediately
/// - Forward ClientHello immediately (starts dest's handshake)
/// - Validate auth (fast, ~1ms, while dest is processing)
/// - Read dest's response (it's been processing in parallel)
/// - Branch based on auth:
///   - Auth failed: forward dest's response, continue bidirectional copy
///   - Auth succeeded: build REALITY response matching dest's structure
#[inline]
pub async fn setup_reality_server_stream(
    server_stream: Box<dyn AsyncStream>,
    target: &RealityServerTarget,
    parsed_client_hello: ParsedClientHello,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    let client_hello_frame = &parsed_client_hello.client_hello_frame;
    let client_pending = Bytes::copy_from_slice(parsed_client_hello.client_reader.unparsed_data());
    log::debug!(
        "REALITY ClientHello frame length: {}",
        client_hello_frame.len()
    );

    // Connect to dest before auth processing to minimize timing differences
    let TcpClientSetupResult {
        client_stream: mut dest_stream,
        early_data,
    } = target
        .dest_client_chain
        .connect_tcp(target.dest.clone().into(), resolver)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("REALITY: Failed to connect to dest {}: {}", target.dest, e),
            )
        })?;

    debug_assert!(
        early_data.is_none(),
        "unexpected early_data from dest connection"
    );

    log::debug!(
        "REALITY: Connected to dest {}, forwarding ClientHello ({} bytes)",
        target.dest,
        client_hello_frame.len()
    );

    write_all(&mut dest_stream, client_hello_frame).await?;
    dest_stream.flush().await?;

    if !parsed_client_hello.supports_tls13 {
        log::warn!("REALITY: Client does not support TLS 1.3, falling back to dest");
        return Ok(start_forward_to_dest(
            server_stream,
            dest_stream,
            vec![],
            Bytes::new(),
            client_pending,
        ));
    }

    let reality_config = RealityServerConfig {
        mldsa65_key: target.mldsa65_key.clone(),
        private_key: target.private_key,
        short_ids: target.short_ids.clone(),
        dest: target.dest.clone(),
        max_time_diff: target.max_time_diff,
        min_client_version: target.min_client_version,
        max_client_version: target.max_client_version,
        cipher_suites: target.cipher_suites.clone(),
    };

    let mut reality_conn = RealityServerConnection::new(reality_config)?;

    let auth_result = reality_conn.validate_client_hello(client_hello_frame);

    // Read dest response until we have enough records. Use 512-byte heuristic like XTLS/REALITY:
    // first encrypted record > 512 bytes = combined mode, <= 512 bytes = separate mode
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut dest_records: Vec<Bytes> = Vec::new();
    let mut buf = allocate_vec(8192).into_boxed_slice();
    let mut dest_handshake_success = false;

    loop {
        let new_records = match timeout_at(deadline, dest_stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                return Err(std::io::Error::other(
                    "REALITY: Dest connection closed during TLS handshake",
                ));
            }
            Ok(Ok(n)) => {
                deframer.feed(&buf[..n]);
                match deframer.next_records() {
                    Ok(records) => records,
                    Err(e) => {
                        log::error!("REALITY: Error parsing dest records: {}", e);
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                return Err(std::io::Error::other(format!(
                    "REALITY: Error reading from dest: {}",
                    e
                )));
            }
            Err(_) => {
                log::debug!("REALITY: Timeout reading from dest");
                break;
            }
        };

        // When we get the first record (ServerHello), check if dest supports TLS 1.3
        if dest_records.is_empty() && !new_records.is_empty() {
            match parse_server_hello(&new_records[0]) {
                Ok(parsed) => {
                    if !parsed.is_tls13 || extract_server_key_share(&new_records[0]).is_err() {
                        log::log!(
                            if auth_result.is_ok() {
                                log::Level::Warn
                            } else {
                                log::Level::Debug
                            },
                            "REALITY: Dest {} has an unsupported TLS hello, forwarding transparently",
                            target.dest
                        );
                        return Ok(start_forward_to_dest(
                            server_stream,
                            dest_stream,
                            new_records,
                            deframer.into_remaining_data(),
                            client_pending,
                        ));
                    }
                    log::debug!("REALITY: Dest confirmed TLS 1.3");
                }
                Err(e) => {
                    log::log!(
                        if auth_result.is_ok() {
                            log::Level::Warn
                        } else {
                            log::Level::Debug
                        },
                        "REALITY: Failed to parse dest ServerHello: {}, forwarding transparently",
                        e
                    );
                    return Ok(start_forward_to_dest(
                        server_stream,
                        dest_stream,
                        new_records,
                        deframer.into_remaining_data(),
                        client_pending,
                    ));
                }
            }
        }

        dest_records.extend(new_records);

        // Separate mode: first encrypted record is small, need more records
        // Keep reading until we have 6 records (SH + CCS + 4 encrypted) or timeout
        // Note: Some servers send NewSessionTicket as a 7th record, but we don't need it
        if dest_records.len() >= 6 {
            log::debug!(
                "REALITY: Separate mode detected, got {} records",
                dest_records.len()
            );
            dest_handshake_success = true;
            break;
        } else if dest_records.len() >= 3 {
            // Check if we have enough records using the 512-byte heuristic
            // Records: [0]=ServerHello, [1]=CCS, [2..]=encrypted handshake
            let first_encrypted = &dest_records[2];
            if first_encrypted.len() > 512 {
                // Combined mode: first encrypted record > 512 bytes contains all messages
                log::debug!(
                    "REALITY: Combined mode detected (first encrypted record {} bytes > 512)",
                    first_encrypted.len()
                );
                dest_handshake_success = true;
                break;
            }
        }
    }

    let remaining_data = deframer.into_remaining_data();

    if !dest_handshake_success {
        log::warn!(
            "REALITY: Dest handshake failed (got {} records), falling back to transparent forward",
            dest_records.len()
        );
        return Ok(start_forward_to_dest(
            server_stream,
            dest_stream,
            dest_records,
            remaining_data,
            client_pending,
        ));
    }

    log::debug!(
        "REALITY: Read {} records from dest ({} bytes remaining)",
        dest_records.len(),
        remaining_data.len()
    );

    // Branch based on auth result. We don't short circuit on permission denied before the
    // read loop above so that the timing is always the same.
    match auth_result {
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::InvalidData
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            log::warn!(
                "REALITY: Auth failed ({}), forwarding to dest transparently",
                e
            );
            return Ok(start_forward_to_dest(
                server_stream,
                dest_stream,
                dest_records,
                remaining_data,
                client_pending,
            ));
        }

        Err(e) => {
            log::error!("REALITY: Unexpected error during auth: {}", e);
            return Err(e);
        }

        Ok(()) => {}
    }

    log::debug!("REALITY: Auth succeeded, building response matching dest structure");

    if should_forward_to_dest(reality_conn.build_server_response(&dest_records))? {
        return Ok(start_forward_to_dest(
            server_stream,
            dest_stream,
            dest_records,
            remaining_data,
            client_pending,
        ));
    }
    drop(dest_stream);

    let connection = CryptoConnection::new_reality_server(reality_conn);
    let mode = match target.inner_protocol {
        InnerProtocol::VisionVless(_) => TlsReadMode::PreserveRecords,
        _ => TlsReadMode::Stream,
    };
    let tls_stream =
        CryptoTlsStream::handshake(server_stream, connection, mode, &client_pending).await?;
    log::debug!("REALITY: TLS 1.3 handshake completed successfully");

    match &target.inner_protocol {
        InnerProtocol::Normal(handler) => handler.setup_server_stream(Box::new(tls_stream)).await,
        InnerProtocol::VisionVless(vision_cfg) => {
            crate::vless::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                tls_stream,
                &vision_cfg.user_id,
                vision_cfg.udp_enabled,
                target.effective_selector.clone(),
                resolver,
                vision_cfg.fallback.clone(),
            )
            .await
        }
        InnerProtocol::Naive(naive_cfg) => {
            crate::naiveproxy::setup_naive_server_stream(
                tls_stream,
                naive_cfg,
                target.effective_selector.clone(),
                resolver.clone(),
            )
            .await
        }
    }
}

fn should_forward_to_dest(response: std::io::Result<()>) -> std::io::Result<bool> {
    match response {
        Ok(()) => Ok(false),
        // Only explicitly classified target incompatibilities permit fallback.
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            log::warn!("REALITY: Cannot synthesize target handshake ({e}), forwarding");
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Return an owned fallback transfer after forwarding the ClientHello.
fn start_forward_to_dest(
    client_stream: Box<dyn AsyncStream>,
    mut dest_stream: Box<dyn AsyncStream>,
    dest_records: Vec<Bytes>,
    remaining_data: Bytes,
    client_pending: Bytes,
) -> TcpServerSetupResult {
    TcpServerSetupResult::Session(Box::pin(async move {
        // Replay preread bytes through the bidirectional pump so a blocked client
        // write cannot prevent the destination's response from reaching the client.
        let mut client_stream = PrependStream::new(
            client_stream,
            (!client_pending.is_empty()).then(|| client_pending.to_vec().into_boxed_slice()),
        );

        for record in &dest_records {
            if let Err(e) = write_all(&mut client_stream, record).await {
                log::debug!("REALITY FALLBACK: Error forwarding record: {}", e);
                futures::join!(
                    crate::util::shutdown_stream(&mut client_stream),
                    crate::util::shutdown_stream(&mut dest_stream),
                );
                return;
            }
            if let Err(e) = client_stream.flush().await {
                log::debug!("REALITY FALLBACK: Error flushing record: {}", e);
                futures::join!(
                    crate::util::shutdown_stream(&mut client_stream),
                    crate::util::shutdown_stream(&mut dest_stream),
                );
                return;
            }
        }

        if !remaining_data.is_empty()
            && let Err(e) = write_all(&mut client_stream, &remaining_data).await
        {
            log::debug!("REALITY FALLBACK: Error forwarding remaining data: {}", e);
            futures::join!(
                crate::util::shutdown_stream(&mut client_stream),
                crate::util::shutdown_stream(&mut dest_stream),
            );
            return;
        }

        log::debug!(
            "REALITY FALLBACK: Forwarded {} records + {} remaining bytes, starting bidirectional copy",
            dest_records.len(),
            remaining_data.len()
        );

        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut client_stream,
            &mut dest_stream,
            !remaining_data.is_empty(), // flush the client if we wrote remaining data
            false,
        )
        .await;

        futures::join!(
            crate::util::shutdown_stream(&mut client_stream),
            crate::util::shutdown_stream(&mut dest_stream),
        );

        if let Err(e) = result {
            log::debug!("REALITY FALLBACK: Connection ended with error: {}", e);
        }
    }))
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[test]
    fn synthesis_failures_only_forward_explicit_incompatibilities() {
        use crate::reality::reality_key_exchange::{
            ClientKeyShares, RealityGroup, server_exchange,
        };

        assert!(!should_forward_to_dest(Ok(())).unwrap());
        assert!(should_forward_to_dest(Err(io::ErrorKind::Unsupported.into())).unwrap());
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::Other,
        ] {
            let error = io::Error::new(kind, "injected synthesis failure");
            let propagated = should_forward_to_dest(Err(error)).unwrap_err();
            assert_eq!(propagated.kind(), kind);
            assert_eq!(propagated.to_string(), "injected synthesis failure");
        }

        // AWS-LC accepts the encoding but rejects this public key during encapsulation.
        let shares = ClientKeyShares {
            x25519: None,
            hybrid: Some(Box::new([255; 1216])),
        };
        let result = server_exchange(RealityGroup::X25519MlKem768, &shares).map(|_| ());
        let error = should_forward_to_dest(result).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "ML-KEM encapsulation failed");
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
        use crate::reality::reality_key_exchange::RealityGroup;
        use crate::reality::reality_pq_tests::{configs, separate_target_records};
        use crate::reality::{CipherSuite, RealityClientConnection, mldsa65_signing_key};
        use crate::tcp::socket_connector_impl::SocketConnectorImpl;

        for case in [
            "small",
            "small-separate",
            "retry",
            "unsupported",
            "client-unknown-shares",
            "client-truncated-share",
        ] {
            let (cc, mut sc) = configs(CipherSuite::AES_128_GCM_SHA256);
            let (seed, _) = crate::reality::generate_mldsa65_keypair().unwrap();
            sc.mldsa65_key = Some(mldsa65_signing_key(&seed).unwrap());
            let mut client = RealityClientConnection::new(cc).unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            let mut response = if matches!(case, "client-unknown-shares" | "client-truncated-share")
            {
                let offsets = client_key_share_offsets(&hello);
                assert_eq!(offsets.len(), 2);
                let expected_error = if case == "client-unknown-shares" {
                    for (offset, group) in offsets.into_iter().zip([0xfe30u16, 0xfe31]) {
                        hello[offset..offset + 2].copy_from_slice(&group.to_be_bytes());
                    }
                    io::ErrorKind::InvalidData
                } else {
                    // Keeps the TLS framing valid while overstating the last share's length.
                    let offset = offsets[1] + 2;
                    assert_eq!(&hello[offset..offset + 2], &[0, 32]);
                    hello[offset..offset + 2].copy_from_slice(&33u16.to_be_bytes());
                    io::ErrorKind::UnexpectedEof
                };
                let mut check = RealityServerConnection::new(sc.clone()).unwrap();
                assert_eq!(
                    check.validate_client_hello(&hello).unwrap_err().kind(),
                    expected_error
                );
                // A valid target flight reaches the admission-error branch, not hello fallback.
                crate::reality::default_target_records(&hello[44..76]).concat()
            } else if matches!(case, "small" | "small-separate") {
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
                let mut encrypted = vec![23, 3, 3, 2, 88];
                encrypted.resize(605, 0);
                records[small_record] = encrypted.into();
                let mut check = RealityServerConnection::new(sc.clone()).unwrap();
                check.validate_client_hello(&hello).unwrap();
                assert!(
                    check
                        .build_server_response(&records)
                        .unwrap_err()
                        .to_string()
                        .contains("insufficient capacity")
                );
                records.concat()
            } else {
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
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&(message.len() as u16).to_be_bytes());
                record.extend_from_slice(&message);
                record
            };
            // A partial trailing record exercises the deframer's retained bytes.
            response.extend_from_slice(&[23, 3, 3]);

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
                        SocketConnectorImpl::from_config(
                            &crate::config::ClientConfig::default(),
                            None,
                        )
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
        }
    }

    #[tokio::test]
    async fn authenticated_non_vision_oversized_preread_returns_error_without_panicking() {
        use crate::client_proxy_chain::InitialHopEntry;
        use crate::port_forward_handler::PortForwardServerHandler;
        use crate::reality::{RealityClientConfig, RealityClientConnection};
        use crate::tcp::socket_connector_impl::SocketConnectorImpl;
        use aws_lc_rs::agreement;

        let private_key = [1; 32];
        let public_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key)
            .unwrap()
            .compute_public_key()
            .unwrap();
        let mut client = RealityClientConnection::new(RealityClientConfig {
            mldsa65_verify: None,
            public_key: public_key.as_ref().try_into().unwrap(),
            short_id: [0; 8],
            server_name: "localhost".into(),
            cipher_suites: Vec::new(),
        })
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
        let mut decoy = CryptoConnection::new_rustls_server(
            rustls::ServerConnection::new(Arc::new(decoy_config)).unwrap(),
        );
        crate::crypto::feed_crypto_connection(&mut decoy, &hello).unwrap();
        decoy.process_new_packets().unwrap();
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
        let (io, mut peer) = tokio::io::duplex(65540);
        let mut flight = hello.clone();
        flight.extend_from_slice(&[0x17, 0x03, 0x03, 0, 1, 0].repeat(6000));
        peer.write_all(&flight).await.unwrap();
        let mut io: Box<dyn AsyncStream> = Box::new(io);
        let parsed = crate::shadow_tls::read_client_hello(&mut io).await.unwrap();
        assert!(parsed.client_reader.unparsed_data().len() > 33290);

        let decoy_io = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut forwarded_hello = vec![0; hello.len()];
            socket.read_exact(&mut forwarded_hello).await.unwrap();
            assert_eq!(forwarded_hello, hello);
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
}
