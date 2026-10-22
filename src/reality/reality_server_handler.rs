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
use crate::crypto::{CryptoTlsStream, TlsReadMode};
use crate::prepend_stream::PrependStream;
use crate::resolver::Resolver;
use crate::shadow_tls::{ParsedClientHello, parse_server_hello};
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerSetupResult};
use crate::tls_server_handler::InnerProtocol;
use crate::util::{allocate_vec, write_all};

use super::RealityServerConfig;
use super::reality_hello::validate_server_key_share;

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

    let auth_result =
        reality_config.authenticate_client_hello(&parsed_client_hello.client_hello_record);

    let TargetFlight {
        records: dest_records,
        remaining: remaining_data,
        usable,
    } = read_target_flight(&mut *dest_stream, &target.dest, auth_result.is_ok()).await?;
    if !usable {
        return Ok(start_forward_to_dest(
            server_stream,
            dest_stream,
            dest_records,
            remaining_data,
            client_pending,
        ));
    }

    // Delay authentication rejection until target collection so probes follow the same read path.
    let authenticated = match auth_result {
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

        Ok(authenticated) => authenticated,
    };

    log::debug!("REALITY: Auth succeeded, building response matching dest structure");

    let Some(connection) = forward_unsupported(authenticated.into_connection(&dest_records))?
    else {
        return Ok(start_forward_to_dest(
            server_stream,
            dest_stream,
            dest_records,
            remaining_data,
            client_pending,
        ));
    };
    drop(dest_stream);

    let mode = match target.inner_protocol {
        InnerProtocol::VisionVless(_) => TlsReadMode::PreserveRecords,
        _ => TlsReadMode::Stream,
    };
    let tls_stream =
        CryptoTlsStream::handshake(server_stream, connection, mode, &client_pending).await?;
    log::debug!(
        "REALITY: TLS 1.3 handshake completed successfully, negotiated_group={:?}",
        tls_stream.negotiated_group()
    );

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

struct TargetFlight {
    records: Vec<Bytes>,
    remaining: Bytes,
    usable: bool,
}

async fn read_target_flight(
    dest_stream: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
    dest: &NetLocation,
    authenticated: bool,
) -> std::io::Result<TargetFlight> {
    // Read dest response until we have enough records. Use 512-byte heuristic like XTLS/REALITY:
    // first encrypted record > 512 bytes = combined mode, <= 512 bytes = separate mode
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut deframer = TlsDeframer::new();
    let mut dest_records: Vec<Bytes> = Vec::new();
    let mut buf = allocate_vec(8192).into_boxed_slice();
    let mut dest_handshake_success = false;

    'collect: loop {
        let first_read = dest_records.is_empty();
        match timeout_at(deadline, dest_stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                break;
            }
            Ok(Ok(n)) => {
                deframer.feed(&buf[..n]);
                loop {
                    match deframer.next_record() {
                        Ok(Some(record)) => {
                            dest_records.push(record);
                            if dest_records.len() > 7 {
                                break 'collect;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            log::debug!("REALITY: Invalid target record: {e}");
                            break 'collect;
                        }
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
        if first_read && !dest_records.is_empty() {
            match parse_server_hello(&dest_records[0]) {
                Ok(parsed) => {
                    if !parsed.is_tls13 || validate_server_key_share(&dest_records[0]).is_err() {
                        log::log!(
                            if authenticated {
                                log::Level::Warn
                            } else {
                                log::Level::Debug
                            },
                            "REALITY: Dest {} has an unsupported TLS hello, forwarding transparently",
                            dest
                        );
                        return Ok(TargetFlight {
                            records: dest_records,
                            remaining: deframer.into_remaining_data(),
                            usable: false,
                        });
                    }
                    log::debug!("REALITY: Dest confirmed TLS 1.3");
                }
                Err(e) => {
                    log::log!(
                        if authenticated {
                            log::Level::Warn
                        } else {
                            log::Level::Debug
                        },
                        "REALITY: Failed to parse dest ServerHello: {}, forwarding transparently",
                        e
                    );
                    return Ok(TargetFlight {
                        records: dest_records,
                        remaining: deframer.into_remaining_data(),
                        usable: false,
                    });
                }
            }
        }

        // Separate mode: first encrypted record is small, need more records
        // Keep reading until we have 6 records (SH + CCS + 4 encrypted) or timeout
        // Mirror an already observed seventh record; do not add a target probe or wait for one.
        if dest_records.len() >= 6 && dest_records[2].len() <= 512 {
            // Finish an already observed optional record across TCP reads, without
            // waiting for a record whose header has not arrived.
            if dest_records.len() == 6 && deframer.pending_bytes() != 0 {
                continue;
            }
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
    let usable = dest_handshake_success && remaining_data.is_empty();
    if !usable {
        log::warn!(
            "REALITY: Dest handshake failed (got {} records), falling back to transparent forward",
            dest_records.len()
        );
    } else {
        log::debug!(
            "REALITY: Read {} records from dest ({} bytes remaining)",
            dest_records.len(),
            remaining_data.len()
        );
    }
    Ok(TargetFlight {
        records: dest_records,
        remaining: remaining_data,
        usable,
    })
}

fn forward_unsupported<T>(response: std::io::Result<T>) -> std::io::Result<Option<T>> {
    match response {
        Ok(connection) => Ok(Some(connection)),
        // Only explicitly classified target incompatibilities permit fallback.
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            log::warn!("REALITY: Cannot synthesize target handshake ({e}), forwarding");
            Ok(None)
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
#[path = "tests/reality_server_handler.rs"]
mod tests;
