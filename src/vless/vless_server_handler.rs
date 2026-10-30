use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpMessageStream;

use super::encryption::ServerEncryption;
use super::vision_stream::{VisionStream, VisionWriteErrorPolicy};
use super::vision_transport::VisionTransport;
use super::vless_message_stream::VlessMessageStream;
use super::vless_util::{
    COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, XTLS_VISION_FLOW, parse_addons_from_reader,
    parse_remote_location_from_reader,
};

pub struct VlessTcpServerHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
    encryption: Option<Arc<ServerEncryption>>,
    vision: bool,
}

impl std::fmt::Debug for VlessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpServerHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl VlessTcpServerHandler {
    pub(crate) fn new(
        user_id: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<NetLocation>,
        encryption: Option<Arc<ServerEncryption>>,
        vision: bool,
    ) -> std::io::Result<Self> {
        if (vision && encryption.is_none()) || (encryption.is_some() && fallback.is_some()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Native VLESS Vision requires encryption; native encryption does not support fallback",
            ));
        }
        Ok(Self {
            user_id: parse_uuid(user_id)?.into_boxed_slice(),
            udp_enabled,
            proxy_selector,
            resolver,
            fallback,
            encryption,
            vision,
        })
    }
}

const SERVER_RESPONSE_HEADER: &[u8] = &[
    0u8, // version
    0u8, // addons length
];

/// Forward the connection to a fallback destination when VLESS authentication fails.
///
/// This makes the server indistinguishable from a legitimate server by transparently
/// proxying failed auth attempts to the configured fallback destination.
///
/// Used by both `VlessTcpServerHandler` and `setup_custom_tls_vision_vless_server_stream`.
async fn vless_fallback_to_dest<S: AsyncStream + 'static>(
    client_stream: S,
    reader: StreamReader,
    fallback: &NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    debug!("VLESS FALLBACK: Connecting to fallback: {}", fallback);

    let unconsumed_data = reader.unparsed_data();
    let dest_addr = crate::resolver::resolve_single_address(resolver, fallback).await?;

    debug!("VLESS FALLBACK: Resolved {} to {}", fallback, dest_addr);

    let socket = crate::socket_util::new_tcp_socket(None, dest_addr.is_ipv6())?;
    let mut dest_stream: Box<dyn AsyncStream> = Box::new(socket.connect(dest_addr).await?);

    debug!(
        "VLESS FALLBACK: Connected to fallback, forwarding {} bytes",
        unconsumed_data.len()
    );

    if !unconsumed_data.is_empty() {
        write_all(&mut dest_stream, unconsumed_data).await?;
        dest_stream.flush().await?;
    }

    debug!("VLESS FALLBACK: Spawning bidirectional copy");

    // Return the transfer to the caller so cancellation owns the entire connection.
    Ok(TcpServerSetupResult::Session(Box::pin(async move {
        let mut client_stream = client_stream;
        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut client_stream,
            &mut *dest_stream,
            false, // client doesn't need initial flush
            false, // dest doesn't need initial flush
        )
        .await;

        futures::join!(
            crate::util::shutdown_stream(&mut client_stream),
            crate::util::shutdown_stream(&mut dest_stream),
        );

        if let Err(e) = result {
            debug!("VLESS FALLBACK: Connection ended: {}", e);
        } else {
            debug!("VLESS FALLBACK: Connection completed");
        }
    })))
}

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(encryption) = &self.encryption {
            let stream = encryption.handshake(server_stream).await?;
            if self.vision {
                return setup_vision_vless_server_stream(
                    stream,
                    &self.user_id,
                    self.udp_enabled,
                    self.proxy_selector.clone(),
                    &self.resolver,
                    None,
                    VisionWriteErrorPolicy::AcknowledgeAccepted,
                )
                .await;
            }
            server_stream = Box::new(stream);
        }
        let mut stream_reader = StreamReader::new_with_buffer_size(800);

        let client_version = stream_reader.peek_u8(&mut server_stream).await?;
        if client_version != 0 {
            debug!("VLESS version mismatch: expected 0, got {}", client_version);
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other(format!(
                "invalid client protocol version, expected 0, got {client_version}"
            )));
        }

        let header = stream_reader.peek_slice(&mut server_stream, 17).await?;
        let target_id = &header[1..17];

        if self.user_id.ct_eq(target_id).unwrap_u8() == 0 {
            debug!("VLESS UUID mismatch");
            if let Some(ref fallback) = self.fallback {
                return vless_fallback_to_dest(
                    server_stream,
                    stream_reader,
                    fallback,
                    &self.resolver,
                )
                .await;
            }
            return Err(std::io::Error::other("Unknown user id"));
        }

        stream_reader.consume(17);

        let addon_length = stream_reader.read_u8(&mut server_stream).await?;
        if addon_length > 0 {
            let message = if self.encryption.is_some() {
                "VLESS addons not supported in current configuration, set vision: true on this VLESS server for VISION support"
            } else {
                "VLESS addons not supported in current configuration, use TLS protocol config for VISION support"
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            ));
        }

        let instruction = stream_reader.read_u8(&mut server_stream).await?;

        match instruction {
            COMMAND_TCP => {
                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;

                // Check for h2mux magic destination
                if let Address::Hostname(host) = remote_location.address()
                    && host == MUX_DESTINATION_HOST
                    && remote_location.port() == MUX_DESTINATION_PORT
                {
                    // Send VLESS success response before spawning h2mux session
                    write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                    server_stream.flush().await?;

                    let proxy_selector = self.proxy_selector.clone();
                    let resolver = self.resolver.clone();
                    let udp_enabled = self.udp_enabled;

                    // Pass any unparsed data for the h2mux session
                    let initial_data = stream_reader.unparsed_data_owned();

                    return Ok(TcpServerSetupResult::Session(Box::pin(async move {
                        if let Err(e) = handle_h2mux_session(
                            server_stream,
                            initial_data,
                            udp_enabled,
                            proxy_selector,
                            resolver,
                        )
                        .await
                        {
                            debug!("H2MUX session ended: {}", e);
                        }
                    })));
                }

                let unparsed_data = stream_reader.unparsed_data();

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: self.encryption.is_some(),
                    connection_success_response: Some(
                        SERVER_RESPONSE_HEADER.to_vec().into_boxed_slice(),
                    ),
                    initial_remote_data: if unparsed_data.is_empty() {
                        None
                    } else {
                        Some(unparsed_data.to_vec().into_boxed_slice())
                    },
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            COMMAND_UDP => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }

                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;
                let unparsed_data = stream_reader.unparsed_data();

                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                let mut vless_stream = VlessMessageStream::new(server_stream);
                if !unparsed_data.is_empty() {
                    vless_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: Box::new(vless_stream),
                    need_initial_flush: self.encryption.is_some(),
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                // MUX/XUDP: Destination comes in XUDP frames, not VLESS header
                let unparsed_data = stream_reader.unparsed_data();
                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;
                let mut xudp_stream = XudpMessageStream::new(server_stream)
                    .with_legacy_resolution(!self.proxy_selector.fake_dns_enabled());
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: self.encryption.is_some(),
                    proxy_selector: self.proxy_selector.clone(),
                })
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {unknown_protocol_type}"),
                ));
            }
        }
    }
}

/// Sets up legacy Vision over a record-preserving TLS transport.
pub(crate) async fn setup_custom_tls_vision_vless_server_stream<S>(
    tls_stream: S,
    user_id: &[u8],
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
) -> std::io::Result<TcpServerSetupResult>
where
    S: VisionTransport + 'static,
{
    setup_vision_vless_server_stream(
        tls_stream,
        user_id,
        udp_enabled,
        proxy_selector,
        resolver,
        fallback,
        VisionWriteErrorPolicy::Legacy,
    )
    .await
}

async fn setup_vision_vless_server_stream<S: VisionTransport + 'static>(
    mut tls_stream: S,
    user_id: &[u8],
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
    policy: VisionWriteErrorPolicy,
) -> std::io::Result<TcpServerSetupResult> {
    let native_encryption = policy == VisionWriteErrorPolicy::AcknowledgeAccepted;
    tls_stream.require_record_framing()?;
    let mut stream_reader = StreamReader::new_with_buffer_size(800);

    let client_version = stream_reader.peek_u8(&mut tls_stream).await?;
    if client_version != 0 {
        debug!(
            "VLESS/Vision version mismatch: expected 0, got {}",
            client_version
        );
        if let Some(ref fb) = fallback {
            tls_stream.allow_streaming_reads();
            return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
        }
        return Err(std::io::Error::other(format!(
            "invalid client protocol version, expected 0, got {client_version}"
        )));
    }

    let header = stream_reader.peek_slice(&mut tls_stream, 17).await?;
    let target_id = &header[1..17];

    // Verify user ID using constant-time comparison to prevent timing attacks
    if user_id.ct_eq(target_id).unwrap_u8() == 0 {
        debug!("VLESS/Vision UUID mismatch");
        if let Some(ref fb) = fallback {
            tls_stream.allow_streaming_reads();
            return vless_fallback_to_dest(tls_stream, stream_reader, fb, resolver).await;
        }
        return Err(std::io::Error::other("Unknown user id"));
    }

    // Both checks passed - copy UUID for VisionStream, then consume version + UUID
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(target_id);
    stream_reader.consume(17);

    let addon_length = stream_reader.read_u8(&mut tls_stream).await?;
    let flow = if addon_length > 0 {
        parse_addons_from_reader(&mut stream_reader, &mut tls_stream, addon_length).await?
    } else {
        String::new()
    };

    let instruction = stream_reader.read_u8(&mut tls_stream).await?;

    match instruction {
        COMMAND_TCP => {
            if flow != XTLS_VISION_FLOW {
                return Err(std::io::Error::other("expected vision flow for TCP"));
            }

            debug!("Parsing remote location...");
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            if native_encryption
                && matches!(remote_location.address(), Address::Hostname(host) if host == MUX_DESTINATION_HOST)
                && remote_location.port() == MUX_DESTINATION_PORT
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Native VLESS Vision does not support H2MUX",
                ));
            }
            debug!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            debug!("Creating VISION stream (Custom TLS) for flow: {}", flow);
            let vision_stream = VisionStream::new_server(tls_stream, user_uuid, unparsed_data)?
                .with_write_error_policy(policy);

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(vision_stream),
                need_initial_flush: false,
                connection_success_response: None, // VisionStream will send VLESS response with first write
                initial_remote_data: None,         // Data fed to VisionStream instead
                proxy_selector: proxy_selector.clone(),
            })
        }
        COMMAND_UDP => {
            if native_encryption && !flow.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VLESS command-2 UDP requires an empty flow with native encryption",
                ));
            }
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP not enabled",
                ));
            }

            debug!("Parsing remote location...");
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            debug!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            tls_stream.allow_streaming_reads();
            write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;
            let mut vless_stream = VlessMessageStream::new(tls_stream);
            if !unparsed_data.is_empty() {
                vless_stream.feed_initial_read_data(unparsed_data)?;
            }

            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vless_stream),
                need_initial_flush: native_encryption,
                proxy_selector: proxy_selector.clone(),
            })
        }
        COMMAND_MUX => {
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "MUX/XUDP requires UDP to be enabled",
                ));
            }
            // MUX/XUDP: Destination is NOT in the VLESS header - it comes in XUDP frames
            debug!("MUX/XUDP: No destination in VLESS header (destinations come in XUDP frames)");
            let unparsed_data = stream_reader.unparsed_data();

            if flow == XTLS_VISION_FLOW {
                debug!("Creating VISION+XUDP stream (Custom TLS) with session-based UDP sockets");

                // Create VISION stream (will send VLESS response automatically on first write)
                let vision_stream = VisionStream::new_server(tls_stream, user_uuid, unparsed_data)?
                    .with_write_error_policy(policy);

                // Wrap VISION stream in XUDP stream
                let xudp_stream = XudpMessageStream::new(Box::new(vision_stream))
                    .with_legacy_resolution(!proxy_selector.fake_dns_enabled());

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false, // VisionStream sends VLESS response on first write
                    proxy_selector: proxy_selector.clone(),
                })
            } else {
                debug!(
                    "Creating XUDP stream (Custom TLS, no VISION) with session-based UDP sockets"
                );

                tls_stream.allow_streaming_reads();
                // Send VLESS response header immediately
                write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;

                // Wrap TLS stream in XUDP stream
                let mut xudp_stream = XudpMessageStream::new(Box::new(tls_stream))
                    .with_legacy_resolution(!proxy_selector.fake_dns_enabled());

                // Feed any unparsed data to XUDP stream
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: native_encryption,
                    proxy_selector,
                })
            }
        }
        unknown_protocol_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unknown requested protocol: {unknown_protocol_type}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::resolver::NativeResolver;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const USER_ID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";

    fn handler(fallback: Option<NetLocation>) -> VlessTcpServerHandler {
        VlessTcpServerHandler::new(
            USER_ID,
            false,
            Arc::new(ClientProxySelector::new(Vec::new())),
            Arc::new(NativeResolver::new()),
            fallback,
            None,
            false,
        )
        .unwrap()
    }

    fn probes() -> [(&'static str, Vec<u8>); 2] {
        let mut wrong_user = vec![0];
        wrong_user.extend_from_slice(&[0x42; 16]);
        wrong_user.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
        wrong_user.extend_from_slice(b"payload after the header");
        [
            ("wrong user id", wrong_user),
            (
                "non-VLESS version",
                b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec(),
            ),
        ]
    }

    #[tokio::test]
    async fn h2mux_response_is_flushed_before_session_handoff() {
        use crate::async_stream::test_streams::FlushGatedStream;

        tokio::time::timeout(Duration::from_secs(5), async {
            let (server_io, mut client) = tokio::io::duplex(4096);
            let mut request = vec![0];
            request.extend_from_slice(&parse_uuid(USER_ID).unwrap());
            request.extend_from_slice(&[0, COMMAND_TCP]);
            request.extend_from_slice(&MUX_DESTINATION_PORT.to_be_bytes());
            request.extend_from_slice(&[2, MUX_DESTINATION_HOST.len() as u8]);
            request.extend_from_slice(MUX_DESTINATION_HOST.as_bytes());
            client.write_all(&request).await.unwrap();

            let setup = handler(None)
                .setup_server_stream(Box::new(FlushGatedStream::new(server_io)))
                .await
                .unwrap();
            assert!(matches!(setup, TcpServerSetupResult::Session(_)));
            let mut response = [0; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, SERVER_RESPONSE_HEADER);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_authentication_relays_every_byte_to_the_fallback() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (name, probe) in probes() {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let fallback = NetLocation::new(
                    Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    listener.local_addr().unwrap().port(),
                );
                let (server_io, mut client) = tokio::io::duplex(4096);
                client.write_all(&probe).await.unwrap();
                let setup = handler(Some(fallback))
                    .setup_server_stream(Box::new(server_io))
                    .await
                    .unwrap();
                let TcpServerSetupResult::Session(session) = setup else {
                    panic!("{name}: expected a fallback session");
                };
                let session = tokio::spawn(session);
                let (mut origin, _) = listener.accept().await.unwrap();

                let mut forwarded = vec![0; probe.len()];
                origin.read_exact(&mut forwarded).await.unwrap();
                assert_eq!(forwarded, probe, "{name}");
                client.write_all(b" and later bytes").await.unwrap();
                let mut later = [0; 16];
                origin.read_exact(&mut later).await.unwrap();
                assert_eq!(&later, b" and later bytes", "{name}");

                origin.write_all(b"camouflage reply").await.unwrap();
                origin.shutdown().await.unwrap();
                let mut reply = [0; 16];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"camouflage reply", "{name}");
                client.shutdown().await.unwrap();
                assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0, "{name}");
                session.await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_authentication_without_a_fallback_is_an_error() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for (name, probe) in probes() {
                let (server_io, mut client) = tokio::io::duplex(4096);
                client.write_all(&probe).await.unwrap();
                assert!(
                    handler(None)
                        .setup_server_stream(Box::new(server_io))
                        .await
                        .is_err(),
                    "{name}"
                );
            }
        })
        .await
        .unwrap();
    }
}
