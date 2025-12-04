use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::CryptoTlsStream;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;
use crate::uuid_util::parse_uuid;
use crate::xudp::XudpMessageStream;

use super::vision_stream::VisionStream;
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
    pub fn new(
        user_id: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
        fallback: Option<NetLocation>,
    ) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
            udp_enabled,
            proxy_selector,
            resolver,
            fallback,
        }
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

    let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

    debug!(
        "VLESS FALLBACK: Connected to fallback, forwarding {} bytes",
        unconsumed_data.len()
    );

    if !unconsumed_data.is_empty() {
        write_all(&mut dest_stream, unconsumed_data).await?;
        dest_stream.flush().await?;
    }

    debug!("VLESS FALLBACK: Spawning bidirectional copy");

    // Spawn the long-running bidirectional copy as a background task.
    // This allows the setup to complete within the timeout while the actual
    // data transfer runs indefinitely.
    tokio::spawn(async move {
        let mut client_stream = client_stream;
        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut client_stream,
            &mut *dest_stream,
            false, // client doesn't need initial flush
            false, // dest doesn't need initial flush
        )
        .await;

        let _ = client_stream.shutdown().await;
        let _ = dest_stream.shutdown().await;

        if let Err(e) = result {
            debug!("VLESS FALLBACK: Connection ended: {}", e);
        } else {
            debug!("VLESS FALLBACK: Connection completed");
        }
    });

    Ok(TcpServerSetupResult::AlreadyHandled)
}

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS addons not supported in current configuration, use TLS protocol config for VISION support",
            ));
        }

        let instruction = stream_reader.read_u8(&mut server_stream).await?;

        match instruction {
            COMMAND_TCP => {
                let remote_location =
                    parse_remote_location_from_reader(&mut stream_reader, &mut server_stream)
                        .await?;
                let unparsed_data = stream_reader.unparsed_data();

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: false,
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
                    need_initial_flush: false,
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
                let mut xudp_stream = XudpMessageStream::new(server_stream);
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
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

/// Setup a VISION+VLESS stream from a CryptoTlsStream (for REALITY+Vision support)
pub async fn setup_custom_tls_vision_vless_server_stream<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    udp_enabled: bool,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    fallback: Option<NetLocation>,
) -> std::io::Result<TcpServerSetupResult>
where
    IO: AsyncStream + 'static,
{
    let mut stream_reader = StreamReader::new_with_buffer_size(800);

    let client_version = stream_reader.peek_u8(&mut tls_stream).await?;
    if client_version != 0 {
        debug!(
            "VLESS/Vision version mismatch: expected 0, got {}",
            client_version
        );
        if let Some(ref fb) = fallback {
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
            debug!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            let flow_stream: Box<dyn AsyncStream> = if flow == XTLS_VISION_FLOW {
                debug!("Creating VISION stream (Custom TLS) for flow: {}", flow);
                let (io, session) = tls_stream.into_inner();

                Box::new(VisionStream::new_server(
                    io,
                    session,
                    user_uuid,
                    unparsed_data,
                )?)
            } else {
                Box::new(tls_stream)
            };

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: flow_stream,
                need_initial_flush: false,
                connection_success_response: None, // VisionStream will send VLESS response with first write
                initial_remote_data: None,         // Data fed to VisionStream instead
                proxy_selector: proxy_selector.clone(),
            })
        }
        COMMAND_UDP => {
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

            write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;
            let mut vless_stream = VlessMessageStream::new(tls_stream);
            if !unparsed_data.is_empty() {
                vless_stream.feed_initial_read_data(unparsed_data)?;
            }

            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vless_stream),
                need_initial_flush: false,
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

                // Extract components from CryptoTlsStream
                let (io, session) = tls_stream.into_inner();

                // Create VISION stream (will send VLESS response automatically on first write)
                let vision_stream =
                    VisionStream::new_server(io, session, user_uuid, unparsed_data)?;

                // Wrap VISION stream in XUDP stream
                let xudp_stream = XudpMessageStream::new(Box::new(vision_stream));

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false, // VisionStream sends VLESS response on first write
                    proxy_selector: proxy_selector.clone(),
                })
            } else {
                debug!(
                    "Creating XUDP stream (Custom TLS, no VISION) with session-based UDP sockets"
                );

                // Send VLESS response header immediately
                write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;

                // Wrap TLS stream in XUDP stream
                let mut xudp_stream = XudpMessageStream::new(Box::new(tls_stream));

                // Feed any unparsed data to XUDP stream
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false, // Response already sent above
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
