use async_trait::async_trait;
use log::info;
use subtle::ConstantTimeEq;

use crate::async_stream::AsyncStream;
use crate::crypto::CryptoTlsStream;
use crate::option_util::NoneOrOne;
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::{parse_uuid, write_all};
use crate::xudp::XudpMessageStream;

use super::vision_stream::VisionStream;
use super::vless_message_stream::VlessMessageStream;
use super::vless_util::{
    parse_addons_from_reader, parse_remote_location_from_reader, COMMAND_MUX, COMMAND_TCP,
    COMMAND_UDP, XTLS_VISION_FLOW,
};

pub struct VlessTcpServerHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
}

impl std::fmt::Debug for VlessTcpServerHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpServerHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl VlessTcpServerHandler {
    pub fn new(user_id: &str, udp_enabled: bool) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
            udp_enabled,
        }
    }
}

const SERVER_RESPONSE_HEADER: &[u8] = &[
    0u8, // version
    0u8, // addons length
];

#[async_trait]
impl TcpServerHandler for VlessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // Parse VLESS header without TLS
        let mut stream_reader = StreamReader::new_with_buffer_size(800);

        let client_version = stream_reader.read_u8(&mut server_stream).await?;
        if client_version != 0 {
            return Err(std::io::Error::other(format!(
                "invalid client protocol version, expected 0, got {client_version}"
            )));
        }

        let target_id = stream_reader.read_slice(&mut server_stream, 16).await?;
        if self.user_id.ct_eq(target_id).unwrap_u8() == 0 {
            return Err(std::io::Error::other("Unknown user id"));
        }

        let addon_length = stream_reader.read_u8(&mut server_stream).await?;
        if addon_length > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "VLESS addons not supported in current configuration, use TLS protocol for VISION support",
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
                    override_proxy_provider: NoneOrOne::Unspecified,
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
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                // MUX/XUDP: Destination is NOT in the VLESS header - it comes in XUDP frames
                // Don't read destination from wire - protocol spec says it's not present for command 3
                info!(
                    "MUX/XUDP: No destination in VLESS header (destinations come in XUDP frames)"
                );
                let unparsed_data = stream_reader.unparsed_data();

                // Send VLESS response header immediately
                write_all(&mut server_stream, SERVER_RESPONSE_HEADER).await?;

                // Wrap raw stream in XUDP stream
                let mut xudp_stream = XudpMessageStream::new(server_stream);

                // Feed any unparsed data to XUDP stream
                if !unparsed_data.is_empty() {
                    xudp_stream.feed_initial_read_data(unparsed_data)?;
                }

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
                    override_proxy_provider: NoneOrOne::Unspecified,
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

// REMOVED: Old tokio-rustls vision function - now using setup_custom_tls_vision_vless_server_stream

/// Setup a VISION+VLESS stream from a CryptoTlsStream (for REALITY+Vision support)
pub async fn setup_custom_tls_vision_vless_server_stream<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    udp_enabled: bool,
) -> std::io::Result<TcpServerSetupResult>
where
    IO: AsyncStream + 'static,
{
    // Parse VLESS header from TLS stream
    let mut stream_reader = StreamReader::new_with_buffer_size(800);

    let client_version = stream_reader.read_u8(&mut tls_stream).await?;
    if client_version != 0 {
        return Err(std::io::Error::other(format!(
            "invalid client protocol version, expected 0, got {client_version}"
        )));
    }

    let target_id = stream_reader.read_slice(&mut tls_stream, 16).await?;
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(target_id);

    // Verify user ID using constant-time comparison to prevent timing attacks
    if user_id.ct_eq(target_id).unwrap_u8() == 0 {
        return Err(std::io::Error::other("Unknown user id"));
    }

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

            info!("Parsing remote location...");
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            info!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            let flow_stream: Box<dyn AsyncStream> = if flow == XTLS_VISION_FLOW {
                info!("Creating VISION stream (Custom TLS) for flow: {}", flow);
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
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        }
        COMMAND_UDP => {
            if !udp_enabled {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP not enabled",
                ));
            }

            info!("Parsing remote location...");
            let remote_location =
                parse_remote_location_from_reader(&mut stream_reader, &mut tls_stream).await?;
            info!("Remote location parsed: {}", remote_location);
            let unparsed_data = stream_reader.unparsed_data();

            write_all(&mut tls_stream, SERVER_RESPONSE_HEADER).await?;
            let mut vless_stream = VlessMessageStream::new(Box::new(tls_stream));
            if !unparsed_data.is_empty() {
                vless_stream.feed_initial_read_data(unparsed_data)?;
            }

            Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: Box::new(vless_stream),
                need_initial_flush: false,
                override_proxy_provider: NoneOrOne::Unspecified,
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
            info!("MUX/XUDP: No destination in VLESS header (destinations come in XUDP frames)");
            let unparsed_data = stream_reader.unparsed_data();

            if flow == XTLS_VISION_FLOW {
                info!("Creating VISION+XUDP stream (Custom TLS) with session-based UDP sockets");

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
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            } else {
                info!(
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
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            }
        }
        unknown_protocol_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Unknown requested protocol: {unknown_protocol_type}"),
        )),
    }
}
