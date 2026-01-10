use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::crypto::CryptoTlsStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::util::{allocate_vec, write_all};
use crate::uuid_util::parse_uuid;

use super::vision_stream::VisionStream;
use super::vless_message_stream::VlessMessageStream;
use super::vless_response_stream::VlessResponseStream;
use super::vless_util::{COMMAND_TCP, COMMAND_UDP, vision_flow_addon_data};

pub struct VlessTcpClientHandler {
    user_id: Box<[u8]>,
    udp_enabled: bool,
}

impl std::fmt::Debug for VlessTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpClientHandler")
            .field("user_id", &self.user_id)
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl VlessTcpClientHandler {
    pub fn new(user_id: &str, udp_enabled: bool) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for VlessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        write_vless_header(&mut client_stream, &self.user_id, &[], remote_location.location())
            .await?;
        client_stream.flush().await?;
        let client_stream = Box::new(VlessResponseStream::new(client_stream));

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled // VLESS supports XUDP for UDP-over-TCP when enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        write_vless_udp_header(&mut client_stream, &self.user_id, target.location()).await?;
        client_stream.flush().await?;
        let response_stream = Box::new(VlessResponseStream::new(client_stream));
        let message_stream = VlessMessageStream::new(response_stream);
        Ok(Box::new(message_stream))
    }
}

/// Helper function for setup_client_udp_bidirectional that can be called from TlsClientHandler
/// for Vision VLESS or regular VLESS over TLS.
pub async fn setup_vless_udp_bidirectional<IO>(
    mut stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    target: NetLocation,
) -> std::io::Result<Box<dyn AsyncMessageStream>>
where
    IO: crate::async_stream::AsyncStream + 'static,
{
    write_vless_udp_header(&mut stream, user_id, &target).await?;
    stream.flush().await?;
    let response_stream = Box::new(VlessResponseStream::new(stream));
    let message_stream = VlessMessageStream::new(response_stream);
    Ok(Box::new(message_stream))
}

pub async fn setup_custom_tls_vision_vless_client_stream<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<TcpClientSetupResult>
where
    IO: crate::async_stream::AsyncStream + 'static,
{
    write_vless_header(
        &mut tls_stream,
        user_id,
        vision_flow_addon_data(),
        remote_location,
    )
    .await?;
    tls_stream.flush().await?;

    let (io, connection) = tls_stream.into_inner();
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(user_id);
    let vision_stream = VisionStream::new_client(io, connection, user_uuid);

    Ok(TcpClientSetupResult {
        client_stream: Box::new(vision_stream),
        early_data: None,
    })
}

/// Write VLESS UDP header for single-target bidirectional UDP (COMMAND_UDP = 2).
/// Same format as TCP header but with command=2.
async fn write_vless_udp_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<()> {
    // VLESS UDP header format (same as TCP but command=2):
    // version (1 byte) + user_id (16 bytes) + addon_length (1 byte) + command (1 byte) + port (2 bytes) + address_type (1 byte) + address

    // Calculate base header size: version + user_id + addon_length + command + port + address_type
    let base_header_size = 1 + 16 + 1 + 1 + 2 + 1;
    let mut header_bytes = allocate_vec(base_header_size);

    // version 0
    header_bytes[0] = 0;
    // Copy user_id
    header_bytes[1..17].copy_from_slice(user_id);
    // addon length = 0
    header_bytes[17] = 0;
    // command = UDP (2)
    header_bytes[18] = COMMAND_UDP;

    // port (2 bytes, big-endian)
    let remote_port = remote_location.port();
    header_bytes[19] = (remote_port >> 8) as u8;
    header_bytes[20] = (remote_port & 0xff) as u8;

    // address_type
    let address_type_offset = 21;

    match remote_location.address() {
        Address::Ipv4(v4addr) => {
            header_bytes[address_type_offset] = 1;
            header_bytes.extend_from_slice(&v4addr.octets());
        }
        Address::Ipv6(v6addr) => {
            header_bytes[address_type_offset] = 3;
            header_bytes.extend_from_slice(&v6addr.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Hostname is too long: {hostname}"),
                ));
            }

            header_bytes[address_type_offset] = 2;
            header_bytes.push(hostname.len() as u8);
            header_bytes.extend_from_slice(hostname.as_bytes());
        }
    }

    write_all(stream, &header_bytes).await?;

    Ok(())
}

async fn write_vless_header<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    user_id: &[u8],
    addon_data: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<()> {
    // VLESS header format:
    // version (1 byte) + user_id (16 bytes) + addon_length (1 byte) + addon_data + command (1 byte) + port (2 bytes) + address_type (1 byte) + address

    // Calculate base header size: version + user_id + addon_length + addon_data + command + port + address_type
    let base_header_size = 1 + 16 + 1 + addon_data.len() + 1 + 2 + 1;
    let mut header_bytes = allocate_vec(base_header_size);

    // version 0, we need to write since it's uninitialized
    header_bytes[0] = 0;
    // Copy user_id
    header_bytes[1..17].copy_from_slice(user_id);

    // addon length
    header_bytes[17] = addon_data.len() as u8;

    // Copy addon data if present
    if !addon_data.is_empty() {
        header_bytes[18..18 + addon_data.len()].copy_from_slice(addon_data);
    }

    let addon_end = 18 + addon_data.len();

    // command (1 = tcp)
    header_bytes[addon_end] = COMMAND_TCP;

    // port (2 bytes, big-endian)
    let remote_port = remote_location.port();
    header_bytes[addon_end + 1] = (remote_port >> 8) as u8;
    header_bytes[addon_end + 2] = (remote_port & 0xff) as u8;

    // address_type
    let address_type_offset = addon_end + 3;

    match remote_location.address() {
        Address::Ipv4(v4addr) => {
            header_bytes[address_type_offset] = 1;
            header_bytes.extend_from_slice(&v4addr.octets());
        }
        Address::Ipv6(v6addr) => {
            header_bytes[address_type_offset] = 3;
            header_bytes.extend_from_slice(&v6addr.octets());
        }
        Address::Hostname(hostname) => {
            if hostname.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Hostname is too long: {hostname}"),
                ));
            }

            header_bytes[address_type_offset] = 2;
            header_bytes.push(hostname.len() as u8);
            header_bytes.extend_from_slice(hostname.as_bytes());
        }
    }

    write_all(stream, &header_bytes).await?;

    Ok(())
}
