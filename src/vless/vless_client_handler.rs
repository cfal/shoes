use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::crypto::CryptoTlsStream;
use crate::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::util::{allocate_vec, parse_uuid, write_all};

use super::vision_stream::VisionStream;
use super::vless_response_stream::VlessResponseStream;
use super::vless_util::{vision_flow_addon_data, COMMAND_TCP};

pub struct VlessTcpClientHandler {
    user_id: Box<[u8]>,
}

impl std::fmt::Debug for VlessTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessTcpClientHandler")
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl VlessTcpClientHandler {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: parse_uuid(user_id).unwrap().into_boxed_slice(),
        }
    }
}

#[async_trait]
impl TcpClientHandler for VlessTcpClientHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        write_vless_header(&mut client_stream, &self.user_id, &[], &remote_location).await?;
        client_stream.flush().await?;

        // Wrap stream to read VLESS response on first read
        let client_stream = Box::new(VlessResponseStream::new(client_stream));

        Ok(TcpClientSetupResult { client_stream })
    }
}

// REMOVED: Old tokio-rustls vision function - now using setup_custom_tls_vision_vless_client_stream

pub async fn setup_custom_tls_vision_vless_client_stream<IO>(
    mut tls_stream: CryptoTlsStream<IO>,
    user_id: &[u8],
    remote_location: &NetLocation,
) -> std::io::Result<TcpClientSetupResult>
where
    IO: crate::async_stream::AsyncStream + 'static,
{
    // Write VLESS request header through TLS
    write_vless_header(
        &mut tls_stream,
        user_id,
        vision_flow_addon_data(),
        remote_location,
    )
    .await?;
    tls_stream.flush().await?;

    // Create stream with VLESS response reading support
    // CryptoTlsStream already wraps a Connection, so we don't need to wrap again
    let (io, connection) = tls_stream.into_inner();

    // VisionStream will read VLESS response header on first read
    let mut user_uuid = [0u8; 16];
    user_uuid.copy_from_slice(user_id);
    let vision_stream = VisionStream::new_client(io, connection, user_uuid);

    Ok(TcpClientSetupResult {
        client_stream: Box::new(vision_stream),
    })
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
