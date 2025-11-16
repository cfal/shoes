use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use tokio::io::AsyncReadExt;

use crate::address::{Address, NetLocation};
use crate::stream_reader::StreamReader;

// VLESS protocol command types
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3; // Also known as XUDP - multiplexes UDP over single TCP connection

pub const XTLS_VISION_FLOW: &str = "xtls-rprx-vision";

pub async fn parse_addons_from_reader<S: AsyncReadExt + Unpin>(
    stream_reader: &mut StreamReader,
    stream: &mut S,
    addon_length: u8,
) -> std::io::Result<String> {
    let addon_bytes = stream_reader
        .read_slice(stream, addon_length as usize)
        .await?;

    log::debug!(
        "Parsing addons: length={}, bytes={:?}",
        addon_length,
        addon_bytes
    );

    // Parse protobuf-encoded addons
    // Format: field_tag length data [field_tag length data ...]
    // Field 1 = flow (string)
    // Field 2 = seed (bytes)

    let mut addon_cursor = 0;
    let mut flow_string = String::new();

    while addon_cursor < addon_bytes.len() {
        // Read field tag
        let field_tag = addon_bytes[addon_cursor];
        addon_cursor += 1;

        let field_number = field_tag >> 3;
        let wire_type = field_tag & 0x07;

        if wire_type != 2 {
            return Err(std::io::Error::other(format!(
                "Unexpected wire type {} for field {}",
                wire_type, field_number
            )));
        }

        // Read length
        if addon_cursor >= addon_bytes.len() {
            return Err(std::io::Error::other(
                "Unexpected end of addon data reading length",
            ));
        }
        let (field_length, bytes_used) = read_varint(&addon_bytes[addon_cursor..])?;
        addon_cursor += bytes_used;

        // Validate field_length is within bounds
        if addon_cursor + field_length as usize > addon_bytes.len() {
            return Err(std::io::Error::other(format!(
                "Field {} length {} exceeds remaining addon bytes (cursor: {}, total: {})",
                field_number,
                field_length,
                addon_cursor,
                addon_bytes.len()
            )));
        }

        // Read field data
        let field_data = &addon_bytes[addon_cursor..addon_cursor + field_length as usize];
        addon_cursor += field_length as usize;

        match field_number {
            1 => {
                // Flow field
                flow_string = std::str::from_utf8(field_data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                    .to_string();
                log::debug!("Parsed flow: {}", flow_string);
            }
            2 => {
                // Seed field (ignored for now)
                log::debug!("Parsed seed: {} bytes", field_data.len());
            }
            _ => {
                log::debug!(
                    "Unknown field {}, skipping {} bytes",
                    field_number,
                    field_data.len()
                );
            }
        }
    }

    Ok(flow_string)
}

/// Parse VLESS remote location from stream
pub async fn parse_remote_location_from_reader<S: AsyncReadExt + Unpin>(
    stream_reader: &mut StreamReader,
    stream: &mut S,
) -> std::io::Result<NetLocation> {
    let port = stream_reader.read_u16_be(stream).await?;
    let address_type = stream_reader.read_u8(stream).await?;

    match address_type {
        1 => {
            // 4 byte ipv4 address
            let address_bytes = stream_reader.read_slice(stream, 4).await?;
            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );
            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        2 => {
            // domain name
            let domain_name_len = stream_reader.read_u8(stream).await?;
            let domain_name_bytes = stream_reader
                .read_slice(stream, domain_name_len as usize)
                .await?;

            let address_str = std::str::from_utf8(domain_name_bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to decode address: {e}"),
                )
            })?;

            Ok(NetLocation::new(Address::from(address_str)?, port))
        }
        3 => {
            // 16 byte ipv6 address
            let address_bytes = stream_reader.read_slice(stream, 16).await?;
            let v6addr = Ipv6Addr::new(
                ((address_bytes[0] as u16) << 8) | (address_bytes[1] as u16),
                ((address_bytes[2] as u16) << 8) | (address_bytes[3] as u16),
                ((address_bytes[4] as u16) << 8) | (address_bytes[5] as u16),
                ((address_bytes[6] as u16) << 8) | (address_bytes[7] as u16),
                ((address_bytes[8] as u16) << 8) | (address_bytes[9] as u16),
                ((address_bytes[10] as u16) << 8) | (address_bytes[11] as u16),
                ((address_bytes[12] as u16) << 8) | (address_bytes[13] as u16),
                ((address_bytes[14] as u16) << 8) | (address_bytes[15] as u16),
            );

            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        invalid_type => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid address type: {invalid_type}"),
        )),
    }
}

pub fn vision_flow_addon_data() -> &'static [u8] {
    static INSTANCE: LazyLock<Vec<u8>> = LazyLock::new(|| {
        encode_flow_addon(XTLS_VISION_FLOW)
            .expect("Failed to encode vision flow addon at initialization")
    });
    &INSTANCE
}

fn read_varint(data: &[u8]) -> std::io::Result<(u64, usize)> {
    let mut cursor = 0usize;
    let mut length = 0u64;
    loop {
        let byte = data[cursor];
        if (byte & 0b10000000) != 0 {
            length = (length << 8) | ((byte ^ 0b10000000) as u64);
        } else {
            length = (length << 8) | (byte as u64);
            return Ok((length, cursor + 1));
        }
        if cursor == 7 || cursor == data.len() {
            return Err(std::io::Error::other("Varint is too long"));
        }
        cursor += 1;
    }
}

/// Encode a flow string as protobuf addon data
/// Format: field_tag(0x0a) + length + data
/// Field 1 = flow (string), wire type 2 (length-delimited)
fn encode_flow_addon(flow: &str) -> std::io::Result<Vec<u8>> {
    let flow_bytes = flow.as_bytes();
    let flow_len = flow_bytes.len();

    if flow_len > 127 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Flow string too long for simple varint encoding",
        ));
    }

    let mut result = Vec::new();

    // Field 1, wire type 2 (0x0a = (1 << 3) | 2)
    result.push(0x0a);

    // Length as varint (simple case: < 128)
    result.push(flow_len as u8);

    // Flow string data
    result.extend_from_slice(flow_bytes);

    Ok(result)
}
