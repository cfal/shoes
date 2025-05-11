use std::io::Cursor;
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngCore;
use tokio::io::AsyncWriteExt; // For write_all // For random bytes

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::buf_reader::BufReader;
use crate::shadow_tls::shadow_tls_hmac::ShadowTlsHmac;
use crate::shadow_tls::shadow_tls_stream::ShadowTlsStream;
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{TcpClientHandler, TcpClientSetupResult};
use crate::util::{allocate_vec, write_all}; // Assuming write_all is from crate::util

use super::shadow_tls_server_handler::parse_server_hello;

// Constants from shadow_tls_server_handler
const TLS_HEADER_LEN: usize = 5;
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65535;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const CONTENT_TYPE_ALERT: u8 = 0x15;

// Handshake message types
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

#[derive(Debug)]
pub struct ShadowTlsClientHandler {
    initial_hmac: ShadowTlsHmac,
    client_config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
    handler: Box<dyn TcpClientHandler>,
}

impl ShadowTlsClientHandler {
    pub fn new(
        password: String,
        client_config: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let hmac_key = aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            &password.into_bytes(),
        );
        let initial_hmac = ShadowTlsHmac::new(&hmac_key);
        Self {
            initial_hmac,
            client_config,
            server_name,
            handler,
        }
    }
}

#[async_trait]
impl TcpClientHandler for ShadowTlsClientHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        _remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_conn =
            rustls::ClientConnection::new(self.client_config.clone(), self.server_name.clone())
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create ClientConnection: {}", e),
                    )
                })?;

        let mut client_hello_buf = Vec::with_capacity(512); // Typical ClientHello
        if client_conn.wants_write() {
            client_conn.write_tls(&mut Cursor::new(&mut client_hello_buf))?;
        }
        if client_hello_buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rustls::ClientConnection did not produce ClientHello",
            ));
        }

        let modified_client_hello = modify_client_hello(&client_hello_buf, &self.initial_hmac)?;

        write_all(&mut client_stream, &modified_client_hello).await?;
        client_stream.flush().await?;

        let mut remote_reader = StreamReader::new_with_buffer_size(TLS_FRAME_MAX_LEN * 2);

        let server_hello_frame =
            read_full_tls_frame(&mut remote_reader, &mut client_stream).await?;

        let parsed_server_hello = parse_server_hello(&server_hello_frame)?;

        feed_client_connection(&mut client_conn, &server_hello_frame)?;
        client_conn.process_new_packets().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to process ServerHello frame: {}", e),
            )
        })?;

        let mut rustls_write_buf = allocate_vec(TLS_FRAME_MAX_LEN); // For client_conn.write_tls()

        let mut hmac_server_random = self.initial_hmac.clone();
        hmac_server_random.update(&parsed_server_hello.server_random);

        let mut hmac_client_data = hmac_server_random.clone();
        hmac_client_data.update(b"C");

        let mut hmac_server_data = hmac_server_random.clone();
        hmac_server_data.update(b"S");

        while client_conn.is_handshaking() {
            if client_conn.wants_write() {
                let mut cursor = Cursor::new(&mut rustls_write_buf[..]);
                match client_conn.write_tls(&mut cursor) {
                    Ok(n) if n > 0 => {
                        write_all(&mut client_stream, &rustls_write_buf[..n]).await?;
                        client_stream.flush().await?;
                    }
                    Ok(_) => { /* wrote 0 bytes */ }
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("rustls write_tls error: {}", e),
                        ))
                    }
                }
                continue;
            }

            let server_frame = read_full_tls_frame(&mut remote_reader, &mut client_stream).await?;
            let content_type = server_frame[0];

            if content_type == CONTENT_TYPE_APPLICATION_DATA {
                // since we are still handshaking, this must be an encrypted TLS 1.3 handshake record from
                // the handshake server, so we expect it to pass the ServerRandom hmac check.
                // once we get here, we are done with the initial handshake and can break.
                let payload_len = u16::from_be_bytes([server_frame[3], server_frame[4]]) as usize;
                if payload_len < 4 + 1 {
                    // must be at least 4 for the hmac digest and non-empty data after it
                    // TODO: should this check for a larger record size?
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "app data record too short for handshake data",
                    ));
                }

                let received_hmac = &server_frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
                let data_after_hmac =
                    &server_frame[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + payload_len];

                hmac_server_random.update(data_after_hmac);
                if hmac_server_random.digest() != received_hmac {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid HMAC for handshake data",
                    ));
                }

                break;
            }

            if content_type == CONTENT_TYPE_ALERT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unexpected alert frame from ShadowTLS server during handshake"),
                ));
            }

            feed_client_connection(&mut client_conn, &server_frame)?;
            client_conn.process_new_packets().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Failed to process handshake frame of type {}: {}",
                        content_type, e
                    ),
                )
            })?;
        }

        // The ShadowTlsStream will need to be adapted for client-side logic:
        // - On read, first try to match HMAC_ServerRandom (from hmac_key_psk + server_random). If match, XOR and discard.
        // - If not, try to match HMAC_ServerRandomS (from hmac_for_receiving_data). If match, this is app data.
        // - Once HMAC_ServerRandomS matches, only use that for future frames.
        // For now, assuming ShadowTlsStream takes the Stage 2 HMACs directly.

        let mut shadow_tls_stream = ShadowTlsStream::new(
            client_stream,
            &[],
            hmac_server_data,
            hmac_client_data,
            Some(hmac_server_random),
        )?;

        // Feed any unconsumed data from StreamReader from handshake phase
        let unparsed_handshake_data = remote_reader.unparsed_data();
        if !unparsed_handshake_data.is_empty() {
            shadow_tls_stream.feed_initial_read_data(unparsed_handshake_data)?;
        }

        self.handler
            .setup_client_stream(
                _server_stream,
                Box::new(shadow_tls_stream),
                _remote_location,
            )
            .await
    }
}

fn modify_client_hello(
    original_frame: &[u8],
    initial_hmac: &ShadowTlsHmac,
) -> std::io::Result<Vec<u8>> {
    if original_frame.len() < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello frame too short for header",
        ));
    }
    if original_frame[0] != CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ClientHello handshake content type",
        ));
    }

    // TLS 1.3 ClientHello is sent in a TLS 1.0 (0x0301) or TLS 1.2 (0x0303) record format.
    let record_protocol_version_ok = (original_frame[1] == 0x03 && original_frame[2] == 0x01)
        || (original_frame[1] == 0x03 && original_frame[2] == 0x03);
    if !record_protocol_version_ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Unexpected ClientHello record TLS version {}.{}",
                original_frame[1], original_frame[2]
            ),
        ));
    }

    let original_payload_len = u16::from_be_bytes([original_frame[3], original_frame[4]]) as usize;
    if original_frame.len() != TLS_HEADER_LEN + original_payload_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello frame length mismatch",
        ));
    }

    let mut reader = BufReader::new(&original_frame[TLS_HEADER_LEN..]);

    let handshake_type = reader.read_u8()?;
    if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected ClientHello handshake message type",
        ));
    }

    let client_hello_payload_len = reader.read_u24_be()? as usize;
    if reader.position() + client_hello_payload_len != original_payload_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ClientHello message length inconsistent with record payload length",
        ));
    }

    let ch_protocol_ver_major = reader.read_u8()?;
    let ch_protocol_ver_minor = reader.read_u8()?;
    // TLS 1.3 ClientHello message itself states version TLS 1.2 (0x0303)
    if ch_protocol_ver_major != 0x03 || ch_protocol_ver_minor != 0x03 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ClientHello message version is {}.{}, expected 3.3 for TLS 1.3",
                ch_protocol_ver_major, ch_protocol_ver_minor
            ),
        ));
    }

    let client_random = reader.read_slice(32)?.to_vec();

    let original_session_id_len = reader.read_u8()? as usize;
    if original_session_id_len != 0 {
        // This is random data for TLS1.3 and unused, but still populated for middlebox compatibility.
        if original_session_id_len != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Original ClientHello SessionID is not 32 bytes",
            ));
        }
        reader.skip(32)?;
    }

    // The rest of the ClientHello message (cipher suites, compression, extensions)
    let remaining_ch_data_offset = reader.position();
    let remaining_ch_data = &original_frame[TLS_HEADER_LEN + remaining_ch_data_offset..];

    let mut new_session_id_value = [0u8; 32];
    rand::rng().fill_bytes(&mut new_session_id_value[0..28]); // First 28 bytes random

    // new length for the session id
    let new_client_hello_payload_len = client_hello_payload_len + (32 - original_session_id_len);

    // 4 bytes more because of handshake message type (1 byte) and hello data length (3 bytes)
    let new_record_payload_len = new_client_hello_payload_len + 4;

    let mut modified_frame = Vec::with_capacity(TLS_HEADER_LEN + new_record_payload_len);

    modified_frame.push(CONTENT_TYPE_HANDSHAKE);
    modified_frame.push(original_frame[1]); // Record protocol major (e.g., 0x03)
    modified_frame.push(original_frame[2]); // Record protocol minor (e.g., 0x01 or 0x03)
    modified_frame.extend_from_slice(&(new_record_payload_len as u16).to_be_bytes());

    // client hello payload
    modified_frame.push(handshake_type);
    modified_frame.extend_from_slice(&(new_client_hello_payload_len as u32).to_be_bytes()[1..]); // u24
    modified_frame.push(ch_protocol_ver_major);
    modified_frame.push(ch_protocol_ver_minor);
    modified_frame.extend_from_slice(&client_random);
    modified_frame.push(32u8);
    modified_frame.extend_from_slice(&new_session_id_value[0..28]);
    let digest_index = modified_frame.len();
    modified_frame.extend_from_slice(&[0u8; 4]);
    modified_frame.extend_from_slice(remaining_ch_data);

    let mut hmac_ctx = initial_hmac.clone();
    hmac_ctx.update(&modified_frame[TLS_HEADER_LEN..]);
    let hmac_tag = hmac_ctx.finalized_digest();
    modified_frame[digest_index..digest_index + 4].copy_from_slice(&hmac_tag);

    Ok(modified_frame)
}

async fn read_full_tls_frame(
    reader: &mut StreamReader,
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<Vec<u8>> {
    let header_bytes = reader.read_slice(stream, TLS_HEADER_LEN).await?;

    let payload_len = u16::from_be_bytes([header_bytes[3], header_bytes[4]]) as usize;
    if payload_len > TLS_FRAME_MAX_LEN - TLS_HEADER_LEN {
        // Check against max possible payload
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS frame payload too large",
        ));
    }

    let mut full_frame = Vec::with_capacity(TLS_HEADER_LEN + payload_len);
    full_frame.extend_from_slice(header_bytes);

    let payload_bytes = reader.read_slice(stream, payload_len).await?;
    full_frame.extend_from_slice(payload_bytes);

    Ok(full_frame)
}

#[inline]
fn feed_client_connection(
    client_connection: &mut rustls::ClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = client_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed client connection: {}", e),
            )
        })?;
        i += n;
    }
    Ok(())
}
