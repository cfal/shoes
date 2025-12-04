/// Shadow TLS implementation.
/// References:
/// - https://github.com/ihciah/shadow-tls
/// - https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art080
/// - https://wiki.osdev.org/TLS_Handshake#Client_Hello_Message
/// - https://tls13.xargs.org/#client-hello/annotated
use std::fmt::Debug;
use std::io::Cursor;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use super::shadow_tls_hmac::ShadowTlsHmac;
use super::shadow_tls_stream::ShadowTlsStream;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::buf_reader::BufReader;
use crate::client_proxy_chain::ClientProxyChain;
use crate::resolver::Resolver;
use crate::rustls_connection_util::feed_rustls_server_connection;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult};
use crate::util::{allocate_vec, write_all};

// context wrapper because it's not Debug
struct ShadowTlsXorContext(aws_lc_rs::digest::Context);

impl Debug for ShadowTlsXorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ShadowTlsXorContext]")
    }
}

#[derive(Debug)]
pub struct ShadowTlsServerTarget {
    initial_hmac: ShadowTlsHmac,
    initial_xor_context: ShadowTlsXorContext,
    handshake: ShadowTlsServerTargetHandshake,
    handler: Box<dyn TcpServerHandler>,
}

impl ShadowTlsServerTarget {
    pub fn new(
        password: String,
        handshake: ShadowTlsServerTargetHandshake,
        handler: Box<dyn TcpServerHandler>,
    ) -> Self {
        let password_bytes = password.into_bytes();
        let hmac_key = aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            &password_bytes,
        );
        let initial_hmac = ShadowTlsHmac::new(&hmac_key);
        let mut initial_xor_context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        initial_xor_context.update(&password_bytes);
        Self {
            initial_hmac,
            initial_xor_context: ShadowTlsXorContext(initial_xor_context),
            handshake,
            handler,
        }
    }
}

#[derive(Debug)]
pub enum ShadowTlsServerTargetHandshake {
    Local(Arc<rustls::ServerConfig>),
    Remote {
        location: NetLocation,
        client_chain: ClientProxyChain,
    },
}

impl ShadowTlsServerTargetHandshake {
    pub fn new_local(server_config: Arc<rustls::ServerConfig>) -> Self {
        ShadowTlsServerTargetHandshake::Local(server_config)
    }

    pub fn new_remote(location: NetLocation, client_chain: ClientProxyChain) -> Self {
        ShadowTlsServerTargetHandshake::Remote {
            location,
            client_chain,
        }
    }
}

const TLS_HEADER_LEN: usize = 5;

// the limit should be 5 (header) + 2^14 + 256 (AEAD encryption overhead) = 16640,
// although draft-mattsson-tls-super-jumbo-record-limit-01 would increase that.
// we set the limit to 5 + u16::MAX to allow for the maximum possible record size.
const TLS_FRAME_MAX_LEN: usize = TLS_HEADER_LEN + 65535;

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

// retry request random value, see https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3
// TODO: should we also check to disallow TLS1.2/TLS1.1 client downgrade requests?
const RETRY_REQUEST_RANDOM_BYTES: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Validates the ClientHello for ShadowTLS authentication.
/// Returns Ok(()) on success, or Err with PermissionDenied on auth failure.
fn validate_shadowtls_client_hello(
    parsed_client_hello: &ParsedClientHello,
    initial_hmac: &ShadowTlsHmac,
) -> std::io::Result<()> {
    let &ParsedClientHello {
        ref client_hello_frame,
        client_hello_record_legacy_version_major,
        client_hello_record_legacy_version_minor,
        client_hello_content_version_major,
        client_hello_content_version_minor,
        ref parsed_digest,
        supports_tls13,
        ..
    } = parsed_client_hello;

    let digest = match parsed_digest {
        Some(d) => d,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "client did not send a 32-byte session id",
            ));
        }
    };

    if !supports_tls13 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "client does not support TLS1.3",
        ));
    }

    if client_hello_record_legacy_version_major != 3
        || client_hello_record_legacy_version_minor != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "expected client TLS record protocol 1.0 (major/minor 3.1), got major/minor {}.{}",
                client_hello_record_legacy_version_major, client_hello_record_legacy_version_minor
            ),
        ));
    }

    if client_hello_content_version_major != 3 || client_hello_content_version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "expected client TLS content protocol 1.2 (major/minor 3.3), got major/minor {}.{}",
                client_hello_content_version_major, client_hello_content_version_minor
            ),
        ));
    }

    let mut hmac = initial_hmac.clone();
    hmac.update(&client_hello_frame[TLS_HEADER_LEN..digest.client_hello_digest_start_index]);
    hmac.update(&[0; 4]);
    hmac.update(&client_hello_frame[digest.client_hello_digest_end_index..]);

    if digest.client_hello_digest != hmac.finalized_digest() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "HMAC tag mismatch",
        ));
    }

    Ok(())
}

/// Fallback mechanism for ShadowTLS authentication failures.
///
/// When a client fails ShadowTLS authentication (invalid HMAC, wrong TLS version,
/// missing session ID, etc.), instead of dropping the connection, we transparently
/// forward it to the configured handshake server. This makes the server
/// indistinguishable from a legitimate SNI proxy, defeating active probing attacks.
async fn shadowtls_fallback_to_handshake_server(
    mut client_stream: Box<dyn AsyncStream>,
    client_hello_bytes: &[u8],
    location: &NetLocation,
    client_chain: &ClientProxyChain,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    log::debug!(
        "SHADOWTLS FALLBACK: Connecting to handshake server: {}",
        location
    );

    let TcpClientSetupResult {
        client_stream: mut handshake_stream,
        early_data,
    } = client_chain
        .connect_tcp(location.clone(), resolver)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("SHADOWTLS FALLBACK: Failed to connect to handshake server: {e}"),
            )
        })?;

    // early_data should never be present since this is a TLS server waiting for a ClientHello
    debug_assert!(
        early_data.is_none(),
        "unexpected early_data from handshake server connection"
    );

    log::debug!(
        "SHADOWTLS FALLBACK: Connected, forwarding ClientHello ({} bytes)",
        client_hello_bytes.len()
    );

    write_all(&mut handshake_stream, client_hello_bytes).await?;
    handshake_stream.flush().await?;

    log::debug!("SHADOWTLS FALLBACK: ClientHello forwarded, spawning bidirectional copy");

    // Spawn the long-running bidirectional copy as a background task.
    // This allows the setup to complete within the timeout while the actual
    // data transfer runs indefinitely.
    tokio::spawn(async move {
        let result = crate::copy_bidirectional::copy_bidirectional(
            &mut *client_stream,
            &mut *handshake_stream,
            false, // client doesn't need initial flush
            false, // handshake server doesn't need initial flush
        )
        .await;

        let _ = client_stream.shutdown().await;
        let _ = handshake_stream.shutdown().await;

        if let Err(e) = result {
            log::debug!("SHADOWTLS FALLBACK: Connection ended: {}", e);
        } else {
            log::debug!("SHADOWTLS FALLBACK: Connection completed");
        }
    });

    Ok(TcpServerSetupResult::AlreadyHandled)
}

#[inline]
pub async fn setup_shadowtls_server_stream(
    server_stream: Box<dyn AsyncStream>,
    target: &ShadowTlsServerTarget,
    parsed_client_hello: ParsedClientHello,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    // Validates ClientHello before consuming anything to allow fallback if needed.
    if let Err(e) = validate_shadowtls_client_hello(&parsed_client_hello, &target.initial_hmac) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            // Falls back to handshake server in Remote mode for auth failures.
            if let ShadowTlsServerTargetHandshake::Remote {
                ref location,
                ref client_chain,
            } = target.handshake
            {
                log::warn!(
                    "ShadowTLS authentication failed, falling back to handshake server: {} - reason: {}",
                    location,
                    e
                );
                return shadowtls_fallback_to_handshake_server(
                    server_stream,
                    &parsed_client_hello.client_hello_frame,
                    location,
                    client_chain,
                    resolver,
                )
                .await;
            }
        }
        // Local mode or non-auth error: propagate the error
        return Err(e);
    }

    let ParsedClientHello {
        client_hello_frame,
        client_reader,
        ..
    } = parsed_client_hello;

    let shadow_tls_stream = match target.handshake {
        ShadowTlsServerTargetHandshake::Remote {
            ref location,
            ref client_chain,
        } => setup_remote_handshake(
            server_stream,
            client_reader,
            client_hello_frame,
            &target.initial_hmac,
            &target.initial_xor_context,
            location.clone(),
            client_chain,
            resolver,
        )
        .await
        .map_err(|e| std::io::Error::other(format!("failed to setup remote handshake: {e}")))?,
        ShadowTlsServerTargetHandshake::Local(ref local_config) => setup_local_handshake(
            server_stream,
            client_reader,
            client_hello_frame,
            &target.initial_hmac,
            &target.initial_xor_context,
            local_config.clone(),
        )
        .await
        .map_err(|e| std::io::Error::other(format!("failed to setup local handshake: {e}")))?,
    };

    let target_setup_result = target
        .handler
        .setup_server_stream(Box::new(shadow_tls_stream))
        .await
        .map_err(|e| {
            std::io::Error::other(format!(
                "failed to setup server stream after shadow tls: {e}"
            ))
        });

    if let Ok(ref setup_result) = target_setup_result
        && matches!(setup_result, TcpServerSetupResult::AlreadyHandled)
    {
        return target_setup_result;
    }
    // Inner handler already has effective_selector from construction

    target_setup_result
}

pub struct ParsedClientHello {
    pub client_hello_frame: Vec<u8>,
    pub client_hello_record_legacy_version_major: u8,
    pub client_hello_record_legacy_version_minor: u8,
    pub client_hello_content_version_major: u8,
    pub client_hello_content_version_minor: u8,
    pub parsed_digest: Option<ParsedClientHelloDigest>,
    pub client_reader: StreamReader,
    pub requested_server_name: Option<String>,
    pub supports_tls13: bool,
}

pub struct ParsedClientHelloDigest {
    pub client_hello_digest: Vec<u8>,
    pub client_hello_digest_start_index: usize,
    pub client_hello_digest_end_index: usize,
}

#[inline]
pub async fn read_client_hello(
    server_stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<ParsedClientHello> {
    let mut client_reader = StreamReader::new_with_buffer_size(TLS_FRAME_MAX_LEN);

    // Allocates to allow borrowing the payload below.
    let client_tls_header_bytes = client_reader
        .read_slice(server_stream, TLS_HEADER_LEN)
        .await?
        .to_vec();

    let client_content_type = client_tls_header_bytes[0];
    if client_content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected client handshake",
        ));
    }

    let client_legacy_version_major = client_tls_header_bytes[1];
    let client_legacy_version_minor = client_tls_header_bytes[2];

    let client_payload_len =
        u16::from_be_bytes([client_tls_header_bytes[3], client_tls_header_bytes[4]]) as usize;
    let client_payload_bytes = client_reader
        .read_slice(server_stream, client_payload_len)
        .await?;

    let mut client_hello = BufReader::new(client_payload_bytes);
    if client_hello.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected ClientHello",
        ));
    }

    let client_hello_message_len = client_hello.read_u24_be()? as usize;
    // this should be 4 bytes less than the payload length (handshake type + 3 bytes length)
    if client_hello_message_len + 4 != client_payload_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "client hello message length mismatch",
        ));
    }

    let client_version_major = client_hello.read_u8()?;
    let client_version_minor = client_hello.read_u8()?;
    let record_protocol_version_ok = client_version_major == 0x03
        && (client_version_minor == 0x01 || client_version_minor == 0x03);
    if !record_protocol_version_ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unexpected ClientHello TLS version {client_version_major}.{client_version_minor}"
            ),
        ));
    }

    client_hello.skip(32)?; // client random

    let client_session_id_len = client_hello.read_u8()?;

    let parsed_digest = if client_session_id_len == 32 {
        let client_session_id = client_hello.read_slice(32)?;

        // Saves HMAC digest and session ID position for later validation.
        let client_hello_digest = client_session_id[28..].to_vec();
        let post_session_id_index = client_hello.position();

        let client_hello_digest_start_index = TLS_HEADER_LEN + post_session_id_index - 4;
        let client_hello_digest_end_index = TLS_HEADER_LEN + post_session_id_index;

        Some(ParsedClientHelloDigest {
            client_hello_digest,
            client_hello_digest_start_index,
            client_hello_digest_end_index,
        })
    } else {
        if client_session_id_len > 0 {
            client_hello.skip(client_session_id_len as usize)?;
        }
        None
    };

    let client_cipher_suite_len = client_hello.read_u16_be()?;
    client_hello.skip(client_cipher_suite_len as usize)?;

    let client_compression_method_len = client_hello.read_u8()?;
    client_hello.skip(client_compression_method_len as usize)?;

    let client_extensions_len = client_hello.read_u16_be()?;
    let client_extension_bytes = client_hello.read_slice(client_extensions_len as usize)?;

    let mut client_extensions = BufReader::new(client_extension_bytes);

    let mut requested_server_name: Option<String> = None;
    let mut client_supports_tls13 = false;

    while !client_extensions.is_consumed() {
        let extension_type = client_extensions.read_u16_be()?;
        let extension_len = client_extensions.read_u16_be()? as usize;

        if extension_type == 0x0000 {
            // server_name
            if requested_server_name.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "multiple server names",
                ));
            }
            // TODO: assert lengths
            let _server_name_list_len = client_extensions.read_u16_be()?;
            let server_name_type = client_extensions.read_u8()?;
            if server_name_type != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected server name type to be hostname (0)",
                ));
            }
            let server_name_len = client_extensions.read_u16_be()?;
            let server_name_str = client_extensions.read_str(server_name_len as usize)?;
            requested_server_name = Some(server_name_str.to_string());
        } else if extension_type == 0x002b {
            // supported_versions
            let version_list_len = client_extensions.read_u8()?;
            if version_list_len % 2 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid odd version list length: 0x{version_list_len:02x}"),
                ));
            }
            let version_list_bytes = client_extensions.read_slice(version_list_len as usize)?;
            for i in (0..version_list_bytes.len()).step_by(2) {
                let version_major = version_list_bytes[i];
                let version_minor = version_list_bytes[i + 1];
                if version_major == 3 && version_minor == 4 {
                    client_supports_tls13 = true;
                    break;
                }
            }
        } else {
            client_extensions.skip(extension_len)?;
        }
    }

    let mut client_hello_frame =
        Vec::with_capacity(client_tls_header_bytes.len() + client_payload_bytes.len());
    client_hello_frame.extend_from_slice(&client_tls_header_bytes);
    client_hello_frame.extend_from_slice(client_payload_bytes);

    Ok(ParsedClientHello {
        client_hello_frame,
        client_hello_record_legacy_version_major: client_legacy_version_major,
        client_hello_record_legacy_version_minor: client_legacy_version_minor,
        client_hello_content_version_major: client_version_major,
        client_hello_content_version_minor: client_version_minor,
        parsed_digest,
        client_reader,
        requested_server_name,
        supports_tls13: client_supports_tls13,
    })
}

pub struct ParsedServerHello {
    pub server_random: Vec<u8>,
    pub cipher_suite: u16,
    pub session_id_len: u8,
    pub is_tls13: bool,
}

/// Parses a ServerHello frame and extracts relevant fields.
/// This is a generic parser that can be used by multiple protocols (ShadowTLS, Vision).
/// It performs strict validation on structure but is lenient on TLS version requirements.
/// Use `parse_validated_server_hello` for ShadowTLS-specific validation.
pub fn parse_server_hello(server_hello_frame: &[u8]) -> std::io::Result<ParsedServerHello> {
    // Minimum size when session_id_len=0 and no extensions:
    // 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random)
    // + 1 (session_id_len byte) + 2 (cipher) + 1 (compression) = 47
    if server_hello_frame.len() < 47 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello frame too short",
        ));
    }

    let content_type = server_hello_frame[0];
    if content_type != CONTENT_TYPE_HANDSHAKE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected handshake content type",
        ));
    }

    let record_version_major = server_hello_frame[1];
    let record_version_minor = server_hello_frame[2];
    if record_version_major != 3 || record_version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected record TLS version {record_version_major}.{record_version_minor}"),
        ));
    }

    let mut reader = BufReader::new(&server_hello_frame[TLS_HEADER_LEN..]);

    let handshake_type = reader.read_u8()?;
    if handshake_type != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected ServerHello handshake type",
        ));
    }

    let message_len = reader.read_u24_be()? as usize;
    if reader.remaining() < message_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello message length exceeds frame",
        ));
    }

    // Legacy version (should be 0x0303 for TLS 1.2/1.3)
    let version_major = reader.read_u8()?;
    let version_minor = reader.read_u8()?;
    if version_major != 3 || version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected TLS version 3.3, got {version_major}.{version_minor}"),
        ));
    }

    let server_random = reader.read_slice(32)?.to_vec();
    if server_random == RETRY_REQUEST_RANDOM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server sent a HelloRetryRequest",
        ));
    }

    // Session ID (variable length, 0-32 bytes)
    let session_id_len = reader.read_u8()?;
    if session_id_len > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid session_id_len {session_id_len}, max is 32"),
        ));
    }
    reader.skip(session_id_len as usize)?;

    let cipher_suite = reader.read_u16_be()?;
    reader.skip(1)?; // compression method
    let mut is_tls13 = false;
    if !reader.is_consumed() {
        let extensions_len = reader.read_u16_be()? as usize;
        if reader.remaining() < extensions_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "extensions length exceeds remaining data",
            ));
        }

        let extensions_data = reader.read_slice(extensions_len)?;
        let mut ext_reader = BufReader::new(extensions_data);

        while !ext_reader.is_consumed() {
            let ext_type = ext_reader.read_u16_be()?;
            let ext_len = ext_reader.read_u16_be()?;

            if ext_type == TLS_EXT_SUPPORTED_VERSIONS {
                // In ServerHello, supported_versions is exactly 2 bytes (single selected version).
                if ext_len != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("supported_versions extension should be 2 bytes, got {ext_len}"),
                    ));
                }
                let version_bytes = ext_reader.read_slice(2)?;
                is_tls13 = version_bytes[0] == 0x03 && version_bytes[1] == 0x04; // TLS 1.3
            } else {
                ext_reader.skip(ext_len as usize)?;
            }
        }
    }

    Ok(ParsedServerHello {
        server_random,
        cipher_suite,
        session_id_len,
        is_tls13,
    })
}

/// ShadowTLS-specific ServerHello parser with additional validation.
/// Requires TLS 1.3 and 32-byte session_id.
pub fn parse_validated_server_hello(
    server_hello_frame: &[u8],
) -> std::io::Result<ParsedServerHello> {
    let parsed = parse_server_hello(server_hello_frame)?;

    if !parsed.is_tls13 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ShadowTLS requires TLS 1.3 (missing or invalid supported_versions extension)",
        ));
    }

    // We sent a 32 byte session ID so this should never happen
    if parsed.session_id_len != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ShadowTLS expects session_id_len 32, got {}",
                parsed.session_id_len
            ),
        ));
    }

    Ok(parsed)
}

#[allow(clippy::too_many_arguments)]
#[inline]
async fn setup_remote_handshake(
    mut server_stream: Box<dyn AsyncStream>,
    mut client_reader: StreamReader,
    client_hello_frame: Vec<u8>,
    initial_hmac: &ShadowTlsHmac,
    initial_xor_context: &ShadowTlsXorContext,
    remote_addr: NetLocation,
    client_chain: &ClientProxyChain,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<ShadowTlsStream> {
    use crate::tcp::tcp_handler::TcpClientSetupResult;

    // The TLS handshake server is called client_stream (we are a client to it).
    let TcpClientSetupResult {
        mut client_stream,
        early_data: _,
    } = client_chain
        .connect_tcp(remote_addr, resolver)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("failed to connect to remote handshake server: {e}"),
            )
        })?;

    write_all(&mut client_stream, &client_hello_frame)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("failed to send ClientHello to remote server: {e}"),
            )
        })?;
    client_stream.flush().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            format!("failed to flush ClientHello to remote server: {e}"),
        )
    })?;

    let mut server_reader = StreamReader::new_with_buffer_size(TLS_FRAME_MAX_LEN);
    let server_header_bytes = server_reader
        .read_slice(&mut client_stream, TLS_HEADER_LEN)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to read ServerHello header from remote server: {e}"),
            )
        })?;

    let server_payload_size = u16::from_be_bytes([server_header_bytes[3], server_header_bytes[4]]);

    let mut server_hello_frame =
        Vec::with_capacity(server_header_bytes.len() + server_payload_size as usize);
    server_hello_frame.extend_from_slice(server_header_bytes);

    let server_payload_bytes = server_reader
        .read_slice(&mut client_stream, server_payload_size as usize)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!(
                    "failed to read ServerHello payload from remote server (size: {server_payload_size}): {e}"
                ),
            )
        })?;
    server_hello_frame.extend_from_slice(server_payload_bytes);

    let ParsedServerHello { server_random, .. } = parse_validated_server_hello(&server_hello_frame)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse ServerHello from remote server: {e}"),
            )
        })?;

    write_all(&mut server_stream, &server_hello_frame)
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("failed to write ServerHello to client: {e}"),
            )
        })?;
    server_stream.flush().await.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            format!("failed to flush ServerHello to client: {e}"),
        )
    })?;

    let mut hmac_server_random = initial_hmac.clone();
    hmac_server_random.update(&server_random);

    let mut hmac_client_data = hmac_server_random.clone();
    hmac_client_data.update(b"C");

    let mut hmac_server_data = hmac_server_random.clone();
    hmac_server_data.update(b"S");

    let server_app_data_xor = {
        let mut key_context = initial_xor_context.0.clone();
        key_context.update(&server_random);
        key_context.finish().as_ref().to_vec()
    };

    let mut server_frame = vec![];
    let mut client_frame = vec![];

    loop {
        tokio::select! {
            server_read_result = server_reader.read_slice(&mut client_stream, TLS_HEADER_LEN) => {
                server_frame.clear();

                let server_header_bytes = server_read_result
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("failed to read TLS header from remote server during handshake: {e}")
                    ))?;
                let server_payload_size = u16::from_be_bytes(server_header_bytes[3..5].try_into().unwrap()) as usize;
                server_frame.extend_from_slice(server_header_bytes);
                let server_payload_bytes = server_reader
                    .read_slice(&mut client_stream, server_payload_size)
                    .await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("failed to read TLS payload from remote server during handshake (size {server_payload_size}): {e}")
                    ))?;
                server_frame.extend_from_slice(server_payload_bytes);

                let server_content_type = server_frame[0];
                if server_content_type == CONTENT_TYPE_APPLICATION_DATA {
                   if server_payload_size > TLS_FRAME_MAX_LEN - 4 {
                       return Err(std::io::Error::new(
                           std::io::ErrorKind::InvalidData,
                           "server payload too large to modify",
                       ));
                   }
                   // TODO: do this in a single loop, see the same comment in local handshake
                   let iter = server_frame[TLS_HEADER_LEN..TLS_HEADER_LEN + server_payload_size].iter_mut().zip(server_app_data_xor.iter().cycle());
                   for (byte, &key) in iter {
                       *byte ^= key;
                   }
                   server_frame.extend([0u8; 4]);
                   server_frame.copy_within(TLS_HEADER_LEN..TLS_HEADER_LEN + server_payload_size, TLS_HEADER_LEN + 4);

                   hmac_server_random.update(&server_frame[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + 4 + server_payload_size]);
                   let hmac_digest = hmac_server_random.digest();
                   server_frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4]
                       .copy_from_slice(&hmac_digest);

                   let updated_payload_size = (server_payload_size as u16).wrapping_add(4);
                   server_frame[3..5].copy_from_slice(&updated_payload_size.to_be_bytes());
                }

                write_all(&mut server_stream, &server_frame).await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("failed to write server frame to client: {e}")
                    ))?;
                server_stream.flush().await.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("failed to flush server frame to client: {e}"),
                    )
                })?;
            }
            client_read_result = client_reader.read_slice(&mut server_stream, TLS_HEADER_LEN) => {
                client_frame.clear();

                let client_header_bytes = client_read_result
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("failed to read TLS header from client during handshake: {e}")
                    ))?;

                let client_content_type = client_header_bytes[0];
                let client_payload_size = u16::from_be_bytes([client_header_bytes[3], client_header_bytes[4]]) as usize;
                client_frame.extend_from_slice(client_header_bytes);

                let client_payload_bytes = client_reader
                    .read_slice(&mut server_stream, client_payload_size)
                    .await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        format!("failed to read TLS payload from client during handshake (size {client_payload_size}): {e}")
                    ))?;

                if client_content_type == CONTENT_TYPE_APPLICATION_DATA {
                    let mut tmp_hmac = hmac_client_data.clone();
                    tmp_hmac.update(&client_payload_bytes[4..]);

                    if tmp_hmac.finalized_digest() == client_payload_bytes[..4] {
                        let initial_client_data = &client_payload_bytes[4..];

                        hmac_client_data.update(initial_client_data);
                        hmac_client_data.update(&hmac_client_data.digest());

                        let _ = client_stream.shutdown().await;

                        let mut shadow_tls_stream = ShadowTlsStream::new(
                            server_stream,
                            initial_client_data,
                            hmac_client_data,
                            hmac_server_data,
                            None,
                        ).map_err(|e| std::io::Error::other(
                            format!("failed to create ShadowTlsStream: {e}")
                        ))?;

                        let unparsed_data = client_reader.unparsed_data();
                        if !unparsed_data.is_empty() {
                            shadow_tls_stream.feed_initial_read_data(unparsed_data)
                                .map_err(|e| std::io::Error::other(
                                    format!("failed to feed initial data to ShadowTlsStream: {e}")
                                ))?;
                        }

                        return Ok(shadow_tls_stream);
                    }
                }

                client_frame.extend_from_slice(client_payload_bytes);
                write_all(&mut client_stream, &client_frame).await
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("failed to write client frame to remote server: {e}")
                    ))?;
                client_stream.flush().await.map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("failed to flush client frame to remote server: {e}"),
                    )
                })?;
            }
        }
    }
}

#[inline]
async fn setup_local_handshake(
    mut server_stream: Box<dyn AsyncStream>,
    mut client_reader: StreamReader,
    client_hello_frame: Vec<u8>,
    initial_hmac: &ShadowTlsHmac,
    initial_xor_context: &ShadowTlsXorContext,
    server_config: Arc<rustls::ServerConfig>,
) -> std::io::Result<ShadowTlsStream> {
    let mut server_connection = rustls::ServerConnection::new(server_config).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to create server connection: {e}"),
        )
    })?;

    feed_rustls_server_connection(&mut server_connection, &client_hello_frame)?;

    server_connection.process_new_packets().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to process ClientHello packet: {e}"),
        )
    })?;

    if !server_connection.wants_write() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server connection wants no write",
        ));
    }

    // enough for full tls frame with header + frame
    let mut server_data = allocate_vec(TLS_FRAME_MAX_LEN);

    let server_data_len = read_server_connection(&mut server_connection, &mut server_data)?;

    if server_data_len < TLS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server data too short for header",
        ));
    }

    let server_hello_payload_size = u16::from_be_bytes([server_data[3], server_data[4]]) as usize;
    if server_data_len < TLS_HEADER_LEN + server_hello_payload_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server data too short for payload",
        ));
    }

    let server_hello_frame = &server_data[0..TLS_HEADER_LEN + server_hello_payload_size];

    let ParsedServerHello { server_random, .. } = parse_validated_server_hello(server_hello_frame)?;

    write_all(&mut server_stream, server_hello_frame).await?;

    // The server sends multiple frames after ServerHello; process remaining data.
    let remaining_server_data_len =
        server_data_len - TLS_HEADER_LEN - server_hello_payload_size as usize;
    if remaining_server_data_len > 0 {
        server_data.copy_within(
            TLS_HEADER_LEN + server_hello_payload_size
                ..TLS_HEADER_LEN + server_hello_payload_size + remaining_server_data_len,
            0,
        );
    }
    let mut server_data_end_index = remaining_server_data_len;

    let mut hmac_server_random = initial_hmac.clone();
    hmac_server_random.update(&server_random);

    let mut hmac_client_data = hmac_server_random.clone();
    hmac_client_data.update(b"C");

    let mut hmac_server_data = hmac_server_random.clone();
    hmac_server_data.update(b"S");

    let server_app_data_xor = {
        let mut key_context = initial_xor_context.0.clone();
        key_context.update(&server_random);
        key_context.finish().as_ref().to_vec()
    };

    // Copies bidirectionally until finding a matching HMAC at the front of an app data frame.
    loop {
        loop {
            if server_data_end_index < TLS_HEADER_LEN {
                if server_connection.wants_write() {
                    let server_data_len = read_server_connection_once(
                        &mut server_connection,
                        &mut server_data[server_data_end_index..],
                    )?;
                    server_data_end_index += server_data_len;
                    continue;
                }
                break;
            }

            let server_content_type = server_data[0];
            let server_legacy_version_major = server_data[1];
            let server_legacy_version_minor = server_data[2];
            if server_legacy_version_major != 3 || server_legacy_version_minor != 3 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unexpected local server TLS version {server_legacy_version_major}.{server_legacy_version_minor}"
                    ),
                ));
            }
            let server_payload_size = u16::from_be_bytes([server_data[3], server_data[4]]) as usize;

            if server_data_end_index < TLS_HEADER_LEN + server_payload_size {
                if server_connection.wants_write() {
                    let server_data_len = read_server_connection_once(
                        &mut server_connection,
                        &mut server_data[server_data_end_index..],
                    )?;
                    server_data_end_index += server_data_len;
                    continue;
                }
                break;
            }

            if server_content_type == CONTENT_TYPE_APPLICATION_DATA {
                if server_payload_size > TLS_FRAME_MAX_LEN - 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "server payload too large to modify",
                    ));
                }
                // Modifying frame requires shifting all following frames back by 4 bytes.
                if server_data_end_index > TLS_FRAME_MAX_LEN + TLS_HEADER_LEN - 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "server data too large to modify",
                    ));
                }

                // TODO: we could possibly do this in a single loop by starting from the end of the payload to the
                // beginning, and placing the xor'ed byte at its initial position + 4 for the
                // hash length. but we'd have to figure out which byte in `xor` it corresponds
                // to.
                let iter = server_data[TLS_HEADER_LEN..TLS_HEADER_LEN + server_payload_size]
                    .iter_mut()
                    .zip(server_app_data_xor.iter().cycle());
                for (byte, &key) in iter {
                    *byte ^= key;
                }

                server_data.copy_within(TLS_HEADER_LEN..server_data_end_index, TLS_HEADER_LEN + 4);
                server_data_end_index += 4;

                hmac_server_random.update(
                    &server_data[TLS_HEADER_LEN + 4..TLS_HEADER_LEN + 4 + server_payload_size],
                );
                server_data[TLS_HEADER_LEN..TLS_HEADER_LEN + 4]
                    .copy_from_slice(&hmac_server_random.digest());

                let updated_payload_size = (server_payload_size as u16).wrapping_add(4);
                server_data[3..5].copy_from_slice(&updated_payload_size.to_be_bytes());

                write_all(&mut server_stream, &server_data[0..9 + server_payload_size]).await?;

                server_data.copy_within(9 + server_payload_size..server_data_end_index, 0);
                server_data_end_index -= 9 + server_payload_size;
            } else {
                write_all(
                    &mut server_stream,
                    &server_data[0..TLS_HEADER_LEN + server_payload_size],
                )
                .await?;

                server_data.copy_within(
                    TLS_HEADER_LEN + server_payload_size..server_data_end_index,
                    0,
                );
                server_data_end_index -= TLS_HEADER_LEN + server_payload_size;
            };
        }

        let client_header_bytes = client_reader
            .read_slice(&mut server_stream, 5)
            .await?
            .to_vec();
        let client_content_type = client_header_bytes[0];
        let _client_legacy_version_major = client_header_bytes[1];
        let _client_legacy_version_minor = client_header_bytes[2];
        let client_payload_size =
            u16::from_be_bytes([client_header_bytes[3], client_header_bytes[4]]);

        let client_payload_bytes = client_reader
            .read_slice(&mut server_stream, client_payload_size as usize)
            .await?;

        if client_content_type == CONTENT_TYPE_APPLICATION_DATA {
            let mut tmp_hmac = hmac_client_data.clone();
            tmp_hmac.update(&client_payload_bytes[4..]);

            if tmp_hmac.finalized_digest() == client_payload_bytes[..4] {
                let initial_client_data = &client_payload_bytes[4..];

                hmac_client_data.update(initial_client_data);
                hmac_client_data.update(&hmac_client_data.digest());

                let mut shadow_tls_stream = ShadowTlsStream::new(
                    server_stream,
                    initial_client_data,
                    hmac_client_data,
                    hmac_server_data,
                    None,
                )?;

                // Feeds any leftover data from the reader to the stream.
                let leftover = client_reader.unparsed_data();
                if !leftover.is_empty() {
                    shadow_tls_stream.feed_initial_read_data(leftover)?;
                }

                return Ok(shadow_tls_stream);
            }
        }

        feed_rustls_server_connection(&mut server_connection, &client_header_bytes)?;
        feed_rustls_server_connection(&mut server_connection, client_payload_bytes)?;

        server_connection.process_new_packets().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to process pre-auth client packets: {e}"),
            )
        })?;
    }
}

#[inline]
fn read_server_connection(
    server_connection: &mut rustls::ServerConnection,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut server_data_cursor = Cursor::new(buf);
    while server_connection.wants_write() {
        server_connection
            .write_tls(&mut server_data_cursor)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to write tls frame: {e}"),
                )
            })?;
    }
    Ok(server_data_cursor.position() as usize)
}

#[inline]
fn read_server_connection_once(
    server_connection: &mut rustls::ServerConnection,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut server_data_cursor = Cursor::new(buf);
    server_connection
        .write_tls(&mut server_data_cursor)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to write tls frame: {e}"),
            )
        })?;
    Ok(server_data_cursor.position() as usize)
}
