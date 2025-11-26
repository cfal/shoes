//! Generic rustls handshake helper that works for both client and server connections.
//!
//! This module provides a unified handshake implementation that works correctly
//! with both TLS 1.2 and TLS 1.3, for both client and server connections.
//!
//! The key insight from tokio-rustls is to use rustls's `wants_read()` and
//! `wants_write()` methods to let the TLS state machine guide the handshake,
//! rather than assuming packet boundaries or TLS version-specific message patterns.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoConnection, feed_crypto_connection};
use crate::util;

/// Perform a complete TLS handshake using the provided rustls connection and stream.
///
/// This function works for both client and server connections (via `rustls::Connection`),
/// and handles both TLS 1.2 and TLS 1.3 correctly by following rustls's state machine
/// guidance via `wants_read()` and `wants_write()`.
///
/// # Arguments
///
/// * `connection` - The rustls::Connection (either Client or Server variant)
/// * `stream` - The underlying async stream to read/write TLS data
/// * `buffer_size` - Size of the read buffer (typically 16384)
///
/// # Returns
///
/// Returns `Ok(())` if the handshake completes successfully.
///
/// # Errors
///
/// Returns an error if:
/// - EOF is encountered during handshake
/// - TLS processing fails (certificate validation, protocol error, etc.)
/// - I/O error occurs
/// - Handshake stalls (neither wants_read nor wants_write but still handshaking)
///
/// # Example
///
/// ```ignore
/// use rustls::Connection;
///
/// let client_conn = rustls::ClientConnection::new(config, server_name)?;
/// let mut connection = Connection::Client(client_conn);
/// perform_crypto_handshake(&mut connection, &mut tcp_stream, 16384).await?;
/// // Handshake complete, connection ready for application data
/// ```
pub async fn perform_crypto_handshake(
    connection: &mut CryptoConnection,
    stream: &mut Box<dyn AsyncStream>,
    buffer_size: usize,
) -> std::io::Result<()> {
    log::debug!("TLS handshake starting");

    let mut iteration = 0;
    let mut eof = false;

    // Pre-allocate read buffer once, reused across all iterations
    let mut read_buf = vec![0u8; buffer_size];

    // Infinite loop - we explicitly break when done
    // This matches tokio-rustls's structure: loop { ... return match ... }
    loop {
        iteration += 1;
        let mut write_would_block = false;
        let mut read_would_block = false;
        let until_handshaked = connection.is_handshaking();

        log::trace!(
            "TLS handshake iteration {}: is_handshaking={}, wants_read={}, wants_write={}",
            iteration,
            connection.is_handshaking(),
            connection.wants_read(),
            connection.wants_write()
        );

        // Early exit: if rustls doesn't want anything, check handshake state
        if !connection.wants_read() && !connection.wants_write() {
            if connection.is_handshaking() {
                // Still handshaking but nothing to do - this shouldn't happen
                log::error!("TLS handshake stalled: neither wants_read nor wants_write");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLS handshake stalled: neither wants_read nor wants_write",
                ));
            }
            // Not handshaking and nothing wanted - we're done
            log::debug!(
                "TLS handshake complete (early exit) after {} iterations",
                iteration
            );
            break;
        }

        // Phase 1: Drain all pending writes
        let mut wrote_data = false;
        while connection.wants_write() {
            match write_pending_data_no_flush(connection, stream).await {
                Ok(did_write) => {
                    wrote_data |= did_write;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    write_would_block = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        // Phase 2: Flush the stream only if we wrote data
        if wrote_data {
            match stream.flush().await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    write_would_block = true;
                }
                Err(e) => return Err(e),
            }
        }

        // Phase 3: Read ONCE if rustls wants more data AND we're still handshaking
        //
        // Unlike tokio-rustls which uses non-blocking I/O with Poll::Pending,
        // we use blocking async I/O. Therefore we can NOT loop on wants_read() because
        // each read() blocks. We only read ONCE per main loop iteration.
        //
        // Note that we don't read after handshake completes - wants_read() may be true for
        // post-handshake messages (session tickets) but we'd block forever waiting.
        if !eof && connection.is_handshaking() && connection.wants_read() {
            match read_and_process_data(connection, stream, &mut read_buf).await {
                Ok(0) => {
                    log::debug!("TLS handshake: EOF from peer");
                    eof = true;
                }
                Ok(n) => {
                    log::debug!("TLS handshake: read and processed {} bytes", n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    read_would_block = true;
                }
                Err(e) => {
                    // Last-gasp write: try to send any pending alert before returning error
                    try_last_gasp_write(connection, stream).await;
                    return Err(e);
                }
            }
        }

        // Phase 4: Check handshake state and decide what to do next
        log::debug!(
            "TLS handshake iteration {} done: eof={}, is_handshaking={}, wants_write={}",
            iteration,
            eof,
            connection.is_handshaking(),
            connection.wants_write()
        );

        // If handshake just completed but there are pending writes, continue loop to flush them
        // (matches rustls complete_io behavior)
        if until_handshaked && !connection.is_handshaking() && connection.wants_write() {
            log::debug!("TLS handshake: complete but has pending writes, continuing");
            continue;
        }

        match (eof, connection.is_handshaking()) {
            // EOF + still handshaking = error
            (true, true) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF during TLS handshake",
                ));
            }
            // Handshake complete! (regardless of EOF state)
            (_, false) => {
                log::debug!("TLS handshake complete after {} iterations", iteration);
                break; // Exit the loop
            }
            // Still handshaking + would block on I/O
            (_, true) if write_would_block || read_would_block => {
                // In blocking mode, this shouldn't happen, but if it does we're stuck
                log::error!("TLS handshake would block at iteration {}", iteration);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "TLS handshake would block (should not happen in blocking mode)",
                ));
            }
            // Still handshaking, no I/O blocking - loop again
            (..) => {
                // Safety check to prevent infinite loops
                if iteration > 100 {
                    log::error!("TLS handshake exceeded 100 iterations");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "TLS handshake exceeded maximum iterations",
                    ));
                }
                log::debug!("TLS handshake continuing to iteration {}", iteration + 1);
                continue;
            }
        }
    }

    // Note: No safety net write loop needed here.
    // The `until_handshaked` pattern continues the loop if handshake completes
    // but wants_write is still true, and the early exit check at loop start
    // handles the case when neither wants_read nor wants_write.

    Ok(())
}

/// Write all pending TLS data from the connection to the stream (without flushing).
///
/// This drains rustls's write buffer and sends all data to the peer.
/// Returns true if any data was written.
async fn write_pending_data_no_flush(
    connection: &mut CryptoConnection,
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<bool> {
    let mut write_buf = Vec::new();

    // Drain all pending writes into our buffer
    while connection.wants_write() {
        connection.write_tls(&mut write_buf)?;
    }

    // Send to peer if we have data
    if !write_buf.is_empty() {
        util::write_all(stream, &write_buf).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Read data from the stream and process it through the TLS connection.
///
/// This reads available data from the network, feeds ALL of it to rustls via the
/// `feed_rustls_connection` helper (which loops until all bytes are consumed),
/// and processes it via `process_new_packets()` to advance the handshake state machine.
///
/// Returns the number of bytes read (0 indicates EOF).
///
/// Takes a mutable reference to a pre-allocated buffer instead of allocating on each call.
async fn read_and_process_data(
    connection: &mut CryptoConnection,
    stream: &mut Box<dyn AsyncStream>,
    read_buf: &mut [u8],
) -> std::io::Result<usize> {
    let n = stream.read(read_buf).await?;

    log::debug!("TLS: read {} bytes from peer", n);

    if n == 0 {
        // EOF - return 0 to let caller handle it
        return Ok(0);
    }

    // Feed the data to rustls using the helper that loops until all bytes are consumed
    feed_crypto_connection(connection, &read_buf[..n])?;

    // Process the new data to advance the state machine
    // This is called after every feed, just like tokio-rustls does
    connection.process_new_packets().map_err(|e| {
        log::error!("TLS error processing packets: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("TLS error: {}", e))
    })?;

    log::debug!("TLS: processed packets successfully");

    Ok(n)
}

/// Attempt a last-gasp write to send any pending TLS alert.
///
/// When a TLS error occurs (e.g., certificate validation failure), rustls may have
/// queued an alert message to send to the peer. This function attempts to send that
/// alert before the connection is closed, helping the peer understand why the
/// handshake failed.
///
/// Errors are intentionally ignored since we're already in an error path.
async fn try_last_gasp_write(connection: &mut CryptoConnection, stream: &mut Box<dyn AsyncStream>) {
    if !connection.wants_write() {
        return;
    }

    let mut alert_buf = Vec::new();
    while connection.wants_write() {
        if connection.write_tls(&mut alert_buf).is_err() {
            return;
        }
    }

    if !alert_buf.is_empty() {
        log::debug!(
            "TLS: sending last-gasp alert ({} bytes) before closing",
            alert_buf.len()
        );
        let _ = util::write_all(stream, &alert_buf).await;
        let _ = stream.flush().await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rustls_connection_enum_exists() {
        // Compile-time test that rustls::Connection exists
        // This will fail to compile if rustls::Connection doesn't exist
        fn _assert_connection_type(_: &rustls::Connection) {}
    }

    #[test]
    fn test_connection_has_required_methods() {
        // This test ensures rustls::Connection has the methods we need
        // It won't compile if the methods don't exist
        use std::sync::Arc;

        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let server_name = rustls::pki_types::ServerName::try_from("example.com")
            .unwrap()
            .to_owned();

        let client_conn = rustls::ClientConnection::new(config, server_name).unwrap();
        let connection = rustls::Connection::Client(client_conn);

        // These method calls will fail to compile if the methods don't exist
        let _handshaking = connection.is_handshaking();
        let _wants_read = connection.wants_read();
        let _wants_write = connection.wants_write();
    }
}
