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
use crate::rustls_connection_util::feed_rustls_connection;

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
/// perform_handshake(&mut connection, &mut tcp_stream, 16384).await?;
/// // Handshake complete, connection ready for application data
/// ```
pub async fn perform_handshake(
    connection: &mut rustls::Connection,
    stream: &mut Box<dyn AsyncStream>,
    buffer_size: usize,
) -> std::io::Result<()> {
    log::debug!("TLS handshake starting");

    let mut iteration = 0;
    let mut eof = false;

    // Infinite loop - we explicitly break when done
    // This matches tokio-rustls's structure: loop { ... return match ... }
    loop {
        iteration += 1;
        let mut write_would_block = false;
        let mut read_would_block = false;

        log::debug!(
            "TLS handshake iteration {}: wants_read={}, wants_write={}",
            iteration,
            connection.wants_read(),
            connection.wants_write()
        );

        // Phase 1: Drain all pending writes
        while connection.wants_write() {
            match write_pending_data(connection, stream).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    write_would_block = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        // Phase 2: Flush the stream to ensure data is sent
        match stream.flush().await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                write_would_block = true;
            }
            Err(e) => return Err(e),
        }

        // Phase 3: Read ONCE if rustls wants more data
        // CRITICAL: Unlike tokio-rustls which uses non-blocking I/O with Poll::Pending,
        // we use blocking async I/O. Therefore we can NOT loop on wants_read() because
        // each read() blocks. We only read ONCE per main loop iteration.
        if !eof && connection.wants_read() {
            match read_and_process_data(connection, stream, buffer_size).await {
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
                Err(e) => return Err(e),
            }
        }

        // Phase 4: Check handshake state and decide what to do next
        // This EXACTLY matches tokio-rustls's logic at lines 173-187
        log::debug!(
            "TLS handshake iteration {} complete: eof={}, is_handshaking={}, write_would_block={}, read_would_block={}",
            iteration, eof, connection.is_handshaking(), write_would_block, read_would_block
        );

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

    // Final write if there's any pending data after handshake completes
    while connection.wants_write() {
        log::debug!("TLS handshake: final write");
        write_pending_data(connection, stream).await?;
    }

    Ok(())
}

/// Write all pending TLS data from the connection to the stream.
///
/// This drains rustls's write buffer and sends all data to the peer,
/// ensuring it's flushed to the network.
async fn write_pending_data(
    connection: &mut rustls::Connection,
    stream: &mut Box<dyn AsyncStream>,
) -> std::io::Result<()> {
    let mut write_buf = Vec::new();

    // Drain all pending writes into our buffer
    while connection.wants_write() {
        connection.write_tls(&mut write_buf)?;
    }

    // Send to peer if we have data
    if !write_buf.is_empty() {
        stream.write_all(&write_buf).await?;
        stream.flush().await?;
    }

    Ok(())
}

/// Read data from the stream and process it through the TLS connection.
///
/// This reads available data from the network, feeds ALL of it to rustls via the
/// `feed_rustls_connection` helper (which loops until all bytes are consumed),
/// and processes it via `process_new_packets()` to advance the handshake state machine.
///
/// Returns the number of bytes read (0 indicates EOF).
async fn read_and_process_data(
    connection: &mut rustls::Connection,
    stream: &mut Box<dyn AsyncStream>,
    buffer_size: usize,
) -> std::io::Result<usize> {
    let mut buf = vec![0u8; buffer_size];
    let n = stream.read(&mut buf).await?;

    log::debug!("TLS: read {} bytes from peer", n);

    if n == 0 {
        // EOF - return 0 to let caller handle it
        return Ok(0);
    }

    // Feed ALL the data to rustls using the helper that loops until all bytes are consumed
    // This is CRITICAL - rustls may not consume all bytes in one read_tls() call
    feed_rustls_connection(connection, &buf[..n])?;

    // Process the new data to advance the state machine
    // This is called after every feed, just like tokio-rustls does
    connection.process_new_packets().map_err(|e| {
        log::error!("TLS error processing packets: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("TLS error: {}", e))
    })?;

    log::debug!("TLS: processed packets successfully");

    Ok(n)
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
