use std::io::Cursor;

use rustls::Connection;

/// Feed all data to a rustls connection, looping until all bytes are consumed.
///
/// rustls's read_tls() may not consume all bytes in one call, so we must loop
/// until all data has been fed. This is critical to avoid losing bytes.
#[inline(always)]
pub fn feed_rustls_connection(connection: &mut Connection, data: &[u8]) -> std::io::Result<()> {
    match connection {
        Connection::Client(client_connection) => {
            feed_rustls_client_connection(client_connection, data)
        }
        Connection::Server(server_connection) => {
            feed_rustls_server_connection(server_connection, data)
        }
    }
}

#[inline(always)]
pub fn feed_rustls_server_connection(
    connection: &mut rustls::ServerConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed rustls server connection: {e}"),
            )
        })?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rustls server connection did not consume all bytes: fed {}/{} bytes",
                    i,
                    data.len()
                ),
            ));
        }
        i += n;
    }
    Ok(())
}

#[inline(always)]
pub fn feed_rustls_client_connection(
    connection: &mut rustls::ClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed rustls client connection: {e}"),
            )
        })?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "rustls client connection did not consume all bytes: fed {}/{} bytes",
                    i,
                    data.len()
                ),
            ));
        }
        i += n;
    }
    Ok(())
}
