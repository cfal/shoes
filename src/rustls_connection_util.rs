use std::io::Cursor;

#[inline]
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

#[inline]
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
