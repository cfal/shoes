/// Combined outgoing plaintext/ciphertext bound, matching rustls's default.
pub const OUTGOING_BUFFER_LIMIT: usize = 64 * 1024;

#[cfg(test)]
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
#[cfg(test)]
pub const VERSION_TLS_1_2_MAJOR: u8 = 3;
#[cfg(test)]
pub const VERSION_TLS_1_2_MINOR: u8 = 3;
#[cfg(test)]
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
#[cfg(test)]
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
#[cfg(test)]
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
#[cfg(test)]
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
#[cfg(test)]
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;
