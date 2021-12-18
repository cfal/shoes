use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use rand::RngCore;
use ring::aead::Aad;
use tokio::io::AsyncWriteExt;

use super::aead_util::TAG_LEN;
use super::shadowsocks_cipher::ShadowsocksCipher;
use crate::address::Location;
use crate::async_stream::AsyncStream;
use crate::protocol_handler::{
    ClientSetupResult, DecryptUdpMessageResult, EncryptUdpMessageResult, ServerSetupResult,
    TcpClientHandler, TcpServerHandler, UdpMessageHandler,
};
use crate::socks_handler::{read_location, read_location_from_vec, write_location};
use crate::util::allocate_vec;

pub struct ShadowsocksTcpHandler {
    cipher: ShadowsocksCipher,
    key_bytes: Box<[u8]>,
}

impl ShadowsocksTcpHandler {
    pub fn new(cipher_name: &str, password: &str) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.into();
        let key_bytes = cipher.get_key_bytes(password);
        Self { cipher, key_bytes }
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<ServerSetupResult> {
        let mut server_stream = self
            .cipher
            .create_cipher_stream(&self.key_bytes, server_stream);

        // We can do this in a blocking manner for the server, because we expect the client to
        // always send the location before we send anything.
        let remote_location = read_location(&mut server_stream).await?;

        Ok(ServerSetupResult {
            server_stream,
            remote_location,
            override_proxy_provider: None,
            initial_remote_data: None,
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: Location,
    ) -> std::io::Result<ClientSetupResult> {
        let mut client_stream = self
            .cipher
            .create_cipher_stream(&self.key_bytes, client_stream);

        write_location(&mut client_stream, &remote_location).await?;
        client_stream.flush().await?;

        Ok(ClientSetupResult { client_stream })
    }
}

pub struct ShadowsocksUdpHandler {
    cipher: ShadowsocksCipher,
    salt_len: usize,
    key_bytes: Box<[u8]>,
}

impl ShadowsocksUdpHandler {
    pub fn new(cipher_name: &str, password: &str) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.into();
        let salt_len = cipher.salt_len();
        let key_bytes = cipher.get_key_bytes(password);
        Self {
            cipher,
            salt_len,
            key_bytes,
        }
    }
}

impl UdpMessageHandler for ShadowsocksUdpHandler {
    fn decrypt_udp_message(
        &self,
        encrypted_data: &mut [u8],
    ) -> std::io::Result<DecryptUdpMessageResult> {
        let salt = &encrypted_data[0..self.salt_len];
        let mut opening_key = self.cipher.create_udp_opening_key(&self.key_bytes, salt);

        if opening_key
            .open_in_place(Aad::empty(), &mut encrypted_data[self.salt_len..])
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to open in place",
            ));
        }

        let decrypted_data = encrypted_data[self.salt_len..encrypted_data.len() - TAG_LEN]
            .to_vec()
            .into_boxed_slice();
        let decrypted_data_len = decrypted_data.len();
        let (remote_location, bytes_used) = read_location_from_vec(&decrypted_data)?;

        Ok(DecryptUdpMessageResult {
            decrypted_data,
            decrypted_data_start_index: bytes_used,
            decrypted_data_end_index_exclusive: decrypted_data_len,
            remote_location,
        })
    }

    fn encrypt_udp_message(
        &self,
        addr: &SocketAddr,
        unencrypted_data: &mut [u8],
    ) -> std::io::Result<EncryptUdpMessageResult> {
        let socks_addr_len = if addr.is_ipv4() {
            1 + 4 + 2
        } else {
            1 + 16 + 2
        };

        let encrypted_data_len = self.salt_len + socks_addr_len + unencrypted_data.len() + TAG_LEN;
        if encrypted_data_len > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "encrypted data is larger than udp packet size",
            ));
        }

        let mut encrypted_data = allocate_vec(encrypted_data_len).into_boxed_slice();
        rand::thread_rng().fill_bytes(&mut encrypted_data[0..self.salt_len]);

        let mut sealing_key = self
            .cipher
            .create_udp_sealing_key(&self.key_bytes, &encrypted_data[0..self.salt_len]);

        let port = addr.port();
        match addr.ip() {
            IpAddr::V4(v4addr) => {
                // ADDR_TYPE_IPV4
                encrypted_data[self.salt_len] = 0x01;
                encrypted_data[self.salt_len + 1..self.salt_len + 5]
                    .copy_from_slice(&v4addr.octets());
                encrypted_data[self.salt_len + 5] = (port >> 8) as u8;
                encrypted_data[self.salt_len + 6] = (port & 0xff) as u8;
            }
            IpAddr::V6(v6addr) => {
                // ADDR_TYPE_IPV6
                encrypted_data[self.salt_len] = 0x04;
                encrypted_data[self.salt_len + 1..self.salt_len + 17]
                    .copy_from_slice(&v6addr.octets());
                encrypted_data[self.salt_len + 17] = (port >> 8) as u8;
                encrypted_data[self.salt_len + 18] = (port & 0xff) as u8;
            }
        }

        encrypted_data[self.salt_len + socks_addr_len
            ..self.salt_len + socks_addr_len + unencrypted_data.len()]
            .copy_from_slice(unencrypted_data);

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_data
                    [self.salt_len..self.salt_len + socks_addr_len + unencrypted_data.len()],
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "failed to encrypted in place")
            })?;

        encrypted_data[self.salt_len + socks_addr_len + unencrypted_data.len()..encrypted_data_len]
            .copy_from_slice(&tag.as_ref()[0..TAG_LEN]);

        Ok(EncryptUdpMessageResult { encrypted_data })
    }
}
