use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::io::AsyncWriteExt;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::line_reader::LineReader;
use crate::option_util::NoneOrOne;
use crate::salt_checker::SaltChecker;
use crate::socks_handler::{read_location, write_location_to_vec};
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::timed_salt_checker::TimedSaltChecker;
use crate::util::write_all;

use super::blake3_key::Blake3Key;
use super::default_key::DefaultKey;
use super::shadowsocks_cipher::ShadowsocksCipher;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream::ShadowsocksStream;
use super::shadowsocks_stream_type::ShadowsocksStreamType;

#[derive(Debug)]
pub struct ShadowsocksTcpHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    aead2022: bool,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
}

impl ShadowsocksTcpHandler {
    pub fn new(cipher_name: &str, password: &str) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.into();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: false,
            salt_checker: None,
        }
    }

    pub fn new_aead2022(cipher_name: &str, key_bytes: &[u8]) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.into();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(Blake3Key::new(
            key_bytes.to_vec().into_boxed_slice(),
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            aead2022: true,
            salt_checker: Some(Arc::new(Mutex::new(TimedSaltChecker::new(60)))),
        }
    }
}

#[async_trait]
impl TcpServerHandler for ShadowsocksTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Server
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        );

        // We can do this in a blocking manner for the server, because we expect the client to
        // always send the location before we send anything.
        let remote_location = read_location(&mut server_stream).await?;

        let initial_remote_data = if self.aead2022 {
            let mut line_reader = LineReader::new_with_buffer_size(1024);

            let padding_len = line_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {}", padding_len),
                    ));
                }
                line_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }

            line_reader.unparsed_data_owned()
        } else {
            None
        };

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            // we don't need an initial flush, let the IV be written when data actually arrives.
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data,
            override_proxy_provider: NoneOrOne::Unspecified,
        })
    }
}

#[async_trait]
impl TcpClientHandler for ShadowsocksTcpHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let stream_type = if self.aead2022 {
            ShadowsocksStreamType::AEAD2022Client
        } else {
            ShadowsocksStreamType::Aead
        };

        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            stream_type,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            self.salt_checker.clone(),
        ));

        let mut location_vec = write_location_to_vec(&remote_location);

        if self.aead2022 {
            let location_len = location_vec.len();

            let mut rng = rand::thread_rng();
            let padding_len: usize = rng.gen_range(1..=900);
            location_vec.resize(location_len + padding_len + 2, 0);

            let padding_len_bytes = (padding_len as u16).to_be_bytes();
            location_vec[location_len..location_len + 2].copy_from_slice(&padding_len_bytes);

            rng.fill_bytes(&mut location_vec[location_len + 2..]);
        }

        write_all(&mut client_stream, &location_vec).await?;
        client_stream.flush().await?;

        Ok(TcpClientSetupResult { client_stream })
    }
}
