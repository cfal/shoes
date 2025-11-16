use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use tokio::io::AsyncWriteExt;

use super::salt_checker::SaltChecker;
use super::timed_salt_checker::TimedSaltChecker;
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::socks_handler::{read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::uot::{UotV1Stream, UotV2Stream, UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS};
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
        let cipher: ShadowsocksCipher = cipher_name.try_into().unwrap();
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
        let cipher: ShadowsocksCipher = cipher_name.try_into().unwrap();
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

        let mut stream_reader = StreamReader::new_with_buffer_size(1024);

        // We can do this in a blocking manner for the server, because we expect the client to
        // always send the location before we send anything.
        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        if self.aead2022 {
            let padding_len = stream_reader.read_u16_be(&mut server_stream).await?;

            if padding_len > 0 {
                if padding_len > 900 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid padding length: {padding_len}"),
                    ));
                }
                stream_reader
                    .read_slice(&mut server_stream, padding_len as usize)
                    .await?;
            }
        }

        // Check for UDP-over-TCP (UoT) magic addresses
        if let Address::Hostname(ref host) = remote_location.address() {
            if host == UOT_V1_MAGIC_ADDRESS {
                // UoT V1: Multi-destination UDP
                // Each packet has: ATYP + address + port + length + data
                let mut uot_stream = UotV1Stream::new(Box::new(server_stream));

                // Feed any unparsed data (first UoT packet might be in same TCP segment)
                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    log::debug!(
                        "Shadowsocks UoT V1: feeding {} bytes of initial data",
                        unparsed_data.len()
                    );
                    uot_stream.feed_initial_data(unparsed_data);
                }

                return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                    stream: Box::new(uot_stream),
                    need_initial_flush: false,
                    override_proxy_provider: NoneOrOne::Unspecified,
                    num_sockets: 4, // TODO: make configurable
                });
            } else if host == UOT_V2_MAGIC_ADDRESS {
                // UoT V2: Read request header first
                // Request: isConnect(u8) + ATYP + address + port
                // Note: V2 uses SOCKS address format (0x01=IPv4, 0x03=Domain, 0x04=IPv6),
                // NOT UoT address format!
                let is_connect = stream_reader.read_u8(&mut server_stream).await?;
                log::debug!("Shadowsocks UoT V2: is_connect = {}", is_connect);

                // Read destination address using SOCKS address format
                let destination = read_location(&mut server_stream, &mut stream_reader).await?;
                log::debug!("Shadowsocks UoT V2: destination = {:?}", destination);

                if is_connect == 1 {
                    // V2 Connect mode: Single destination, length-prefixed packets only
                    // Reuse UotV2Stream which has identical format: length(u16be) + data
                    let unparsed_data = stream_reader.unparsed_data();
                    let mut uot_v2_stream = UotV2Stream::new(Box::new(server_stream));
                    if !unparsed_data.is_empty() {
                        uot_v2_stream.feed_initial_read_data(unparsed_data)?;
                    }

                    return Ok(TcpServerSetupResult::BidirectionalUdp {
                        remote_location: destination,
                        stream: Box::new(uot_v2_stream),
                        need_initial_flush: false,
                        override_proxy_provider: NoneOrOne::Unspecified,
                    });
                } else {
                    // V2 Non-connect mode: Same as V1 (multi-destination)
                    let mut uot_stream = UotV1Stream::new(Box::new(server_stream));

                    // Feed any unparsed data
                    let unparsed_data = stream_reader.unparsed_data();
                    if !unparsed_data.is_empty() {
                        log::debug!(
                            "Shadowsocks UoT V2 non-connect: feeding {} bytes of initial data",
                            unparsed_data.len()
                        );
                        uot_stream.feed_initial_data(unparsed_data);
                    }

                    return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                        stream: Box::new(uot_stream),
                        need_initial_flush: false,
                        override_proxy_provider: NoneOrOne::Unspecified,
                        num_sockets: 4,
                    });
                }
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: Box::new(server_stream),
            // we don't need an initial flush, let the IV be written when data actually arrives.
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
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

            let mut rng = rand::rng();
            let padding_len: usize = rng.random_range(1..=900);
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
