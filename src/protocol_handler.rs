use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::Location;
use crate::async_stream::AsyncStream;
use crate::client_proxy_provider::ClientProxyProvider;

pub struct ServerSetupResult {
    pub server_stream: Box<dyn AsyncStream>,
    pub remote_location: Location,
    pub override_proxy_provider: Option<Arc<ClientProxyProvider>>,
    // initial data to send to the remote location.
    pub initial_remote_data: Option<Box<[u8]>>,
}

#[async_trait]
pub trait TcpServerHandler: Send + Sync {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<ServerSetupResult>;
}

pub struct ClientSetupResult {
    pub client_stream: Box<dyn AsyncStream>,
}

#[async_trait]
pub trait TcpClientHandler: Send + Sync {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: Location,
    ) -> std::io::Result<ClientSetupResult>;
}

pub struct DecryptUdpMessageResult {
    pub decrypted_data: Box<[u8]>,
    pub decrypted_data_start_index: usize,
    pub decrypted_data_end_index_exclusive: usize,
    pub remote_location: Location,
}

pub struct EncryptUdpMessageResult {
    pub encrypted_data: Box<[u8]>,
}

pub trait UdpMessageHandler: Send + Sync {
    fn decrypt_udp_message(
        &self,
        encrypted_data: &mut [u8],
    ) -> std::io::Result<DecryptUdpMessageResult>;

    fn encrypt_udp_message(
        &self,
        addr: &SocketAddr,
        unencrypted_data: &mut [u8],
    ) -> std::io::Result<EncryptUdpMessageResult>;
}
