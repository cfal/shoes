use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::async_stream::AsyncStream;

pub trait AsyncTlsFactory: Unpin + Send + Sync {
    fn create_acceptor(&self, cert_bytes: &[u8], key_bytes: &[u8]) -> Box<dyn AsyncTlsAcceptor>;
    // TODO: support different configs/certs.
    fn create_connector(&self, verify: bool) -> Box<dyn AsyncTlsConnector>;
}

#[async_trait]
pub trait AsyncTlsAcceptor: Unpin + Send + Sync {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>>;
}

#[async_trait]
pub trait AsyncTlsConnector: Unpin + Send + Sync {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>>;
}
