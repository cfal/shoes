use crate::async_stream::AsyncStream;
use crate::async_tls::{AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};

use std::io::{Error, ErrorKind, Result};

use async_trait::async_trait;
use native_tls::Identity;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use tokio::net::TcpStream;

#[async_trait]
impl AsyncStream for tokio_native_tls::TlsStream<TcpStream> {}

#[async_trait]
impl AsyncTlsAcceptor for tokio_native_tls::TlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>> {
        tokio_native_tls::TlsAcceptor::accept(&self, stream)
            .await
            .map(|s| Box::new(s) as Box<dyn AsyncStream>)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

#[async_trait]
impl AsyncTlsConnector for tokio_native_tls::TlsConnector {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        tokio_native_tls::TlsConnector::connect(&self, domain, stream)
            .await
            .map(|s| Box::new(s) as Box<dyn AsyncStream>)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

pub struct NativeTlsFactory;

impl NativeTlsFactory {
    pub fn new() -> Self {
        Self
    }
}

impl AsyncTlsFactory for NativeTlsFactory {
    fn create_acceptor(&self, cert_bytes: &[u8], key_bytes: &[u8]) -> Box<dyn AsyncTlsAcceptor> {
        let identity =
            create_identity(cert_bytes, key_bytes).expect("Failed to parse cert or private key");

        let acceptor: tokio_native_tls::TlsAcceptor =
            native_tls::TlsAcceptor::new(identity).unwrap().into();
        Box::new(acceptor)
    }

    fn create_connector(&self, verify: bool) -> Box<dyn AsyncTlsConnector> {
        let connector: tokio_native_tls::TlsConnector = native_tls::TlsConnector::builder()
            // TODO: make SNI configurable
            .use_sni(true)
            .danger_accept_invalid_certs(!verify)
            .danger_accept_invalid_hostnames(!verify)
            .build()
            .unwrap()
            .into();
        Box::new(connector)
    }
}

fn create_identity(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<Identity> {
    let pkey = PKey::private_key_from_pem(&key_bytes)?;
    let cert = X509::stack_from_pem(&cert_bytes)?.remove(0);

    let mut builder = Pkcs12::builder();
    builder.ca(Stack::<X509>::new().unwrap());

    // Empty passwords seem to cause an error:
    // { code: -25264, message: "MAC verification failed during PKCS12 import (wrong password?)" }
    let password = ".";

    let pkcs12 = builder.build(password, "pkcs12", &pkey, &cert)?;
    let pkcs12_bytes = pkcs12.to_der()?;

    Identity::from_pkcs12(&pkcs12_bytes, password).map_err(|e| Error::new(ErrorKind::Other, e))
}
