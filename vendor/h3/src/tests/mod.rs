// This is to avoid an import loop:
// h3 tests depend on having private access to the crate.
// They must be part of the crate so as not to break privacy.
// They also depend on h3_quinn which depends on the crate.
// Having a dev-dependency on h3_quinn would work as far as cargo is
// concerned, but quic traits wouldn't match between the "h3" crate that
// comes before h3_quinn and the one that comes after and runs the tests
#[path = "../../../h3-quinn/src/lib.rs"]
mod h3_quinn;

mod connection;
mod request;

use std::{
    convert::TryInto,
    net::{Ipv6Addr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::Request;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::quic;
use h3_quinn::{quinn::TransportConfig, Connection};

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_test_writer()
        .try_init();
}

/// This accepts an incoming request. After the bidirectional stream is started it will not poll the
/// connection or receive further requests until the first headers are received.
/// Only use this for testing purposes.
async fn get_stream_blocking<C: quic::Connection<B>, B: Buf>(
    incoming: &mut crate::server::Connection<C, B>,
) -> Option<(Request<()>, crate::server::RequestStream<C::BidiStream, B>)> {
    let request_resolver = incoming.accept().await.ok()??;
    let (request, stream) = request_resolver.resolve_request().await.ok()?;
    Some((request, stream))
}

pub struct Pair {
    port: u16,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    config: Arc<TransportConfig>,
}

impl Default for Pair {
    fn default() -> Self {
        let (cert, key) = build_certs();
        Self {
            cert,
            key,
            port: 0,
            config: Arc::new(TransportConfig::default()),
        }
    }
}

impl Pair {
    pub fn with_timeout(&mut self, duration: Duration) {
        Arc::get_mut(&mut self.config)
            .unwrap()
            .max_idle_timeout(Some(
                duration.try_into().expect("idle timeout duration invalid"),
            ))
            .initial_rtt(Duration::from_millis(10));
    }

    pub fn server_inner(&mut self) -> h3_quinn::Endpoint {
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![self.cert.clone()], self.key.clone_key())
        .unwrap();
        crypto.max_early_data_size = u32::MAX;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let mut server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).unwrap(),
        ));
        server_config.transport = self.config.clone();
        let endpoint =
            h3_quinn::quinn::Endpoint::server(server_config, "[::]:0".parse().unwrap()).unwrap();

        self.port = endpoint.local_addr().unwrap().port();

        endpoint
    }

    pub fn server(&mut self) -> Server {
        let endpoint = self.server_inner();
        Server { endpoint }
    }

    pub async fn client_inner(&self) -> quinn::Connection {
        let addr = (Ipv6Addr::LOCALHOST, self.port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add(self.cert.clone()).unwrap();
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
        crypto.enable_early_data = true;
        crypto.alpn_protocols = vec![b"h3".to_vec()];

        let client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        ));

        let mut client_endpoint =
            h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        client_endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    pub async fn client(&self) -> h3_quinn::Connection {
        Connection::new(self.client_inner().await)
    }
}

pub struct Server {
    pub endpoint: h3_quinn::Endpoint,
}

impl Server {
    pub async fn next(&mut self) -> impl quic::Connection<Bytes> {
        Connection::new(self.endpoint.accept().await.unwrap().await.unwrap())
    }
}

pub fn build_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        cert.cert.into(),
        PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
    )
}
