use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use super::{Source, invalid};

pub(super) struct Pending {
    pub domain: String,
    pub token: String,
    pub authorization: String,
    pub expires: Instant,
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

pub(super) struct Cleanup(pub Arc<Source>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.challenges.write().clear();
    }
}

pub(super) fn tls_config(domain: &str, digest: &[u8]) -> io::Result<Arc<rustls::ServerConfig>> {
    if digest.len() != 32 {
        return Err(invalid("invalid ACME authorization digest"));
    }
    let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let mut params =
        rcgen::CertificateParams::new(vec![domain.to_owned()]).map_err(io::Error::other)?;
    let now = std::time::SystemTime::now();
    params.not_before = (now - Duration::from_secs(60)).into();
    params.not_after = (now + Duration::from_secs(600)).into();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let cert = params.self_signed(&key).map_err(io::Error::other)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let private = rustls::pki_types::PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes())
        .map_err(io::Error::other)?;
    let signing_key = provider
        .key_provider
        .load_private_key(private)
        .map_err(io::Error::other)?;
    // The key and certificate were generated together. with_single_cert's generic
    // WebPKI parsing rejects RFC 8737's intentionally critical acmeIdentifier.
    let certified = rustls::sign::CertifiedKey::new(vec![cert.der().clone()], signing_key);
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(super::FixedCertificate(Some(Arc::new(certified)))));
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok(Arc::new(config))
}

pub(super) async fn serve(listeners: Vec<Arc<TcpListener>>, source: Arc<Source>) -> io::Result<()> {
    // Own accept loops directly so cancellation releases listener sockets synchronously.
    let servers = listeners
        .into_iter()
        .map(|listener| serve_listener(listener, source.clone()));
    futures::future::join_all(servers).await;
    std::future::pending().await
}

async fn serve_listener(listener: Arc<TcpListener>, source: Arc<Source>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                if connections.len() >= 64 {
                    drop(stream);
                    continue;
                }
                let source = source.clone();
                connections.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(10), respond(stream, &source)).await;
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn respond(mut stream: TcpStream, source: &Source) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let mut used = 0;
    let (status, body) = loop {
        if used == buffer.len() {
            break (431, String::new());
        }
        let read = stream.read(&mut buffer[used..]).await?;
        if read == 0 {
            return Ok(());
        }
        used += read;
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&buffer[..used]) {
            Ok(httparse::Status::Partial) => continue,
            Err(_) => break (400, String::new()),
            Ok(httparse::Status::Complete(_)) => {}
        }
        if request.method != Some("GET")
            || request.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case("transfer-encoding")
                    || (header.name.eq_ignore_ascii_case("content-length") && header.value != b"0")
            })
        {
            break (400, String::new());
        }
        let hosts: Vec<_> = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("host"))
            .collect();
        let host = if hosts.len() == 1 {
            std::str::from_utf8(hosts[0].value)
                .ok()
                .and_then(|host| host.parse::<http::uri::Authority>().ok())
        } else {
            None
        };
        let token = request
            .path
            .and_then(|path| path.strip_prefix("/.well-known/acme-challenge/"));
        let response = source.challenges.read().iter().find_map(|pending| {
            (Some(pending.token.as_str()) == token
                && host
                    .as_ref()
                    .is_some_and(|host| host.host().eq_ignore_ascii_case(&pending.domain))
                && pending.expires > Instant::now())
            .then(|| pending.authorization.clone())
        });
        break match response {
            Some(body) => (200, body),
            None => (404, String::new()),
        };
    };
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_releases_listener_without_yielding() {
        let source = Source::new(
            "test".into(),
            super::super::Spec::Acme(super::super::AcmeConfig {
                domains: vec!["proxy.test".into()],
                directory_url: "http://127.0.0.1:9/directory".into(),
                state_dir: "unused".into(),
                terms_of_service: None,
                contacts: vec![],
                challenge: super::super::ChallengeConfig::Http01 { listen: vec![] },
                ca_cert: None,
            }),
        )
        .unwrap();
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let weak = Arc::downgrade(&listener);
        let mut serving = Box::pin(serve(vec![listener], source.clone()));
        assert!(futures::poll!(&mut serving).is_pending());
        tokio::task::yield_now().await;
        drop(serving);
        assert!(weak.upgrade().is_none());
        let rebound = std::net::TcpListener::bind(address).unwrap();
        drop(rebound);

        let mut empty = Box::pin(serve(vec![], source));
        assert!(futures::poll!(&mut empty).is_pending());
    }

    #[tokio::test]
    async fn exact_http_routing_expiry_and_bounded_headers() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let source = Source::new("test".into(), super::super::Spec::Acme(super::super::AcmeConfig {
                domains: vec!["proxy.test".into()], directory_url: "http://127.0.0.1:9/directory".into(),
                state_dir: "unused".into(), terms_of_service: Some("https://ca.test/terms".into()), contacts: vec![],
                challenge: super::super::ChallengeConfig::Http01 { listen: vec![] }, ca_cert: None,
            })).unwrap();
            source.challenges.write().push(Pending { domain: "proxy.test".into(), token: "known-token".into(), authorization: "known-token.authorization".into(), expires: Instant::now() + Duration::from_secs(60), tls: None });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let mut serving = JoinSet::new();
            let serving_source = source.clone();
            serving.spawn(async move { serve(vec![Arc::new(listener)], serving_source).await });
            for (request, status) in [
                ("GET /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: proxy.test\r\n\r\n".to_owned(), 200),
                ("GET /.well-known/acme-challenge/unknown HTTP/1.1\r\nHost: proxy.test\r\n\r\n".to_owned(), 404),
                ("GET /.well-known/acme-challenge/known-token?query HTTP/1.1\r\nHost: proxy.test\r\n\r\n".to_owned(), 404),
                ("GET /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: other.test\r\n\r\n".to_owned(), 404),
                ("POST /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: proxy.test\r\n\r\n".to_owned(), 400),
                ("GET /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: proxy.test\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(), 400),
                (format!("GET / HTTP/1.1\r\nX-Large: {}", "x".repeat(8200)), 431),
            ] {
                let mut stream = TcpStream::connect(address).await.unwrap();
                stream.write_all(request.as_bytes()).await.unwrap();
                let mut response = Vec::new();
                let _ = stream.read_to_end(&mut response).await;
                assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status} ")));
            }
            source.challenges.write()[0].expires = Instant::now();
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(b"GET /.well-known/acme-challenge/known-token HTTP/1.1\r\nHost: proxy.test\r\n\r\n").await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 404 "));
            serving.shutdown().await;
            assert!(TcpListener::bind(address).await.is_ok());
        }).await.unwrap();
    }
}
