use super::Limits;
use crate::async_stream::AsyncStream;
use crate::config::{ClientChainHop, ConfigSelection, GlobalLimits};
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use crate::dns::DnsRegistry;
use crate::option_util::OneOrSome;
use crate::rule_set::{Download, RuleSource};
use crate::rules::invalid;
use bytes::Bytes;
use http::{Request, StatusCode, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use std::io;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

const MAX_HEADER_COUNT: usize = 64;
const MAX_HEADER_BYTES: usize = 32 * 1024;

#[derive(Clone, Default)]
pub(super) struct DownloadState {
    indices: Vec<u32>,
}

struct DownloadAttempt<'a> {
    chain: crate::client_proxy_chain::ClientProxyChain,
    state: &'a mut DownloadState,
}

impl Drop for DownloadAttempt<'_> {
    fn drop(&mut self) {
        // Failed and cancelled attempts still advance rotation; connectors remain transient.
        self.state.indices = self.chain.tcp_selection_indices();
    }
}

fn target(url: &url::Url) -> io::Result<crate::address::NetLocation> {
    use crate::address::{Address, NetLocation};
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("missing URL port"))?;
    match url.host().ok_or_else(|| invalid("missing URL host"))? {
        url::Host::Domain(name) => Ok(NetLocation::new(Address::Hostname(name.to_owned()), port)),
        url::Host::Ipv4(ip) => Ok(NetLocation::from_ip_addr(ip.into(), port)),
        url::Host::Ipv6(ip) => Ok(NetLocation::from_ip_addr(ip.into(), port)),
    }
}

async fn connect(
    url: &url::Url,
    download: &Download,
    dns: &DnsRegistry,
    global: GlobalLimits,
    state: &mut DownloadState,
) -> io::Result<Box<dyn AsyncStream>> {
    let host = match url.host().ok_or_else(|| invalid("missing URL host"))? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let resolver = dns.rule_bootstrap(&download.bootstrap_url)?;
    let target = target(url)?;
    let targets = crate::resolver::resolve_addresses(&resolver, &target)
        .await
        .map_err(|_| invalid("rule download bootstrap lookup failed"))?;
    if targets.iter().any(|target| {
        dns.forbidden_ranges()
            .iter()
            .any(|range| range.contains(target.ip().to_canonical()))
    }) {
        return Err(invalid(
            "rule download destination overlaps a synthetic endpoint",
        ));
    }
    for hop in download.client_chain.hops.iter() {
        let members = match hop {
            ClientChainHop::Single(member) | ClientChainHop::Pool(OneOrSome::One(member)) => {
                std::slice::from_ref(member)
            }
            ClientChainHop::Pool(OneOrSome::Some(members)) => members.as_slice(),
        };
        for member in members {
            let ConfigSelection::Config(client) = member else {
                return Err(invalid("unexpanded rule download chain"));
            };
            if client
                .address
                .to_socket_addr_nonblocking()
                .is_some_and(|addr| {
                    dns.forbidden_ranges()
                        .iter()
                        .any(|range| range.contains(addr.ip().to_canonical()))
                })
            {
                return Err(invalid("rule download proxy overlaps a synthetic endpoint"));
            }
        }
    }
    let mut chain = crate::tcp::chain_builder::build_client_proxy_chain_with_limits(
        download.client_chain.hops.clone(),
        resolver.clone(),
        global,
    )?;
    if !state.indices.is_empty() {
        chain.restore_tcp_selection_indices(&state.indices);
    }
    let attempt = DownloadAttempt { chain, state };
    let mut connected = None;
    for target in targets {
        let target = crate::address::NetLocation::from_ip_addr(target.ip(), target.port());
        if let Ok(result) = attempt
            .chain
            .connect_rule_download(target.into(), &resolver)
            .await
        {
            connected = Some(result);
            break;
        }
    }
    let connected = connected.ok_or_else(|| invalid("configured rule download chain failed"))?;
    let tcp = crate::prepend_stream::PrependStream::new(
        connected.client_stream,
        connected.early_data.map(Vec::into_boxed_slice),
    );
    let stream: Box<dyn AsyncStream> = if url.scheme() == "https" {
        let config = crate::rustls_config_util::create_dns_client_config();
        let name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|_| invalid("invalid TLS server name"))?;
        let connection = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|_| invalid("TLS setup failed"))?;
        Box::new(
            CryptoTlsStream::handshake(
                tcp,
                TlsConnection::new(connection),
                TlsReadMode::Stream,
                &[],
            )
            .await
            .map_err(|_| invalid("TLS certificate verification or handshake failed"))?,
        )
    } else {
        Box::new(tcp)
    };
    Ok(stream)
}

pub(super) async fn download(
    source: &RuleSource,
    dns: &DnsRegistry,
    global: GlobalLimits,
    file: &mut File,
    limits: Limits,
    state: &mut DownloadState,
) -> io::Result<blake3::Hash> {
    let url = source
        .parsed_url()?
        .ok_or_else(|| invalid("remote URL required"))?;
    let download = source
        .download
        .as_ref()
        .ok_or_else(|| invalid("download policy required"))?;
    let stream = timeout(limits.connect, connect(&url, download, dns, global, state))
        .await
        .map_err(|_| invalid("connect/DNS/TLS deadline exceeded"))??;

    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(MAX_HEADER_COUNT)
        .max_buf_size(MAX_HEADER_BYTES)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|_| invalid("HTTP handshake failed"))?;
    let uri: Uri = url
        .as_str()
        .parse()
        .map_err(|_| invalid("invalid HTTP URL"))?;
    let request = Request::builder()
        .uri(uri.path_and_query().unwrap().as_str())
        .header(header::HOST, uri.authority().unwrap().as_str())
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| invalid("invalid HTTP request"))?;
    let receive = async {
        let response = timeout(limits.idle, sender.send_request(request))
            .await
            .map_err(|_| invalid("HTTP header deadline exceeded"))?
            .map_err(|_| invalid("invalid or oversized HTTP response headers"))?;
        if response.status() != StatusCode::OK {
            return Err(invalid(format!(
                "HTTP status {} rejected",
                response.status().as_u16()
            )));
        }
        let headers = response.headers();
        let header_bytes = headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
            .sum::<usize>();
        if headers.len() > MAX_HEADER_COUNT || header_bytes > MAX_HEADER_BYTES {
            return Err(invalid("oversized HTTP response headers"));
        }
        if headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .any(|value| value != "identity")
        {
            return Err(invalid("HTTP content encoding unsupported; serve identity"));
        }
        let length = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if length.is_some_and(|length| length == 0 || length > limits.bytes) {
            return Err(invalid("download size outside permitted range"));
        }
        let mut body = response.into_body();
        let mut bytes = 0u64;
        let mut digest = blake3::Hasher::new();
        while let Some(frame) = timeout(limits.idle, body.frame())
            .await
            .map_err(|_| invalid("HTTP body idle deadline exceeded"))?
        {
            let frame = frame.map_err(|_| invalid("invalid or truncated HTTP body"))?;
            let data = frame
                .into_data()
                .map_err(|_| invalid("HTTP trailers unsupported"))?;
            bytes = bytes
                .checked_add(data.len() as u64)
                .ok_or_else(|| invalid("body size overflow"))?;
            if bytes > limits.bytes || length.is_some_and(|length| bytes > length) {
                return Err(invalid("download exceeds byte limit"));
            }
            file.write_all(&data).await?;
            digest.update(&data);
        }
        if bytes == 0 || length.is_some_and(|length| bytes != length) {
            return Err(invalid("truncated HTTP body"));
        }
        file.flush().await?;
        Ok(digest.finalize())
    };
    // Drive HTTP in this future, so timeout/cancellation drops the socket too.
    tokio::pin!(receive);
    tokio::select! {
        biased;
        result = &mut receive => result,
        _ = connection => receive.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_targets_preserve_host_and_port_without_reparsing_authorities() {
        for (raw, address, port) in [
            ("http://[::1]:8080/rules", "::1", 8080),
            (
                "http://[2001:db8::1:8080]:9090/rules",
                "2001:db8::1:8080",
                9090,
            ),
            ("https://[::ffff:192.0.2.1]/rules", "::ffff:192.0.2.1", 443),
            ("https://example.com:8443/rules", "example.com", 8443),
            ("http://192.0.2.1/rules", "192.0.2.1", 80),
        ] {
            let location = target(&url::Url::parse(raw).unwrap()).unwrap();
            assert_eq!(
                location.address(),
                &crate::address::Address::from(address).unwrap()
            );
            assert_eq!(location.port(), port, "{raw}");
        }
    }
}
