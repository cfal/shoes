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
use std::fs::File;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::time::timeout;

const MAX_HEADER_COUNT: usize = 64;
const MAX_HEADER_BYTES: usize = 32 * 1024;

async fn connect(
    url: &url::Url,
    download: &Download,
    dns: &DnsRegistry,
    global: GlobalLimits,
) -> io::Result<Box<dyn AsyncStream>> {
    let host = match url.host().ok_or_else(|| invalid("missing URL host"))? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let resolver = dns.rule_bootstrap(&download.bootstrap_url)?;
    let target =
        crate::address::NetLocation::from_str(&host, Some(url.port_or_known_default().unwrap()))?;
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
    let chain = crate::tcp::chain_builder::build_client_chain_group_with_limits(
        crate::option_util::NoneOrSome::One(download.client_chain.clone()),
        resolver.clone(),
        global,
    )?;
    let mut connected = None;
    for target in targets {
        let target = crate::address::NetLocation::from_ip_addr(target.ip(), target.port());
        if let Ok(result) = chain.connect_tcp(target.into(), &resolver).await {
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
) -> io::Result<blake3::Hash> {
    let url = source
        .parsed_url()?
        .ok_or_else(|| invalid("remote URL required"))?;
    let download = source
        .download
        .as_ref()
        .ok_or_else(|| invalid("download policy required"))?;
    let stream = timeout(limits.connect, connect(&url, download, dns, global))
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
            file.write_all(&data)?;
            digest.update(&data);
        }
        if bytes == 0 || length.is_some_and(|length| bytes != length) {
            return Err(invalid("truncated HTTP body"));
        }
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
