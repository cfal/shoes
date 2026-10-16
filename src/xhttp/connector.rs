use std::{io, sync::Arc};

use super::client::Client;
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::xhttp::{XhttpMode, XhttpVersion, invalid},
    config::{ClientConfig, ClientProxyConfig, GlobalLimits, Transport},
    crypto::{CryptoConnection, CryptoTlsStream, TlsReadMode},
    resolver::Resolver,
    tcp::tcp_handler::TcpClientHandler,
};

#[derive(Debug)]
pub enum Security {
    Plain,
    Tls {
        config: Arc<rustls::ClientConfig>,
        name: rustls::pki_types::ServerName<'static>,
        buffer_size: Option<usize>,
    },
    Reality(Box<dyn TcpClientHandler>),
}

impl Security {
    pub async fn wrap(
        &self,
        stream: Box<dyn AsyncStream>,
        endpoint: &NetLocation,
        version: XhttpVersion,
    ) -> io::Result<Box<dyn AsyncStream>> {
        match self {
            Self::Plain => Ok(stream),
            Self::Reality(handler) => Ok(handler
                .setup_client_tcp_stream(stream, endpoint.into())
                .await?
                .client_stream),
            Self::Tls {
                config,
                name,
                buffer_size,
            } => {
                let mut connection = rustls::ClientConnection::new(config.clone(), name.clone())
                    .map_err(io::Error::other)?;
                if let Some(size) = buffer_size {
                    connection.set_buffer_limit(Some(*size));
                }
                let stream = CryptoTlsStream::handshake(
                    stream,
                    CryptoConnection::new_rustls_client(connection),
                    TlsReadMode::Stream,
                    &[],
                )
                .await?;
                let expected: &[u8] = if version == XhttpVersion::H1 {
                    b"http/1.1"
                } else {
                    b"h2"
                };
                if stream.alpn_protocol().is_some_and(|alpn| alpn != expected)
                    || (version == XhttpVersion::H2 && stream.alpn_protocol().is_none())
                {
                    return Err(invalid(
                        "XHTTP TLS ALPN does not match selected HTTP version",
                    ));
                }
                Ok(Box::new(stream))
            }
        }
    }
}

pub fn contains(config: &ClientProxyConfig) -> bool {
    match config {
        ClientProxyConfig::Xhttp(_) => true,
        ClientProxyConfig::Tls(tls) => contains(&tls.protocol),
        ClientProxyConfig::Reality { protocol, .. }
        | ClientProxyConfig::ShadowTls { protocol, .. } => contains(protocol),
        ClientProxyConfig::Websocket(ws) => contains(&ws.protocol),
        _ => false,
    }
}

type ClientTransport = (Arc<Client>, Box<dyn TcpClientHandler>);

pub fn build(
    config: &ClientConfig,
    resolver: Arc<dyn Resolver>,
) -> io::Result<Option<ClientTransport>> {
    // DNS preparation can build connectors before candidate limits replace the live policy.
    // Candidate capacity is checked separately during full-config validation.
    build_with_limits(config, resolver, GlobalLimits::default())
}

pub(crate) fn build_with_limits(
    config: &ClientConfig,
    resolver: Arc<dyn Resolver>,
    global_limits: GlobalLimits,
) -> io::Result<Option<ClientTransport>> {
    if !contains(&config.protocol) {
        return Ok(None);
    }
    if config.transport == Transport::Udp {
        return Err(invalid("XHTTP requires TCP or QUIC transport"));
    }
    let mut outer = config.protocol.clone();
    let default_sni = config.address.address().hostname().map(str::to_owned);
    let (xhttp, effective_sni, security, tls_alpn, reality) = match &mut outer {
        ClientProxyConfig::Xhttp(xhttp) => (
            xhttp.clone(),
            match config.quic_settings.as_ref() {
                Some(q) if !q.sni_hostname.is_unspecified() => q.sni_hostname.clone().into_option(),
                _ => default_sni,
            },
            Security::Plain,
            None,
            false,
        ),
        ClientProxyConfig::Tls(tls) => {
            let ClientProxyConfig::Xhttp(xhttp) = tls.protocol.as_ref() else {
                return Err(invalid("XHTTP must be directly inside TLS"));
            };
            if tls.vision {
                return Err(invalid("Vision cannot wrap XHTTP"));
            }
            let xhttp = xhttp.clone();
            let sni = if tls.sni_hostname.is_unspecified() {
                default_sni
            } else {
                tls.sni_hostname.clone().into_option()
            };
            let explicit_alpn = tls.alpn_protocols.clone().into_vec();
            let version = match xhttp.http_version {
                XhttpVersion::Auto if explicit_alpn == ["http/1.1"] => XhttpVersion::H1,
                XhttpVersion::Auto => XhttpVersion::H2,
                v => v,
            };
            let alpn = match version {
                XhttpVersion::H1 => "http/1.1",
                XhttpVersion::H2 => "h2",
                _ => return Err(invalid("H3 cannot be wrapped in TLS")),
            };
            if !explicit_alpn.is_empty() && explicit_alpn != [alpn] {
                return Err(invalid(
                    "XHTTP TLS ALPN must select the configured HTTP version",
                ));
            }
            let client = crate::rustls_config_util::try_create_client_config(
                tls.verify,
                tls.server_fingerprints.clone().into_vec(),
                vec![alpn.into()],
                sni.is_some(),
                tls.key
                    .clone()
                    .zip(tls.cert.clone())
                    .map(|(k, c)| (k.into_bytes(), c.into_bytes())),
                false,
                &tls.key_exchange_groups,
            )?;
            let name = rustls::pki_types::ServerName::try_from(
                sni.clone().unwrap_or_else(|| "example.com".into()),
            )
            .map_err(io::Error::other)?;
            (
                xhttp,
                sni,
                Security::Tls {
                    config: Arc::new(client),
                    name,
                    buffer_size: tls.tls_buffer_size,
                },
                Some(version),
                false,
            )
        }
        ClientProxyConfig::Reality {
            protocol,
            sni_hostname,
            vision,
            ..
        } => {
            let ClientProxyConfig::Xhttp(xhttp) = protocol.as_ref() else {
                return Err(invalid("XHTTP must be directly inside REALITY"));
            };
            if *vision {
                return Err(invalid("Vision cannot wrap XHTTP"));
            }
            let xhttp = xhttp.clone();
            let sni = sni_hostname.clone().or(default_sni.clone());
            **protocol = ClientProxyConfig::PortForward;
            let handler = crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
                outer,
                default_sni,
                resolver.clone(),
            )?;
            if !matches!(xhttp.http_version, XhttpVersion::Auto | XhttpVersion::H2) {
                return Err(invalid("REALITY XHTTP requires H2"));
            }
            (
                xhttp,
                sni,
                Security::Reality(handler),
                Some(XhttpVersion::H2),
                true,
            )
        }
        _ => return Err(invalid("unsupported wrapper outside XHTTP")),
    };
    xhttp.validate()?;
    if contains(&xhttp.protocol) {
        return Err(invalid("nested XHTTP is not supported"));
    }
    let version = match (config.transport.clone(), tls_alpn, xhttp.http_version) {
        (Transport::Quic, None, XhttpVersion::Auto | XhttpVersion::H3) => XhttpVersion::H3,
        (Transport::Quic, _, _) => return Err(invalid("QUIC XHTTP requires top-level H3")),
        (_, Some(version), _) => version,
        (_, None, XhttpVersion::Auto) => XhttpVersion::H1,
        (_, None, XhttpVersion::H3) => return Err(invalid("H3 requires QUIC transport")),
        (_, None, version) => version,
    };
    if version == XhttpVersion::H3
        && config.quic_settings.as_ref().is_some_and(|q| {
            !q.alpn_protocols.is_unspecified() && q.alpn_protocols.clone().into_vec() != ["h3"]
        })
    {
        return Err(invalid("XHTTP QUIC ALPN must be h3"));
    }
    let authority = xhttp
        .host
        .clone()
        .filter(|host| !host.is_empty())
        .or(effective_sni)
        .unwrap_or_else(|| {
            if config.address.address().is_ipv6() {
                format!("[{}]:{}", config.address.address(), config.address.port())
            } else {
                config.address.to_string()
            }
        });
    let _: http::uri::Authority = authority.parse().map_err(io::Error::other)?;
    let mode = match xhttp.mode {
        XhttpMode::Auto if reality => XhttpMode::StreamOne,
        XhttpMode::Auto => XhttpMode::PacketUp,
        mode => mode,
    };
    let capacity = if version == XhttpVersion::H1 {
        xhttp.pool.max_h1_connections
    } else {
        xhttp
            .pool
            .max_connections
            .saturating_mul(xhttp.limits.request_limit_with(global_limits))
    };
    if mode != XhttpMode::StreamOne && capacity < 2 {
        return Err(invalid(
            "XHTTP split modes require at least two request lanes",
        ));
    }
    let inner = crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
        *xhttp.protocol.clone(),
        None,
        resolver,
    )?;
    Ok(Some((
        Arc::new(Client::new(
            xhttp,
            config.address.clone(),
            authority,
            version,
            mode,
            security,
        )?),
        inner,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ipv6_literal_endpoints_do_not_require_a_host_override() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        for transport in ["tcp", "quic"] {
            let config = serde_json::from_value(json!({
                "address": "[::1]:443",
                "transport": transport,
                "protocol": {"type": "xhttp", "protocol": {"type": "socks"}}
            }))
            .unwrap();
            assert!(build(&config, resolver.clone()).unwrap().is_some());
        }
    }

    #[test]
    fn split_modes_require_two_effective_lanes_after_auto_resolution() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let public_key =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [1; 32]);
        for carrier in [
            "plain-auto",
            "h1",
            "h2",
            "h3",
            "tls-auto",
            "tls-h1",
            "reality",
        ] {
            for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
                for (connections, h1_connections, requests) in
                    [(1, 1, 1), (2, 1, 1), (1, 2, 1), (1, 1, 2)]
                {
                    let version = match carrier {
                        "h1" | "h2" | "h3" => carrier,
                        _ => "auto",
                    };
                    let mut protocol = json!({
                        "type": "xhttp", "mode": mode, "http_version": version,
                        "pool": {"max_connections": connections, "max_h1_connections": h1_connections},
                        "limits": {"max_requests_per_connection": requests},
                        "protocol": {"type": "socks"}
                    });
                    protocol = match carrier {
                        "tls-auto" => json!({"type": "tls", "protocol": protocol}),
                        "tls-h1" => {
                            json!({"type": "tls", "alpn_protocols": ["http/1.1"], "protocol": protocol})
                        }
                        "reality" => {
                            json!({"type": "reality", "public_key": public_key, "protocol": protocol})
                        }
                        _ => protocol,
                    };
                    let config = serde_json::from_value(json!({
                        "address": "localhost:443",
                        "transport": if carrier == "h3" { "quic" } else { "tcp" },
                        "protocol": protocol
                    }))
                    .unwrap();
                    let single = mode == "stream-one" || (mode == "auto" && carrier == "reality");
                    for stream_limit in [None, Some(1), Some(2)] {
                        let global_limits = GlobalLimits {
                            max_streams_per_connection: stream_limit,
                            ..Default::default()
                        };
                        let capacity = if matches!(carrier, "plain-auto" | "h1" | "tls-h1") {
                            h1_connections
                        } else {
                            connections * requests.min(stream_limit.unwrap_or(requests))
                        };
                        let result = build_with_limits(&config, resolver.clone(), global_limits);
                        assert_eq!(
                            result.is_ok(),
                            single || capacity >= 2,
                            "carrier={carrier}, mode={mode}, pool=({connections}, {h1_connections}, {requests}), stream_limit={stream_limit:?}: {result:?}"
                        );
                        if let Err(error) = result {
                            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                            assert!(error.to_string().contains("at least two request lanes"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn xhttp_rejects_invalid_wrappers_carriers_and_headers() {
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
        let inner = json!({"type":"xhttp","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}});
        for protocol in [
            json!({"type":"xhttp","protocol":{"type":"direct"}}),
            json!({"type":"xhttp","protocol":inner}),
            json!({"type":"websocket","protocol":inner}),
            json!({"type":"tls","vision":true,"protocol":inner}),
            json!({"type":"xhttp","http_version":"h3","protocol":{"type":"socks"}}),
            json!({"type":"xhttp","headers":{"Connection":"keep-alive"},"protocol":{"type":"socks"}}),
            json!({"type":"xhttp","pool":{"max_h1_connections":usize::MAX},"protocol":{"type":"socks"}}),
        ] {
            let config =
                serde_json::from_value(json!({"address":"localhost:443","protocol":protocol}))
                    .unwrap();
            assert!(build(&config, resolver.clone()).is_err());
        }
        for alpn in [json!([]), json!(["h2"]), json!(["h3", "h2"])] {
            let config = serde_json::from_value(json!({"address":"localhost:443","transport":"quic", "quic_settings":{"alpn_protocols":alpn},"protocol":inner})).unwrap();
            assert!(build(&config, resolver.clone()).is_err());
        }
    }
}
