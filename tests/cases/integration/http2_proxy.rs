use std::{io, sync::Arc, time::Duration};

use serde_json::json;
use shoes_test_support::{
    port_helper::PortHelper, test_fixture::start_shoes_server,
    test_servers::start_tcp_stream_echo_server,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[path = "../http_proxy_support.rs"]
mod support;

#[tokio::test]
async fn h2_and_h1_through_http_and_mixed_with_optional_auth_and_tls() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for tls in [false, true] {
            for (listener, auth) in [("http", false), ("http", true), ("mixed", false), ("mixed", true)] {
                for version in ["h1", "h2"] {
                    let mut ports = PortHelper::new();
                    let (_, server) = ports.get_localhost_listener_port();
                    let (_, entry) = ports.get_localhost_listener_port();
                    let mut inbound = json!({"type": listener});
                    let mut outbound = json!({"type": "http", "http_version": version});
                    if auth {
                        inbound["username"] = json!("user");
                        inbound["password"] = json!("pass");
                        outbound["username"] = json!("user");
                        outbound["password"] = json!("pass");
                    }
                    if tls {
                        inbound = json!({"type": "tls", "default_tls_target": {
                            "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                            "alpn_protocols": ["h2", "http/1.1"], "protocol": inbound
                        }});
                        outbound = json!({"type": "tls", "verify": false, "sni_hostname": "localhost",
                            "alpn_protocols": [if version == "h2" { "h2" } else { "http/1.1" }],
                            "protocol": outbound
                        });
                    }
                    let config = json!([
                        {"address": format!("0.0.0.0:{server}"), "protocol": inbound},
                        support::relay_config(entry, server, outbound)
                    ]);
                    let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
                    ports.wait_for_all_ports().await?;
                    let target = format!("127.0.0.1:{}", echo.local_addr().port());
                    // Open the first tunnel before concurrent warm opens.
                    let first = support::connect(entry, &target).await?;
                    let (second, third) = tokio::try_join!(
                        support::connect(entry, &target), support::connect(entry, &target),
                    )?;
                    tokio::try_join!(
                        support::exchange(first), support::exchange(second), support::exchange(third),
                    )?;
                }
            }
        }
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn h2_tls_alpn_mismatch_fails_instead_of_falling_back() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for alpn in [vec!["http/1.1"], vec![], vec!["custom"]] {
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let config = json!([
                {"address": format!("0.0.0.0:{server}"), "protocol": {"type": "tls", "default_tls_target": {
                    "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                    "alpn_protocols": alpn, "protocol": {"type": "http"}
                }}},
                support::relay_config(entry, server, json!({
                    "type": "tls", "sni_hostname": "localhost", "verify": false,
                    "alpn_protocols": alpn, "protocol": {"type": "http", "http_version": "h2"}
                }))
            ]);
            let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
            ports.wait_for_all_ports().await?;
            let result = tokio::time::timeout(Duration::from_secs(2),
                support::connect(entry, &format!("127.0.0.1:{}", echo.local_addr().port())),
            ).await.expect("ALPN mismatch must fail promptly");
            assert!(result.is_err(), "H2 accepted ALPN {alpn:?}");
        }
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn default_and_explicit_h1_preserve_permissive_tls_alpn() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for explicit_h1 in [false, true] {
            for alpn in [vec![], vec!["http/1.1"], vec!["h2"], vec!["custom"]] {
                let mut ports = PortHelper::new();
                let (_, server) = ports.get_localhost_listener_port();
                let (_, entry) = ports.get_localhost_listener_port();
                let mut outbound = json!({"type": "http"});
                if explicit_h1 {
                    outbound["http_version"] = json!("h1");
                }
                let config = json!([
                    {"address": format!("0.0.0.0:{server}"), "protocol": {"type": "tls", "default_tls_target": {
                        "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                        "alpn_protocols": alpn, "protocol": {"type": "http"}
                    }}},
                    support::relay_config(entry, server, json!({
                        "type": "tls", "sni_hostname": "localhost", "verify": false,
                        "alpn_protocols": alpn, "protocol": outbound
                    }))
                ]);
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
                ports.wait_for_all_ports().await?;
                support::exchange(support::connect(entry,
                    &format!("127.0.0.1:{}", echo.local_addr().port()),
                ).await?).await?;
            }
        }
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn named_tls_target_routing_and_h2_proxy_chaining() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, middle) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let target_rules = json!([{"mask": "0.0.0.0/0", "action": "allow",
            "override_address": format!("127.0.0.1:{}", echo.local_addr().port()), "client_chain": "direct"}]);
        let config = json!([
            {"address": format!("0.0.0.0:{server}"),
                "rules": [{"mask": "0.0.0.0/0", "action": "block"}],
                "protocol": {"type": "tls", "tls_targets": {"localhost": {
                    "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                    "alpn_protocols": ["h2"], "protocol": {"type": "http"},
                    "override_rules": target_rules
                }}}},
            {"address": format!("0.0.0.0:{middle}"), "protocol": {"type": "http"}},
            {"address": format!("0.0.0.0:{entry}"), "protocol": {"type": "http"},
                "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": {"chain": [
                    {"address": format!("127.0.0.1:{middle}"), "protocol": {"type": "http", "http_version": "h2"}},
                    {"address": format!("127.0.0.1:{server}"), "protocol": {"type": "tls", "verify": false,
                        "sni_hostname": "localhost", "alpn_protocols": ["h2"],
                        "protocol": {"type": "http", "http_version": "h2", "resolve_hostname": true}}}
                ]}}]}
        ]);
        let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
        ports.wait_for_all_ports().await?;
        for _ in 0..2 {
            support::exchange(support::connect(entry, "localhost:1").await?).await?;
        }
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn pooled_prefixes_do_not_share_a_subsequent_h2_carrier() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut markers = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        for marker in b"AB" {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
            markers.push(listener.local_addr()?.port());
            let marker = *marker;
            tasks.spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await?;
                    stream.write_all(&[marker]).await?;
                    stream.read_to_end(&mut Vec::new()).await?;
                }
                Ok::<_, io::Error>(())
            });
        }
        let mut ports = PortHelper::new();
        let (_, h2_a) = ports.get_localhost_listener_port();
        let (_, h2_b) = ports.get_localhost_listener_port();
        let (_, prefix_a) = ports.get_localhost_listener_port();
        let (_, prefix_b) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let listener = |port, target| json!({
            "address": format!("0.0.0.0:{port}"), "protocol": {"type": "http"},
            "rules": [{"mask": "0.0.0.0/0", "action": "allow", "override_address": format!("127.0.0.1:{target}")}]
        });
        let hop = |port, version| json!({
            "address": format!("127.0.0.1:{port}"), "protocol": {"type": "http", "http_version": version}
        });
        let config = json!([
            listener(h2_a, markers[0]), listener(h2_b, markers[1]),
            listener(prefix_a, h2_a), listener(prefix_b, h2_b),
            {"address": format!("0.0.0.0:{entry}"), "protocol": {"type": "http"},
                "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": {"chain": [
                    {"pool": [hop(prefix_a, "h1"), hop(prefix_b, "h1")]}, hop(h2_a, "h2")
                ]}}]}
        ]);
        let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
        ports.wait_for_all_ports().await?;
        for expected in b"ABAB" {
            let mut stream = support::connect(entry, "example.test:443").await?;
            assert_eq!(stream.read_u8().await?, *expected);
            stream.shutdown().await?;
            stream.read_to_end(&mut Vec::new()).await?;
        }
        while let Some(task) = tasks.join_next().await { task.unwrap()?; }
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn h2_tls_tunnels_share_one_socket_and_handshake() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            ).unwrap();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let mut ports = PortHelper::new();
        let (_, entry) = ports.get_localhost_listener_port();
        let config = json!([support::relay_config(entry, listener.local_addr()?.port(), json!({
            "type": "tls", "sni_hostname": "localhost", "verify": false, "alpn_protocols": ["h2"],
            "protocol": {"type": "http", "http_version": "h2", "username": "user", "password": "pass"}
        }))]);
        let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
        ports.wait_for_all_ports().await?;
        let (finished, mut done) = tokio::sync::oneshot::channel();
        let server = async {
            let (socket, _) = listener.accept().await?;
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)).accept(socket).await?;
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let mut connection = h2::server::handshake(tls).await.map_err(io::Error::other)?;
            let mut tasks = tokio::task::JoinSet::new();
            let mut requests = 0;
            loop {
                tokio::select! {
                    incoming = connection.accept() => {
                        let (request, mut respond) = incoming.expect("carrier closed before tunnels finished")
                            .map_err(io::Error::other)?;
                        requests += 1;
                        assert_eq!(request.method(), http::Method::CONNECT);
                        assert_eq!(request.version(), http::Version::HTTP_2);
                        assert_eq!(request.uri().authority().unwrap(), "example.test:443");
                        assert_eq!(request.headers()["proxy-authorization"], "Basic dXNlcjpwYXNz");
                        let mut send = respond.send_response(http::Response::new(()), false).map_err(io::Error::other)?;
                        tasks.spawn(async move {
                            let mut receive = request.into_body();
                            let mut payload = Vec::new();
                            while let Some(data) = receive.data().await {
                                let data = data.map_err(io::Error::other)?;
                                receive.flow_control().release_capacity(data.len()).map_err(io::Error::other)?;
                                payload.extend_from_slice(&data);
                            }
                            send.send_data(payload.into(), true).map_err(io::Error::other)
                        });
                    }
                    extra = listener.accept() => {
                        extra?;
                        panic!("warm HTTP/2 tunnel opened another TCP connection");
                    }
                    task = tasks.join_next(), if !tasks.is_empty() => { task.unwrap().unwrap()?; }
                    result = &mut done => { result.unwrap(); break; }
                }
            }
            while let Some(task) = tasks.join_next().await { task.unwrap()?; }
            assert_eq!(requests, 3);
            Ok::<_, io::Error>(())
        };
        let client = async {
            let first = support::connect(entry, "example.test:443").await?;
            let (second, third) = tokio::try_join!(
                support::connect(entry, "example.test:443"),
                support::connect(entry, "example.test:443"),
            )?;
            tokio::try_join!(support::exchange(first), support::exchange(second), support::exchange(third))?;
            finished.send(()).unwrap();
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(server, client)?;
        Ok::<_, io::Error>(())
    }).await?
}

#[tokio::test]
async fn legacy_http_forwarding_and_mixed_socks_remain_compatible() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for listener in ["http", "mixed"] {
            for auth in [false, true] {
                let mut ports = PortHelper::new();
                let (_, entry) = ports.get_localhost_listener_port();
                let mut protocol = json!({"type": listener});
                if auth {
                    protocol["username"] = json!("user");
                    protocol["password"] = json!("pass");
                }
                let config = json!([{"address": format!("0.0.0.0:{entry}"), "protocol": protocol}]);
                let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
                ports.wait_for_all_ports().await?;
                for version in ["HTTP/1.0", "HTTP/1.1"] {
                    let origin = TcpListener::bind("0.0.0.0:0").await?;
                    let origin_port = origin.local_addr()?.port();
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
                    let server = async {
                        let (mut stream, _) = origin.accept().await?;
                        let expected = format!("POST /path?q=1 {version}\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
                        let mut received = vec![0; expected.len()];
                        stream.read_exact(&mut received).await?;
                        assert_eq!(received, expected.as_bytes());
                        assert_eq!(stream.read(&mut [0]).await?, 0);
                        stream.write_all(response).await?;
                        stream.shutdown().await
                    };
                    let client = async {
                        let mut stream = TcpStream::connect(("127.0.0.1", entry)).await?;
                        let request = format!("POST http://127.0.0.1:{origin_port}/path?q=1 {version}\r\nHost: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nContent-Length: 4\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\nbody");
                        stream.write_all(request.as_bytes()).await?;
                        stream.shutdown().await?;
                        let mut received = Vec::new();
                        stream.read_to_end(&mut received).await?;
                        assert_eq!(received, response);
                        Ok::<_, io::Error>(())
                    };
                    tokio::try_join!(server, client)?;
                }
                if listener == "mixed" {
                    let mut stream = TcpStream::connect(("127.0.0.1", entry)).await?;
                    let method = if auth { 2 } else { 0 };
                    stream.write_all(&[5, 1, method]).await?;
                    let mut response = [0; 2];
                    stream.read_exact(&mut response).await?;
                    assert_eq!(response, [5, method]);
                    if auth {
                        stream.write_all(b"\x01\x04user\x04pass").await?;
                        stream.read_exact(&mut response).await?;
                        assert_eq!(response, [1, 0]);
                    }
                    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend_from_slice(&echo.local_addr().port().to_be_bytes());
                    stream.write_all(&request).await?;
                    let mut response = [0; 10];
                    stream.read_exact(&mut response).await?;
                    assert_eq!(&response[..4], &[5, 0, 0, 1]);
                    support::exchange(stream).await?;
                }
            }
        }
        Ok::<_, io::Error>(())
    }).await?
}
