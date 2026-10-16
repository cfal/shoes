use std::{io, time::Duration};

use serde_json::json;
use shoes_test_support::{
    port_helper::PortHelper, test_fixture::start_shoes_server,
    test_servers::start_tcp_stream_echo_server,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../http_proxy_support.rs"]
mod support;

#[tokio::test]
async fn h2_and_h1_through_http_and_mixed_with_optional_auth_and_tls() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for tls in [false, true] {
            for auth in [false, true] {
                for version in ["h1", "h2"] {
                    let mut ports = PortHelper::new();
                    let (_, server) = ports.get_localhost_listener_port();
                    let (_, entry) = ports.get_localhost_listener_port();
                    let mut inbound = json!({"type": if auth { "mixed" } else { "http" }});
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
async fn tls_alpn_mismatch_fails_instead_of_falling_back() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for (version, alpn) in [("h2", vec!["http/1.1"]), ("h2", vec![]), ("h1", vec!["h2"])] {
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
                    "alpn_protocols": alpn, "protocol": {"type": "http", "http_version": version}
                }))
            ]);
            let _shoes = start_shoes_server(&serde_yaml::to_string(&config).unwrap())?;
            ports.wait_for_all_ports().await?;
            let result = tokio::time::timeout(Duration::from_secs(2),
                support::connect(entry, &format!("127.0.0.1:{}", echo.local_addr().port())),
            ).await.expect("ALPN mismatch must fail promptly");
            assert!(result.is_err(), "version {version} accepted ALPN {alpn:?}");
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
                "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [
                    {"address": format!("127.0.0.1:{middle}"), "protocol": {"type": "http", "http_version": "h2"}},
                    {"address": format!("127.0.0.1:{server}"), "protocol": {"type": "tls", "verify": false,
                        "sni_hostname": "localhost", "alpn_protocols": ["h2"],
                        "protocol": {"type": "http", "http_version": "h2", "resolve_hostname": true}}}
                ]}]}
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
                "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [
                    [hop(prefix_a, "h1"), hop(prefix_b, "h1")], hop(h2_a, "h2")
                ]}]}
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
