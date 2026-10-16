use std::{io, path::PathBuf, time::Duration};

use serde_json::json;
use shoes_test_support::{
    certs::generate_test_cert_files,
    port_helper::PortHelper,
    process::{start_mihomo_server, start_singbox_server_with_binary},
    test_fixture::start_shoes_server,
    test_servers::start_tcp_stream_echo_server,
};

use crate::http_proxy_support as support;

#[tokio::test]
#[ignore = "Requires sing-box >=1.15.0-alpha.7; set SHOES_TEST_HTTP2_SING_BOX_BIN"]
async fn singbox_h2_both_directions_without_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let binary = PathBuf::from(std::env::var_os("SHOES_TEST_HTTP2_SING_BOX_BIN").expect(
        "set SHOES_TEST_HTTP2_SING_BOX_BIN to a sing-box build with native H2 HTTP proxy support",
    ));
    tokio::time::timeout(Duration::from_secs(30), async {
        let (cert, key) = generate_test_cert_files()?;
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        for shoes_is_server in [false, true] {
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, entry) = ports.get_localhost_listener_port();
            let (shoes, singbox) = if shoes_is_server {
                (
                    json!([{"address": format!("0.0.0.0:{server}"), "protocol": {
                        "type": "tls", "default_tls_target": {
                            "cert": cert.to_str().unwrap(), "key": key.to_str().unwrap(),
                            "alpn_protocols": ["h2"], "protocol": {"type": "http", "username": "user", "password": "pass"}
                        }
                    }}]),
                    json!({
                        "log": {"level": "warn"},
                        "inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": entry, "version": [1]}],
                        "outbounds": [{"type": "http", "server": "127.0.0.1", "server_port": server,
                            "version": 2, "disable_version_fallback": true, "username": "user", "password": "pass",
                            "tls": {"enabled": true, "server_name": "test.local", "insecure": true, "alpn": ["h2"]}}]
                    }),
                )
            } else {
                (
                    json!([support::relay_config(entry, server, json!({
                        "type": "tls", "verify": false, "sni_hostname": "test.local", "alpn_protocols": ["h2"],
                        "protocol": {"type": "http", "http_version": "h2", "username": "user", "password": "pass"}
                    }))]),
                    json!({
                        "log": {"level": "warn"},
                        "inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": server, "version": [2],
                            "users": [{"username": "user", "password": "pass"}],
                            "tls": {"enabled": true, "certificate_path": cert.to_str().unwrap(), "key_path": key.to_str().unwrap(), "alpn": ["h2"]}}],
                        "outbounds": [{"type": "direct"}]
                    }),
                )
            };
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes)?)?;
            let _singbox = start_singbox_server_with_binary(&singbox.to_string(), &binary, &[("GOMAXPROCS", "1")])?;
            ports.wait_for_all_ports().await?;
            let target = format!("127.0.0.1:{}", echo.local_addr().port());
            let first = support::connect(entry, &target).await?;
            let (second, third) = tokio::try_join!(support::connect(entry, &target), support::connect(entry, &target))?;
            tokio::try_join!(support::exchange(first), support::exchange(second), support::exchange(third))?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}

#[tokio::test]
async fn mihomo_h1_http_remains_compatible_with_dual_alpn_listener() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let mut ports = PortHelper::new();
        let (_, server) = ports.get_localhost_listener_port();
        let (_, entry) = ports.get_localhost_listener_port();
        let shoes = json!([{"address": format!("0.0.0.0:{server}"), "protocol": {
            "type": "tls", "default_tls_target": {
                "cert": cert.cert.pem(), "key": cert.signing_key.serialize_pem(),
                "alpn_protocols": ["h2", "http/1.1"],
                "protocol": {"type": "http", "username": "user", "password": "pass"}
            }
        }}]);
        let mihomo = json!({
            "mixed-port": entry, "allow-lan": true, "bind-address": "0.0.0.0",
            "mode": "rule", "log-level": "warning", "ipv6": false,
            "proxies": [{"name": "proxy", "type": "http", "server": "127.0.0.1", "port": server,
                "username": "user", "password": "pass", "tls": true, "sni": "localhost",
                "skip-cert-verify": true}],
            "rules": ["MATCH,proxy"]
        });
        let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes).unwrap())?;
        let _mihomo = start_mihomo_server(&serde_yaml::to_string(&mihomo).unwrap()).await?;
        ports.wait_for_all_ports().await?;
        support::exchange(
            support::connect(entry, &format!("127.0.0.1:{}", echo.local_addr().port())).await?,
        )
        .await
    })
    .await?
}
