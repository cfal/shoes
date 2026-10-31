use std::{path::Path, time::Duration};

use serde_json::json;
use shoes_test_support::{
    certs::generate_test_cert_files,
    port_helper::PortHelper,
    test_fixture::{find_singbox_binary, start_shoes_server, start_singbox_server_with_binary},
    test_servers::start_tcp_stream_echo_server,
};

#[tokio::test]
async fn large_server_scheme_interoperates_in_both_directions()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let sing_binary = match std::env::var_os("SHOES_TEST_ANYTLS_SING_BOX_BIN") {
            Some(path) => path.into(),
            None => find_singbox_binary()?,
        };
        let (cert, key) = generate_test_cert_files()?;
        let cert: &Path = cert.as_ref();
        let key: &Path = key.as_ref();
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let scheme = ["stop=8", "0=40000-40000", "1=200000-200000", "2=1048576-1048576", "3=65536-65536"];
        for shoes_server in [false, true] {
            let mut ports = PortHelper::new();
            let (_, server) = ports.get_localhost_listener_port();
            let (_, client) = ports.get_localhost_listener_port();
            let (shoes, sing) = if shoes_server {
                (json!([{
                    "address": format!("0.0.0.0:{server}"), "protocol": {"type": "tls", "default_tls_target": {
                        "cert": cert, "key": key, "protocol": {"type": "anytls",
                            "users": [{"name": "test", "password": "secret"}], "padding_scheme": scheme}
                    }}
                }]), json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": client}],
                    "outbounds": [{"type": "anytls", "server": "127.0.0.1", "server_port": server, "password": "secret",
                        "tls": {"enabled": true, "server_name": "test.local", "insecure": true}}]
                }))
            } else {
                (json!([{
                    "address": format!("0.0.0.0:{client}"), "protocol": {"type": "http"},
                    "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [{
                        "address": format!("127.0.0.1:{server}"), "protocol": {"type": "tls", "verify": false,
                            "sni_hostname": "test.local", "protocol": {"type": "anytls", "password": "secret"}}
                    }]}]
                }]), json!({
                    "log": {"level": "warn"},
                    "inbounds": [{"type": "anytls", "listen": "0.0.0.0", "listen_port": server,
                        "users": [{"name": "test", "password": "secret"}], "padding_scheme": scheme,
                        "tls": {"enabled": true, "certificate_path": cert, "key_path": key}}],
                    "outbounds": [{"type": "direct"}]
                }))
            };
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes)?)?;
            let _sing = start_singbox_server_with_binary(&sing.to_string(), &sing_binary, &[("GOMAXPROCS", "1")])?;
            ports.wait_for_all_ports().await?;
            for _ in 0..3 {
                super::tls_hybrid::echo_through_http(client, echo.local_addr().port()).await?;
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}
