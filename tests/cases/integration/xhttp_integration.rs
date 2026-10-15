use std::{net::SocketAddr, time::Duration};

use serde_json::json;
use shoes_test_support::{
    socks5::Socks5UdpAssociation,
    test_fixture::{generate_reality_keypair, start_shoes_server},
    test_servers::{start_tcp_stream_echo_server, start_udp_echo_server_with_suffix},
    xray,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

fn port() -> u16 {
    static USED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::LazyLock::new(Default::default);
    loop {
        let port = std::net::TcpListener::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if USED.lock().unwrap().insert(port) {
            return port;
        }
    }
}

async fn matrix(
    shoes_client: bool,
    protocol: &str,
    versions: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let _udp_echo = start_udp_echo_server_with_suffix("0.0.0.0", echo_port, b"").await?;
    // REALITY's combined-flight mimicry needs an encrypted flight over 512 bytes.
    let names: Vec<String> = std::iter::once("localhost".into())
        .chain((0..40).map(|i| format!("fixture-{i}.local.test")))
        .collect();
    let certificate = rcgen::generate_simple_self_signed(names)?;
    let pin: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.cert.der())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let files = tempfile::tempdir()?;
    let cert = files.path().join("cert.pem");
    let key = files.path().join("key.pem");
    std::fs::write(&cert, certificate.cert.pem())?;
    std::fs::write(&key, certificate.signing_key.serialize_pem())?;
    let (private_key, public_key) = generate_reality_keypair();
    let destination = port();
    let _destination = start_shoes_server(&serde_yaml::to_string(&json!([
        {"address":format!("0.0.0.0:{destination}"),"protocol":{"type":"tls","default_target":{"cert":cert,"key":key,"alpn_protocols":["h2","http/1.1"],"protocol":{"type":"http"}}}}
    ]))?)?;
    for &version in versions {
        for mode in ["packet-up", "stream-up", "stream-one", "auto"] {
            if mode == "auto" && version != "reality" {
                continue;
            }
            eprintln!("XHTTP shoes_client={shoes_client} {version} {mode} {protocol}");
            let remote = port();
            let socks_port = port();
            let readiness = port();
            let socks: SocketAddr = ([127, 0, 0, 1], socks_port).into();
            let alpn = match version {
                "h1" => "http/1.1",
                "h2" => "h2",
                _ => "h3",
            };
            let path = "/tunnel%2Freserved?test=a%2Bb";
            let mut xray_stream = json!({"network":"xhttp","xhttpSettings":{"path":path,"host":"front.test:8443","mode":mode},"security":"tls","tlsSettings":{"serverName":"localhost","alpn":[alpn],"certificates":[{"certificateFile":cert,"keyFile":key}]}});
            if shoes_client {
                xray_stream["xhttpSettings"]["host"] = json!("front.test");
            }
            if !shoes_client {
                xray_stream["tlsSettings"]["pinnedPeerCertSha256"] = json!(pin);
            }
            if matches!(version, "plain" | "h2c") {
                xray_stream["security"] = json!("none");
                xray_stream.as_object_mut().unwrap().remove("tlsSettings");
            }
            if version == "reality" {
                xray_stream["security"] = json!("reality");
                xray_stream.as_object_mut().unwrap().remove("tlsSettings");
                xray_stream["realitySettings"] = if shoes_client {
                    json!({"target":format!("127.0.0.1:{destination}"),"serverNames":["localhost"],"privateKey":private_key,"shortIds":["0123456789abcdef"]})
                } else {
                    json!({"serverName":"localhost","password":public_key,"shortId":"0123456789abcdef","fingerprint":"chrome"})
                };
            }
            let xhttp_version = match version {
                "plain" => "h1",
                "h2c" => "h2",
                "reality" => "auto",
                v => v,
            };
            let inner = if protocol == "vless" {
                json!({"type":"vless","user_id":UUID,"udp_enabled":true})
            } else {
                json!({"type":"trojan","password":"xhttp-test-password"})
            };
            let xhttp = json!({"type":"xhttp","path":path,"host":"front.test:8443","http_version":xhttp_version,"mode":mode,"protocol":inner});
            let mut shoes_remote =
                json!({"address":format!("127.0.0.1:{remote}"),"protocol":xhttp});
            if version == "reality" {
                shoes_remote["protocol"] = if shoes_client {
                    json!({"type":"reality","public_key":public_key,"short_id":"0123456789abcdef","sni_hostname":"localhost","protocol":xhttp})
                } else {
                    json!({"type":"tls","reality_targets":{"localhost":{"private_key":private_key,"short_ids":["0123456789abcdef"],"dest":format!("localhost:{destination}"),"protocol":xhttp}}})
                };
            } else if version == "h3" {
                shoes_remote["transport"] = json!("quic");
                shoes_remote["quic_settings"] = if shoes_client {
                    json!({"verify":false,"sni_hostname":"localhost"})
                } else {
                    json!({"cert":cert,"key":key})
                };
            } else if !matches!(version, "plain" | "h2c") {
                shoes_remote["protocol"] = if shoes_client {
                    json!({"type":"tls","verify":false,"sni_hostname":"localhost","protocol":xhttp})
                } else {
                    json!({"type":"tls","default_target":{"cert":cert,"key":key,"protocol":xhttp}})
                };
            }
            let mut xray_config;
            let mut shoes_config;
            if shoes_client {
                xray_config = json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":remote,"protocol":"vless","settings":{"clients":[{"id":UUID}],"decryption":"none"},"streamSettings":xray_stream}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"]}]}}]});
                shoes_config = json!([{"address":format!("0.0.0.0:{socks_port}"),"protocol":{"type":"socks","udp_enabled":true},"rules":[{"masks":"0.0.0.0/0","client_chains":[[shoes_remote]]}]}]);
            } else {
                xray_config = json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":socks_port,"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":remote,"users":[{"id":UUID,"encryption":"none"}]}]},"streamSettings":xray_stream}]});
                shoes_remote["address"] = json!(format!("0.0.0.0:{remote}"));
                shoes_config = json!([shoes_remote,{"address":format!("0.0.0.0:{readiness}"),"protocol":{"type":"socks"}}]);
            }
            if protocol == "trojan" {
                if shoes_client {
                    xray_config["inbounds"][0]["protocol"] = json!("trojan");
                    xray_config["inbounds"][0]["settings"] =
                        json!({"clients":[{"password":"xhttp-test-password"}]});
                } else {
                    xray_config["outbounds"][0]["protocol"] = json!("trojan");
                    xray_config["outbounds"][0]["settings"] = json!({"servers":[{"address":"127.0.0.1","port":remote,"password":"xhttp-test-password"}]});
                }
            }
            if version == "h3" && mode == "stream-one" {
                shoes_config
                    .as_array_mut()
                    .unwrap()
                    .insert(0, json!({"global_limits":{"max_streams_per_connection":1}}));
            }
            let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config)?)?;
            xray::wait_socks(
                (
                    [127, 0, 0, 1],
                    if shoes_client { socks_port } else { readiness },
                )
                    .into(),
            )
            .await?;
            let _xray = xray::start(xray_config).await?;
            xray::wait_socks(socks).await?;
            tokio::time::timeout(Duration::from_secs(20), async {
                for _ in 0..2 {
                    let mut stream = xray::connect(socks, target).await?;
                    for size in [1, 32768, 300_000] {
                        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                        let mut response = vec![0; size];
                        let (mut read, mut write) = stream.split();
                        tokio::try_join!(write.write_all(&data), read.read_exact(&mut response))?;
                        assert_eq!(data, response);
                    }
                    stream.shutdown().await?;
                    // Packet mode has no upload FIN. Xray may also couple the
                    // streaming halves, so duplex progress is the interop gate.
                }
                if protocol == "vless" {
                    let udp = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
                    for data in [
                        b"ok\0\xff".as_slice(),
                        b"data: SSE-looking bytes\n\n",
                        &[0; 4096],
                    ] {
                        assert_eq!(udp.send_to(target, data).await?, data);
                    }
                }
                Ok::<_, std::io::Error>(())
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn shoes_client_xray_server_all_modes_and_versions() -> Result<(), Box<dyn std::error::Error>>
{
    matrix(true, "vless", &["h1", "h2", "h3", "plain", "h2c"]).await
}

#[tokio::test]
async fn xray_client_shoes_server_all_modes_and_versions() -> Result<(), Box<dyn std::error::Error>>
{
    matrix(false, "vless", &["h1", "h2", "h3", "plain", "reality"]).await
}

#[tokio::test]
async fn trojan_transport_independence() -> Result<(), Box<dyn std::error::Error>> {
    matrix(true, "trojan", &["h1", "h2", "h3", "plain", "h2c"]).await?;
    matrix(false, "trojan", &["h1", "h2", "h3", "plain", "reality"]).await
}

#[tokio::test]
#[ignore = "Existing Shoes REALITY client lacks the X25519MLKEM768 key share required by Xray 26.10.10"]
async fn shoes_client_xray_reality_server() -> Result<(), Box<dyn std::error::Error>> {
    matrix(true, "vless", &["reality"]).await
}
