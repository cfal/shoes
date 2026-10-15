use std::{net::SocketAddr, time::Duration};

use aws_lc_rs::signature::{self, KeyPair};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
        {"address":format!("0.0.0.0:{destination}"),"protocol":{"type":"tls","default_target":{"cert":cert,"key":key,"key_exchange_groups":["X25519MLKEM768"],"alpn_protocols":["h2","http/1.1"],"protocol":{"type":"http"}}}}
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
                for session in 0..2 {
                    let mut stream = xray::connect(socks, target).await?;
                    for size in [1, 32768, 300_000] {
                        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                        let mut response = vec![0; size];
                        let (mut read, mut write) = stream.split();
                        tokio::try_join!(write.write_all(&data), read.read_exact(&mut response))?;
                        assert_eq!(data, response);
                    }
                    if !shoes_client
                        && protocol == "vless"
                        && version == "plain"
                        && mode == "packet-up"
                        && session == 0
                    {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                        stream.write_all(b"idle").await?;
                        let mut response = [0; 4];
                        stream.read_exact(&mut response).await?;
                        assert_eq!(&response, b"idle");
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
    matrix(
        true,
        "trojan",
        &["h1", "h2", "h3", "plain", "h2c", "reality"],
    )
    .await?;
    matrix(false, "trojan", &["h1", "h2", "h3", "plain", "reality"]).await
}

#[tokio::test]
async fn shoes_reality_client_and_udp_through_a_tcp_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let _udp = start_udp_echo_server_with_suffix("0.0.0.0", echo_port, b"").await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()])?;
    // The cover flight must fit REALITY's ML-DSA certificate.
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0; 5000],
        ));
    let certificate = params.self_signed(&key)?;
    let (private_key, public_key) = generate_reality_keypair();
    let seed = URL_SAFE_NO_PAD.encode([7; 32]);
    let [verify, wrong_verify] = [7, 8].map(|byte| {
        let signing =
            signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[byte; 32]).unwrap();
        URL_SAFE_NO_PAD.encode(signing.public_key().as_ref())
    });
    for (mode, sign, pin, accepted) in [
        ("auto", false, None, true),
        ("stream-one", false, None, true),
        ("stream-up", false, None, true),
        ("packet-up", false, None, true),
        ("auto", true, Some(&verify), true),
        ("stream-one", true, Some(&verify), true),
        ("stream-up", true, Some(&verify), true),
        ("packet-up", true, Some(&verify), true),
        ("auto", true, None, true),
        ("auto", true, Some(&wrong_verify), false),
        ("auto", false, Some(&verify), false),
    ] {
        eprintln!(
            "REALITY XHTTP prefix: {mode}, sign={sign}, pin={}, accepted={accepted}",
            pin.is_some()
        );
        let destination = port();
        let remote = port();
        let prefix = port();
        let socks = port();
        let inner = json!({"type":"vless","user_id":UUID,"udp_enabled":true});
        let xhttp = json!({"type":"xhttp","path":"/reality","mode":mode,"protocol":inner});
        let config = json!([
            {"address":format!("0.0.0.0:{destination}"),"protocol":{"type":"tls","default_target":{
                "cert":certificate.pem(),"key":key.serialize_pem(),
                "key_exchange_groups":["X25519MLKEM768"],
                "alpn_protocols":["h2","http/1.1"],"protocol":{"type":"http"}
            }}},
            {"address":format!("0.0.0.0:{remote}"),"protocol":{"type":"tls","reality_targets":{"localhost":{
                "private_key":private_key,"short_ids":["0123456789abcdef"],
                "mldsa65_seed":sign.then_some(&seed),
                "dest":format!("localhost:{destination}"),"protocol":xhttp
            }}}},
            {"address":format!("0.0.0.0:{prefix}"),"protocol":{"type":"socks"}},
            {"address":format!("0.0.0.0:{socks}"),"protocol":{"type":"socks","udp_enabled":true},
                "rules":[{"masks":"0.0.0.0/0","client_chains":[[
                    {"address":format!("127.0.0.1:{prefix}"),"protocol":{"type":"socks"}},
                    {"address":format!("127.0.0.1:{remote}"),"protocol":{"type":"reality",
                        "public_key":public_key,"short_id":"0123456789abcdef",
                        "mldsa65_verify":pin,
                        "sni_hostname":"localhost","protocol":xhttp}}
                ]]}]}
        ]);
        let _server = start_shoes_server(&serde_yaml::to_string(&config)?)?;
        let address: SocketAddr = ([127, 0, 0, 1], socks).into();
        xray::wait_socks(address).await?;
        let connected =
            tokio::time::timeout(Duration::from_secs(15), xray::connect(address, target)).await?;
        if !accepted {
            assert!(
                connected.is_err(),
                "REALITY pin must fail before SOCKS CONNECT succeeds"
            );
            continue;
        }
        let mut stream = connected?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let payload = vec![71; 300_000];
            let mut response = vec![0; payload.len()];
            let (mut read, mut write) = stream.split();
            tokio::try_join!(write.write_all(&payload), read.read_exact(&mut response))?;
            assert_eq!(response, payload);
            let udp = Socks5UdpAssociation::connect("127.0.0.1", socks).await?;
            assert_eq!(udp.send_to(target, b"prefix\0\xff").await?, b"prefix\0\xff");
            Ok::<_, std::io::Error>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn xray_packet_upload_survives_a_slow_consumer() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&listener).set_recv_buffer_size(65536)?;
    let target: SocketAddr = ([127, 0, 0, 1], listener.local_addr()?.port()).into();
    let size = 16 * 1024 * 1024;
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = 0;
        let mut buffer = [0; 16 * 1024];
        while received < size {
            let len = socket.read(&mut buffer).await.unwrap();
            assert_ne!(len, 0, "upload ended after {received} bytes");
            assert!(buffer[..len].iter().all(|byte| *byte == 73));
            received += len;
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        socket.write_all(b"ok").await.unwrap();
    });
    let remote = port();
    let socks_port = port();
    let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([
        {"address":format!("0.0.0.0:{remote}"),"protocol":{"type":"xhttp","path":"/slow",
            "protocol":{"type":"vless","user_id":UUID}}}
    ]))?)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(("127.0.0.1", remote))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let _xray = xray::start(json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"0.0.0.0","port":socks_port,"protocol":"socks","settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{
            "address":"127.0.0.1","port":remote,"users":[{"id":UUID,"encryption":"none"}]
        }]},"streamSettings":{"network":"xhttp","security":"none",
            "xhttpSettings":{"path":"/slow","mode":"packet-up"}}}]
    })).await?;
    let socks = ([127, 0, 0, 1], socks_port).into();
    xray::wait_socks(socks).await?;
    tokio::time::timeout(Duration::from_secs(25), async {
        let mut stream = xray::connect(socks, target).await?;
        stream.write_all(&vec![73; size]).await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, b"ok");
        tasks.join_next().await.unwrap().unwrap();
        Ok::<_, std::io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn xhttp_tls_and_quic_enforce_key_exchange_allowlists()
-> Result<(), Box<dyn std::error::Error>> {
    let echo_port = port();
    let _echo = start_tcp_stream_echo_server("0.0.0.0", echo_port).await?;
    let target: SocketAddr = ([127, 0, 0, 1], echo_port).into();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let mut configs = Vec::new();
    let mut cases = Vec::new();
    for version in ["h2", "h3"] {
        for client_group in ["X25519MLKEM768", "X25519"] {
            for server_group in ["X25519MLKEM768", "X25519"] {
                let remote = port();
                let socks = port();
                let xhttp = json!({"type":"xhttp", "http_version":version, "mode":"stream-one",
                    "protocol":{"type":"vless", "user_id":UUID}});
                let server_tls = json!({"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(),
                    "key_exchange_groups":[server_group]});
                let client_tls = json!({"verify":false, "sni_hostname":"localhost",
                    "key_exchange_groups":[client_group]});
                let mut server = json!({"address":format!("0.0.0.0:{remote}"), "protocol":xhttp});
                let mut client = json!({"address":format!("127.0.0.1:{remote}"), "protocol":xhttp});
                if version == "h3" {
                    server["transport"] = json!("quic");
                    server["quic_settings"] = server_tls;
                    client["transport"] = json!("quic");
                    client["quic_settings"] = client_tls;
                } else {
                    let mut server_tls = server_tls;
                    server_tls["protocol"] = xhttp.clone();
                    server["protocol"] = json!({"type":"tls", "default_target":server_tls});
                    client["protocol"] = client_tls;
                    client["protocol"]["type"] = json!("tls");
                    client["protocol"]["protocol"] = xhttp;
                }
                configs.push(server);
                configs.push(
                    json!({"address":format!("0.0.0.0:{socks}"), "protocol":{"type":"socks"},
                    "rules":[{"masks":"0.0.0.0/0", "client_chain":client}]}),
                );
                cases.push((version, client_group, server_group, socks));
            }
        }
    }
    let _server = start_shoes_server(&serde_yaml::to_string(&configs)?)?;
    for (version, client_group, server_group, socks) in cases {
        let address = ([127, 0, 0, 1], socks).into();
        xray::wait_socks(address).await?;
        let connected =
            tokio::time::timeout(Duration::from_secs(10), xray::connect(address, target)).await?;
        assert_eq!(
            connected.is_ok(),
            client_group == server_group,
            "{version}: {client_group} client / {server_group} server: {connected:?}"
        );
        if let Ok(mut stream) = connected {
            tokio::time::timeout(Duration::from_secs(10), async {
                stream.write_all(b"allowlisted").await?;
                let mut response = [0; 11];
                stream.read_exact(&mut response).await?;
                assert_eq!(&response, b"allowlisted");
                Ok::<_, std::io::Error>(())
            })
            .await??;
        }
    }
    Ok(())
}

#[tokio::test]
async fn shoes_client_xray_reality_server() -> Result<(), Box<dyn std::error::Error>> {
    matrix(true, "vless", &["reality"]).await
}
