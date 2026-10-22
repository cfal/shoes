use std::{io, net::SocketAddr, path::PathBuf};

use serde_json::{Value, json};
use shoes_test_support::{
    process::{ProcessGuard, start_mihomo_server_with_env},
    test_fixture::{generate_reality_keypair, start_shoes_server},
    xray,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";
pub const POST_BYTES: usize = 32 * 1024;
pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    Shoes,
    Xray,
    Mihomo,
}

pub struct Case<'a> {
    pub peer: Peer,
    pub shoes_client: bool,
    pub protocol: &'a str,
    pub version: &'a str,
    pub mode: &'a str,
}

impl Case<'_> {
    fn alpn(&self) -> &str {
        match self.version {
            "h1" | "plain" => "http/1.1",
            "h3" => "h3",
            _ => "h2",
        }
    }

    fn path(&self) -> &str {
        // Mihomo treats query syntax as literal path text, unlike Xray and Shoes.
        match self.peer {
            Peer::Mihomo => "/tunnel",
            Peer::Shoes | Peer::Xray => "/tunnel%2Freserved?test=a%2Bb",
        }
    }
}

pub fn port() -> u16 {
    static USED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<u16>>> =
        std::sync::LazyLock::new(Default::default);
    loop {
        let tcp = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let Ok(_udp) = std::net::UdpSocket::bind(("0.0.0.0", port)) else {
            continue;
        };
        if USED.lock().unwrap().insert(port) {
            return port;
        }
    }
}

pub struct Fixture {
    pub post_bytes: usize,
    pub post_interval_ms: u64,
    pub latency_ms: u64,
    pub server_request_limit: Option<usize>,
    pub server_packet_timeout_secs: Option<u64>,
    pub h2_window_bytes: Option<usize>,
    pub matching_headers: Option<Value>,
    pub pressure: bool,
    cert: PathBuf,
    key: PathBuf,
    pin: String,
    private_key: String,
    public_key: String,
    destination: u16,
    destination_ready: u16,
    _destination: (ProcessGuard, tempfile::NamedTempFile),
    _files: tempfile::TempDir,
}

pub struct Pair {
    pub socks: SocketAddr,
    _shoes: Option<(ProcessGuard, tempfile::NamedTempFile)>,
    _xray: Option<xray::Peer>,
    _mihomo: Option<(ProcessGuard, tempfile::NamedTempFile)>,
    _reference: Option<xray::Peer>,
    _relay: Option<LatencyRelay>,
}

impl Pair {
    pub fn pids(&self) -> Vec<u32> {
        self._shoes
            .iter()
            .map(|process| process.0.id())
            .chain(self._xray.iter().map(xray::Peer::id))
            .chain(self._reference.iter().map(xray::Peer::id))
            .chain(self._mihomo.iter().map(|process| process.0.id()))
            .collect()
    }
}

struct LatencyRelay(tokio::task::JoinHandle<()>);

impl Drop for LatencyRelay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl LatencyRelay {
    async fn start(remote: u16, latency_ms: u64) -> io::Result<(u16, Option<Self>)> {
        if latency_ms == 0 {
            return Ok((remote, None));
        }
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();
        let delay = std::time::Duration::from_micros(latency_ms * 500);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let Ok((incoming, _)) = accepted else { break };
                connections.spawn(async move {
                    let outgoing =
                        tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, remote))
                            .await?;
                    let (read_client, write_client) = incoming.into_split();
                    let (read_server, write_server) = outgoing.into_split();
                    tokio::try_join!(
                        delayed_copy(read_client, write_server, delay),
                        delayed_copy(read_server, write_client, delay),
                    )?;
                    Ok::<_, io::Error>(())
                });
            }
        });
        Ok((port, Some(Self(task))))
    }
}

async fn delayed_copy(
    mut read: tokio::net::tcp::OwnedReadHalf,
    mut write: tokio::net::tcp::OwnedWriteHalf,
    delay: std::time::Duration,
) -> io::Result<()> {
    let (send, mut receive) = tokio::sync::mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(512);
    tokio::try_join!(
        async {
            loop {
                let mut data = vec![0; 16384];
                let size = read.read(&mut data).await?;
                if size == 0 {
                    break;
                }
                data.truncate(size);
                send.send((tokio::time::Instant::now() + delay, data))
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
            }
            drop(send);
            Ok::<_, io::Error>(())
        },
        async {
            while let Some((ready, data)) = receive.recv().await {
                tokio::time::sleep_until(ready).await;
                write.write_all(&data).await?;
            }
            write.shutdown().await
        }
    )?;
    Ok(())
}

impl Fixture {
    pub fn new(peer: Peer) -> Result<Self> {
        // REALITY's combined-flight mimicry needs an encrypted flight over 512 bytes.
        let names: Vec<String> = std::iter::once("localhost".into())
            .chain((0..40).map(|i| format!("fixture-{i}.local.test")))
            .collect();
        let certificate = rcgen::generate_simple_self_signed(names)?;
        let pin = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.cert.der())
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
        let destination_ready = port();
        let groups = if peer == Peer::Mihomo {
            vec!["X25519MLKEM768", "X25519"]
        } else {
            vec!["X25519MLKEM768"]
        };
        let server = start_shoes_server(&serde_yaml::to_string(&json!([
            {"address":format!("0.0.0.0:{destination}"),"protocol":{"type":"tls","default_target":{
                "cert":cert,"key":key,"key_exchange_groups":groups,
                "alpn_protocols":["h2","http/1.1"],"protocol":{"type":"http"}
            }}},
            {"address":format!("0.0.0.0:{destination_ready}"),"protocol":{"type":"socks"}}
        ]))?)?;
        Ok(Self {
            post_bytes: POST_BYTES,
            post_interval_ms: 1,
            latency_ms: 0,
            server_request_limit: None,
            server_packet_timeout_secs: None,
            h2_window_bytes: None,
            matching_headers: None,
            pressure: false,
            cert,
            key,
            pin,
            private_key,
            public_key,
            destination,
            destination_ready,
            _destination: server,
            _files: files,
        })
    }

    pub fn shoes_endpoint(
        &self,
        client: bool,
        remote: u16,
        version: &str,
        mut xhttp: Value,
    ) -> Value {
        if self.pressure {
            xhttp["limits"] = json!({
                "max_buffered_bytes":1024 * 1024,
                "max_session_buffered_bytes":256 * 1024,
            });
        }
        if !client && let Some(limit) = self.server_request_limit {
            xhttp["limits"]["max_requests_per_session"] = json!(limit);
        }
        if !client && let Some(timeout) = self.server_packet_timeout_secs {
            xhttp["limits"]["packet_timeout_secs"] = json!(timeout);
        }
        if !client && let Some(headers) = &self.matching_headers {
            xhttp["matching_headers"] = headers.clone();
        }
        if let Some(window) = self.h2_window_bytes {
            xhttp["limits"]["h2_stream_window_bytes"] = json!(window);
            xhttp["limits"]["h2_connection_window_bytes"] = json!(window);
        }
        let host = if client { "127.0.0.1" } else { "0.0.0.0" };
        let mut endpoint = json!({"address":format!("{host}:{remote}"),"protocol":xhttp});
        if version == "reality" {
            endpoint["protocol"] = if client {
                json!({"type":"reality","public_key":self.public_key,"short_id":"0123456789abcdef",
                    "sni_hostname":"localhost","protocol":xhttp})
            } else {
                json!({"type":"tls","reality_targets":{"localhost":{
                    "private_key":self.private_key,"short_ids":["0123456789abcdef"],
                    "dest":format!("localhost:{}",self.destination),"protocol":xhttp
                }}})
            };
        } else if version == "h3" {
            endpoint["transport"] = json!("quic");
            endpoint["quic_settings"] = if client {
                json!({"verify":false,"sni_hostname":"localhost"})
            } else {
                json!({"cert":self.cert,"key":self.key})
            };
        } else if !matches!(version, "plain" | "h2c") {
            endpoint["protocol"] = if client {
                json!({"type":"tls","verify":false,"sni_hostname":"localhost","protocol":xhttp})
            } else {
                json!({"type":"tls","default_target":{"cert":self.cert,"key":self.key,"protocol":xhttp}})
            };
        }
        endpoint
    }

    pub async fn start(
        &self,
        peer: Peer,
        shoes_client: bool,
        protocol: &str,
        version: &str,
        mode: &str,
    ) -> Result<Pair> {
        self.start_with_client_patch(
            Case {
                peer,
                shoes_client,
                protocol,
                version,
                mode,
            },
            |_| {},
        )
        .await
    }

    fn shoes_config(&self, case: &Case<'_>, remote: u16, socks_port: u16, readiness: u16) -> Value {
        let Case {
            peer,
            shoes_client,
            protocol,
            version,
            mode,
        } = *case;
        let path = case.path();
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
        let xhttp = json!({"type":"xhttp","path":path,"host":"front.test:8443",
            "http_version":xhttp_version,"mode":mode,"sc_max_each_post_bytes":self.post_bytes,
            "protocol":inner});
        let mut shoes_endpoint = self.shoes_endpoint(shoes_client, remote, version, xhttp.clone());
        // Pacing is a client-only setting.
        if shoes_client {
            shoes_xhttp(&mut shoes_endpoint)["sc_min_posts_interval_ms"] =
                json!(self.post_interval_ms);
        }
        let mut shoes_config = if shoes_client {
            json!([{"address":format!("0.0.0.0:{socks_port}"),"protocol":{"type":"socks","udp_enabled":true},
                "rules":[{"masks":"0.0.0.0/0","client_chain":shoes_endpoint}]}])
        } else {
            json!([shoes_endpoint,{"address":format!("0.0.0.0:{readiness}"),"protocol":{"type":"socks"}}])
        };
        if peer == Peer::Shoes {
            assert!(shoes_client);
            shoes_config
                .as_array_mut()
                .unwrap()
                .insert(0, self.shoes_endpoint(false, remote, version, xhttp));
        }
        shoes_config
    }

    fn xray_config(&self, case: &Case<'_>, remote: u16, socks_port: u16) -> Value {
        let Case {
            shoes_client,
            protocol,
            version,
            mode,
            ..
        } = *case;
        let path = case.path();
        let alpn = case.alpn();
        let mut stream = json!({
            "network":"xhttp",
            "xhttpSettings":{
                "path":path,
                "host":if shoes_client {"front.test"} else {"front.test:8443"},
                "mode":mode,
                "extra":{"scMaxEachPostBytes":self.post_bytes,"scMinPostsIntervalMs":self.post_interval_ms}
            },
            "security":"tls",
            "tlsSettings":{
                "serverName":"localhost",
                "alpn":[alpn],
                "certificates":[{"certificateFile":self.cert,"keyFile":self.key}]
            }
        });
        if !shoes_client {
            stream["tlsSettings"]["pinnedPeerCertSha256"] = json!(self.pin);
        }
        if matches!(version, "plain" | "h2c" | "reality") {
            stream.as_object_mut().unwrap().remove("tlsSettings");
            stream["security"] = json!(if version == "reality" {
                "reality"
            } else {
                "none"
            });
        }
        if version == "reality" {
            stream["realitySettings"] = if shoes_client {
                json!({"target":format!("127.0.0.1:{}",self.destination),"serverNames":["localhost"],
                    "privateKey":self.private_key,"shortIds":["0123456789abcdef"]})
            } else {
                json!({"serverName":"localhost","password":self.public_key,
                    "shortId":"0123456789abcdef","fingerprint":"chrome"})
            };
        }
        if shoes_client {
            let settings = if protocol == "vless" {
                json!({"clients":[{"id":UUID}],"decryption":"none"})
            } else {
                json!({"clients":[{"password":"xhttp-test-password"}]})
            };
            json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":remote,
                "protocol":protocol,"settings":settings,"streamSettings":stream}],
                "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1"]}]}}]})
        } else {
            let settings = if protocol == "vless" {
                json!({"vnext":[{"address":"127.0.0.1","port":remote,"users":[{"id":UUID,"encryption":"none"}]}]})
            } else {
                json!({"servers":[{"address":"127.0.0.1","port":remote,"password":"xhttp-test-password"}]})
            };
            json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"0.0.0.0","port":socks_port,
                "protocol":"socks","settings":{"auth":"noauth","udp":true}}],
                "outbounds":[{"protocol":protocol,"settings":settings,"streamSettings":stream}]})
        }
    }

    fn mihomo_config(&self, case: &Case<'_>, remote: u16, socks_port: u16) -> Result<Value> {
        let Case {
            shoes_client,
            version,
            mode,
            ..
        } = *case;
        let path = case.path();
        let alpn = case.alpn();
        let binary = shoes_test_support::process::find_mihomo_binary()?;
        let version_output = std::process::Command::new(binary).arg("-v").output()?;
        if !String::from_utf8_lossy(&version_output.stdout).contains("alpha-94b13aed") {
            return Err(
                "XHTTP tests require Mihomo Alpha 94b13aed; set SHOES_TEST_MIHOMO_BIN".into(),
            );
        }
        let mut config = json!({"mode":"rule","log-level":"warning","ipv6":false,
            "allow-lan":true,"bind-address":"0.0.0.0"});
        if shoes_client {
            let mut listener = json!({"name":"xhttp","type":"vless","listen":"0.0.0.0","port":remote,
                "users":[{"username":"test","uuid":UUID}],
                "xhttp-config":{"path":path,"host":"front.test:8443","mode":mode,
                    "sc-max-each-post-bytes":self.post_bytes.to_string()}});
            if version == "reality" {
                listener["reality-config"] = json!({"dest":format!("localhost:{}",self.destination),
                    "private-key":self.private_key,"short-id":["0123456789abcdef"],"server-names":["localhost"]});
            } else if !matches!(version, "plain" | "h2c") {
                listener["certificate"] = json!(std::fs::read_to_string(&self.cert)?);
                listener["private-key"] = json!(std::fs::read_to_string(&self.key)?);
            } else {
                listener["allow-insecure"] = json!(true);
            }
            config["listeners"] = json!([listener]);
            config["rules"] = json!(["MATCH,DIRECT"]);
        } else {
            let mut proxy = json!({"name":"xhttp","type":"vless","server":"127.0.0.1","port":remote,
                "uuid":UUID,"udp":true,"tls":!matches!(version,"plain"|"h2c"),
                "servername":"localhost","skip-cert-verify":true,"network":"xhttp","alpn":[alpn],
                "xhttp-opts":{"path":path,"host":"front.test:8443","mode":mode,
                    "sc-max-each-post-bytes":self.post_bytes.to_string(),"sc-min-posts-interval-ms":self.post_interval_ms.to_string()}});
            if version == "reality" {
                proxy["client-fingerprint"] = json!("chrome");
                proxy["reality-opts"] =
                    json!({"public-key":self.public_key,"short-id":"0123456789abcdef"});
            }
            config["mixed-port"] = json!(socks_port);
            config["proxies"] = json!([proxy]);
            config["rules"] = json!(["MATCH,xhttp"]);
        }
        Ok(config)
    }

    pub async fn start_with_client_patch(
        &self,
        case: Case<'_>,
        patch: impl FnOnce(&mut Value),
    ) -> Result<Pair> {
        let Case {
            peer,
            shoes_client,
            protocol,
            version,
            mode,
        } = case;
        xray::wait_socks(([127, 0, 0, 1], self.destination_ready).into()).await?;
        assert!(peer != Peer::Mihomo || protocol == "vless");
        assert!(peer != Peer::Mihomo || !shoes_client || version != "h3");
        let remote = port();
        assert!(
            version != "h3" || self.latency_ms == 0,
            "latency relay is TCP-only"
        );
        assert!(
            peer != Peer::Shoes || self.latency_ms == 0,
            "latency qualification requires a separate peer process"
        );
        let (client_remote, relay) = LatencyRelay::start(remote, self.latency_ms).await?;
        let socks_port = port();
        let readiness = port();
        let socks = ([127, 0, 0, 1], socks_port).into();
        let mut shoes_config = self.shoes_config(
            &case,
            if shoes_client { client_remote } else { remote },
            socks_port,
            readiness,
        );
        let mut peer_config = match peer {
            Peer::Shoes => Value::Null,
            Peer::Xray => self.xray_config(
                &case,
                if shoes_client { remote } else { client_remote },
                socks_port,
            ),
            Peer::Mihomo => self.mihomo_config(
                &case,
                if shoes_client { remote } else { client_remote },
                socks_port,
            )?,
        };
        if shoes_client {
            let index = usize::from(peer == Peer::Shoes);
            patch(&mut shoes_config[index]["rules"][0]["client_chain"]);
        } else {
            patch(&mut peer_config);
        }
        if version == "h3" && mode == "stream-one" {
            shoes_config
                .as_array_mut()
                .unwrap()
                .insert(0, json!({"global_limits":{"max_streams_per_connection":1}}));
        }
        let shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config)?)?;
        xray::wait_socks(
            (
                [127, 0, 0, 1],
                if shoes_client { socks_port } else { readiness },
            )
                .into(),
        )
        .await?;
        let mut pair = Pair {
            socks,
            _shoes: Some(shoes),
            _xray: None,
            _mihomo: None,
            _reference: None,
            _relay: relay,
        };
        match peer {
            Peer::Shoes => {}
            Peer::Xray => pair._xray = Some(xray::start(peer_config).await?),
            Peer::Mihomo => {
                // Independent loopback connections can share source IP/port across
                // different destinations, which Mihomo mistakes for a routing loop.
                pair._mihomo = Some(
                    start_mihomo_server_with_env(
                        &serde_yaml::to_string(&peer_config)?,
                        &[("DISABLE_LOOPBACK_DETECTOR", "true")],
                    )
                    .await?,
                )
            }
        }
        xray::wait_socks(socks)
            .await
            .map_err(|error| io::Error::other(format!("{peer:?} {version} {mode}: {error}")))?;
        Ok(pair)
    }

    pub async fn start_xray_reference(&self) -> Result<Pair> {
        let remote = port();
        let socks_port = port();
        let (client_remote, relay) = LatencyRelay::start(remote, self.latency_ms).await?;
        let mut case = Case {
            peer: Peer::Xray,
            shoes_client: true,
            protocol: "vless",
            version: "h2",
            mode: "packet-up",
        };
        let server = xray::start(self.xray_config(&case, remote, socks_port)).await?;
        case.shoes_client = false;
        let client = xray::start(self.xray_config(&case, client_remote, socks_port)).await?;
        let socks = ([127, 0, 0, 1], socks_port).into();
        xray::wait_socks(socks).await?;
        Ok(Pair {
            socks,
            _shoes: None,
            _xray: Some(client),
            _mihomo: None,
            _reference: Some(server),
            _relay: relay,
        })
    }
}

pub fn shoes_xhttp(endpoint: &mut Value) -> &mut Value {
    let protocol = &mut endpoint["protocol"];
    if protocol["type"] == "xhttp" {
        protocol
    } else {
        &mut protocol["protocol"]
    }
}
