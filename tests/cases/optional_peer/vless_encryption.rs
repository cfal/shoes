use std::{
    io,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde_json::{Value, json};
use shoes_test_support::process::ProcessGuard;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const USER: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
const LIMIT: Duration = Duration::from_secs(10);

#[path = "vless_encryption/benchmarks.rs"]
mod benchmarks;
#[path = "vless_encryption/chained.rs"]
mod chained;
#[path = "vless_encryption/composition.rs"]
mod composition;
#[path = "vless_encryption/legacy.rs"]
mod legacy;
#[path = "vless_encryption/lifecycle.rs"]
mod lifecycle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Shoes,
    Xray,
    Mihomo,
    SingBox,
}

impl Kind {
    fn binary(self) -> PathBuf {
        match self {
            Self::Shoes => std::env::var_os("SHOES_TEST_SHOES_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_shoes").into()),
            Self::Xray => std::env::var_os("XRAY_BINARY")
                .expect("XRAY_BINARY must name the pinned Xray binary; no silent skips")
                .into(),
            Self::Mihomo => std::env::var_os("MIHOMO_BINARY")
                .expect("MIHOMO_BINARY must name the pinned Mihomo binary; no silent skips")
                .into(),
            Self::SingBox => {
                std::env::var_os("SHOES_TEST_SING_BOX_BIN").expect(
                    "SHOES_TEST_SING_BOX_BIN must name the pinned sing-box binary; no silent skips",
                );
                shoes_test_support::process::find_singbox_binary().unwrap()
            }
        }
    }
}

struct Task(JoinHandle<()>);
impl Task {
    async fn stop(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Peer {
    process: ProcessGuard,
    directory: tempfile::TempDir,
}
impl Peer {
    fn logs(&self) -> String {
        std::fs::read_to_string(self.directory.path().join("peer.log")).unwrap_or_default()
    }

    fn assert_handshakes(&self, expected: &[&str]) {
        let logs = self.logs();
        let actual: Vec<_> = logs
            .lines()
            .filter_map(|line| {
                let (_, handshake) = line
                    .split_once("VLESS encryption client: ")
                    .or_else(|| line.split_once("VLESS encryption server: "))?;
                handshake.strip_suffix(" handshake")
            })
            .collect();
        assert_eq!(actual, expected, "{logs}");
    }
}

fn pair_logs(client: &Peer, server: &Peer) -> String {
    format!("client: {}\nserver: {}", client.logs(), server.logs())
}

fn peer_roles(peer: Kind, peer_is_client: bool) -> (Kind, Kind) {
    if peer_is_client {
        (Kind::Shoes, peer)
    } else {
        (peer, Kind::Shoes)
    }
}

async fn start(kind: Kind, port: u16, config: Value) -> Peer {
    start_binary(kind, port, config, kind.binary()).await
}

async fn start_binary(kind: Kind, port: u16, config: Value, binary: PathBuf) -> Peer {
    start_options(kind, port, config, binary, None).await
}

async fn start_options(
    kind: Kind,
    port: u16,
    mut config: Value,
    binary: PathBuf,
    go_debug: Option<&str>,
) -> Peer {
    // Mihomo opens listeners before its tunnel becomes Running. A separate
    // direct route probes readiness without warming any native ticket cache.
    let mut readiness = if kind == Kind::Mihomo {
        let (target, _, task) = echo().await;
        let socks = match config["socks-port"].as_u64() {
            Some(port) => port as u16,
            None => free_port().await,
        };
        config["socks-port"] = json!(socks);
        config["allow-lan"] = json!(true);
        config["bind-address"] = json!("0.0.0.0");
        config["rules"]
            .as_array_mut()
            .unwrap()
            .insert(0, json!(format!("DST-PORT,{target},DIRECT")));
        Some((socks, target, task))
    } else {
        None
    };
    let directory = tempfile::Builder::new()
        .prefix("vless-peer-")
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = std::fs::File::create(directory.path().join("peer.log")).unwrap();
    let mut command = Command::new(binary);
    match kind {
        Kind::Shoes => {
            command.args(["--threads", "1", "--no-reload"]);
            command.arg(&path);
        }
        Kind::Xray | Kind::SingBox => {
            command.args(["run", "-c"]).arg(&path);
        }
        Kind::Mihomo => {
            command.arg("-d").arg(directory.path()).arg("-f").arg(&path);
        }
    }
    if let Some(value) = go_debug {
        command.env("GODEBUG", value);
    }
    let child = command
        .env("GOMAXPROCS", "1")
        .env("RUST_LOG", "shoes=debug")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut peer = Peer {
        process: ProcessGuard::new(child, format!("vless-{kind:?}")),
        directory,
    };
    timeout(LIMIT, async {
        loop {
            assert!(
                peer.process.try_wait().unwrap().is_none(),
                "peer exited: {}",
                peer.logs()
            );
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                match &readiness {
                    Some((socks, target, _)) => {
                        if matches!(
                            timeout(
                                Duration::from_millis(200),
                                exchange(*socks, *target, b"ready")
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    None => break,
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("peer startup timed out: {}", peer.logs()));
    if let Some((_, _, task)) = &mut readiness {
        task.stop().await;
    }
    peer
}

async fn free_port() -> u16 {
    static ALLOCATED: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    for _ in 0..100 {
        let tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        // SOCKS and QUIC peers also bind UDP on this port.
        match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(_udp) => {
                let mut allocated = ALLOCATED.lock().unwrap();
                if allocated.contains(&port) {
                    continue;
                }
                allocated.push(port);
                return port;
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("reserve UDP port: {error}"),
        }
    }
    panic!("could not find a free TCP/UDP port");
}

#[tokio::test]
async fn allocated_peer_ports_are_not_reused_before_listeners_start() {
    let mut ports = std::collections::HashSet::new();
    for _ in 0..512 {
        assert!(ports.insert(free_port().await));
    }
}

fn credentials(mode: &str, auth: &[&str]) -> (String, String, usize) {
    let mut command = Command::new(Kind::Shoes.binary());
    command.args(["generate-vless-encryption", "--mode", mode]);
    for key in auth {
        command.args(["--auth", key]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
    let unpadded = |name: &str| {
        let mut fields: Vec<_> = settings[name].as_str().unwrap().split('.').collect();
        fields.insert(3, "100-35-35");
        fields.join(".")
    };
    let relay_len = auth
        .iter()
        .map(|key| if *key == "x25519" { 32 } else { 1088 })
        .sum::<usize>()
        + 32 * (auth.len() - 1);
    (
        unpadded("encryption"),
        unpadded("decryption"),
        16 + relay_len + 18 + 1232,
    )
}

fn server_config(kind: Kind, port: u16, decryption: &str, vision: bool) -> Value {
    let flow = if vision { "xtls-rprx-vision" } else { "" };
    match kind {
        Kind::Shoes => json!([{"address": format!("0.0.0.0:{port}"), "protocol": {
            "type": "vless", "user_id": USER, "decryption": decryption, "vision": vision,
        }}]),
        Kind::Xray => json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{"listen": "0.0.0.0", "port": port, "protocol": "vless", "settings": {
                "decryption": decryption, "clients": [{"id": USER, "flow": flow}],
            }}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"ip": ["0.0.0.0/0", "::/0"], "action": "allow"}]}}],
        }),
        Kind::Mihomo => json!({
            "log-level": "debug", "mode": "rule", "rules": ["MATCH,DIRECT"],
            "listeners": [{"name": "encrypted", "type": "vless", "listen": "0.0.0.0", "port": port,
                "decryption": decryption, "users": [{"username": "test", "uuid": USER, "flow": flow}]}],
        }),
        Kind::SingBox => {
            assert_eq!(decryption, "none");
            json!({"log":{"level":"debug"},"inbounds":[{"type":"vless","listen":"0.0.0.0","listen_port":port,
                "users":[{"uuid":USER,"flow":flow}]}],"outbounds":[{"type":"direct"}]})
        }
    }
}

fn client_config(kind: Kind, port: u16, server_port: u16, encryption: &str, vision: bool) -> Value {
    let flow = if vision { "xtls-rprx-vision" } else { "" };
    match kind {
        Kind::Shoes => json!([{"address": format!("0.0.0.0:{port}"), "protocol": {"type": "socks"},
            "rules": [{"masks": "0.0.0.0/0", "action": "allow", "client_chain": {
                "address": format!("127.0.0.1:{server_port}"),
                "protocol": {"type": "vless", "user_id": USER, "encryption": encryption, "vision": vision},
            }}],
        }]),
        Kind::Xray => json!({
            "log": {"loglevel": "debug"},
            "inbounds": [{"listen": "0.0.0.0", "port": port, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port,
                "users": [{"id": USER, "encryption": encryption, "flow": flow}]}]}}],
        }),
        Kind::Mihomo => json!({
            "socks-port": port, "allow-lan": true, "bind-address": "0.0.0.0", "log-level": "debug",
            "proxies": [{"name": "encrypted", "type": "vless", "server": "127.0.0.1", "port": server_port,
                "uuid": USER, "encryption": encryption, "flow": flow, "udp": true, "packet-encoding": "packetaddr"}],
            "mode": "rule", "rules": ["MATCH,encrypted"],
        }),
        Kind::SingBox => {
            assert_eq!(encryption, "none");
            json!({"log":{"level":"debug"},"inbounds":[{"type":"socks","listen":"0.0.0.0","listen_port":port}],
                "outbounds":[{"type":"vless","server":"127.0.0.1","server_port":server_port,"uuid":USER,"flow":flow}]})
        }
    }
}

type Captures = Arc<Mutex<Vec<Vec<u8>>>>;

async fn tap(upstream: u16) -> (u16, Captures, Task) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captures: Captures = Arc::default();
    let output = captures.clone();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((client, _)) = result else { break };
                    let captures = captures.clone();
                    children.spawn(async move {
                        let index = {
                            let mut guard = captures.lock().unwrap();
                            let index = guard.len();
                            guard.push(Vec::new());
                            index
                        };
                        let server = TcpStream::connect(("127.0.0.1", upstream)).await?;
                        let (mut cr, mut cw) = client.into_split();
                        let (mut sr, mut sw) = server.into_split();
                        tokio::try_join!(async {
                            let mut bytes = [0; 8192];
                            loop {
                                let n = cr.read(&mut bytes).await?;
                                if n == 0 { break; }
                                {
                                    let mut captures = captures.lock().unwrap();
                                    let n = n.min(262144usize.saturating_sub(captures[index].len()));
                                    captures[index].extend_from_slice(&bytes[..n]);
                                }
                                sw.write_all(&bytes[..n]).await?;
                            }
                            sw.shutdown().await
                        }, async { tokio::io::copy(&mut sr, &mut cw).await?; cw.shutdown().await })?;
                        Ok::<_, io::Error>(())
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (port, output, Task(task))
}

async fn echo() -> (u16, Arc<AtomicUsize>, Task) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((mut io, _)) = result else { break };
                    count.fetch_add(1, Ordering::SeqCst);
                    children.spawn(async move {
                        let (mut r, mut w) = io.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (port, connections, Task(task))
}

async fn socks_connect(port: u16, target: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS authentication rejected"));
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!(
            "SOCKS connect rejected: {header:?}"
        )));
    }
    let len = match header[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err(io::Error::other("invalid SOCKS address")),
    };
    stream.read_exact(&mut vec![0; len + 2]).await?;
    Ok(stream)
}

async fn exchange(port: u16, target: u16, data: &[u8]) -> io::Result<()> {
    timeout(LIMIT, async {
        let mut stream = socks_connect(port, target).await?;
        let (mut r, mut w) = stream.split();
        let (_, bytes) = tokio::try_join!(
            async {
                w.write_all(data).await?;
                w.flush().await
            },
            async {
                let mut bytes = vec![0; data.len()];
                r.read_exact(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            }
        )?;
        if bytes != data {
            return Err(io::Error::other("payload mismatch"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "encrypted roundtrip timed out"))?
}

async fn run_case(peer: Kind, peer_client: bool, mode: &str, auth: &[&str], vision: bool) {
    eprintln!(
        "case: {peer:?}, peer_client={peer_client}, mode={mode}, auth={auth:?}, vision={vision}"
    );
    let (encryption, decryption, fresh_min) = credentials(mode, auth);
    let (server_kind, client_kind) = peer_roles(peer, peer_client);
    let (target, connections, mut target_task) = echo().await;
    let server_port = free_port().await;
    let server = start(
        server_kind,
        server_port,
        server_config(server_kind, server_port, &decryption, vision),
    )
    .await;
    let (tap_port, captures, mut tap_task) = tap(server_port).await;
    let client_port = free_port().await;
    let client = start(
        client_kind,
        client_port,
        client_config(client_kind, client_port, tap_port, &encryption, vision),
    )
    .await;
    for resumed in [false, true] {
        exchange(client_port, target, b"native VLESS encryption interop")
            .await
            .unwrap_or_else(|error| panic!("{error}\n{}", pair_logs(&client, &server)));
        let lengths: Vec<_> = captures.lock().unwrap().iter().map(Vec::len).collect();
        assert_eq!(lengths.len(), if resumed { 2 } else { 1 });
        assert_eq!(
            *lengths.last().unwrap() < fresh_min,
            resumed,
            "abbreviated wire proof: {lengths:?}, fresh minimum {fresh_min}"
        );
    }
    if server_kind == Kind::Shoes {
        let replay = captures.lock().unwrap()[1].clone();
        let mut attacker = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        attacker.write_all(&replay).await.unwrap();
        let mut byte = [0];
        let outcome = timeout(LIMIT, attacker.read(&mut byte))
            .await
            .expect("replay did not close");
        assert!(
            matches!(outcome, Ok(0) | Err(_)),
            "duplicate replay must close without a response"
        );
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "replay reached destination"
        );
    }
    let data: Vec<_> = (0..131072).map(|n| (n % 251) as u8).collect();
    exchange(client_port, target, &data)
        .await
        .unwrap_or_else(|error| panic!("{error}\n{}", pair_logs(&client, &server)));
    assert_eq!(connections.load(Ordering::SeqCst), 3);
    drop((client, server));
    tap_task.stop().await;
    target_task.stop().await;
}

#[tokio::test]
async fn default_and_gapped_padding_preserve_payloads() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for peer_client in [false, true] {
            for gap in [false, true] {
                let (encryption, decryption, _) = credentials("random", &["mlkem768"]);
                let encryption = encryption.replace(".100-35-35", "");
                let decryption = decryption.replace(
                    ".100-35-35",
                    if gap {
                        ".100-35-35.100-50-50.100-64-64.100-10-10"
                    } else {
                        ""
                    },
                );
                let (server_kind, client_kind) = peer_roles(peer, peer_client);
                let (target, connections, mut target_task) = echo().await;
                let server_port = free_port().await;
                let server = start(
                    server_kind,
                    server_port,
                    server_config(server_kind, server_port, &decryption, true),
                )
                .await;
                let client_port = free_port().await;
                let client = start(
                    client_kind,
                    client_port,
                    client_config(client_kind, client_port, server_port, &encryption, true),
                )
                .await;
                let payload: Vec<_> = (0..131072).map(|n| (n % 251) as u8).collect();
                for _ in 0..3 {
                    exchange(client_port, target, &payload)
                        .await
                        .unwrap_or_else(|error| {
                            panic!(
                                "{peer:?} client={peer_client} gap={gap}: {error}\n{}",
                                pair_logs(&client, &server)
                            )
                        });
                }
                assert_eq!(connections.load(Ordering::SeqCst), 3);
                drop((client, server));
                target_task.stop().await;
            }
        }
    }
}

#[tokio::test]
async fn xray_fresh_resumed_matrix() {
    for client in [false, true] {
        for mode in ["native", "xorpub", "random"] {
            for auth in ["x25519", "mlkem768"] {
                for vision in [false, true] {
                    run_case(Kind::Xray, client, mode, &[auth], vision).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn mihomo_fresh_resumed_matrix() {
    for client in [false, true] {
        for mode in ["native", "xorpub", "random"] {
            for auth in ["x25519", "mlkem768"] {
                for vision in [false, true] {
                    run_case(Kind::Mihomo, client, mode, &[auth], vision).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn mixed_and_repeated_key_chains() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for auth in [
                &["x25519", "mlkem768"][..],
                &["mlkem768", "mlkem768"][..],
                &["x25519", "x25519"][..],
            ] {
                run_case(peer, client, "random", auth, true).await;
            }
        }
    }
}

async fn tls_echo(tls12: bool) -> (u16, tokio_rustls::TlsConnector, Task) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13][..]
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let Ok((stream, _)) = result else { break };
                    let acceptor = acceptor.clone();
                    children.spawn(async move {
                        let mut stream = acceptor.accept(stream).await?;
                        let (mut r, mut w) = tokio::io::split(&mut stream);
                        tokio::io::copy(&mut r, &mut w).await?;
                        w.shutdown().await?;
                        Ok::<_, io::Error>(())
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (
        port,
        tokio_rustls::TlsConnector::from(Arc::new(client)),
        Task(task),
    )
}

#[derive(Clone, Copy, Debug)]
enum Transport {
    Raw,
    Tls,
    Websocket,
    Wss,
    Xhttp,
    XhttpMode {
        version: &'static str,
        mode: &'static str,
    },
    Quic,
    Reality,
}

fn shoes_protocol_mut(config: &mut Value, server: bool) -> &mut Value {
    if server {
        &mut config[0]["protocol"]
    } else {
        &mut config[0]["rules"][0]["client_chain"]["protocol"]
    }
}

fn xray_endpoint_mut(config: &mut Value, server: bool) -> &mut Value {
    if server {
        &mut config["inbounds"][0]
    } else {
        &mut config["outbounds"][0]
    }
}

fn reality_keys() -> (String, String) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let private = [42; 32];
    let public =
        aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, &private)
            .unwrap()
            .compute_public_key()
            .unwrap();
    (
        URL_SAFE_NO_PAD.encode(private),
        URL_SAFE_NO_PAD.encode(public.as_ref()),
    )
}

fn wrap(
    kind: Kind,
    mut config: Value,
    server: bool,
    transport: Transport,
    cert: &str,
    key: &str,
    cover_port: u16,
) -> Value {
    match (kind, transport) {
        (Kind::SingBox, _) => {
            return legacy::wrap_singbox(config, server, transport, cert, key, cover_port);
        }
        (_, Transport::Wss) => {
            config = wrap(
                kind,
                config,
                server,
                Transport::Websocket,
                cert,
                key,
                cover_port,
            );
            // TLS wraps the WebSocket stream, not the inner VLESS stream.
            let ws = if kind == Kind::Xray {
                Some(xray_endpoint_mut(&mut config, server)["streamSettings"].clone())
            } else {
                None
            };
            config = wrap(kind, config, server, Transport::Tls, cert, key, cover_port);
            if let Some(ws) = ws {
                let stream = &mut xray_endpoint_mut(&mut config, server)["streamSettings"];
                stream["network"] = ws["network"].clone();
                stream["wsSettings"] = ws["wsSettings"].clone();
            }
        }
        (_, Transport::XhttpMode { version, mode }) => {
            return composition::wrap_xhttp(
                kind,
                config,
                server,
                (version, mode),
                cert,
                key,
                cover_port,
            );
        }
        (Kind::Shoes, Transport::Quic) => {
            let endpoint = if server {
                &mut config[0]
            } else {
                &mut config[0]["rules"][0]["client_chain"]
            };
            endpoint["transport"] = json!("quic");
            endpoint["quic_settings"] = if server {
                json!({"cert": cert, "key": key})
            } else {
                json!({"verify": false, "sni_hostname": "localhost"})
            };
            if server {
                let address = config[0]["address"].clone();
                config
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"address":address,"protocol":{"type":"socks"}}));
            }
        }
        (_, Transport::Quic) => unreachable!("raw QUIC is a Shoes transport"),
        (_, Transport::Raw) => {}
        (Kind::Shoes, Transport::Tls) => {
            let field = shoes_protocol_mut(&mut config, server);
            let inner = field.take();
            *field = if server {
                json!({"type": "tls", "default_target": {"cert": cert, "key": key, "protocol": inner}})
            } else {
                json!({"type": "tls", "verify": false, "sni_hostname": "localhost", "protocol": inner})
            };
        }
        (Kind::Shoes, Transport::Websocket) => {
            let field = shoes_protocol_mut(&mut config, server);
            let inner = field.take();
            *field = if server {
                json!({"type": "websocket", "targets": [{"matching_path": "/native", "protocol": inner}]})
            } else {
                json!({"type": "websocket", "matching_path": "/native", "matching_headers": {"Host": "localhost"}, "protocol": inner})
            };
        }
        (Kind::Xray, Transport::Tls) => {
            let certificate = rustls_pemfile::certs(&mut cert.as_bytes())
                .next()
                .unwrap()
                .unwrap();
            let pin: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &certificate)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let field = xray_endpoint_mut(&mut config, server);
            field["streamSettings"] = if server {
                json!({"network": "raw", "security": "tls", "tlsSettings": {"certificates": [{"certificate": cert.lines().collect::<Vec<_>>(), "key": key.lines().collect::<Vec<_>>() }]}})
            } else {
                json!({"network": "raw", "security": "tls", "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": pin}})
            };
        }
        (Kind::Xray, Transport::Websocket) => {
            let field = xray_endpoint_mut(&mut config, server);
            field["streamSettings"] = json!({"network": "ws", "wsSettings": {"path": "/native"}});
        }
        (Kind::Mihomo, Transport::Tls) => {
            if server {
                config["listeners"][0]["certificate"] = json!(cert);
                config["listeners"][0]["private-key"] = json!(key);
            } else {
                config["proxies"][0]["tls"] = json!(true);
                config["proxies"][0]["servername"] = json!("localhost");
                config["proxies"][0]["skip-cert-verify"] = json!(true);
            }
        }
        (Kind::Mihomo, Transport::Websocket) => {
            if server {
                config["listeners"][0]["ws-path"] = json!("/native");
            } else {
                config["proxies"][0]["network"] = json!("ws");
                config["proxies"][0]["ws-opts"] = json!({"path": "/native"});
            }
        }
        (Kind::Shoes, Transport::Xhttp) => {
            let field = shoes_protocol_mut(&mut config, server);
            let inner = field.take();
            *field = json!({"type": "xhttp", "path": "/native", "host": "localhost", "mode": "packet-up", "http_version": "h1", "protocol": inner});
        }
        (Kind::Xray, Transport::Xhttp) => {
            let field = xray_endpoint_mut(&mut config, server);
            field["streamSettings"] = json!({"network": "xhttp", "security": "none", "xhttpSettings": {"path": "/native", "host": "localhost", "mode": "packet-up"}});
        }
        (Kind::Shoes | Kind::Xray, Transport::Reality) => {
            let (private, public) = reality_keys();
            if kind == Kind::Shoes {
                let field = shoes_protocol_mut(&mut config, server);
                let inner = field.take();
                *field = if server {
                    json!({"type": "tls", "reality_targets": {"localhost": {"private_key": private, "short_ids": ["0123456789abcdef"], "dest": format!("localhost:{cover_port}"), "protocol": inner}}})
                } else {
                    json!({"type": "reality", "public_key": public, "short_id": "0123456789abcdef", "sni_hostname": "localhost", "protocol": inner})
                };
            } else {
                let field = xray_endpoint_mut(&mut config, server);
                let reality = if server {
                    json!({"target": format!("127.0.0.1:{cover_port}"), "serverNames": ["localhost"], "privateKey": private, "shortIds": ["0123456789abcdef"]})
                } else {
                    json!({"serverName": "localhost", "publicKey": public, "shortId": "0123456789abcdef", "fingerprint": "chrome"})
                };
                field["streamSettings"] =
                    json!({"network": "raw", "security": "reality", "realitySettings": reality});
            }
        }
        (Kind::Mihomo, Transport::Xhttp) => {
            return composition::wrap_xhttp(
                kind,
                config,
                server,
                ("plain", "packet-up"),
                cert,
                key,
                cover_port,
            );
        }
        (Kind::Mihomo, Transport::Reality) => {
            let (private, public) = reality_keys();
            if server {
                config["listeners"][0]["reality-config"] = json!({
                    "dest":format!("localhost:{cover_port}"), "server-names":["localhost"],
                    "private-key":private, "short-id":["0123456789abcdef"]
                });
            } else {
                let proxy = &mut config["proxies"][0];
                proxy["tls"] = json!(true);
                proxy["servername"] = json!("localhost");
                proxy["client-fingerprint"] = json!("chrome");
                proxy["reality-opts"] = json!({"public-key":public, "short-id":"0123456789abcdef"});
            }
        }
    }
    config
}

async fn direct_case(peer: Kind, peer_client: bool, transport: Transport, mode: &str, tls12: bool) {
    eprintln!(
        "inner TLS: {peer:?}, peer_client={peer_client}, {transport:?}, {mode}, tls12={tls12}"
    );
    let (encryption, decryption, _) = credentials(mode, &["mlkem768"]);
    let (server_kind, client_kind) = peer_roles(peer, peer_client);
    let (target, connector, mut target_task) = tls_echo(tls12).await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (cert, key) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let server_port = free_port().await;
    let server = start(
        server_kind,
        server_port,
        wrap(
            server_kind,
            server_config(server_kind, server_port, &decryption, true),
            true,
            transport,
            &cert,
            &key,
            target,
        ),
    )
    .await;
    let (tap_port, captures, mut tap_task) = tap(server_port).await;
    let client_port = free_port().await;
    let client = start(
        client_kind,
        client_port,
        wrap(
            client_kind,
            client_config(client_kind, client_port, tap_port, &encryption, true),
            false,
            transport,
            &cert,
            &key,
            target,
        ),
    )
    .await;
    let result = timeout(LIMIT, async {
        for _ in 0..2 {
            let socket = socks_connect(client_port, target).await?;
            let mut tls = connector
                .connect("localhost".try_into().unwrap(), socket)
                .await?;
            // Reference Vision only switches on a complete record in one read.
            // Small warm-up records avoid its 8 KiB read boundary before measuring DIRECT.
            for (round, size) in [64, 64, 8192].into_iter().enumerate() {
                let before = captures.lock().unwrap().last().unwrap().len();
                let data = vec![42 + round as u8; size];
                tls.write_all(&data).await?;
                tls.flush().await?;
                let mut response = vec![0; data.len()];
                tls.read_exact(&mut response).await?;
                assert_eq!(response, data);
                if !tls12 && round == 2 && matches!(transport, Transport::Raw) {
                    let after = captures.lock().unwrap().last().unwrap().len();
                    assert_eq!(
                        after - before,
                        data.len() + 22,
                        "DIRECT must remove native records, including in random mode\n{}",
                        pair_logs(&client, &server)
                    );
                }
            }
            // WebSocket and Mihomo's masked native wrapper can close both transport halves.
            tls.get_mut().1.send_close_notify();
            tls.flush().await?;
            assert_eq!(tls.read(&mut [0]).await?, 0, "data after TLS close");
        }
        Ok::<_, io::Error>(())
    })
    .await;
    if !matches!(result, Ok(Ok(()))) {
        panic!("{result:?}\n{}", pair_logs(&client, &server));
    }
    let shoes = if peer_client { &server } else { &client };
    shoes.assert_handshakes(&["fresh", "resumed"]);
    for direction in ["READ", "WRITE"] {
        assert_eq!(
            shoes.logs().contains(&format!(
                "VISION {direction}: Switching to direct copy mode"
            )),
            !tls12,
            "{}",
            shoes.logs()
        );
    }
    drop((client, server));
    tap_task.stop().await;
    target_task.stop().await;
}

#[tokio::test]
async fn native_vision_direct_preserves_outer_transports() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for client in [false, true] {
            for transport in [Transport::Raw, Transport::Tls, Transport::Websocket] {
                for mode in ["native", "random"] {
                    direct_case(peer, client, transport, mode, false).await;
                }
            }
            direct_case(peer, client, Transport::Raw, "native", true).await;
        }
    }
}

#[tokio::test]
async fn native_vision_direct_preserves_xhttp_and_reality() {
    for client in [false, true] {
        for transport in [Transport::Xhttp, Transport::Reality] {
            for mode in ["native", "random"] {
                direct_case(Kind::Xray, client, transport, mode, false).await;
            }
        }
    }
}

#[tokio::test]
async fn peer_clients_recover_after_ticket_capacity_and_server_restart() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for mode in ["native", "random"] {
            let (encryption, decryption, fresh_min) = credentials(mode, &["x25519"]);
            let (target, connections, mut target_task) = echo().await;
            let server_port = free_port().await;
            let mut config = server_config(Kind::Shoes, server_port, &decryption, false);
            config[0]["protocol"]["encryption_limits"] =
                json!({"max_sessions": 100, "max_replays": 100, "max_replays_per_session": 1});
            let mut server = start(Kind::Shoes, server_port, config.clone()).await;
            let (tap_port, captures, mut tap_task) = tap(server_port).await;
            let client_port = free_port().await;
            let client = start(
                peer,
                client_port,
                client_config(peer, client_port, tap_port, &encryption, false),
            )
            .await;
            for _ in 0..2 {
                exchange(client_port, target, b"warm").await.unwrap();
            }
            assert!(
                exchange(client_port, target, b"capacity rejection")
                    .await
                    .is_err()
            );
            assert_eq!(connections.load(Ordering::SeqCst), 2);
            exchange(client_port, target, b"fresh recovery")
                .await
                .unwrap();
            assert_eq!(connections.load(Ordering::SeqCst), 3);
            let lengths: Vec<_> = captures.lock().unwrap().iter().map(Vec::len).collect();
            assert_eq!(
                lengths.iter().map(|n| *n < fresh_min).collect::<Vec<_>>(),
                [false, true, true, false],
                "{lengths:?}"
            );
            drop(server);
            server = start(Kind::Shoes, server_port, config).await;
            assert!(
                exchange(client_port, target, b"stale after restart")
                    .await
                    .is_err()
            );
            assert_eq!(connections.load(Ordering::SeqCst), 3);
            exchange(client_port, target, b"restart recovery")
                .await
                .unwrap();
            assert_eq!(connections.load(Ordering::SeqCst), 4);
            assert!(captures.lock().unwrap().last().unwrap().len() >= fresh_min);
            drop((client, server));
            tap_task.stop().await;
            target_task.stop().await;
        }
    }
}

#[tokio::test]
async fn fresh_only_and_zero_lifetime_never_resume() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for peer_client in [false, true] {
            for zero_lifetime in [false, true] {
                let (mut encryption, mut decryption, fresh_min) =
                    credentials("native", &["x25519"]);
                if zero_lifetime {
                    decryption = decryption.replacen(".600s.", ".0s.", 1);
                } else {
                    encryption = encryption.replacen(".0rtt.", ".1rtt.", 1);
                }
                let (server_kind, client_kind) = peer_roles(peer, peer_client);
                let (target, _, mut target_task) = echo().await;
                let server_port = free_port().await;
                let server = start(
                    server_kind,
                    server_port,
                    server_config(server_kind, server_port, &decryption, false),
                )
                .await;
                let (tap_port, captures, mut tap_task) = tap(server_port).await;
                let client_port = free_port().await;
                let client = start(
                    client_kind,
                    client_port,
                    client_config(client_kind, client_port, tap_port, &encryption, false),
                )
                .await;
                for _ in 0..2 {
                    exchange(client_port, target, b"fresh only").await.unwrap();
                }
                assert!(
                    captures
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|bytes| bytes.len() >= fresh_min)
                );
                drop((client, server));
                tap_task.stop().await;
                target_task.stop().await;
            }
        }
    }
}

#[tokio::test]
async fn native_h2mux_preserves_concurrent_connections() {
    for mode in ["native", "xorpub", "random"] {
        let (encryption, decryption, _) = credentials(mode, &["mlkem768"]);
        let (target, connections, mut target_task) = echo().await;
        let server_port = free_port().await;
        let server = start(
            Kind::Shoes,
            server_port,
            server_config(Kind::Shoes, server_port, &decryption, false),
        )
        .await;
        let (tap_port, captures, mut tap_task) = tap(server_port).await;
        let client_port = free_port().await;
        let mut config = client_config(Kind::Shoes, client_port, tap_port, &encryption, false);
        config[0]["rules"][0]["client_chain"]["protocol"]["h2mux"] =
            json!({"max_connections": 1, "min_streams": 16, "padding": true});
        let client = start(Kind::Shoes, client_port, config).await;
        let mut tasks = JoinSet::new();
        for _ in 0..16 {
            tasks.spawn(async move { exchange(client_port, target, &vec![42; 131072]).await });
        }
        timeout(LIMIT, async {
            while let Some(result) = tasks.join_next().await {
                result
                    .unwrap()
                    .unwrap_or_else(|error| panic!("{error}\n{}", pair_logs(&client, &server)));
            }
        })
        .await
        .unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 16);
        // Shoes intentionally creates one H2MUX session per supplied transport.
        assert_eq!(captures.lock().unwrap().len(), 16);
        drop((client, server));
        tap_task.stop().await;
        target_task.stop().await;
    }
}

#[tokio::test]
async fn wrong_uuid_and_key_order_have_no_destination_side_effects() {
    for peer in [Kind::Xray, Kind::Mihomo] {
        for peer_client in [false, true] {
            for wrong_uuid in [false, true] {
                let (encryption, decryption, _) = credentials("native", &["x25519", "x25519"]);
                let (server_kind, client_kind) = peer_roles(peer, peer_client);
                let (target, connections, mut target_task) = echo().await;
                let server_port = free_port().await;
                let server = start(
                    server_kind,
                    server_port,
                    server_config(server_kind, server_port, &decryption, false),
                )
                .await;
                let client_port = free_port().await;
                let mut config =
                    client_config(client_kind, client_port, server_port, &encryption, false);
                if wrong_uuid {
                    let user = match client_kind {
                        Kind::Shoes => &mut shoes_protocol_mut(&mut config, false)["user_id"],
                        Kind::Xray => {
                            &mut xray_endpoint_mut(&mut config, false)["settings"]["vnext"][0]["users"]
                                [0]["id"]
                        }
                        Kind::Mihomo => &mut config["proxies"][0]["uuid"],
                        Kind::SingBox => {
                            unreachable!("sing-box does not implement native encryption")
                        }
                    };
                    *user = json!("c85798ef-e9dc-46a4-9a87-8da4499d36d0");
                } else {
                    let mut fields: Vec<_> = encryption.split('.').collect();
                    fields.swap(4, 5);
                    config = client_config(
                        client_kind,
                        client_port,
                        server_port,
                        &fields.join("."),
                        false,
                    );
                }
                let client = start(client_kind, client_port, config).await;
                assert!(
                    exchange(client_port, target, b"must not arrive")
                        .await
                        .is_err()
                );
                assert_eq!(connections.load(Ordering::SeqCst), 0);
                drop((client, server));
                target_task.stop().await;
            }
        }
    }
}

#[tokio::test]
async fn encrypted_command_two_and_xudp_roundtrip_multiple_destinations() {
    use shoes_test_support::{
        socks5::Socks5UdpAssociation, test_servers::start_udp_echo_server_with_suffix,
    };
    for peer in [Kind::Xray, Kind::Mihomo] {
        for peer_client in [false, true] {
            for vision in [false, true] {
                let (encryption, decryption, _) = credentials("random", &["mlkem768"]);
                let (server_kind, client_kind) = peer_roles(peer, peer_client);
                let a = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
                    .await
                    .unwrap();
                let b = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"")
                    .await
                    .unwrap();
                let server_port = free_port().await;
                let server = start(
                    server_kind,
                    server_port,
                    server_config(server_kind, server_port, &decryption, vision),
                )
                .await;
                let client_port = free_port().await;
                let mut config =
                    client_config(client_kind, client_port, server_port, &encryption, vision);
                if client_kind == Kind::Mihomo {
                    config["proxies"][0]["packet-encoding"] = json!("xudp");
                }
                let client = start(client_kind, client_port, config).await;
                for _ in 0..2 {
                    let association = Socks5UdpAssociation::connect("127.0.0.1", client_port)
                        .await
                        .unwrap();
                    for target in [&a, &b, &a] {
                        let target =
                            (std::net::Ipv4Addr::LOCALHOST, target.local_addr().port()).into();
                        // Xray's XUDP writer reserves 666 of its 8192-byte buffer.
                        for payload in [b"UDP over encrypted VLESS".as_slice(), &[42; 7526][..]] {
                            let response = association.send_to(target, payload).await.unwrap_or_else(|error| {
                                panic!(
                                    "{error}: {peer:?}, peer_client={peer_client}, vision={vision}\n{}",
                                    pair_logs(&client, &server)
                                )
                            });
                            assert_eq!(response, payload);
                        }
                    }
                }
                drop((client, server));
            }
        }
    }
}
