use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const NATIVE: [(&str, &str); 2] = [("-4", "192.0.2.2"), ("-6", "fd00:1::2")];
const TARGETS: [&str; 2] = ["198.51.100.2", "fd00:2::2"];
const SOURCES: [&str; 2] = ["192.0.2.1", "fd00:1::1"];
const PROXY_ID: &str = "00000000-0000-4000-8000-000000000001";

struct Flow {
    tcp: TcpStream,
    udp: UdpSocket,
}

impl Flow {
    async fn connect(target: SocketAddr, source: Option<IpAddr>) -> io::Result<Self> {
        let ip = match source {
            Some(ip) => ip,
            None if target.is_ipv6() => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let bind = SocketAddr::new(ip, 0);
        let tcp = if target.is_ipv6() {
            tokio::net::TcpSocket::new_v6()?
        } else {
            tokio::net::TcpSocket::new_v4()?
        };
        tcp.bind(bind)?;
        let tcp = tokio::time::timeout(Duration::from_secs(3), tcp.connect(target))
            .await
            .map_err(|error| io::Error::other(format!("TCP connect {target}: {error}")))??;
        let udp = UdpSocket::bind(bind).await?;
        udp.connect(target).await?;
        let mut flow = Self { tcp, udp };
        flow.exchange().await?;
        Ok(flow)
    }

    async fn exchange(&mut self) -> io::Result<()> {
        const PAYLOAD: &[u8] = b"native-route-fallback";
        self.tcp.write_all(PAYLOAD).await?;
        let mut bytes = [0; PAYLOAD.len()];
        tokio::time::timeout(Duration::from_secs(3), self.tcp.read_exact(&mut bytes))
            .await
            .map_err(|error| io::Error::other(format!("TCP payload: {error}")))??;
        assert_eq!(&bytes, PAYLOAD);
        self.udp.send(PAYLOAD).await?;
        let length = tokio::time::timeout(Duration::from_secs(3), self.udp.recv(&mut bytes))
            .await
            .map_err(|error| io::Error::other(format!("UDP payload: {error}")))??;
        assert_eq!(&bytes[..length], PAYLOAD);
        Ok(())
    }
}

pub(super) async fn proxy_delivery() -> io::Result<()> {
    ownership().await?;
    noncapture().await?;
    virtual_dns().await?;
    let mut echoes = Vec::new();
    let mut targets = Vec::new();
    for address in TARGETS {
        let (tcp, udp) = in_peer(move || {
            let tcp = std::net::TcpListener::bind((address, 0))?;
            let udp = std::net::UdpSocket::bind(tcp.local_addr()?)?;
            tcp.set_nonblocking(true)?;
            udp.set_nonblocking(true)?;
            Ok((tcp, udp))
        })?;
        targets.push(tcp.local_addr()?);
        let tcp = TcpListener::from_std(tcp)?;
        let udp = UdpSocket::from_std(udp)?;
        echoes.push(AbortOnDropHandle::new(tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (mut stream, _) = tcp.accept().await.unwrap();
                connections.spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        })));
        echoes.push(AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
                udp.send_to(&bytes[..length], peer).await.unwrap();
            }
        })));
    }
    let port = in_peer(|| {
        std::net::TcpListener::bind("192.0.2.2:0")?
            .local_addr()
            .map(|address| address.port())
    })?;
    let path = "/run/fallback-proxy.yaml";
    let proxies = [format!("192.0.2.2:{port}"), format!("[fd00:1::2]:{port}")];
    let configs: Vec<_> = proxies
        .iter()
        .map(|address| {
            json!({
                "address": address, "protocol": {"type": "vless", "user_id": PROXY_ID},
                "rules": "allow-all-direct"
            })
        })
        .collect();
    std::fs::write(
        path,
        serde_yaml::to_string(&configs).map_err(io::Error::other)?,
    )?;
    let mut proxy = tokio::process::Command::new("ip")
        .args(["netns", "exec", "peer"])
        .arg(std::env::current_exe()?)
        .env("SHOES_MANAGED_PROCESS_CONFIG", path)
        .args(KERNEL_TEST_ARGS)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = tokio::io::BufReader::new(proxy.stdout.take().unwrap());
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut line = String::new();
        loop {
            line.clear();
            if output.read_line(&mut line).await? == 0 {
                return Err(io::Error::other("fallback proxy exited before readiness"));
            }
            if line.contains("Servers ready") {
                return Ok(());
            }
        }
    })
    .await??;

    for missing in [[false, true], [true, false], [true, true]] {
        for redirect in [false, true] {
            for ((family, _), missing) in NATIVE.into_iter().zip(missing) {
                if missing {
                    run("ip", &[family, "route", "del", "default"])?;
                }
            }
            let proxy_address = if missing[1] { &proxies[0] } else { &proxies[1] };
            let result = capture_without_defaults(&targets, proxy_address, missing, redirect).await;
            for ((family, gateway), missing) in NATIVE.into_iter().zip(missing) {
                if missing {
                    run("ip", &[family, "route", "add", "default", "via", gateway])?;
                }
            }
            result.map_err(|error| {
                io::Error::other(format!(
                    "missing native defaults {missing:?}, REDIRECT={redirect}: {error}"
                ))
            })?;
        }
    }
    proxy.kill().await?;
    proxy.wait().await?;
    drop(echoes);
    Ok(())
}

async fn ownership() -> io::Result<()> {
    use rtnetlink::packet_route::rule::RuleAttribute;

    for ipv6 in [false, true] {
        let family = if ipv6 { "-6" } else { "-4" };
        run(
            "ip",
            &[family, "rule", "add", "priority", "32768", "table", "main"],
        )?;
        let error = Session::prepare(spec(false)).await.err().unwrap();
        assert!(error.to_string().contains("fallback priority 32768"));
        run(
            "ip",
            &[family, "rule", "del", "priority", "32768", "table", "main"],
        )?;

        let mut session = Session::prepare(spec(false)).await?;
        session.prepare_network().await?;
        session.activate().await?;
        run(
            "ip",
            &[family, "rule", "add", "priority", "32768", "table", "main"],
        )?;
        let error = session.reconcile().await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "managed TUN policy rules are missing, changed, or conflicting"
        );
        let error = session.close().await.unwrap_err();
        assert!(
            error.to_string().contains(
                "managed TUN policy rule is changed or conflicting; refusing to remove it"
            ),
            "{error}"
        );
        assert!(session.journal.load()?.is_some());
        run(
            "ip",
            &[family, "rule", "del", "priority", "32768", "table", "main"],
        )?;
        session.close().await?;
        drop(session);

        for change in ["missing", "additional", "changed"] {
            let mut session = Session::prepare(spec(false)).await?;
            session.prepare_network().await?;
            session.activate().await?;
            let expected = routes::fallback_rule(&session.record.spec, ipv6);
            let actual = routes::rules(&session.handle, ipv6)
                .await?
                .into_iter()
                .find(|rule| routes::same_rule(rule, &expected))
                .unwrap();
            if change != "additional" {
                routes::request(session.handle.rule().del(actual).execute()).await?;
            }
            if change != "missing" {
                let mut rule = expected;
                rule.attributes.push(RuleAttribute::FwMark(7));
                let mut add = session.handle.rule().add();
                *add.message_mut() = rule;
                routes::request(add.execute()).await?;
            }
            assert!(session.reconcile().await.is_err());
            if change != "missing" {
                assert!(session.close().await.is_err());
                assert!(session.journal.load()?.is_some());
                assert!(run("ip", &[family, "rule", "show"])?.contains("32768:"));
                run("ip", &[family, "rule", "del", "priority", "32768"])?;
            }
            session.close().await?;
        }
    }
    // Older v1 journals and partial setup can have only the early rules.
    let mut session = Session::prepare(spec(false)).await?;
    session.prepare_network().await?;
    for family in ["-4", "-6"] {
        run("ip", &[family, "rule", "del", "priority", "32768"])?;
    }
    drop(session);
    cleanup().await?;
    cleanup().await?;
    assert!(Journal::lock()?.load()?.is_none());
    assert_no_owned_firewall()?;

    let mut session = Session::prepare(spec(false)).await?;
    session.prepare_network().await?;
    let retained = session.ingress().unwrap();
    run(
        "ip",
        &["link", "set", "shoes0", "alias", "externally-changed"],
    )?;
    assert!(
        session
            .close()
            .await
            .unwrap_err()
            .to_string()
            .contains("retaining its egress guard")
    );
    quiescent_capture_rejected(&session).await?;
    run(
        "ip",
        &["link", "set", "shoes0", "alias", &session.record.alias()],
    )?;
    session.close().await?;
    drop(retained);
    assert_no_owned_firewall()
}

async fn noncapture() -> io::Result<()> {
    run("nft", &["add", "table", "inet", "fallback_probe"])?;
    run(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "fallback_probe",
            "tracker",
            "{ type filter hook output priority -200; }",
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "fallback_probe",
            "tracker",
            "ct",
            "state",
            "established",
            "counter",
        ],
    )?;
    let mut native = native_unreplied_udp().await?;
    let replied = native_unreplied_udp().await?;
    for (client, peer) in &replied {
        peer.send_to(b"native-reply", client.local_addr()?).await?;
        let mut bytes = [0; 32];
        let length =
            tokio::time::timeout(Duration::from_secs(3), client.recv(&mut bytes)).await??;
        assert_eq!(&bytes[..length], b"native-reply");
    }
    native.extend(replied);
    let mut config = configuration(true);
    config.route_address = vec![
        "198.51.100.0/24".parse().unwrap(),
        "fd00:2::/64".parse().unwrap(),
    ];
    config.route_exclude_address = vec![
        "198.51.100.3/32".parse().unwrap(),
        "fd00:2::3/128".parse().unwrap(),
    ];
    let mut session =
        Session::prepare(Spec::from_configs(&[crate::config::Config::TunServer(config)])?.unwrap())
            .await?;
    session.prepare_network().await?;
    session.activate().await?;
    for (family, _) in NATIVE {
        run("ip", &[family, "route", "del", "default"])?;
    }
    run(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "fallback_probe",
            "egress",
            "{ type filter hook postrouting priority 1; }",
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "fallback_probe",
            "egress",
            "oifname",
            "shoes0",
            "counter",
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "fallback_probe",
            "untracked",
            "{ type filter hook output priority -300; }",
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            "fallback_probe",
            "untracked",
            "udp",
            "dport",
            "30003",
            "notrack",
        ],
    )?;
    let before = redirect_counts(&session).await?;
    for (family, addresses) in [
        ["198.51.100.2", "198.51.100.3", "203.0.113.2"],
        ["fd00:2::2", "fd00:2::3", "fd00:3::2"],
    ]
    .into_iter()
    .enumerate()
    {
        let bind = if family == 0 { "0.0.0.0:0" } else { "[::]:0" };
        let capture = session.record.spec.linux.capture_mark;
        for (address, port, mark) in [
            (addresses[1], 30002, 0),
            (addresses[2], 30002, 0),
            (addresses[1], 30002, capture),
            (addresses[2], 30002, capture),
            (addresses[0], 30003, 0),
            (addresses[0], 30003, capture),
            (addresses[0], 30002, capture | 7),
            (addresses[0], 30002, 7),
            (addresses[0], 30002, session.record.spec.linux.bypass_mark),
        ] {
            let socket = UdpSocket::bind(bind).await?;
            socket2::SockRef::from(&socket).set_mark(mark)?;
            assert!(
                socket
                    .send_to(b"must-not-capture", (address, port))
                    .await
                    .is_err(),
                "{address}:{port}, mark={mark:#x}"
            );
        }
        let socket = UdpSocket::bind(bind).await?;
        socket2::SockRef::from(&socket).bind_device(Some(b"native0"))?;
        let _ = socket.send_to(b"device-bound", (addresses[0], 30002)).await;
        let target = SocketAddr::new(addresses[0].parse().unwrap(), 0);
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(target),
            socket2::Type::RAW,
            Some(socket2::Protocol::from(253)),
        )?;
        assert!(socket.send_to(b"unsupported", &target.into()).is_err());
    }
    for (client, _) in native {
        let _ = client.send(b"retained-native").await;
    }
    let listing: serde_json::Value = serde_json::from_str(&run(
        "nft",
        &["-j", "list", "chain", "inet", "fallback_probe", "egress"],
    )?)?;
    let count = listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|entry| entry.get("rule"))
        .unwrap()["expr"][1]["counter"]["packets"]
        .as_u64()
        .unwrap();
    assert_eq!(count, 0, "unauthorized traffic passed the TUN egress guard");
    let listing = firewall_listing(&session).await?;
    let dropped = listing["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("rule"))
        .find(|rule| {
            rule["comment"]
                .as_str()
                .is_some_and(|comment| comment.ends_with(":uncaptured-egress"))
        })
        .unwrap()["expr"][1]["counter"]["packets"]
        .as_u64()
        .unwrap();
    assert!(
        dropped >= 16,
        "noncapture cases did not reach the egress guard: {dropped}"
    );
    assert_eq!(redirect_counts(&session).await?, before);
    session.reconcile().await?;
    session.close().await?;
    run("nft", &["delete", "table", "inet", "fallback_probe"])?;
    for (family, gateway) in NATIVE {
        run("ip", &[family, "route", "add", "default", "via", gateway])?;
    }
    Ok(())
}

async fn virtual_dns() -> io::Result<()> {
    for redirect in [false, true] {
        for routes in [
            vec!["198.51.100.0/24"],
            vec!["198.51.100.0/24", "fd00:2::/64"],
            vec!["0.0.0.0/0", "::/0"],
        ] {
            let mut config = configuration(redirect);
            config.auto_dns = Some(true);
            config.dns_hijack = Some(true);
            config.route_address = routes
                .into_iter()
                .map(|route| route.parse().unwrap())
                .collect();
            config.route_exclude_address =
                vec!["10.0.0.0/8".parse().unwrap(), "fc00::/7".parse().unwrap()];
            let (config, spec) = validated_configuration(config)?;
            let selected_v6 = spec.routes.iter().any(ipnetwork::IpNetwork::is_ipv6);
            if !selected_v6 {
                run(
                    "ip",
                    &["-6", "rule", "add", "priority", "32768", "table", "main"],
                )?;
            }
            let mut session = Session::prepare(spec).await?;
            session.prepare_network().await?;
            let mut tasks = Vec::new();
            session
                .ingress()
                .unwrap()
                .start(
                    &config,
                    Arc::new(crate::resolver::NativeResolver::new()),
                    None,
                    &mut tasks,
                )
                .await?;
            session.activate().await?;
            assert_eq!(
                routes::rules(&session.handle, true)
                    .await?
                    .iter()
                    .any(|rule| routes::same_rule(
                        rule,
                        &routes::fallback_rule(&session.record.spec, true)
                    )),
                selected_v6
            );
            if !selected_v6 {
                run("ip", &["-6", "route", "del", "default"])?;
                let socket = UdpSocket::bind("[::]:0").await?;
                assert_eq!(
                    socket
                        .send_to(b"not-selected", "[fd00:3::2]:9")
                        .await
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ENETUNREACH)
                );
            }
            dns_ready(&session.record).await?;
            for address in session.record.spec.dns_addresses()? {
                let socket = UdpSocket::bind(if address.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })
                .await?;
                assert!(socket.send_to(b"not-dns", (address, 54)).await.is_err());
                socket2::SockRef::from(&socket).set_mark(session.record.spec.linux.bypass_mark)?;
                assert!(socket.send_to(b"protected", (address, 53)).await.is_err());
            }
            session.reconcile().await?;
            session.deactivate().await?;
            quiescent_capture_rejected(&session).await?;
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            session.close().await?;
            if !selected_v6 {
                assert!(run("ip", &["-6", "rule", "show"])?.contains("32768:"));
                run(
                    "ip",
                    &["-6", "rule", "del", "priority", "32768", "table", "main"],
                )?;
                run("ip", &["-6", "route", "add", "default", "via", "fd00:1::2"])?;
            }
        }
    }
    Ok(())
}

async fn capture_without_defaults(
    targets: &[SocketAddr],
    proxy: &str,
    missing: [bool; 2],
    redirect: bool,
) -> io::Result<()> {
    let mut config = serde_json::to_value(configuration(redirect))?;
    config["rules"] = json!([{
        "masks": ["0.0.0.0/0", "::/0"], "action": "allow",
        "client_chain": {"address": proxy, "protocol": {"type": "vless", "user_id": PROXY_ID}}
    }]);
    let (config, spec) = validated_configuration(serde_json::from_value(config)?)?;
    let mut session = Session::prepare(spec).await?;
    session.prepare_network().await?;
    let ingress = session.ingress().unwrap();
    let mut tasks = Vec::new();
    ingress
        .start(
            &config,
            Arc::new(crate::resolver::NativeResolver::new()),
            None,
            &mut tasks,
        )
        .await?;
    quiescent_capture_rejected(&session).await?;
    session.activate().await?;
    let mut flows = Vec::new();
    for (family, target) in targets.iter().copied().enumerate() {
        for source in [None, Some(SOURCES[family].parse().unwrap())] {
            let flow = Flow::connect(target, source).await.map_err(|error| {
                io::Error::other(format!("destination {target}, source {source:?}: {error}"))
            })?;
            if missing[family] && source.is_none() {
                assert!(
                    session
                        .record
                        .spec
                        .addresses
                        .iter()
                        .any(|network| { network.contains(flow.tcp.local_addr().unwrap().ip()) })
                );
            }
            flows.push(flow);
        }
    }
    for restored in [true, false] {
        for ((family, gateway), missing) in NATIVE.into_iter().zip(missing) {
            if missing {
                let operation = if restored { "add" } else { "del" };
                run(
                    "ip",
                    &[family, "route", operation, "default", "via", gateway],
                )?;
            }
        }
        session.reconcile().await?;
        for flow in &mut flows {
            flow.exchange().await?;
        }
        if restored {
            for target in targets.iter().copied() {
                flows.push(Flow::connect(target, None).await?);
            }
        }
    }
    let counts = redirect_counts(&session).await?;
    for (count, port) in counts.into_iter().zip(session.redirect_ports) {
        if port.is_some() {
            assert!(count.unwrap() > 0);
        } else {
            assert!(count.is_none());
        }
    }
    drop(flows);
    session.deactivate().await?;
    quiescent_capture_rejected(&session).await?;
    session.activate().await?;
    Flow::connect(targets[0], None).await?;
    session.deactivate().await?;
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    session.close().await?;
    assert_no_owned_firewall()?;
    for family in ["-4", "-6"] {
        assert!(!run("ip", &[family, "rule", "show"])?.contains("32768:"));
    }
    Ok(())
}
