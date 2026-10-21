//! Requires kernel WireGuard, iproute2, wireguard-tools, util-linux and passwordless sudo.
//! SHOES_TEST_WG_BIN may override the wg executable. Each test owns network/PID namespaces.

use crate::wireguard_support as config;
use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper,
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    wireguard::{ECHO_TCP_BYTES, EchoTargets, connect},
};
use std::{
    ffi::OsStr,
    future::Future,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    process::Command,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};

const TCP_BYTES: usize = 512_007;
const PARENT_NETNS: &str = "SHOES_TEST_WG_PARENT_NETNS";
const PARENT_MOUNTNS: &str = "SHOES_TEST_WG_PARENT_MOUNTNS";

#[path = "wireguard_kernel/network.rs"]
mod network;

#[path = "wireguard_kernel/resolution.rs"]
mod resolution;

fn run(program: impl AsRef<OsStr>, args: &[&str]) -> io::Result<String> {
    let output = Command::new(program.as_ref()).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{:?} {args:?}: {}",
            program.as_ref(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn wg(args: &[&str]) -> io::Result<String> {
    run(
        std::env::var_os("SHOES_TEST_WG_BIN").unwrap_or_else(|| "wg".into()),
        args,
    )
}

fn isolated_test(name: &str, cases: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    let namespace = std::fs::read_link("/proc/self/ns/net")?;
    if let Some(parent) = std::env::var_os(PARENT_NETNS) {
        assert_ne!(
            namespace.as_os_str(),
            parent,
            "refusing to modify host networking"
        );
        let links: Value = serde_json::from_str(&run("ip", &["-j", "link", "show"])?)?;
        assert_eq!(links.as_array().unwrap().len(), 1);
        assert_eq!(links[0]["ifname"], "lo");
        run("ip", &["link", "set", "lo", "up"])?;
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async { timeout(Duration::from_secs(180), cases).await? });
    }

    // PID namespace teardown also kills Shoes if the test aborts or exceeds the deadline.
    let output = Command::new("sudo")
        .args(["-n", "-E", "--"])
        .args(["timeout", "--kill-after=5s", "210s"])
        .args([
            "unshare",
            "--net",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child",
            "--",
        ])
        .arg("env")
        .arg(format!("{PARENT_NETNS}={}", namespace.display()))
        .arg(format!(
            "{PARENT_MOUNTNS}={}",
            std::fs::read_link("/proc/self/ns/mnt")?.display()
        ))
        .arg(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "isolated kernel WireGuard test failed: {}\n{}\n{}",
        output.status,
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

struct KernelPeer {
    name: &'static str,
}

struct KernelConfig {
    name: &'static str,
    local_key_seed: u8,
    peer_key_seed: u8,
    addresses: [&'static str; 2],
    routes: [&'static str; 2],
    endpoint: Option<SocketAddr>,
}

impl KernelPeer {
    fn start(shoes_server: bool, mtu: u16, psk: bool, shoes_port: u16) -> io::Result<Self> {
        let (local_key_seed, peer_key_seed, addresses, routes) = if shoes_server {
            (
                42,
                41,
                ["10.77.0.2/32", "fd77::2/128"],
                ["10.88.0.1/32", "fd88::1/128"],
            )
        } else {
            (
                41,
                42,
                ["10.77.0.1/32", "fd77::1/128"],
                ["10.77.0.2/32", "fd77::2/128"],
            )
        };
        Self::configured(
            mtu,
            psk,
            KernelConfig {
                name: "wg0",
                local_key_seed,
                peer_key_seed,
                addresses,
                routes,
                endpoint: shoes_server.then(|| SocketAddr::from(([127, 0, 0, 1], shoes_port))),
            },
        )
    }

    fn configured(mtu: u16, psk: bool, config: KernelConfig) -> io::Result<Self> {
        let KernelConfig {
            name,
            local_key_seed,
            peer_key_seed,
            addresses,
            routes,
            endpoint,
        } = config;
        run("ip", &["link", "add", name, "type", "wireguard"])?;
        let peer = Self { name };
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(
            file,
            "[Interface]\nPrivateKey={}\n[Peer]\nPublicKey={}\nAllowedIPs={}",
            config::key(local_key_seed),
            config::public(peer_key_seed),
            routes.join(",")
        )?;
        if psk {
            writeln!(file, "PresharedKey={}", config::key(43))?;
        }
        if let Some(endpoint) = endpoint {
            writeln!(file, "Endpoint={endpoint}")?;
        }
        file.flush()?;
        wg(&["setconf", name, file.path().to_str().unwrap()])?;
        run("ip", &["link", "set", name, "mtu", &mtu.to_string(), "up"])?;
        for (family, address, route) in [
            ("-4", addresses[0], routes[0]),
            ("-6", addresses[1], routes[1]),
        ] {
            let mut args = vec![family, "address", "add", address, "dev", name];
            if family == "-6" {
                args.push("nodad");
            }
            run("ip", &args)?;
            run("ip", &[family, "route", "add", route, "dev", name])?;
            let destination = route.split_once('/').unwrap().0;
            let lookup: Value =
                serde_json::from_str(&run("ip", &["-j", family, "route", "get", destination])?)?;
            assert_eq!(lookup[0]["dev"], name, "wrong kernel route: {lookup}");
            assert_ne!(lookup[0]["type"], "local", "traffic would bypass WireGuard");
        }
        let link: Value =
            serde_json::from_str(&run("ip", &["-d", "-j", "link", "show", "dev", name])?)?;
        assert_eq!(link[0]["linkinfo"]["info_kind"], "wireguard");
        assert_eq!(link[0]["mtu"], mtu);
        Ok(peer)
    }

    fn port(&self) -> io::Result<u16> {
        wg(&["show", self.name, "listen-port"])?
            .trim()
            .parse()
            .map_err(io::Error::other)
    }

    fn set_preshared_key(&self, peer_key_seed: u8, psk_seed: u8) -> io::Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "{}", config::key(psk_seed))?;
        file.flush()?;
        wg(&[
            "set",
            self.name,
            "peer",
            &config::public(peer_key_seed),
            "preshared-key",
            file.path().to_str().unwrap(),
        ])?;
        Ok(())
    }

    fn counters(&self) -> io::Result<[u64; 2]> {
        let output = wg(&["show", self.name, "transfer"])?;
        let fields: Vec<_> = output.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            3,
            "expected exactly one kernel peer: {output}"
        );
        Ok([fields[1].parse().unwrap(), fields[2].parse().unwrap()])
    }

    fn assert_transfer(&self, before: [u64; 2], bytes: usize) -> io::Result<()> {
        let after = self.counters()?;
        for (before, after) in before.into_iter().zip(after) {
            assert!(
                after >= before + bytes as u64,
                "payload bypassed WireGuard: {before} -> {after}, expected {bytes} bytes"
            );
        }
        assert!(self.handshake()? > 0, "no authenticated kernel handshake");
        Ok(())
    }

    fn handshake(&self) -> io::Result<u64> {
        let output = wg(&["show", self.name, "latest-handshakes"])?;
        Ok(output.split_whitespace().nth(1).unwrap().parse().unwrap())
    }

    async fn wait_for_handshake(&self) -> io::Result<()> {
        timeout(Duration::from_secs(10), async {
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            loop {
                tick.tick().await;
                if self.handshake()? > 0 {
                    return Ok(());
                }
            }
        })
        .await?
    }
}

impl Drop for KernelPeer {
    fn drop(&mut self) {
        if let Err(error) = run("ip", &["link", "del", self.name]) {
            eprintln!("kernel WireGuard cleanup: {error}");
        }
    }
}

async fn bulk_echo(mut stream: TcpStream) -> io::Result<()> {
    let payload: Vec<_> = (0..TCP_BYTES).map(|i| (i ^ (i >> 8)) as u8).collect();
    let (mut read, mut write) = stream.split();
    tokio::try_join!(
        async {
            write.write_all(&payload).await?;
            write.shutdown().await
        },
        async {
            let mut response = vec![0; payload.len()];
            read.read_exact(&mut response).await?;
            assert_eq!(response, payload);
            assert_eq!(
                read.read(&mut [0]).await?,
                0,
                "missing EOF after half-close"
            );
            io::Result::Ok(())
        }
    )?;
    Ok(())
}

async fn run_cases(shoes_server: bool, detour: bool) -> io::Result<()> {
    for mtu in [1280, 1408] {
        for psk in [false, true] {
            for chain in [false, true] {
                for ipv6 in [false, true] {
                    eprintln!(
                        "kernel WireGuard: shoes_server={shoes_server} detour={detour} mtu={mtu} psk={psk} chain={chain} ipv6={ipv6}"
                    );
                    timeout(
                        Duration::from_secs(20),
                        run_case(shoes_server, mtu, psk, chain, ipv6, detour),
                    )
                    .await??;
                }
            }
        }
    }
    Ok(())
}

async fn run_case(
    shoes_server: bool,
    mtu: u16,
    psk: bool,
    chain: bool,
    ipv6: bool,
    detour: bool,
) -> io::Result<()> {
    let echo = EchoTargets::new(ipv6).await?;
    let mut ports = PortHelper::new();
    let (_, socks_port) = ports.get_localhost_listener_port();
    let (_, vless_port) = ports.get_localhost_listener_port();
    let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let shoes_port = reservation.local_addr()?.port();
    let kernel = KernelPeer::start(shoes_server, mtu, psk, shoes_port)?;
    let mut endpoint = if shoes_server {
        config::server(shoes_port)
    } else {
        config::client(kernel.port()?)
    };
    if shoes_server {
        endpoint["protocol"]["mtu"] = json!(mtu);
        if !psk {
            endpoint["protocol"]["peers"][0]
                .as_object_mut()
                .unwrap()
                .remove("pre_shared_key");
        }
    } else {
        endpoint["client_proxies"][0]["protocol"]["mtu"] = json!(mtu);
        if !psk {
            endpoint["client_proxies"][0]["protocol"]
                .as_object_mut()
                .unwrap()
                .remove("pre_shared_key");
        }
    }
    let kernel_server_ip: IpAddr = if ipv6 { "fd77::1" } else { "10.77.0.1" }.parse().unwrap();
    // Only the VLESS server can translate this unroutable destination to the echo target.
    let chained_target_ip: IpAddr = if ipv6 { "2001:db8::77" } else { "192.0.2.77" }
        .parse()
        .unwrap();
    let vless_protocol = config::vless_protocol();
    // The SOCKS listener also provides readiness for inbound-only exchanges.
    let mut socks = config::socks(socks_port);
    if shoes_server {
        socks["rules"] = json!("allow-all-direct");
    }
    if chain {
        let proxy_ip = if shoes_server {
            echo.tcp().ip()
        } else {
            kernel_server_ip
        };
        let hop = json!({
            "address": SocketAddr::new(proxy_ip, vless_port).to_string(),
            "protocol": vless_protocol,
        });
        if shoes_server {
            for rule in endpoint["rules"].as_array_mut().unwrap() {
                rule["client_chain"] = json!([hop]);
                rule["override_address"] = json!(SocketAddr::new(chained_target_ip, 0).to_string());
            }
        } else {
            socks["rules"][0]["client_chain"]
                .as_array_mut()
                .unwrap()
                .push(hop);
        }
    }
    let prefix_length = if ipv6 { 128 } else { 32 };
    let vless_server = json!({
        "address": format!("[::]:{vless_port}"),
        "protocol": vless_protocol,
        "rules": [{
            "masks": [format!("{chained_target_ip}/{prefix_length}")],
            "action": "allow",
            "override_address": SocketAddr::new(echo.tcp().ip(), 0).to_string(),
        }],
    });
    let mut outer_servers = Vec::new();
    if detour {
        let (_, outer_socks_port) = ports.get_localhost_listener_port();
        let (_, outer_vless_port) = ports.get_localhost_listener_port();
        // The isolated namespace has no route to this address. Only the proxy rewrites it.
        let outer_ip = if ipv6 { "2001:db8::200" } else { "192.0.2.200" };
        let family = if ipv6 { "-6" } else { "-4" };
        assert!(run("ip", &[family, "route", "get", outer_ip]).is_err());
        let peer_address = SocketAddr::new(outer_ip.parse().unwrap(), kernel.port()?).to_string();
        let protocol = if shoes_server {
            endpoint.as_object_mut().unwrap().remove("address");
            endpoint["protocol"]["peers"][0]["endpoint"] = json!(peer_address);
            endpoint["protocol"]["peers"][0]["persistent_keepalive"] = json!(1);
            &mut endpoint["protocol"]
        } else {
            endpoint["client_proxies"][0]["address"] = json!(peer_address);
            endpoint["client_proxies"][0]["protocol"]["persistent_keepalive"] = json!(1);
            &mut endpoint["client_proxies"][0]["protocol"]
        };
        protocol["peer_client_chain"] = json!([
            {"address": format!("127.0.0.1:{outer_socks_port}"), "protocol": {"type": "socks"}},
            {"address": format!("127.0.0.1:{outer_vless_port}"), "protocol": vless_protocol},
        ]);
        outer_servers.push(json!({
            "address": format!("0.0.0.0:{outer_socks_port}"), "protocol": {"type": "socks"},
            "rules": [{"masks": "127.0.0.1/32", "action": "allow"}],
        }));
        let outer_override = if ipv6 { "[::1]:0" } else { "127.0.0.1:0" };
        outer_servers.push(json!({
            "address": format!("0.0.0.0:{outer_vless_port}"), "protocol": vless_protocol,
            "rules": [{"masks": format!("{outer_ip}/{prefix_length}"), "action": "allow", "override_address": outer_override}],
        }));
    }
    let mut shoes_config = vec![endpoint, socks, vless_server];
    shoes_config.extend(outer_servers);
    drop(reservation);
    let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config).unwrap())?;
    ports.wait_for_all_ports().await?;
    if detour {
        // Inbound tests need the initiated association before the kernel sends its first flow.
        kernel.wait_for_handshake().await?;
    }

    let inbound_target_ip: IpAddr = if ipv6 { "fd88::1" } else { "10.88.0.1" }.parse().unwrap();
    let target_ip = if shoes_server {
        inbound_target_ip
    } else if chain {
        chained_target_ip
    } else {
        kernel_server_ip
    };
    let tcp_target = SocketAddr::new(target_ip, echo.tcp().port());
    let before = kernel.counters()?;
    let stream = if shoes_server {
        let socket = if ipv6 {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        socket.connect(tcp_target).await?
    } else {
        connect(socks_port, tcp_target).await?
    };
    bulk_echo(stream).await?;
    kernel.assert_transfer(before, TCP_BYTES)?;

    let udp_target = SocketAddr::new(target_ip, echo.udp().port());
    let before = kernel.counters()?;
    let mut udp_bytes = 0;
    let socket = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).await?;
    let association = if shoes_server {
        None
    } else {
        Some(Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?)
    };
    let ip_udp_overhead = if ipv6 { 48 } else { 28 };
    let payload_sizes = [1, 64, 1200, usize::from(mtu) - ip_udp_overhead];
    for sequence in 0..12 {
        let payload_len = payload_sizes[sequence % payload_sizes.len()];
        let payload = vec![sequence as u8; payload_len];
        if let Some(association) = &association {
            if !chain && sequence == 1 {
                let error = association
                    .send_to_with_timeout(
                        shoes_test_support::socks5::SocksDestination::Ip(udp_target),
                        &vec![0xff; usize::from(mtu)],
                        Duration::from_millis(100),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            }
            assert_eq!(association.send_to(udp_target, &payload).await?, payload);
        } else {
            assert_eq!(socket.send_to(&payload, udp_target).await?, payload.len());
            let mut response = vec![0; payload_len + 1];
            let (received_len, source) =
                timeout(Duration::from_secs(5), socket.recv_from(&mut response)).await??;
            assert_eq!(source, udp_target);
            assert_eq!(&response[..received_len], payload);
        }
        udp_bytes += payload_len;
    }
    kernel.assert_transfer(before, udp_bytes)
}

#[test]
fn kernel_client_to_shoes_server() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_client_to_shoes_server",
        run_cases(true, false),
    )
}

#[test]
fn kernel_reset_half_open_does_not_capture_the_next_connection() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_reset_half_open_does_not_capture_the_next_connection",
        async {
            timeout(Duration::from_secs(15), async {
                let reservation = std::net::UdpSocket::bind("0.0.0.0:0")?;
                let port = reservation.local_addr()?.port();
                let kernel = KernelPeer::start(true, 1408, true, port)?;
                let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
                let target =
                    SocketAddr::new("10.88.0.1".parse().unwrap(), listener.local_addr()?.port());
                let mut ports = PortHelper::new();
                let (_, entry) = ports.get_localhost_listener_port();
                let mut endpoint = config::server(port);
                endpoint["protocol"]["resource_limits"] = json!({"max_tcp_connections": 1});
                let mut socks = config::socks(entry);
                socks["rules"] = json!("allow-all-direct");
                drop(reservation);
                let _shoes =
                    start_shoes_server(&serde_yaml::to_string(&json!([endpoint, socks])).unwrap())?;
                ports.wait_for_all_ports().await?;
                let source_port = {
                    let reservation = std::net::TcpListener::bind("10.77.0.2:0")?;
                    reservation.local_addr()?.port()
                };
                let before = kernel.counters()?;
                let probe = tokio::task::spawn_blocking(move || -> io::Result<()> {
                    use socket2::{Domain, Protocol, Socket, Type};
                    use std::io::Read;

                    let mut raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
                    raw.bind(&SocketAddr::from(([10, 77, 0, 2], 0)).into())?;
                    raw.set_header_included_v4(true)?;
                    raw.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let mut syn = Vec::new();
                    etherparse::PacketBuilder::ipv4([10, 77, 0, 2], [10, 88, 0, 1], 64)
                        .tcp(source_port, target.port(), 1000, 65535)
                        .syn()
                        .write(&mut syn, &[])
                        .map_err(io::Error::other)?;
                    raw.send_to(&syn, &target.into())?;
                    let mut bytes = [0; 1500];
                    let len = raw.read(&mut bytes)?;
                    let ip = smoltcp::wire::Ipv4Packet::new_checked(&bytes[..len])
                        .map_err(io::Error::other)?;
                    let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload())
                        .map_err(io::Error::other)?;
                    assert_eq!(tcp.dst_port(), source_port);
                    assert!(tcp.syn() && tcp.ack());
                    // No kernel TCP socket owns the raw SYN, so Linux resets the received SYN-ACK.
                    Ok(())
                });
                probe.await.map_err(io::Error::other)??;
                let mut stream = TcpStream::connect(target).await?;
                let (mut upstream, _) = listener.accept().await?;
                stream.write_all(b"after reset").await?;
                let mut data = [0; 11];
                upstream.read_exact(&mut data).await?;
                upstream.write_all(&data).await?;
                stream.read_exact(&mut data).await?;
                assert_eq!(&data, b"after reset");
                assert!(futures::FutureExt::now_or_never(listener.accept()).is_none());
                kernel.assert_transfer(before, data.len())
            })
            .await?
        },
    )
}

#[test]
fn shoes_client_to_kernel_server() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::shoes_client_to_kernel_server",
        run_cases(false, false),
    )
}

#[test]
fn shoes_client_through_outer_chain_to_kernel_server() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::shoes_client_through_outer_chain_to_kernel_server",
        run_cases(false, true),
    )
}

#[test]
fn kernel_client_to_detoured_shoes_inbound() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_client_to_detoured_shoes_inbound",
        run_cases(true, true),
    )
}

fn detoured_client_configs(
    kernel: &KernelPeer,
    socks_port: u16,
    outer_port: u16,
    peer_host: &str,
) -> io::Result<(String, String)> {
    let protocol = config::vless_protocol();
    let outer_config = serde_yaml::to_string(&json!([{
        "address": format!("0.0.0.0:{outer_port}"), "protocol": protocol,
        "rules": [{"masks": format!("{peer_host}/32"), "action": "allow", "override_address": "127.0.0.1:0"}],
    }])).unwrap();
    let kernel_port = kernel.port()?;
    let mut client = config::client(kernel_port);
    client["client_proxies"][0]["protocol"]["mtu"] = json!(1280);
    client["client_proxies"][0]["address"] = json!(format!("{peer_host}:{kernel_port}"));
    client["client_proxies"][0]["protocol"]["persistent_keepalive"] = json!(1);
    client["client_proxies"][0]["protocol"]["peer_client_chain"] =
        json!([{"address": format!("127.0.0.1:{outer_port}"), "protocol": protocol}]);
    let client_config = serde_yaml::to_string(&json!([client, config::socks(socks_port)])).unwrap();
    Ok((client_config, outer_config))
}

async fn run_recovery_case() -> io::Result<()> {
    let echo = EchoTargets::new(false).await?;
    let kernel = KernelPeer::start(false, 1280, true, 0)?;
    let mut ports = PortHelper::new();
    let (_, socks_port) = ports.get_localhost_listener_port();
    let (_, outer_port) = ports.get_localhost_listener_port();
    // A reachable peer makes forbidden direct fallback observable during the outage.
    let (client_config, outer_config) =
        detoured_client_configs(&kernel, socks_port, outer_port, "127.0.0.1")?;
    let outer = start_shoes_server(&outer_config)?;
    let _shoes = start_shoes_server(&client_config)?;
    ports.wait_for_all_ports().await?;
    let tcp_target = SocketAddr::new("10.77.0.1".parse().unwrap(), echo.tcp().port());
    let mut stream = connect(socks_port, tcp_target).await?;
    stream.write_all(b"before outage").await?;
    let mut bytes = [0; 13];
    stream.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"before outage");

    let udp_target = SocketAddr::new("10.77.0.1".parse().unwrap(), echo.udp().port());
    let udp = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
    assert_eq!(
        udp.send_to(udp_target, b"before outage").await?,
        b"before outage"
    );
    drop(outer);
    for _ in 0..8 {
        assert!(
            timeout(
                Duration::from_millis(750),
                udp.send_to(udp_target, b"no direct fallback")
            )
            .await
            .is_err()
        );
    }
    let _outer = start_shoes_server(&outer_config)?;
    let before = kernel.counters()?;
    // TCP retransmission and a fresh outer association recover the existing inner flow.
    timeout(Duration::from_secs(20), bulk_echo(stream)).await??;
    kernel.assert_transfer(before, TCP_BYTES)?;
    assert_eq!(
        udp.send_to(udp_target, b"after recovery").await?,
        b"after recovery"
    );
    Ok(())
}

#[test]
fn kernel_detour_recovers_existing_tcp_and_udp_without_direct_fallback() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_detour_recovers_existing_tcp_and_udp_without_direct_fallback",
        run_recovery_case(),
    )
}

async fn run_rekey_case() -> io::Result<()> {
    let echo = EchoTargets::new(false).await?;
    let kernel = KernelPeer::start(false, 1280, true, 0)?;
    let mut ports = PortHelper::new();
    let (_, socks_port) = ports.get_localhost_listener_port();
    let (_, outer_port) = ports.get_localhost_listener_port();
    let (client_config, outer_config) =
        detoured_client_configs(&kernel, socks_port, outer_port, "192.0.2.200")?;
    let _outer = start_shoes_server(&outer_config)?;
    let _shoes = start_shoes_server(&client_config)?;
    ports.wait_for_all_ports().await?;
    let target = SocketAddr::new("10.77.0.1".parse().unwrap(), echo.tcp().port());
    let mut stream = connect(socks_port, target).await?;
    kernel.wait_for_handshake().await?;
    let first_handshake = kernel.handshake()?;
    let udp = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
    let udp_target = SocketAddr::new(target.ip(), echo.udp().port());
    assert_eq!(
        udp.send_to(udp_target, b"before rekey").await?,
        b"before rekey"
    );
    let started = tokio::time::Instant::now();
    timeout(Duration::from_secs(150), async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut sequence = 0u64;
        loop {
            tick.tick().await;
            let payload = sequence.to_be_bytes();
            stream.write_all(&payload).await?;
            let mut response = [0; 8];
            stream.read_exact(&mut response).await?;
            assert_eq!(response, payload);
            assert_eq!(udp.send_to(udp_target, &payload).await?, payload);
            if kernel.handshake()? > first_handshake {
                assert!(
                    started.elapsed() >= Duration::from_secs(100),
                    "unexpected handshake replacement before normal rekey"
                );
                return io::Result::Ok(());
            }
            sequence += 1;
        }
    })
    .await??;
    let before = kernel.counters()?;
    timeout(Duration::from_secs(20), bulk_echo(stream)).await??;
    kernel.assert_transfer(before, TCP_BYTES)?;
    assert_eq!(
        udp.send_to(udp_target, b"after rekey").await?,
        b"after rekey"
    );
    Ok(())
}

#[test]
fn kernel_detoured_tcp_survives_real_rekey() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_detoured_tcp_survives_real_rekey",
        run_rekey_case(),
    )
}

async fn inbound_exchange(
    kernel: &KernelPeer,
    target: IpAddr,
    echo: &EchoTargets,
    marker: u8,
) -> io::Result<()> {
    let before = kernel.counters()?;
    let stream = TcpStream::connect(SocketAddr::new(target, echo.tcp().port())).await?;
    bulk_echo(stream).await?;
    let socket = UdpSocket::bind(if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;
    let target = SocketAddr::new(target, echo.udp().port());
    let payload = vec![marker; 1200];
    for _ in 0..8 {
        socket.send_to(&payload, target).await?;
        let mut response = vec![0; payload.len() + 1];
        let (len, source) = socket.recv_from(&mut response).await?;
        assert_eq!(source, target);
        assert_eq!(&response[..len], payload);
    }
    kernel.assert_transfer(before, TCP_BYTES + 8 * payload.len())
}

async fn run_multi_peer_case() -> io::Result<()> {
    let first = KernelPeer::configured(
        1280,
        true,
        KernelConfig {
            name: "wg0",
            local_key_seed: 42,
            peer_key_seed: 41,
            addresses: ["10.77.0.2/32", "fd77::2/128"],
            routes: ["10.88.0.1/32", "fd88::1/128"],
            endpoint: None,
        },
    )?;
    let second = KernelPeer::configured(
        1280,
        true,
        KernelConfig {
            name: "wg1",
            local_key_seed: 44,
            peer_key_seed: 41,
            addresses: ["10.77.0.3/32", "fd77::3/128"],
            routes: ["10.88.0.2/32", "fd88::2/128"],
            endpoint: None,
        },
    )?;
    assert!(run("ip", &["route", "get", "192.0.2.200"]).is_err());
    let mut ports = PortHelper::new();
    let (_, outer_port) = ports.get_localhost_listener_port();
    let protocol = config::vless_protocol();
    let mut endpoint = config::server(0);
    endpoint.as_object_mut().unwrap().remove("address");
    endpoint["protocol"]["mtu"] = json!(1280);
    endpoint["protocol"]["peer_client_chain"] =
        json!([{"address": format!("127.0.0.1:{outer_port}"), "protocol": protocol}]);
    endpoint["protocol"]["peers"] = json!([
        {"public_key": config::public(42), "pre_shared_key": config::key(43),
         "allowed_ips": ["10.77.0.2/32", "fd77::2/128"], "persistent_keepalive": 1,
         "endpoint": format!("192.0.2.200:{}", first.port()?)},
        {"public_key": config::public(44), "pre_shared_key": config::key(43),
         "allowed_ips": ["10.77.0.3/32", "fd77::3/128"], "persistent_keepalive": 1,
         "endpoint": format!("192.0.2.200:{}", second.port()?)},
    ]);
    endpoint["rules"][0]["masks"] = json!(["fd88::1/128", "fd88::2/128"]);
    let outer = json!({
        "address": format!("0.0.0.0:{outer_port}"), "protocol": protocol,
        "rules": [{"masks": "192.0.2.200/32", "action": "allow", "override_address": "127.0.0.1:0"}],
    });
    let _shoes = start_shoes_server(&serde_yaml::to_string(&json!([endpoint, outer])).unwrap())?;
    ports.wait_for_all_ports().await?;
    tokio::try_join!(first.wait_for_handshake(), second.wait_for_handshake())?;
    for ipv6 in [false, true] {
        let echo = EchoTargets::new(ipv6).await?;
        let first_target = if ipv6 { "fd88::1" } else { "10.88.0.1" }.parse().unwrap();
        let second_target = if ipv6 { "fd88::2" } else { "10.88.0.2" }.parse().unwrap();
        timeout(Duration::from_secs(20), async {
            tokio::try_join!(
                inbound_exchange(&first, first_target, &echo, 42),
                inbound_exchange(&second, second_target, &echo, 44),
            )?;
            io::Result::Ok(())
        })
        .await??;

        // Distinct keys must not allow one peer to impersonate another peer's inner source.
        let protected = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).await?;
        let source = if ipv6 { "[fd77::3]:0" } else { "10.77.0.3:0" };
        let forged = UdpSocket::bind(source).await?;
        let target = SocketAddr::new(first_target, protected.local_addr()?.port());
        let before = first.counters()?;
        forged.send_to(b"wrong peer source", target).await?;
        let mut response = [0; 64];
        assert!(
            timeout(
                Duration::from_millis(750),
                protected.recv_from(&mut response)
            )
            .await
            .is_err(),
            "forwarded an authenticated packet with another peer's source address"
        );
        assert!(first.counters()?[1] > before[1]);
        let source = if ipv6 { "[fd77::2]:0" } else { "10.77.0.2:0" };
        let allowed = UdpSocket::bind(source).await?;
        allowed.send_to(b"allowed source", target).await?;
        let (len, _) =
            timeout(Duration::from_secs(5), protected.recv_from(&mut response)).await??;
        assert_eq!(&response[..len], b"allowed source");
    }
    run("ip", &["link", "set", "wg1", "down"])?;
    let echo = EchoTargets::new(false).await?;
    timeout(
        Duration::from_secs(20),
        inbound_exchange(&first, "10.88.0.1".parse().unwrap(), &echo, 45),
    )
    .await??;
    Ok(())
}

#[test]
fn kernel_peers_share_detoured_inbound_without_cross_delivery() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_peers_share_detoured_inbound_without_cross_delivery",
        run_multi_peer_case(),
    )
}

async fn run_psk_rejection_case() -> io::Result<()> {
    let echo = EchoTargets::new(false).await?;
    let protected = UdpSocket::bind("0.0.0.0:0").await?;
    let kernel = KernelPeer::start(false, 1280, true, 0)?;
    kernel.set_preshared_key(42, 99)?;
    let mut ports = PortHelper::new();
    let (_, socks_port) = ports.get_localhost_listener_port();
    let (_, outer_port) = ports.get_localhost_listener_port();
    let (client_config, outer_config) =
        detoured_client_configs(&kernel, socks_port, outer_port, "192.0.2.200")?;
    let _outer = start_shoes_server(&outer_config)?;
    let _shoes = start_shoes_server(&client_config)?;
    ports.wait_for_all_ports().await?;
    let target = SocketAddr::new("10.77.0.1".parse().unwrap(), protected.local_addr()?.port());
    let udp = Socks5UdpAssociation::connect("127.0.0.1", socks_port).await?;
    assert!(
        timeout(Duration::from_secs(6), udp.send_to(target, b"wrong psk"))
            .await
            .is_err()
    );
    assert_eq!(kernel.handshake()?, 0);
    assert_eq!(
        protected.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "unauthenticated traffic reached the target"
    );
    drop(udp);
    kernel.set_preshared_key(42, 43)?;
    kernel.wait_for_handshake().await?;
    let before = kernel.counters()?;
    echo.check(socks_port, Some(target.ip())).await?;
    kernel.assert_transfer(before, ECHO_TCP_BYTES)?;
    Ok(())
}

#[test]
fn kernel_detour_rejects_wrong_psk_and_recovers_after_correction() -> io::Result<()> {
    isolated_test(
        "wireguard_kernel::kernel_detour_rejects_wrong_psk_and_recovers_after_correction",
        run_psk_rejection_case(),
    )
}
