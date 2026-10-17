//! Requires kernel WireGuard, iproute2, wireguard-tools, util-linux and passwordless sudo.
//! SHOES_TEST_WG_BIN may override the wg executable. Each test owns network/PID namespaces.

use crate::wireguard_support as config;
use serde_json::{Value, json};
use shoes_test_support::{
    port_helper::PortHelper,
    socks5::Socks5UdpAssociation,
    test_fixture::start_shoes_server,
    wireguard::{EchoTargets, connect},
};
use std::{
    ffi::OsStr,
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

fn isolated_test(name: &str, shoes_server: bool) -> io::Result<()> {
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
            .block_on(async { timeout(Duration::from_secs(120), run_cases(shoes_server)).await? });
    }

    // PID namespace teardown also kills Shoes if the test aborts or exceeds the deadline.
    let output = Command::new("sudo")
        .args(["-n", "-E", "--"])
        .args(["timeout", "--kill-after=5s", "150s"])
        .args(["unshare", "--net", "--pid", "--fork", "--kill-child", "--"])
        .arg("env")
        .arg(format!("{PARENT_NETNS}={}", namespace.display()))
        .arg(std::env::current_exe()?)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .output()?;
    assert!(
        output.status.success(),
        "isolated kernel WireGuard test failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

struct KernelPeer;

impl KernelPeer {
    fn start(shoes_server: bool, mtu: u16, psk: bool, shoes_port: u16) -> io::Result<Self> {
        run("ip", &["link", "add", "wg0", "type", "wireguard"])?;
        let peer = Self;
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
        if shoes_server {
            writeln!(file, "Endpoint=127.0.0.1:{shoes_port}")?;
        }
        file.flush()?;
        wg(&["setconf", "wg0", file.path().to_str().unwrap()])?;
        run("ip", &["link", "set", "wg0", "mtu", &mtu.to_string(), "up"])?;
        for (family, address, route) in [
            ("-4", addresses[0], routes[0]),
            ("-6", addresses[1], routes[1]),
        ] {
            let mut args = vec![family, "address", "add", address, "dev", "wg0"];
            if family == "-6" {
                args.push("nodad");
            }
            run("ip", &args)?;
            run("ip", &[family, "route", "add", route, "dev", "wg0"])?;
            let destination = route.split_once('/').unwrap().0;
            let lookup: Value =
                serde_json::from_str(&run("ip", &["-j", family, "route", "get", destination])?)?;
            assert_eq!(lookup[0]["dev"], "wg0", "wrong kernel route: {lookup}");
            assert_ne!(lookup[0]["type"], "local", "traffic would bypass WireGuard");
        }
        let link: Value =
            serde_json::from_str(&run("ip", &["-d", "-j", "link", "show", "dev", "wg0"])?)?;
        assert_eq!(link[0]["linkinfo"]["info_kind"], "wireguard");
        assert_eq!(link[0]["mtu"], mtu);
        Ok(peer)
    }

    fn port(&self) -> io::Result<u16> {
        wg(&["show", "wg0", "listen-port"])?
            .trim()
            .parse()
            .map_err(io::Error::other)
    }

    fn counters(&self) -> io::Result<[u64; 2]> {
        let output = wg(&["show", "wg0", "transfer"])?;
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
        let output = wg(&["show", "wg0", "latest-handshakes"])?;
        let latest_handshake: u64 = output.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(latest_handshake > 0, "no authenticated kernel handshake");
        Ok(())
    }
}

impl Drop for KernelPeer {
    fn drop(&mut self) {
        if let Err(error) = run("ip", &["link", "del", "wg0"]) {
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

async fn run_cases(shoes_server: bool) -> io::Result<()> {
    for mtu in [1280, 1408] {
        for psk in [false, true] {
            for chain in [false, true] {
                for ipv6 in [false, true] {
                    eprintln!(
                        "kernel WireGuard: shoes_server={shoes_server} mtu={mtu} psk={psk} chain={chain} ipv6={ipv6}"
                    );
                    timeout(
                        Duration::from_secs(20),
                        run_case(shoes_server, mtu, psk, chain, ipv6),
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
    endpoint["mtu"] = json!(mtu);
    if !psk {
        endpoint["peers"][0]
            .as_object_mut()
            .unwrap()
            .remove("pre_shared_key");
    }
    let kernel_server_ip: IpAddr = if ipv6 { "fd77::1" } else { "10.77.0.1" }.parse().unwrap();
    // Only the VLESS server can translate this unroutable destination to the echo target.
    let chained_target_ip: IpAddr = if ipv6 { "2001:db8::77" } else { "192.0.2.77" }
        .parse()
        .unwrap();
    let vless_protocol = json!({
        "type": "vless",
        "user_id": "b85798ef-e9dc-46a4-9a87-8da4499d36d0",
        "udp_enabled": true,
    });
    // The SOCKS listener also provides readiness for inbound-only exchanges.
    let mut socks = config::socks(socks_port);
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
            for rule in endpoint["inbound"]["rules"].as_array_mut().unwrap() {
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
    let shoes_config = json!([endpoint, socks, vless_server]);
    drop(reservation);
    let _shoes = start_shoes_server(&serde_yaml::to_string(&shoes_config).unwrap())?;
    ports.wait_for_all_ports().await?;

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
    isolated_test("wireguard_kernel::kernel_client_to_shoes_server", true)
}

#[test]
fn shoes_client_to_kernel_server() -> io::Result<()> {
    isolated_test("wireguard_kernel::shoes_client_to_kernel_server", false)
}
