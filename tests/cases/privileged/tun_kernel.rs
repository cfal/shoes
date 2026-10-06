//! Linux kernel-TUN coverage; requires /dev/net/tun, IPv6 loopback and passwordless sudo.
//! Run with --features privileged-tests --test privileged tun_kernel:: -- --test-threads=1.

use shoes_test_support::test_fixture::{
    ProcessGuard, RouteGuard, add_route_via_device, start_shoes_server_with_sudo,
};
use shoes_test_support::test_servers::{
    start_tcp_stream_echo_server, start_udp_echo_server_with_suffix,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Barrier, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

struct KernelTun {
    _route: RouteGuard,
    _process: ProcessGuard,
    _config: tempfile::NamedTempFile,
    source: IpAddr,
    target: IpAddr,
}

fn run_ip(args: &[&str]) -> io::Result<String> {
    let output = Command::new("sudo")
        .args(["-n", "ip"])
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "sudo -n ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl KernelTun {
    async fn start(ipv6: bool) -> io::Result<Self> {
        std::fs::metadata("/dev/net/tun")?;
        let id: u32 = rand::random();
        let name = format!("shcov{id:08x}");
        let (source, target, management, destination, loopback) = if ipv6 {
            let prefix = format!("fdab:{:x}:{:x}", id >> 16, id & 0xffff);
            (
                format!("{prefix}::1"),
                format!("{prefix}::2"),
                "10.203.254.1".to_string(),
                format!("{prefix}::2/128"),
                // NetLocation's YAML syntax uses unbracketed IPv6 with a final port.
                "::1:0",
            )
        } else {
            let subnet = (id % 250 + 1) as u8;
            (
                format!("10.203.{subnet}.1"),
                format!("10.203.{subnet}.2"),
                format!("10.203.{subnet}.1"),
                format!("10.203.{subnet}.2/32"),
                "127.0.0.1:0",
            )
        };
        let config = format!(
            r#"
- device_name: {name}
  address: "{management}"
  netmask: 255.255.255.255
  mtu: 1500
  rules:
    - masks: "{destination}"
      action: allow
      override_address: "{loopback}"
      client_chain:
        - protocol:
            type: direct
"#
        );
        let (process, config) = start_shoes_server_with_sudo(&config)?;
        timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(addresses) = run_ip(&["-j", "-4", "address", "show", "dev", &name]) {
                    let devices: serde_json::Value = serde_json::from_str(&addresses).unwrap();
                    if devices[0]["addr_info"].as_array().is_some_and(|addresses| {
                        addresses
                            .iter()
                            .any(|address| address["local"] == management)
                    }) {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUN interface did not appear"))?;
        if ipv6 {
            run_ip(&[
                "-6",
                "addr",
                "add",
                &format!("{source}/128"),
                "dev",
                &name,
                "nodad",
            ])?;
        }
        let route = add_route_via_device(&destination, &name)?;
        let family = if ipv6 { "-6" } else { "-4" };
        let lookup = run_ip(&["-j", family, "route", "get", &target, "from", &source])?;
        let routes: serde_json::Value = serde_json::from_str(&lookup)?;
        assert_eq!(routes[0]["dev"], name, "wrong TUN route: {lookup}");
        assert_ne!(routes[0]["type"], "local", "test traffic would bypass TUN");
        let tun = Self {
            _route: route,
            _process: process,
            _config: config,
            source: source.parse().unwrap(),
            target: target.parse().unwrap(),
        };
        // An interface address alone does not establish that the handlers are ready.
        let peer =
            start_udp_echo_server_with_suffix(if ipv6 { "::" } else { "0.0.0.0" }, 0, b"").await?;
        let socket = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await?;
        udp_exchange(
            &socket,
            SocketAddr::new(tun.target, peer.local_addr().port()),
            b"ready",
        )
        .await?;
        Ok(tun)
    }

    async fn connect_tcp(&self, port: u16) -> io::Result<TcpStream> {
        let socket = if self.source.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        socket.bind(SocketAddr::new(self.source, 0))?;
        socket.connect(SocketAddr::new(self.target, port)).await
    }
}

fn payload(flow: usize, sequence: usize, size: usize) -> Vec<u8> {
    let mut data = vec![0; size];
    for (offset, chunk) in data.chunks_mut(8).enumerate() {
        let value = ((flow as u64) << 48) | ((sequence as u64) << 32) | offset as u64;
        chunk.copy_from_slice(&value.to_be_bytes()[..chunk.len()]);
    }
    if size >= 16 {
        data[..8].copy_from_slice(&(flow as u64).to_be_bytes());
        data[8..16].copy_from_slice(&(sequence as u64).to_be_bytes());
    }
    data
}

async fn udp_exchange(socket: &UdpSocket, target: SocketAddr, data: &[u8]) -> io::Result<()> {
    assert_eq!(socket.send_to(data, target).await?, data.len());
    let mut received = vec![0; data.len() + 1];
    let (length, source) =
        timeout(Duration::from_secs(5), socket.recv_from(&mut received)).await??;
    assert_eq!(source, target);
    assert_eq!(&received[..length], data);
    Ok(())
}

async fn tcp_exchange(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(data).await?;
    let mut received = vec![0; data.len()];
    stream.read_exact(&mut received).await?;
    assert_eq!(received, data);
    Ok(())
}

async fn tcp_eof(stream: &mut TcpStream) -> io::Result<()> {
    stream.shutdown().await?;
    assert_eq!(
        stream.read(&mut [0]).await?,
        0,
        "surplus TCP data after half-close"
    );
    Ok(())
}

#[tokio::test]
async fn ipv6_udp_and_tcp_roundtrip_through_kernel_tun() -> io::Result<()> {
    timeout(TEST_TIMEOUT, async {
        let udp_peer = start_udp_echo_server_with_suffix("::", 0, b"").await?;
        let tcp_peer = start_tcp_stream_echo_server("::", 0).await?;
        let tun = KernelTun::start(true).await?;
        let socket = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await?;
        let target = SocketAddr::new(tun.target, udp_peer.local_addr().port());
        for (sequence, length) in [0, 1, 64, 1200, 0, 512].into_iter().enumerate() {
            udp_exchange(&socket, target, &payload(1, sequence, length)).await?;
        }
        let mut stream = tun.connect_tcp(tcp_peer.local_addr().port()).await?;
        for sequence in 0..16 {
            tcp_exchange(&mut stream, &payload(2, sequence, 32 * 1024)).await?;
        }
        tcp_eof(&mut stream).await
    })
    .await?
}

#[tokio::test]
async fn sustained_udp_preserves_all_flow_ids() -> io::Result<()> {
    timeout(TEST_TIMEOUT, async {
        let peer = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"").await?;
        let tun = KernelTun::start(false).await?;
        let target = SocketAddr::new(tun.target, peer.local_addr().port());
        let mut flows = JoinSet::new();
        for flow in 0..16 {
            let socket = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await?;
            flows.spawn(async move {
                for sequence in 0..512 {
                    let length = [64, 256, 1200][sequence % 3];
                    udp_exchange(&socket, target, &payload(flow, sequence, length)).await?;
                }
                io::Result::Ok(512)
            });
        }
        let mut received = 0;
        while let Some(result) = flows.join_next().await {
            received += result??;
        }
        assert_eq!(received, 16 * 512);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn tcp_and_udp_make_progress_during_overlapping_load() -> io::Result<()> {
    timeout(TEST_TIMEOUT, async {
        const TCP_FLOWS: usize = 8;
        const UDP_FLOWS: usize = 16;
        let tcp_peer = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let udp_peer = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"").await?;
        let tun = KernelTun::start(false).await?;
        let start = Arc::new(Barrier::new(TCP_FLOWS + UDP_FLOWS + 1));
        let (stop_tx, stop_rx) = watch::channel(false);
        let udp_in_flight = Arc::new(AtomicUsize::new(0));
        let udp_midpoint = Arc::new(Barrier::new(UDP_FLOWS));
        let tcp_progress: Arc<Vec<AtomicUsize>> =
            Arc::new((0..TCP_FLOWS).map(|_| AtomicUsize::new(0)).collect());
        let mut tcp = JoinSet::new();
        for flow in 0..TCP_FLOWS {
            let mut stream = tun.connect_tcp(tcp_peer.local_addr().port()).await?;
            tcp_exchange(&mut stream, &payload(flow, 0, 256)).await?;
            let start = start.clone();
            let stop = stop_rx.clone();
            let in_flight = udp_in_flight.clone();
            let tcp_progress = tcp_progress.clone();
            tcp.spawn(async move {
                start.wait().await;
                let mut sequence = 1;
                while !*stop.borrow() {
                    tcp_exchange(&mut stream, &payload(flow, sequence, 16 * 1024)).await?;
                    if in_flight.load(Ordering::Acquire) != 0 {
                        tcp_progress[flow].fetch_add(1, Ordering::Release);
                    }
                    sequence += 1;
                }
                tcp_eof(&mut stream).await
            });
        }
        let mut udp = JoinSet::new();
        for flow in 0..UDP_FLOWS {
            let socket = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await?;
            let target = SocketAddr::new(tun.target, udp_peer.local_addr().port());
            let start = start.clone();
            let udp_midpoint = udp_midpoint.clone();
            let in_flight = udp_in_flight.clone();
            udp.spawn(async move {
                start.wait().await;
                for sequence in 0..256 {
                    let data = payload(flow, sequence, 256);
                    let second_phase = sequence >= 128;
                    if second_phase {
                        in_flight.fetch_add(1, Ordering::AcqRel);
                    }
                    let result = udp_exchange(&socket, target, &data).await;
                    if second_phase {
                        in_flight.fetch_sub(1, Ordering::AcqRel);
                    }
                    result?;
                    if sequence == 127 {
                        udp_midpoint.wait().await;
                    }
                }
                io::Result::Ok(())
            });
        }
        start.wait().await;
        while let Some(result) = udp.join_next().await {
            result??;
        }
        assert_eq!(udp_in_flight.load(Ordering::Acquire), 0);
        for (flow, count) in tcp_progress.iter().enumerate() {
            assert!(
                count.load(Ordering::Acquire) > 0,
                "TCP flow {flow} made no progress with second-phase UDP exchanges in flight"
            );
        }
        stop_tx.send(true).unwrap();
        while let Some(result) = tcp.join_next().await {
            result??;
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn udp_progresses_while_a_tcp_reader_is_stalled() -> io::Result<()> {
    timeout(TEST_TIMEOUT, async {
        let tcp_peer = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let udp_peer = start_udp_echo_server_with_suffix("0.0.0.0", 0, b"").await?;
        let tun = KernelTun::start(false).await?;
        let mut stream = tun.connect_tcp(tcp_peer.local_addr().port()).await?;
        tcp_exchange(&mut stream, b"ready").await?;
        socket2::SockRef::from(&stream).set_recv_buffer_size(16 * 1024)?;
        let socket = UdpSocket::bind(SocketAddr::new(tun.source, 0)).await?;
        let target = SocketAddr::new(tun.target, udp_peer.local_addr().port());
        let data = payload(1, 0, 4 * 1024 * 1024);
        let (write_stalled_tx, write_stalled_rx) = tokio::sync::oneshot::channel();
        let (mut reader, mut writer) = stream.split();
        let sending = async {
            writer.write_all(&data[..64 * 1024]).await?;
            let remaining_write = writer.write_all(&data[64 * 1024..]);
            tokio::pin!(remaining_write);
            assert!(
                futures::poll!(remaining_write.as_mut()).is_pending(),
                "TCP write must stall before starting UDP"
            );
            let _ = write_stalled_tx.send(());
            remaining_write.await?;
            writer.shutdown().await
        };
        let receiving = async {
            write_stalled_rx.await.map_err(io::Error::other)?;
            for sequence in 0..128 {
                udp_exchange(&socket, target, &payload(2, sequence, 1200)).await?;
            }
            let mut received = vec![0; data.len()];
            reader.read_exact(&mut received).await?;
            assert_eq!(received, data);
            assert_eq!(reader.read(&mut [0]).await?, 0);
            io::Result::Ok(())
        };
        tokio::try_join!(sending, receiving)?;
        Ok(())
    })
    .await?
}
