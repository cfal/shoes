use super::start_from_config;
use serde_json::json;
use std::{io, os::fd::AsRawFd, os::unix::net::UnixDatagram, time::Duration};
use tokio::{net::UdpSocket, sync::oneshot, time::timeout};

#[tokio::test]
async fn invalid_sources_fail_before_ffi_opens_listeners_or_tun() {
    let dir = tempfile::tempdir().unwrap();
    let corrupt = dir.path().join("corrupt.srs");
    std::fs::write(&corrupt, b"SRS\x02").unwrap();
    let (_wire, tun) = UnixDatagram::pair().unwrap();
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let flags = unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFL) };
    for (path, message) in [
        (dir.path().join("missing.srs"), "missing.srs"),
        (corrupt, "corrupt.srs"),
        ("relative.srs".into(), "must be absolute for string configs"),
    ] {
        for named in [false, true] {
            let mut configs = Vec::new();
            let masks = if named {
                configs.push(json!({"rule_group": "source", "rule": {"path": path}}));
                json!({"rule_group": "source"})
            } else {
                json!({"path": path})
            };
            configs.push(json!({"device_fd": tun.as_raw_fd(), "rules": [{"masks": masks}]}));
            configs.push(json!({
                "address": listener.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}
            }));
            let (_shutdown, shutdown_rx) = oneshot::channel();
            let error = timeout(
                Duration::from_secs(5),
                start_from_config(&serde_json::to_string(&configs).unwrap(), shutdown_rx),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(
                error.to_string().contains(message),
                "named={named}: {error}"
            );
            assert_eq!(
                error.kind(),
                if path.is_absolute() && !path.exists() {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
            assert_eq!(
                unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFL) },
                flags,
                "source rejection changed the caller's TUN descriptor"
            );
        }
    }
}

#[test]
fn ffi_sources_route_tun_packets_and_preserve_the_borrowed_fd() {
    const CHILD: &str = "SHOES_FFI_RULE_SOURCES_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ffi::common::rule_source_tests::ffi_sources_route_tun_packets_and_preserve_the_borrowed_fd", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "FFI source test failed: {}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("list.srs");
    std::fs::write(
        &path,
        include_bytes!("../../tests/fixtures/rule_sets/singbox-v2.srs"),
    )
    .unwrap();
    runtime.block_on(async {
        for named in [false, true] {
            timeout(Duration::from_secs(10), route_source(&path, named))
                .await
                .expect("FFI source routing stalled");
        }
    });
}

async fn route_source(path: &std::path::Path, named: bool) {
    let (wire, tun) = UnixDatagram::pair().unwrap();
    wire.set_nonblocking(true).unwrap();
    let wire = tokio::net::UnixDatagram::from_std(wire).unwrap();
    let echo = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let mut configs = Vec::new();
    let masks = if named {
        configs.push(json!({"rule_group": "source", "rule": path}));
        json!({"rule_group": "source"})
    } else {
        json!({"path": path})
    };
    configs.push(json!({
        "device_fd": tun.as_raw_fd(), "packet_information": false,
        "rules": [{"masks": masks,
            "override_address": format!("127.0.0.1:{}", echo.local_addr().unwrap().port())}, "block-all"]
    }));
    let config = serde_json::to_string(&configs).unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let mut service = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        start_from_config(&config, shutdown_rx).await
    }));
    let packet = |destination, port, payload: &[u8]| {
        let mut bytes = Vec::new();
        etherparse::PacketBuilder::ipv4([10, 23, 0, 2], destination, 64)
            .udp(12001, port)
            .write(&mut bytes, payload)
            .unwrap();
        bytes
    };
    wire.send(&packet([192, 0, 2, 1], 443, b"allowed"))
        .await
        .unwrap();
    let mut bytes = [0; 2048];
    let (length, peer) = tokio::select! {
        result = &mut service => panic!("FFI service exited before routing: {result:?}"),
        result = echo.recv_from(&mut bytes) => result.unwrap(),
    };
    assert_eq!(&bytes[..length], b"allowed");
    echo.send_to(&bytes[..length], peer).await.unwrap();
    let length = wire.recv(&mut bytes).await.unwrap();
    let ip = smoltcp::wire::Ipv4Packet::new_checked(&bytes[..length]).unwrap();
    assert_eq!(ip.src_addr().octets(), [192, 0, 2, 1]);
    assert_eq!(ip.dst_addr().octets(), [10, 23, 0, 2]);
    let udp = smoltcp::wire::UdpPacket::new_checked(ip.payload()).unwrap();
    assert_eq!((udp.src_port(), udp.dst_port()), (443, 12001));
    assert_eq!(udp.payload(), b"allowed");

    wire.send(&packet([198, 51, 100, 1], 443, b"blocked IP"))
        .await
        .unwrap();
    wire.send(&packet([192, 0, 2, 1], 80, b"blocked port"))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(250), echo.recv_from(&mut bytes))
            .await
            .is_err(),
        "unmatched TUN packet reached the override target"
    );
    wire.send(&packet([192, 0, 2, 1], 443, b"still usable"))
        .await
        .unwrap();
    let (length, _) = echo.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..length], b"still usable");
    shutdown.send(()).unwrap();
    service.await.unwrap().unwrap();
    assert!(
        unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFD) } >= 0,
        "FFI closed the caller's TUN descriptor"
    );
}
