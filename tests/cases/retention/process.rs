use super::*;
use shoes_test_support::measure::settle;
use shoes_test_support::test_servers::start_tcp_stream_echo_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CLEANUP: Duration = Duration::from_secs(5);

#[path = "quic.rs"]
mod quic;

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    tasks: usize,
    fds: Option<usize>,
    connections: usize,
    streams: usize,
    quic_bytes: usize,
}

fn sample() -> Snapshot {
    let resources = resources::snapshot();
    #[cfg(target_os = "linux")]
    let fds = Some(
        shoes_test_support::measure::process_usage(std::process::id())
            .unwrap()
            .fds,
    );
    #[cfg(not(target_os = "linux"))]
    let fds = None;
    Snapshot {
        tasks: tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        fds,
        connections: resources.connections.active,
        streams: resources.streams.active,
        quic_bytes: resources.quic_buffer_bytes.active,
    }
}

async fn restored(label: &str, expected: &Snapshot) {
    let actual = settle(label, CLEANUP, sample, |value| value == expected).await;
    #[cfg(target_os = "linux")]
    let rss = Some(
        shoes_test_support::measure::process_usage(std::process::id())
            .unwrap()
            .rss_kib,
    );
    #[cfg(not(target_os = "linux"))]
    let rss: Option<usize> = None;
    println!("state={label} {actual:?} rss_kib={rss:?} (informational)");
}

async fn connect(port: u16) -> TcpStream {
    timeout(CLEANUP, TcpStream::connect(("127.0.0.1", port)))
        .await
        .unwrap()
        .unwrap()
}

async fn echo(stream: &mut TcpStream, cycle: usize) {
    let bytes = format!("retention-cycle-{cycle:04}\0exact-payload");
    timeout(CLEANUP, async {
        stream.write_all(bytes.as_bytes()).await.unwrap();
        let mut reply = vec![0; bytes.len()];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, bytes.as_bytes());
    })
    .await
    .unwrap();
}

async fn closed(stream: &mut TcpStream) {
    let result = timeout(CLEANUP, stream.read(&mut [0]))
        .await
        .expect("peer did not close within cleanup deadline");
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("expected EOF/reset, got {other:?}"),
    }
}

fn run_isolated(name: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("SHOES_RETENTION_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated child failed: {}",
        output.status
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("test result: ok. 1 passed;")),
        "isolated child did not run exactly one test"
    );
}

#[test]
#[should_panic(expected = "isolated child did not run exactly one test")]
fn isolated_child_rejects_empty_filter() {
    run_isolated("process::retention_tests::nonexistent_test");
}

#[test]
fn repeated_setup_cancellation_reload_and_owner_drop_restore_resources() {
    // Global budgets and /proc/self/fd cannot be measured alongside other libtests.
    const NAME: &str = "process::retention_tests::repeated_setup_cancellation_reload_and_owner_drop_restore_resources";
    if std::env::var_os("SHOES_RETENTION_CHILD").is_none() {
        run_isolated(NAME);
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { timeout(Duration::from_secs(90), exercise()).await.unwrap() });
}

async fn exercise() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retention.json");
    let paths = [path.to_str().unwrap().to_owned()];
    let echo_server = start_tcp_stream_echo_server("0.0.0.0", 0).await.unwrap();
    let forward_reservation = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let socks_reservation = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let forward = forward_reservation.local_addr().unwrap().port();
    let socks = socks_reservation.local_addr().unwrap().port();
    let occupied = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    drop((forward_reservation, socks_reservation));
    let config = serde_json::json!([
        {"global_limits": {"reload_grace_secs": 1, "max_connections": 4, "max_streams": 4}},
        {"address": format!("0.0.0.0:{forward}"), "protocol": {"type": "forward", "target": format!("127.0.0.1:{}", echo_server.local_addr().port())}},
        {"address": format!("0.0.0.0:{socks}"), "protocol": {"type": "socks"}}
    ]);
    let baseline = sample();
    assert_eq!(baseline.connections, 0);
    assert_eq!(baseline.streams, 0);
    assert_eq!(baseline.quic_bytes, 0);
    println!("cycles=12 grace_secs=1 cleanup_secs=5 baseline={baseline:?}");
    for cycle in 0..12 {
        let mut invalid = config.clone();
        invalid.as_array_mut().unwrap().push(serde_json::json!({
            "address": occupied.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}
        }));
        std::fs::write(&path, invalid.to_string()).unwrap();
        let mut prepared = prepare(&paths, None).await.unwrap();
        let mut running = RunningServers::default();
        assert_eq!(
            running.start(&mut prepared).await.unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop((running, prepared));
        restored("failed_partial_start", &baseline).await;

        std::fs::write(&path, config.to_string()).unwrap();
        let mut prepared = prepare(&paths, None).await.unwrap();
        let mut running = RunningServers::default();
        running.start(&mut prepared).await.unwrap();
        let idle = sample();
        for _ in 0..4 {
            let mut rejected = connect(socks).await;
            rejected.write_all(&[0]).await.unwrap();
            closed(&mut rejected).await;
            drop(rejected);
            restored("failed_handshake", &idle).await;
            let mut cancelled = connect(socks).await;
            cancelled.write_all(&[5]).await.unwrap();
            settle("stalled handshake admitted", CLEANUP, sample, |s| {
                s.connections == 1 && s.streams == 1
            })
            .await;
            drop(cancelled);
            restored("cancelled_handshake", &idle).await;
        }

        let mut live = connect(forward).await;
        echo(&mut live, cycle).await;
        let mut stalled = connect(socks).await;
        stalled.write_all(&[5]).await.unwrap();
        settle("live and stalled sessions", CLEANUP, sample, |s| {
            s.connections == 2 && s.streams == 2
        })
        .await;
        let mut candidate = prepare(&paths, Some(&prepared.dns)).await.unwrap();
        candidate.tcp =
            TcpListeners::prepare(&candidate.validated.configs, &prepared.tcp, &[]).unwrap();
        running.stop().await;
        prepared.tcp.retain_shared(&candidate.tcp);
        running.start(&mut candidate).await.unwrap();
        candidate.tcp.activate();
        drop(prepared);
        echo(&mut live, cycle).await;
        let mut replacement = connect(forward).await;
        echo(&mut replacement, cycle + 1).await;
        drop(replacement);
        closed(&mut live).await;
        closed(&mut stalled).await;
        drop((live, stalled));
        restored("reload_drained", &idle).await;

        let mut live = connect(forward).await;
        echo(&mut live, cycle).await;
        let mut stalled = connect(socks).await;
        stalled.write_all(&[5]).await.unwrap();
        settle("owner has active work", CLEANUP, sample, |s| {
            s.connections == 2 && s.streams == 2
        })
        .await;
        drop((running, candidate));
        closed(&mut live).await;
        closed(&mut stalled).await;
        drop((live, stalled));
        restored("owner_destroyed", &baseline).await;
        // SO_REUSEADDR allows TCP TIME_WAIT, not another live listener.
        for port in [forward, socks] {
            drop(
                crate::socket_util::new_tcp_listener(([0, 0, 0, 0], port).into(), 128, None)
                    .unwrap(),
            );
        }
    }
    quic::exercise(&baseline).await;
}
