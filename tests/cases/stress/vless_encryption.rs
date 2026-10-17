use std::{
    io,
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::json;
use shoes_test_support::process::ProcessGuard;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{interval, timeout},
};

const LIMIT: Duration = Duration::from_secs(20);

async fn port() -> u16 {
    TcpListener::bind("0.0.0.0:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn connect(proxy: u16, target: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS authentication failed"));
    }
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err(io::Error::other("SOCKS connect failed"));
    }
    let size = match reply[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err(io::Error::other("invalid SOCKS reply")),
    };
    stream.read_exact(&mut vec![0; size + 2]).await?;
    Ok(stream)
}

async fn probe(proxy: u16, target: u16) -> io::Result<TcpStream> {
    let mut stream = connect(proxy, target).await?;
    stream.write_all(b"probe").await?;
    let mut reply = [0; 5];
    stream.read_exact(&mut reply).await?;
    if &reply != b"probe" {
        return Err(io::Error::other("probe payload mismatch"));
    }
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn high_water_kib(pid: u32) -> usize {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn vless_encryption_pressure_cancellation_and_slow_duplex_remain_bounded() {
    timeout(Duration::from_secs(180), run()).await.unwrap();
}

async fn run() {
    for mode in ["native", "xorpub", "random"] {
        let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args([
                "generate-vless-encryption",
                "--mode",
                mode,
                "--auth",
                "x25519",
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let settings: serde_yaml::Value = serde_yaml::from_slice(&output.stdout).unwrap();
        let padding = |field: &str| {
            let mut parts: Vec<_> = settings[field].as_str().unwrap().split('.').collect();
            parts.insert(3, "100-35-35");
            parts.join(".")
        };
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (mut stream, _) = result.unwrap();
                        clients.spawn(async move {
                            let (mut read, mut write) = stream.split();
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        });
                    }
                    _ = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        let server_port = port().await;
        let proxy = port().await;
        let directory = tempfile::Builder::new()
            .prefix("vless-stress-")
            .tempdir_in(std::env::var_os("HOME").unwrap())
            .unwrap();
        let path = directory.path().join("config.json");
        let user = "550e8400-e29b-41d4-a716-446655440000";
        let config = json!([
            {"address": format!("0.0.0.0:{server_port}"), "protocol": {
                "type": "vless", "user_id": user, "vision": true,
                "decryption": padding("decryption"),
                "encryption_limits": {"max_sessions": 8, "max_replays": 16, "max_replays_per_session": 4},
            }},
            {"address": format!("0.0.0.0:{proxy}"), "protocol": {"type": "socks"}, "rules": [{
                "masks": "0.0.0.0/0", "action": "allow", "client_chain": {
                    "address": format!("127.0.0.1:{server_port}"), "protocol": {
                        "type": "vless", "user_id": user, "vision": true, "encryption": padding("encryption"),
                    },
                },
            }]},
        ]);
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log_path = directory.path().join("shoes.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
            .args(["--threads", "1", "--no-reload"])
            .arg(path)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut process = ProcessGuard::new(child, format!("vless-stress-{mode}"));
        timeout(LIMIT, async {
            let mut delay = interval(Duration::from_millis(10));
            loop {
                assert!(
                    process.try_wait().unwrap().is_none(),
                    "{}",
                    std::fs::read_to_string(&log_path).unwrap()
                );
                if probe(proxy, target).await.is_ok() {
                    break;
                }
                delay.tick().await;
            }
        })
        .await
        .unwrap();
        #[cfg(target_os = "linux")]
        let initial_memory = high_water_kib(process.id());

        let mut failures = 0;
        let mut rate = interval(Duration::from_millis(2));
        for _ in 0..256 {
            rate.tick().await;
            if timeout(LIMIT, probe(proxy, target)).await.unwrap().is_err() {
                failures += 1;
                // A capacity failure rejects this request; the next independent request must recover.
                timeout(LIMIT, probe(proxy, target)).await.unwrap().unwrap();
            }
            let mut abandoned = TcpStream::connect(("127.0.0.1", server_port))
                .await
                .unwrap();
            abandoned.write_all(&[0; 17]).await.unwrap();
        }
        assert!(
            failures > 16,
            "replay pressure was not exercised: {failures}"
        );

        for _ in 0..4 {
            let mut transfers = JoinSet::new();
            // Establish sequentially so deliberate cache invalidations do not mask transfer failures.
            for index in 0..16u8 {
                let stream = match timeout(LIMIT, probe(proxy, target)).await.unwrap() {
                    Ok(stream) => stream,
                    Err(_) => timeout(LIMIT, probe(proxy, target)).await.unwrap().unwrap(),
                };
                transfers.spawn(async move {
                    let (mut read, mut write) = stream.into_split();
                    let data = [index; 16384];
                    let transfer = async {
                        tokio::try_join!(
                            async {
                                for _ in 0..128 {
                                    write.write_all(&data).await?;
                                }
                                write.shutdown().await
                            },
                            async {
                                let mut reply = [0; 16384];
                                for block in 0..128 {
                                    read.read_exact(&mut reply).await?;
                                    assert_eq!(reply, data);
                                    if block % 16 == 0 {
                                        tokio::time::sleep(Duration::from_millis(1)).await;
                                    }
                                }
                                Ok::<_, io::Error>(())
                            }
                        )?;
                        Ok::<_, io::Error>(())
                    };
                    if index % 4 == 0 {
                        assert!(timeout(Duration::from_millis(1), transfer).await.is_err());
                    } else {
                        timeout(LIMIT, transfer).await.unwrap().unwrap();
                    }
                });
            }
            while let Some(result) = transfers.join_next().await {
                result.unwrap();
            }
        }
        // New handshakes must remain available after all cancelled and slow connections.
        if timeout(LIMIT, probe(proxy, target)).await.unwrap().is_err() {
            timeout(LIMIT, probe(proxy, target)).await.unwrap().unwrap();
        }
        assert!(
            std::fs::read_to_string(log_path)
                .unwrap()
                .contains("VLESS encryption cache capacity reached")
        );
        #[cfg(target_os = "linux")]
        {
            let peak = high_water_kib(process.id());
            eprintln!(
                "{mode}: {failures} capacity failures recovered; VmHWM {initial_memory} -> {peak} KiB"
            );
            assert!(
                peak.saturating_sub(initial_memory) < 64 * 1024,
                "unbounded memory growth"
            );
        }
        tasks.shutdown().await;
    }
}
