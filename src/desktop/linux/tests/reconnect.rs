use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

pub(super) async fn policy_table_is_not_a_native_path() -> io::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(io::Error::other)?;
    let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
    let mark = spec(false).linux.bypass_mark;
    assert!(underlay::snapshot(&handle, 0, mark).await?.available());
    let mark_text = mark.to_string();
    for (family, gateway) in [("-4", "192.0.2.2"), ("-6", "fd00:1::2")] {
        run(
            "ip",
            &[
                family, "route", "add", "table", "100", "default", "via", gateway,
            ],
        )?;
        run(
            "ip",
            &[
                family, "rule", "add", "priority", "32000", "fwmark", &mark_text, "table", "100",
            ],
        )?;
    }
    let selected = underlay::snapshot(&handle, 0, mark).await;
    for family in ["-4", "-6"] {
        run(
            "ip",
            &[
                family, "rule", "del", "priority", "32000", "fwmark", &mark_text, "table", "100",
            ],
        )?;
        run("ip", &[family, "route", "flush", "table", "100"])?;
    }
    assert!(
        !selected?.available(),
        "policy-table route reported as a native default path"
    );
    assert!(underlay::snapshot(&handle, 0, mark).await?.available());
    Ok(())
}

pub(super) async fn echo() -> io::Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for address in ["198.51.100.2:19123", "[fd00:2::2]:19123"] {
        let tcp = tokio::net::TcpListener::bind(address).await?;
        let udp = tokio::net::UdpSocket::bind(address).await?;
        tasks.spawn(async move {
            let mut flows = tokio::task::JoinSet::new();
            loop {
                let (mut stream, peer) = tokio::select! {
                    result = tcp.accept() => result.unwrap(),
                    _ = flows.join_next(), if !flows.is_empty() => continue,
                };
                flows.spawn(async move {
                    let mut packet = [0; 4];
                    while stream.read_exact(&mut packet).await.is_ok() {
                        if &packet != b"ping" {
                            break;
                        }
                        if stream
                            .write_all(format!("{}\n", peer.ip()).as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
        tasks.spawn(async move {
            let mut packet = [0; 4];
            loop {
                let (_, peer) = udp.recv_from(&mut packet).await.unwrap();
                udp.send_to(peer.ip().to_string().as_bytes(), peer)
                    .await
                    .unwrap();
            }
        });
    }
    println!("Peer echo ready");
    tasks.join_next().await;
    Err(io::Error::other("echo service stopped"))
}

async fn line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
    expected: &str,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Err(io::Error::other(format!("child exited before {expected}")));
            }
            if line.contains(expected) {
                return Ok(());
            }
        }
    })
    .await?
}

async fn payload(sources: [&str; 2]) -> io::Result<()> {
    for (target, expected) in ["198.51.100.2:19123", "[fd00:2::2]:19123"]
        .into_iter()
        .zip(sources)
    {
        let mut stream = tokio::net::TcpStream::connect(target).await?;
        stream.write_all(b"ping").await?;
        let mut reader = tokio::io::BufReader::new(stream);
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut reply)).await??;
        assert_eq!(reply.trim(), expected);
        let udp = tokio::net::UdpSocket::bind(if target.starts_with('[') {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?;
        udp.send_to(b"ping", target).await?;
        let mut bytes = [0; 128];
        let length = tokio::time::timeout(Duration::from_secs(3), udp.recv(&mut bytes)).await??;
        assert_eq!(std::str::from_utf8(&bytes[..length]).unwrap(), expected);
    }
    Ok(())
}

fn identity() -> io::Result<serde_json::Value> {
    let links: serde_json::Value =
        serde_json::from_str(&run("ip", &["-j", "link", "show", "shoes0"])?)?;
    let tables: serde_json::Value = serde_json::from_str(&run("nft", &["-j", "list", "tables"])?)?;
    Ok(json!({"index":links[0]["ifindex"], "alias":links[0]["ifalias"], "tables":tables}))
}

pub(super) async fn handover(redirect: bool) -> io::Result<()> {
    run(
        "ip",
        &[
            "link", "add", "native1", "type", "veth", "peer", "name", "remote1",
        ],
    )?;
    for name in ["native1", "remote1"] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "0")?;
    }
    run("ip", &["link", "set", "remote1", "netns", "peer"])?;
    for args in [
        vec!["link", "set", "native1", "up"],
        vec!["addr", "add", "192.0.3.1/24", "dev", "native1"],
        vec![
            "-6",
            "addr",
            "add",
            "fd00:3::1/64",
            "dev",
            "native1",
            "nodad",
        ],
        vec!["-n", "peer", "link", "set", "remote1", "up"],
        vec![
            "-n",
            "peer",
            "addr",
            "add",
            "192.0.3.2/24",
            "dev",
            "remote1",
        ],
        vec![
            "-n",
            "peer",
            "-6",
            "addr",
            "add",
            "fd00:3::2/64",
            "dev",
            "remote1",
            "nodad",
        ],
    ] {
        run("ip", &args)?;
    }
    let mut peer = tokio::process::Command::new("ip")
        .args(["netns", "exec", "peer"])
        .arg(std::env::current_exe()?)
        .args(KERNEL_TEST_ARGS)
        .env("SHOES_MANAGED_PEER_ECHO", "1")
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    line(
        &mut tokio::io::BufReader::new(peer.stdout.take().unwrap()),
        "Peer echo ready",
    )
    .await?;
    let path = "/run/reconnect.yaml";
    let unix_path = "/run/reconnect.sock";
    let mut config = vec![
        serde_json::to_value(configuration(redirect))?,
        json!({"path":unix_path, "protocol":{"type":"socks"}}),
    ];
    std::fs::write(
        path,
        serde_yaml::to_string(&config).map_err(io::Error::other)?,
    )?;
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .args(KERNEL_TEST_ARGS)
        .env("SHOES_MANAGED_PROCESS_CONFIG", path)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    line(&mut stdout, "Servers ready").await?;
    let original = identity()?;
    payload(["192.0.2.1", "fd00:1::1"]).await?;
    let mut stale = tokio::net::TcpStream::connect("198.51.100.2:19123").await?;
    stale.write_all(b"ping").await?;
    let mut stale = tokio::io::BufReader::new(stale);
    let mut reply = String::new();
    stale.read_line(&mut reply).await?;
    run("ip", &["link", "add", "unused0", "type", "dummy"])?;
    run("ip", &["link", "set", "unused0", "up"])?;
    run("ip", &["addr", "add", "192.0.99.1/24", "dev", "unused0"])?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    stale.write_all(b"ping").await?;
    reply.clear();
    tokio::time::timeout(Duration::from_secs(3), stale.read_line(&mut reply)).await??;
    assert_eq!(
        reply.trim(),
        "192.0.2.1",
        "unrelated interface churn reset a live flow"
    );
    run("ip", &["link", "del", "unused0"])?;
    std::fs::write(path, "invalid: [")?;
    run("ip", &["route", "replace", "default", "via", "192.0.3.2"])?;
    run(
        "ip",
        &["-6", "route", "replace", "default", "via", "fd00:3::2"],
    )?;
    line(&mut stdout, "Network reconnected").await?;
    assert_eq!(identity()?, original);
    let result = tokio::time::timeout(Duration::from_secs(3), stale.read(&mut [0])).await?;
    assert!(matches!(result, Ok(0)) || result.is_err(), "{result:?}");
    payload(["192.0.3.1", "fd00:3::1"]).await?;

    // Both families disappear and return unchanged; recovery must not require a new config.
    run("ip", &["route", "del", "default"])?;
    run("ip", &["-6", "route", "del", "default"])?;
    line(&mut stdout, "Network unavailable; waiting for underlay").await?;
    assert!(child.try_wait()?.is_none());
    assert_eq!(identity()?, original);
    // A retryable bind failure must not remove capture or block a correcting reload.
    std::fs::remove_file(unix_path)?;
    std::fs::create_dir(unix_path)?;
    run("ip", &["route", "add", "default", "via", "192.0.3.2"])?;
    run("ip", &["-6", "route", "add", "default", "via", "fd00:3::2"])?;
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3),
            line(&mut stdout, "Network reconnected")
        )
        .await
        .is_err()
    );
    assert!(child.try_wait()?.is_none());
    assert_eq!(identity()?, original);
    config.pop();
    config.push(json!({"address":"127.0.0.1:19124", "protocol":{"type":"socks"}}));
    std::fs::write(
        path,
        serde_yaml::to_string(&config).map_err(io::Error::other)?,
    )?;
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGHUP) },
        0
    );
    line(&mut stdout, "Network reconnected").await?;
    line(&mut stdout, "Servers ready").await?;
    assert!(std::path::Path::new(unix_path).is_dir());
    std::fs::remove_dir(unix_path)?;
    let mut socks = tokio::net::TcpStream::connect("127.0.0.1:19124").await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    tokio::time::timeout(Duration::from_secs(3), socks.read_exact(&mut greeting)).await??;
    assert_eq!(greeting, [5, 0]);
    drop(socks);
    payload(["192.0.3.1", "fd00:3::1"]).await?;

    // Same-interface source replacement within the existing subnet.
    run("ip", &["addr", "add", "192.0.3.9/24", "dev", "native1"])?;
    run(
        "ip",
        &[
            "route",
            "replace",
            "default",
            "via",
            "192.0.3.2",
            "src",
            "192.0.3.9",
        ],
    )?;
    run(
        "ip",
        &[
            "-6",
            "addr",
            "add",
            "fd00:3::9/64",
            "dev",
            "native1",
            "nodad",
        ],
    )?;
    run(
        "ip",
        &[
            "-6",
            "route",
            "replace",
            "default",
            "via",
            "fd00:3::2",
            "src",
            "fd00:3::9",
        ],
    )?;
    line(&mut stdout, "Network reconnected").await?;
    payload(["192.0.3.9", "fd00:3::9"]).await?;
    assert_eq!(identity()?, original);
    // Multipath defaults use nested nexthops even with only one eligible path.
    run(
        "ip",
        &[
            "route",
            "replace",
            "default",
            "src",
            "192.0.3.9",
            "nexthop",
            "via",
            "192.0.3.2",
            "dev",
            "native1",
        ],
    )?;
    run(
        "ip",
        &[
            "-6",
            "route",
            "replace",
            "default",
            "src",
            "fd00:3::9",
            "nexthop",
            "via",
            "fd00:3::2",
            "dev",
            "native1",
        ],
    )?;
    run("ip", &["link", "set", "native1", "down"])?;
    run("ip", &["link", "set", "native1", "up"])?;
    // Link-down can remove IPv6 addresses; restore the same lease before its default.
    for address in ["fd00:3::1/64", "fd00:3::9/64"] {
        run(
            "ip",
            &["-6", "addr", "replace", address, "dev", "native1", "nodad"],
        )?;
    }
    run(
        "ip",
        &[
            "route",
            "replace",
            "default",
            "src",
            "192.0.3.9",
            "nexthop",
            "via",
            "192.0.3.2",
            "dev",
            "native1",
        ],
    )?;
    run(
        "ip",
        &[
            "-6",
            "route",
            "replace",
            "default",
            "src",
            "fd00:3::9",
            "nexthop",
            "via",
            "fd00:3::2",
            "dev",
            "native1",
        ],
    )?;
    line(&mut stdout, "Network reconnected").await?;
    payload(["192.0.3.9", "fd00:3::9"]).await?;
    run("ip", &["route", "del", "default"])?;
    run("ip", &["-6", "route", "del", "default"])?;
    line(&mut stdout, "Network unavailable; waiting for underlay").await?;
    assert_eq!(
        unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) },
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await??
            .success()
    );
    peer.kill().await?;
    peer.wait().await?;
    run("ip", &["link", "del", "native1"])?;
    run("ip", &["route", "replace", "default", "via", "192.0.2.2"])?;
    run(
        "ip",
        &["-6", "route", "replace", "default", "via", "fd00:1::2"],
    )?;
    Ok(())
}
