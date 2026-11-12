use super::*;

#[cfg(unix)]
use hickory_resolver::proto::{
    op::Message,
    rr::{RData, Record, rdata},
};

#[cfg(unix)]
fn signal(signal: i32) {
    assert_eq!(unsafe { libc::kill(std::process::id() as i32, signal) }, 0);
}

#[cfg(unix)]
fn loopback_dns_reply(request: Message) -> Vec<u8> {
    let mut reply = request.into_response();
    reply.add_answer(Record::from_rdata(
        reply.queries[0].name().clone(),
        300,
        RData::A(rdata::A::new(127, 0, 0, 1)),
    ));
    reply.to_vec().unwrap()
}

#[cfg(unix)]
async fn ntp_reply(
    socket: &tokio::net::UdpSocket,
    request: [u8; 48],
    peer: std::net::SocketAddr,
    offset_secs: u64,
) {
    let mut response = [0; 48];
    response[0] = 0x24;
    response[1] = 1;
    response[3] = (-20i8) as u8;
    response[24..32].copy_from_slice(&request[40..48]);
    let timestamp = (u64::from_be_bytes(request[40..48].try_into().unwrap()) + (offset_secs << 32))
        .to_be_bytes();
    response[32..40].copy_from_slice(&timestamp);
    response[40..48].copy_from_slice(&timestamp);
    socket.send_to(&response, peer).await.unwrap();
}

#[cfg(unix)]
async fn wait_for_socks(address: std::net::SocketAddr) -> tokio::net::TcpStream {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(address).await {
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn ntp_initial_sync_precedes_deferred_certificate_binds() {
    const CHILD: &str = "SHOES_NTP_DEFERRED_BIND_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "process::tests::ntp_initial_sync_precedes_deferred_certificate_binds",
            CHILD,
            "1",
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let challenge = occupied.local_addr().unwrap();
    let ntp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let old =
        serde_json::json!([{"address": challenge.to_string(), "protocol": {"type": "socks"}}]);
    std::fs::write(&path, old.to_string()).unwrap();
    let paths = [path.to_str().unwrap().to_owned()];
    let previous = prepare(&paths, None).await.unwrap();
    let config = serde_json::json!([
        {"global_settings": {"ntp": {"server": ntp.local_addr().unwrap().to_string(), "timeout_secs": 1}}},
        {"certificate_source": "managed", "type": "acme", "domains": ["proxy.test"],
         "directory_url": "http://127.0.0.1:9/directory", "state_dir": directory.path().join("state"),
         "challenge": {"type": "http01", "listen": [challenge.to_string()]}},
        {"address": "127.0.0.1:0", "protocol": {"type": "tls", "default_tls_target": {
            "certificate_source": "managed", "protocol": {"type": "socks"}}}}
    ]);
    std::fs::write(&path, config.to_string()).unwrap();
    let mut candidate = prepare_tracking(
        &paths,
        config::load_config_files(&paths).await.unwrap(),
        Some(&previous.dns),
        Some(&previous),
        &mut |_, _, _| {},
        &mut None,
        &crate::desktop::NetworkSession::default().topology(),
    )
    .await
    .unwrap();
    let mut packet = [0; 48];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), ntp.recv_from(&mut packet))
            .await
            .is_err()
    );
    let mut running = RunningServers::default();
    let error = running.start(&mut candidate).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    assert!(error.to_string().contains("HTTP-01 bind"), "{error}");
    tokio::time::timeout(Duration::from_secs(1), ntp.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    running.shutdown(&[&candidate, &previous]).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn network_reconciliation_does_not_cancel_inflight_refresh() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let cache = root.join("cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = cache.join("rules.json");
        std::fs::write(&path, br#"{"version":1,"rules":[{"domain":["old.example"]}]}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(
            std::time::SystemTime::UNIX_EPOCH
        ).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = root.join("config.yaml");
        std::fs::write(&config, serde_json::json!([
            {"global_settings": {"rule_cache_dir": cache}},
            {"address":"127.0.0.1:0", "protocol":{"type":"socks"}, "rules":[{
                "masks":{"path":path, "url":format!("http://{}/rules.json", listener.local_addr().unwrap()),
                    "download":{"client_chain":"direct", "bootstrap_url":"system"}, "update_interval":"7d"},
                "action":"block"
            }]}
        ]).to_string()).unwrap();
        let mut prepared = prepare(&[config.to_str().unwrap().into()], None).await.unwrap();
        let (events, receiver) = mpsc::channel(1);
        let (ack, mut reconciled) = mpsc::channel(1);
        let mut network = crate::desktop::NetworkSession::with_test_events(receiver, ack);
        let body = br#"{"version":1,"rules":[{"domain":["new.example"]}]}"#;
        let fixture = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            for _ in 0..3 {
                events.send(None).await.unwrap();
                reconciled.recv().await.unwrap();
            }
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            result = wait_with_reconciliation(remote_rule_change(&mut prepared), &mut network) => result.unwrap().unwrap(),
            _ = fixture => unreachable!(),
        }
        assert_eq!(std::fs::read(path).unwrap(), body);
    }).await.unwrap();
}

#[tokio::test]
async fn underlay_change_interrupts_the_wait_without_consuming_a_reload() {
    let (events, receiver) = mpsc::channel(1);
    let (ack, _reconciled) = mpsc::channel(1);
    let mut network = crate::desktop::NetworkSession::with_test_events(receiver, ack);
    events.send(Some(true)).await.unwrap();
    assert!(
        wait_with_reconciliation(std::future::pending::<()>(), &mut network)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn reconnect_loop_defers_offline_reload_and_accepts_repairs_after_failed_start() {
    const NAME: &str = "process::tests::reconnect_loop_defers_offline_reload_and_accepts_repairs_after_failed_start";
    const CHILD: &str = "SHOES_RECONNECT_LOOP_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        shoes_test_support::isolated::assert_one_test_passed(&output);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Reload rejected; recovery will retry previous configuration:")
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Reload rejected; workers unavailable, recovery continues:")
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr)
                .contains("Reload rejected; previous servers restored:")
        );
        return;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let unix = directory.path().join("listener.sock");
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = first.local_addr().unwrap();
        let added = second.local_addr().unwrap();
        let mut config = vec![
            serde_json::json!({"address":address.to_string(), "protocol":{"type":"socks"}}),
            serde_json::json!({"path":unix, "protocol":{"type":"socks"}}),
        ];
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        drop((first, second));
        let (events, receiver) = mpsc::channel(1);
        let (ack, mut reconciled) = mpsc::channel(1);
        let network = crate::desktop::NetworkSession::with_test_events(receiver, ack);
        let process = crate::desktop::TEST_NETWORK.scope(
            std::cell::RefCell::new(Some(network)),
            Box::pin(run(vec![path.to_string_lossy().into_owned()], false, true)),
        );
        tokio::pin!(process);
        let fixture = async {
            let mut live = wait_for_socks(address).await;
            events.send(Some(false)).await.unwrap();
            reconciled.recv().await.unwrap();
            assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
            config.push(
                serde_json::json!({"address":added.to_string(), "protocol":{"type":"socks"}}),
            );
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            signal(libc::SIGHUP);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(tokio::net::TcpStream::connect(added).await.is_err());
            events.send(Some(true)).await.unwrap();
            let mut live = wait_for_socks(added).await;

            events.send(Some(false)).await.unwrap();
            assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
            config.push(serde_json::json!({"path":directory.path(), "protocol":{"type":"socks"}}));
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            signal(libc::SIGHUP);
            tokio::time::sleep(Duration::from_millis(100)).await;
            events.send(Some(true)).await.unwrap();
            // Recovery must retry the accepted config without another reload of the rejected file.
            let mut live = wait_for_socks(added).await;
            config.pop();

            events.send(Some(false)).await.unwrap();
            assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
            std::fs::remove_file(&unix).unwrap();
            std::fs::create_dir(&unix).unwrap();
            events.send(Some(true)).await.unwrap();
            // A non-AddrInUse startup error must keep retrying while reload remains usable.
            tokio::time::sleep(Duration::from_millis(2300)).await;
            let mut queued = tokio::net::TcpStream::connect(address).await.unwrap();
            queued.write_all(&[5, 1, 0]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), queued.read_u8())
                    .await
                    .is_err()
            );
            std::fs::write(&path, "invalid: [").unwrap();
            signal(libc::SIGHUP);
            assert!(
                tokio::time::timeout(Duration::from_secs(1), queued.read_u8())
                    .await
                    .is_err()
            );
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            signal(libc::SIGHUP);
            // An unchanged reload fails activation, but must not end recovery.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), queued.read_u8())
                    .await
                    .is_err()
            );
            config.remove(1);
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            signal(libc::SIGHUP);
            assert_eq!(queued.read_u8().await.unwrap(), 5);
            assert_eq!(queued.read_u8().await.unwrap(), 0);
            assert!(unix.is_dir());
            let mut live = wait_for_socks(added).await;
            events.send(Some(false)).await.unwrap();
            assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
            signal(libc::SIGTERM);
        };
        tokio::select! {
            result = &mut process => panic!("process exited before recovery: {result:?}"),
            _ = fixture => {},
        }
        process.await.unwrap();
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn reconnect_respects_dns_deadlines_and_remains_shutdown_cancellable() {
    const NAME: &str =
        "process::tests::reconnect_respects_dns_deadlines_and_remains_shutdown_cancellable";
    const CHILD: &str = "SHOES_RECONNECT_DNS_DEADLINE_TEST";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(NAME, CHILD, "1");
        return;
    }
    use hickory_resolver::proto::rr::RecordType;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use tokio::io::AsyncReadExt;
    use tokio_util::task::AbortOnDropHandle;

    for repair_reload in [false, true] {
        tokio::time::timeout(Duration::from_secs(30), async {
            let dns = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let dns_address = dns.local_addr().unwrap();
            let delay = Arc::new(AtomicU64::new(0));
            let response_delay = delay.clone();
            let (requested, mut requests) = mpsc::unbounded_channel();
            let _dns = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut responses = tokio::task::JoinSet::new();
                let mut bytes = [0; 1500];
                loop {
                    let (length, peer) = tokio::select! {
                        result = dns.recv_from(&mut bytes) => result.unwrap(),
                        _ = responses.join_next(), if !responses.is_empty() => continue,
                    };
                    let request = Message::from_vec(&bytes[..length]).unwrap();
                    assert_eq!(request.queries[0].query_type, RecordType::A);
                    let bytes = loopback_dns_reply(request);
                    let socket = dns.clone();
                    let delay = Duration::from_secs(response_delay.load(Ordering::Relaxed));
                    requested.send(()).unwrap();
                    responses.spawn(async move {
                        tokio::time::sleep(delay).await;
                        socket.send_to(&bytes, peer).await.unwrap();
                    });
                }
            }));
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reserved.local_addr().unwrap();
            let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let added = second.local_addr().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.json");
            let mut config = vec![
                serde_json::json!({"dns_group":"bootstrap", "dns_servers":[{
                    "url":format!("udp://{dns_address}"), "timeout_secs":20,
                    "ip_strategy":"ipv4_only", "attempts":1
                }]}),
                serde_json::json!({"dns_group":"upstream", "dns_servers":[{
                    "url":"udp://upstream.test", "bootstrap_url":"bootstrap"
                }]}),
                serde_json::json!({"address":address.to_string(), "protocol":{"type":"socks"}}),
            ];
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            drop((reserved, second));
            let (events, receiver) = mpsc::channel(1);
            let (ack, _reconciled) = mpsc::channel(1);
            let network = crate::desktop::NetworkSession::with_test_events(receiver, ack);
            let process = crate::desktop::TEST_NETWORK.scope(
                std::cell::RefCell::new(Some(network)),
                Box::pin(run(vec![path.to_string_lossy().into_owned()], false, true)),
            );
            tokio::pin!(process);
            let fixture = async {
                let mut live = wait_for_socks(address).await;
                while requests.try_recv().is_ok() {}
                events.send(Some(false)).await.unwrap();
                assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
                if repair_reload {
                    config.drain(..2);
                    config.push(serde_json::json!({"address":added.to_string(), "protocol":{"type":"socks"}}));
                    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
                    signal(libc::SIGHUP);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                delay.store(if repair_reload { 60 } else { 11 }, Ordering::Relaxed);
                events.send(Some(true)).await.unwrap();
                if !repair_reload {
                    requests.recv().await.unwrap();
                }
                let mut live = tokio::time::timeout(
                    Duration::from_secs(if repair_reload { 3 } else { 15 }),
                    wait_for_socks(if repair_reload { added } else { address }),
                ).await.expect("recovery cancelled a valid slow DNS bootstrap");
                if repair_reload {
                    assert!(requests.try_recv().is_err(), "repair rebuilt the broken accepted DNS config");
                }
                if !repair_reload {
                    events.send(Some(false)).await.unwrap();
                    assert_eq!(live.read(&mut [0]).await.unwrap(), 0);
                    delay.store(60, Ordering::Relaxed);
                    events.send(Some(true)).await.unwrap();
                    requests.recv().await.unwrap();
                }
                signal(libc::SIGTERM);
            };
            tokio::select! {
                result = &mut process => panic!("process exited before recovery: {result:?}"),
                _ = fixture => {},
            }
            tokio::time::timeout(Duration::from_secs(3), process).await.unwrap().unwrap();
        }).await.unwrap();
    }
}

#[tokio::test]
async fn reconnect_restarts_certificate_workers_retired_by_a_rejected_candidate() {
    const NAME: &str =
        "process::tests::reconnect_restarts_certificate_workers_retired_by_a_rejected_candidate";
    const CHILD: &str = "SHOES_RECONNECT_CERTIFICATE_TEST";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(NAME, CHILD, "1");
        return;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn challenge(address: std::net::SocketAddr) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n")
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 404 "));
        })
        .await
        .unwrap();
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    std::fs::write(&path, serde_json::json!([
        {"certificate_source":"managed", "type":"acme", "domains":["proxy.test"],
         "directory_url":"http://127.0.0.1:9/directory", "state_dir":directory.path().join("state"),
         "challenge":{"type":"http01", "listen":[address.to_string()]}},
        {"address":"127.0.0.1:0", "protocol":{"type":"socks"}}
    ]).to_string()).unwrap();
    drop(reserved);
    let old = crate::network_tasks::NetworkLifetime::default();
    let mut prepared = old
        .scope(prepare(&[path.to_string_lossy().into_owned()], None))
        .await
        .unwrap();
    let mut running = RunningServers::default();
    old.scope(running.start_retry(&mut prepared)).await.unwrap();
    old.scope(running.commit_activation(&prepared, None))
        .await
        .unwrap();
    challenge(address).await;

    // Candidate retirement can stop accepted certificate workers before candidate activation fails.
    prepared
        .certificates
        .retire_unused(&Default::default())
        .await;
    running
        .pause_network(&mut prepared, None, &old)
        .await
        .unwrap();
    let fresh = crate::network_tasks::NetworkLifetime::default();
    fresh
        .scope(running.refresh_network(&mut prepared, &crate::desktop::NetworkSession::default()))
        .await
        .unwrap();
    fresh
        .scope(running.start_retry(&mut prepared))
        .await
        .unwrap();
    let mut queued = tokio::net::TcpStream::connect(address).await.unwrap();
    queued
        .write_all(b"GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), queued.read(&mut [0]))
            .await
            .is_err(),
        "certificate worker admitted a request before recovery activation"
    );
    fresh
        .scope(running.finish_activation(&prepared, None))
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(2), queued.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 404 "));
    challenge(address).await;
    running.shutdown(&[&prepared]).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn recovery_retry_restores_runtime_before_dns_bootstrap() {
    const NAME: &str = "process::tests::recovery_retry_restores_runtime_before_dns_bootstrap";
    const CHILD: &str = "SHOES_RECOVERY_RETRY_RUNTIME_TEST";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(NAME, CHILD, "1");
        return;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::task::AbortOnDropHandle;

    tokio::time::timeout(Duration::from_secs(10), async {
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_address = dns.local_addr().unwrap();
        let (observed, mut observations) = mpsc::unbounded_channel();
        let _dns = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut bytes = [0; 1500];
            loop {
                let (length, peer) = dns.recv_from(&mut bytes).await.unwrap();
                // Bootstrap transports consume live admission and the published TLS clock.
                observed.send((
                    resources::try_quic_memory(2).is_some(),
                    crate::clock::now().unwrap().duration_since(std::time::SystemTime::now()).unwrap_or_default(),
                )).unwrap();
                let reply = loopback_dns_reply(Message::from_vec(&bytes[..length]).unwrap());
                dns.send_to(&reply, peer).await.unwrap();
            }
        }));
        let ntp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ntp_address = ntp.local_addr().unwrap();
        let ntp_task = tokio::spawn(async move {
            let mut request = [0; 48];
            let (_, peer) = ntp.recv_from(&mut request).await.unwrap();
            ntp_reply(&ntp, request, peer, 86_400).await;
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let paths = [path.to_string_lossy().into_owned()];
        std::fs::write(&path, serde_json::json!([
            {"dns_group":"bootstrap", "dns_servers":[{
                "url":format!("udp://{dns_address}"), "ip_strategy":"ipv4_only", "attempts":1
            }]},
            {"dns_group":"upstream", "dns_servers":[{
                "url":"udp://upstream.test", "bootstrap_url":"bootstrap"
            }]},
            {"address":address.to_string(), "protocol":{"type":"socks"}, "dns":{"servers":"upstream"}}
        ]).to_string()).unwrap();
        drop(reserved);
        let old = crate::network_tasks::NetworkLifetime::default();
        let mut previous = old.scope(prepare(&paths, None)).await.unwrap();
        let mut running = RunningServers::default();
        old.scope(running.start_retry(&mut previous)).await.unwrap();
        old.scope(running.commit_activation(&previous, None)).await.unwrap();
        assert!(observations.recv().await.unwrap().0);
        running.pause_network(&mut previous, None, &old).await.unwrap();

        std::fs::write(&path, serde_json::json!([
            {"global_settings":{"quic_memory_bytes":1,
                "ntp":{"server":ntp_address.to_string(), "timeout_secs":1}}},
            {"path":directory.path(), "protocol":{"type":"socks"}}
        ]).to_string()).unwrap();
        let fresh = crate::network_tasks::NetworkLifetime::default();
        let mut candidate = fresh.scope(prepare(&paths, Some(&previous.dns))).await.unwrap();
        fresh.scope(running.start_retry(&mut candidate)).await.unwrap_err();
        ntp_task.await.unwrap();
        assert_eq!(resources::limits().quic_memory_bytes, Some(1));
        assert!(crate::clock::now().unwrap() > std::time::SystemTime::now() + Duration::from_secs(86_399));
        fresh.scope(running.discard_candidate(&mut previous, &mut candidate)).await.unwrap();
        running.pause_network(&mut previous, None, &fresh).await.unwrap();
        assert!(previous.dns.get_by_name("upstream").is_none());
        assert!(observations.try_recv().is_err(), "candidate cleanup rebuilt accepted DNS");
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), stream.read_u8()).await.is_err());

        let retry = crate::network_tasks::NetworkLifetime::default();
        retry.scope(running.refresh_network(
            &mut previous, &crate::desktop::NetworkSession::default(),
        )).await.unwrap();
        retry.scope(running.start_retry(&mut previous)).await.unwrap();
        retry.scope(running.finish_activation(&previous, None)).await.unwrap();
        let (admitted, offset) = observations.recv().await.unwrap();
        assert!(admitted, "recovery bootstrap used the rejected QUIC limit");
        assert!(offset < Duration::from_secs(1), "recovery bootstrap used the rejected clock: {offset:?}");
        assert!(previous.dns.get_by_name("upstream").is_some());
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        running.pause_network(&mut previous, None, &retry).await.unwrap();
        running.shutdown(&[&previous, &candidate]).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn network_reset_keeps_controller_generation_and_explicit_selection() {
    const CHILD: &str = "SHOES_RECONNECT_CONTROL_TEST";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "process::tests::network_reset_keeps_controller_generation_and_explicit_selection",
            CHILD,
            "1",
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        serde_json::json!([
            {"client_group":"chosen", "type":"selector", "client_chains":[
                {"chain":[{"name":"first", "protocol":{"type":"direct"}}]},
                {"chain":[{"name":"second", "protocol":{"type":"direct"}}]}
            ]},
            {"address":"127.0.0.1:0", "protocol":{"type":"socks"}}
        ])
        .to_string(),
    )
    .unwrap();
    let paths = [path.to_string_lossy().into_owned()];
    let configs = config::load_config_files(&paths).await.unwrap();
    let mut control = None;
    let network = crate::desktop::NetworkSession::default();
    let old = crate::network_tasks::NetworkLifetime::default();
    let mut prepared = old
        .scope(prepare_tracking(
            &paths,
            configs,
            None,
            None,
            &mut |_, _, _| {},
            &mut control,
            &network.topology(),
        ))
        .await
        .unwrap();
    let mut control = control.unwrap();
    let generation = prepared.generation.clone().unwrap();
    control.runtime.publish(generation.clone()).await.unwrap();
    control.runtime.resume().await.unwrap();
    control
        .runtime
        .select(generation.id, "chosen".into(), "second".into())
        .await
        .unwrap();
    let selection = generation.catalog.selection.snapshot();
    let mut running = RunningServers::default();
    old.scope(running.start(&mut prepared)).await.unwrap();
    running
        .pause_network(&mut prepared, Some(&control), &old)
        .await
        .unwrap();
    assert!(
        control
            .runtime
            .activating
            .load(std::sync::atomic::Ordering::Acquire)
    );
    let fresh = crate::network_tasks::NetworkLifetime::default();
    fresh
        .scope(running.refresh_network(&mut prepared, &network))
        .await
        .unwrap();
    fresh
        .scope(running.start_retry(&mut prepared))
        .await
        .unwrap();
    fresh
        .scope(running.finish_activation(&prepared, Some(&control)))
        .await
        .unwrap();
    assert!(
        !control
            .runtime
            .activating
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(std::sync::Arc::ptr_eq(
        &generation,
        &control.runtime.generation().unwrap()
    ));
    assert!(std::sync::Arc::ptr_eq(
        &selection,
        &generation.catalog.selection.snapshot()
    ));
    assert_eq!(selection["chosen"], "second");
    running
        .pause_network(&mut prepared, Some(&control), &fresh)
        .await
        .unwrap();
    running.shutdown(&[&prepared]).await.unwrap();
    control.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn repair_reload_restores_runtime_and_checks_underlay_before_publication() {
    const NAME: &str =
        "process::tests::repair_reload_restores_runtime_and_checks_underlay_before_publication";
    const CHILD: &str = "SHOES_REPAIR_ACTIVATION_TEST";
    if std::env::var_os(CHILD).is_none() {
        for state in ["unavailable", "available"] {
            shoes_test_support::isolated::run_isolated(NAME, CHILD, state);
        }
        return;
    }
    let available_after_change = std::env::var(CHILD).unwrap() == "available";
    use std::sync::{Arc, atomic::Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let accepted = vec![
            serde_json::json!({"client_group":"chosen", "type":"selector", "client_chains":[
                {"chain":[{"name":"direct", "protocol":{"type":"direct"}}]}
            ]}),
            serde_json::json!({"address":address.to_string(), "protocol":{"type":"socks"}}),
        ];
        std::fs::write(&path, serde_json::to_vec(&accepted).unwrap()).unwrap();
        drop(reserved);
        let ntp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ntp_address = ntp.local_addr().unwrap();
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_address = dns.local_addr().unwrap();
        let (events, receiver) = mpsc::channel(1);
        let (ack, mut reconciled) = mpsc::channel(8);
        let session = crate::desktop::NetworkSession::with_test_events(receiver, ack);
        let service = crate::control::runtime::ControlService::new(Default::default()).unwrap();
        let runtime = service.runtime.clone();
        let mut control = Some(service);
        let mut api = None;
        let mut network = crate::desktop::NetworkSession::default();
        let mut shutdown = ShutdownSignals::new().unwrap();
        let mut reload = ReloadSignal::new().unwrap();
        {
            let process = crate::desktop::TEST_NETWORK.scope(
                std::cell::RefCell::new(Some(session)),
                Box::pin(run_inner(
                    vec![path.to_string_lossy().into_owned()],
                    true,
                    &mut control,
                    &mut api,
                    &mut network,
                    &mut shutdown,
                    &mut reload,
                )),
            );
            tokio::pin!(process);
            let fixture = async {
                let mut live = wait_for_socks(address).await;
                let generation = runtime.generation().unwrap();
                events.send(Some(false)).await.unwrap();
                assert_eq!(live.read(&mut [0]).await.unwrap(), 0);

                let mut rejected = accepted.clone();
                rejected.push(serde_json::json!({"global_settings":{"quic_memory_bytes":1,
                    "ntp":{"server":ntp_address.to_string(), "timeout_secs":2}}}));
                rejected.push(
                    serde_json::json!({"path":directory.path(), "protocol":{"type":"socks"}}),
                );
                std::fs::write(&path, serde_json::to_vec(&rejected).unwrap()).unwrap();
                signal(libc::SIGHUP);
                tokio::time::sleep(Duration::from_millis(100)).await;
                events.send(Some(true)).await.unwrap();
                let mut packet = [0; 48];
                let (_, peer) = ntp.recv_from(&mut packet).await.unwrap();
                ntp_reply(&ntp, packet, peer, 86_400).await;
                while crate::clock::now().unwrap()
                    < std::time::SystemTime::now() + Duration::from_secs(86_399)
                {
                    tokio::task::yield_now().await;
                }
                assert_eq!(resources::limits().quic_memory_bytes, Some(1));

                let mut repair = accepted.clone();
                repair.push(serde_json::json!({"dns_group":"bootstrap", "dns_servers":[{
                    "url":format!("udp://{dns_address}"), "ip_strategy":"ipv4_only", "attempts":1
                }]}));
                repair.push(serde_json::json!({"dns_group":"upstream", "dns_servers":[{
                    "url":"udp://repair.test", "bootstrap_url":"bootstrap"
                }]}));
                repair.push(serde_json::json!({"global_settings":{
                    "ntp":{"server":ntp_address.to_string(), "timeout_secs":2}}}));
                std::fs::write(&path, serde_json::to_vec(&repair).unwrap()).unwrap();
                signal(libc::SIGHUP);
                let mut bytes = [0; 1500];
                let (len, peer) = dns.recv_from(&mut bytes).await.unwrap();
                assert!(
                    resources::try_quic_memory(2).is_some(),
                    "repair preparation used rejected limits"
                );
                let offset = crate::clock::now()
                    .unwrap()
                    .duration_since(std::time::SystemTime::now())
                    .unwrap_or_default();
                assert!(
                    offset < Duration::from_secs(1),
                    "repair preparation used rejected clock: {offset:?}"
                );
                let reply = loopback_dns_reply(Message::from_vec(&bytes[..len]).unwrap());
                dns.send_to(&reply, peer).await.unwrap();

                let (_, peer) = ntp.recv_from(&mut packet).await.unwrap();
                let mut queued = tokio::net::TcpStream::connect(address).await.unwrap();
                queued.write_all(&[5, 1, 0]).await.unwrap();
                while reconciled.try_recv().is_ok() {}
                events.send(Some(available_after_change)).await.unwrap();
                ntp_reply(&ntp, packet, peer, 0).await;
                reconciled.recv().await.unwrap();
                events.send(None).await.unwrap();
                reconciled.recv().await.unwrap();
                assert!(
                    Arc::ptr_eq(&generation, &runtime.generation().unwrap()),
                    "unreconciled repair was published"
                );
                assert!(runtime.activating.load(Ordering::Acquire));
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(100), queued.read(&mut [0])).await
                {
                    assert_eq!(n, 0, "unreconciled repair admitted a client");
                }
                if !available_after_change {
                    events.send(Some(true)).await.unwrap();
                }
                let (len, peer) = dns.recv_from(&mut bytes).await.unwrap();
                let reply = loopback_dns_reply(Message::from_vec(&bytes[..len]).unwrap());
                dns.send_to(&reply, peer).await.unwrap();
                let (_, peer) = ntp.recv_from(&mut packet).await.unwrap();
                ntp_reply(&ntp, packet, peer, 0).await;
                let _live = wait_for_socks(address).await;
                assert_ne!(
                    generation.id,
                    runtime.generation().unwrap().id,
                    "underlay interruption discarded the correcting reload"
                );
                assert!(!runtime.activating.load(Ordering::Acquire));
                signal(libc::SIGTERM);
            };
            tokio::select! {
                result = &mut process => panic!("process exited before recovery: {result:?}"),
                _ = fixture => {},
            }
            process.await.unwrap();
        }
        control.as_mut().unwrap().shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reconnect_uses_memory_and_cancels_current_and_draining_connections() {
    const NAME: &str =
        "process::tests::reconnect_uses_memory_and_cancels_current_and_draining_connections";
    const CHILD: &str = "SHOES_RECONNECT_PROCESS_TEST";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(NAME, CHILD, "1");
        return;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(15), async {
        let echo = shoes_test_support::test_servers::start_tcp_stream_echo_server("127.0.0.1", 0).await.unwrap();
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = reserved.local_addr().unwrap();
        let reserved_socks = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socks = reserved_socks.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        std::fs::write(&path, serde_json::json!([
            {"global_settings": {"reload_grace_secs":300}},
            {"address":listen.to_string(), "protocol":{"type":"forward", "target":echo.local_addr().to_string()}},
            {"address":socks.to_string(), "protocol":{"type":"socks"}}
        ]).to_string()).unwrap();
        drop((reserved, reserved_socks));
        let mut lifetime = crate::network_tasks::NetworkLifetime::default();
        let mut prepared = lifetime.scope(prepare(&[path.to_string_lossy().into_owned()], None)).await.unwrap();
        let mut running = RunningServers::default();
        lifetime.scope(running.start(&mut prepared)).await.unwrap();
        let mut draining = tokio::net::TcpStream::connect(listen).await.unwrap();
        draining.write_all(b"before").await.unwrap();
        let mut bytes = [0; 6];
        draining.read_exact(&mut bytes).await.unwrap();
        running.stop().await;
        lifetime.scope(running.start(&mut prepared)).await.unwrap();
        draining.write_all(b"reload").await.unwrap();
        draining.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"reload");
        let mut pending = tokio::net::TcpStream::connect(socks).await.unwrap();
        pending.write_all(&[5]).await.unwrap();
        let mut current = tokio::net::TcpStream::connect(listen).await.unwrap();
        current.write_all(b"active").await.unwrap();
        current.read_exact(&mut bytes).await.unwrap();
        std::fs::write(&path, "invalid: [").unwrap();
        running.pause_network(&mut prepared, None, &lifetime).await.unwrap();
        for stream in [&mut draining, &mut pending, &mut current] {
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0])).await
                .expect("network reset waited for ordinary reload grace");
            assert!(matches!(result, Ok(0)) || result.is_err(), "{result:?}");
        }
        lifetime = crate::network_tasks::NetworkLifetime::default();
        lifetime.scope(running.refresh_network(&mut prepared, &crate::desktop::NetworkSession::default()))
            .await.unwrap();
        lifetime.scope(running.start_retry(&mut prepared)).await.unwrap();
        lifetime.scope(running.finish_activation(&prepared, None)).await.unwrap();
        let mut fresh = tokio::net::TcpStream::connect(listen).await.unwrap();
        fresh.write_all(b"fresh!").await.unwrap();
        fresh.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"fresh!");
        running.pause_network(&mut prepared, None, &lifetime).await.unwrap();
    }).await.unwrap();
}

async fn load_validated(
    paths: &[String],
    discovered: &mut DiscoverDependencies<'_>,
) -> io::Result<ValidatedConfigs> {
    let configs = config::load_config_files(paths).await?;
    validate_configs(paths, configs, discovered).await
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_reload_retains_a_lost_lease_without_reacquiring_it() {
    for replace_root in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let cache = root.join("cache");
        let config = root.join("config.yaml");
        std::fs::write(
            &config,
            serde_json::json!([
                {"global_settings": {"rule_cache_dir": cache}},
                {"address":"127.0.0.1:0", "protocol":{"type":"socks"}}
            ])
            .to_string(),
        )
        .unwrap();
        let paths = [config.to_str().unwrap().to_owned()];
        let previous = prepare(&paths, None).await.unwrap();
        if replace_root {
            std::fs::rename(&cache, root.join("moved")).unwrap();
            crate::rule_updater::create_cache_directory(&cache).unwrap();
        } else {
            std::fs::remove_file(cache.join("owner.lock")).unwrap();
        }
        let _other = crate::rule_updater::cache_lease(&cache).unwrap();
        let mut lease = previous.cache_lease.clone();
        let configs = config::load_config_files(&paths).await.unwrap();
        load_candidate(
            &paths,
            configs,
            &mut |_, _, _| {},
            true,
            Some(&previous),
            &mut lease,
            &[],
        )
        .await
        .unwrap();
        assert!(std::sync::Arc::ptr_eq(
            lease.as_ref().unwrap(),
            previous.cache_lease.as_ref().unwrap()
        ));
        let error = lease.unwrap().check().unwrap_err();
        assert!(error.to_string().contains("lease lost"), "{error}");
        load_validated(&paths, &mut |_, _, _| {}).await.unwrap();
    }
}

#[tokio::test]
async fn validation_errors_preserve_io_kind_and_file_context() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let missing = directory.path().join("missing.pem");
    let yaml = serde_yaml::to_string(&serde_json::json!([
        {"pem": "missing", "path": missing}
    ]))
    .unwrap();
    std::fs::write(&path, yaml).unwrap();
    let paths = [path.to_str().unwrap().to_owned()];

    let Err(error) = load_validated(&paths, &mut |_, _, _| {}).await else {
        panic!("missing PEM file must reject");
    };
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains(&format!("Could not validate config files {paths:?}:")),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("Failed to read PEM file"),
        "{diagnostic}"
    );
}

#[tokio::test]
async fn unchanged_tcp_socket_queues_connections_between_generations() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        std::fs::write(
            &path,
            format!("- address: '{address}'\n  protocol: {{type: socks}}\n"),
        )
        .unwrap();
        let paths = [path.to_str().unwrap().to_owned()];
        let mut previous = prepare(&paths, None).await.unwrap();
        let mut running = RunningServers::default();
        running.start(&mut previous).await.unwrap();
        let mut next = prepare(&paths, Some(&previous.dns)).await.unwrap();
        next.tcp = TcpListeners::prepare(&next.validated.configs, &previous.tcp, &[]).unwrap();
        running.stop().await;
        previous.tcp.retain_shared(&next.tcp);
        let mut queued = tokio::net::TcpStream::connect(address).await.unwrap();
        queued.write_all(&[5, 1, 0]).await.unwrap();
        drop(previous);
        assert!(std::net::TcpListener::bind(address).is_err());
        running.start(&mut next).await.unwrap();
        let mut response = [0; 2];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), queued.read_exact(&mut response))
                .await
                .is_err()
        );
        next.tcp.activate();
        queued.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 0]);
        drop(queued);
        running.shutdown(&[&next]).await.unwrap();
        drop(next);
        crate::socket_util::new_tcp_listener(address, 128, None).unwrap();
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn rejected_or_cancelled_activation_does_not_admit_candidate_dns_flows() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tokio::time::timeout(Duration::from_secs(10), async {
        for shutdown in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.yaml");
            let paths = [path.to_str().unwrap().to_owned()];
            std::fs::write(
                &path,
                "- address: '127.0.0.1:0'\n  protocol: {type: socks}\n",
            )
            .unwrap();
            let mut previous = prepare(&paths, None).await.unwrap();
            let mut running = RunningServers::default();
            running.start(&mut previous).await.unwrap();

            let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let unix_path = directory.path().join("listener.sock");
            std::fs::write(
                &path,
                serde_json::json!([
                    {"dns_group":"candidate", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{
                        "state_file":directory.path().join("state.json"), "max_entries":16
                    }},
                    {"address":address.to_string(), "protocol":{"type":"socks"},
                     "dns":{"servers":"candidate"}},
                    {"path":unix_path, "protocol":{"type":"socks"},
                     "dns":{"servers":"candidate"}}
                ])
                .to_string(),
            )
            .unwrap();
            let mut candidate = prepare(&paths, Some(&previous.dns)).await.unwrap();
            let resolver =
                std::sync::Arc::downgrade(&candidate.dns.get_by_name("candidate").unwrap());
            candidate.tcp =
                TcpListeners::prepare(&candidate.validated.configs, &previous.tcp, &[]).unwrap();
            running.stop().await;
            previous.tcp.retain_shared(&candidate.tcp);
            running.start(&mut candidate).await.unwrap();
            let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut unix = tokio::net::UnixStream::connect(&unix_path).await.unwrap();
            // Pipelined negotiation would open a lease-owning DNS stream without the gate.
            let request = [5, 1, 0, 5, 1, 0, 1, 198, 18, 0, 1, 0, 53];
            tcp.write_all(&request).await.unwrap();
            unix.write_all(&request).await.unwrap();
            for stream in [
                &mut tcp as &mut dyn crate::async_stream::AsyncStream,
                &mut unix,
            ] {
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), stream.read_u8())
                        .await
                        .is_err(),
                    "uncommitted listener admitted a flow"
                );
            }
            if shutdown {
                running.shutdown(&[&previous, &candidate]).await.unwrap();
            } else {
                // Covers failure after listener startup but before activation commits.
                running
                    .discard_candidate(&mut previous, &mut candidate)
                    .await
                    .unwrap();
                running.start_retry(&mut previous).await.unwrap();
                running.commit_activation(&previous, None).await.unwrap();
            }
            drop(candidate);
            assert!(resolver.upgrade().is_none());

            // Queued clients stay open while the same persistent pool is acquired again.
            let mut next = prepare(&paths, Some(&previous.dns)).await.unwrap();
            running.stop().await;
            next.tcp = TcpListeners::prepare(&next.validated.configs, &previous.tcp, &[]).unwrap();
            running.start(&mut next).await.unwrap();
            let mut queued = tokio::net::UnixStream::connect(&unix_path).await.unwrap();
            queued.write_all(&[5, 1, 0]).await.unwrap();
            next.tcp.activate();
            let mut response = [0; 2];
            queued.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0]);
            drop((tcp, unix, queued));
            running.shutdown(&[&previous, &next]).await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn activation_discards_candidate_identity_events_but_preserves_reload_events() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.yaml");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        let trust = directory.path().join("ca.pem");
        let pair = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(&cert, pair.cert.pem()).unwrap();
        std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
        std::fs::write(&trust, pair.cert.pem()).unwrap();
        std::fs::write(
            &config,
            serde_yaml::to_string(&serde_json::json!([
                {"address": "127.0.0.1:18443", "protocol": {"type": "tls", "default_tls_target": {
                    "cert": cert, "key": key, "protocol": {"type": "socks"}
                }}}
            ]))
            .unwrap(),
        )
        .unwrap();
        let paths = [config.to_str().unwrap().to_owned()];
        let (tx, mut changes) = mpsc::channel(1);
        let mut watches = ConfigWatches::new(&paths, tx, false).unwrap();
        let validated = load_validated(&paths, &mut |reload, recovery, root| {
            assert!(!reload.contains(&cert) && !reload.contains(&key));
            assert!(recovery.contains(&cert) && recovery.contains(&key));
            watches.discovered(reload, recovery, root);
        })
        .await
        .unwrap();
        // Native fixture-creation events can arrive after watch registration.
        // Settle both setup queues before isolating the deliberate key write.
        let contents = std::fs::read(&config).unwrap();
        std::fs::write(&config, contents).unwrap();
        changes.recv().await.unwrap();
        while tokio::time::timeout(Duration::from_millis(100), watches.changed(&mut changes))
            .await
            .is_ok()
        {}
        assert!(changes.is_empty());
        assert!(watches.recovery_changes.is_empty());
        // A renewal while preparation is still in progress must not leak into
        // the active reload queue, even if a notifier callback arrives late.
        let late_callback = watches.recovery_tx.clone();
        std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
        while watches.recovery_changes.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(changes.is_empty());
        watches.activated(&validated.reload_files);
        assert!(late_callback.try_send(()).is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), watches.changed(&mut changes))
                .await
                .is_err()
        );

        for changed in [&config, &trust] {
            watches.discovered(
                std::slice::from_ref(&trust),
                &[cert.clone(), key.clone()],
                None,
            );
            let contents = std::fs::read(changed).unwrap();
            std::fs::write(changed, contents).unwrap();
            while changes.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            watches.activated(std::slice::from_ref(&trust));
            assert!(
                changes.try_recv().is_ok(),
                "activation must retain YAML and reload-only dependency events"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dependencies_are_discovered_before_the_candidate_reads_them() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("local.json");
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &source,
        r#"{"version":1,"rules":[{"domain":["example.com"]}]}"#,
    )
    .unwrap();
    std::fs::write(
        &config,
        serde_json::json!([{
            "address": "127.0.0.1:0", "protocol": {"type": "socks"},
            "rules": [{"path": source, "action": "block"}]
        }])
        .to_string(),
    )
    .unwrap();
    let paths = [config.to_str().unwrap().to_owned()];
    let configs = config::load_config_files(&paths).await.unwrap();
    let error = load_candidate(
        &paths,
        configs,
        &mut |paths, _, _| {
            assert!(paths.contains(&source));
            std::fs::write(&source, "invalid").unwrap();
        },
        true,
        None,
        &mut None,
        &[],
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("rule source"), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn rejected_candidate_and_recovery_watches_exclude_managed_caches() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    std::fs::create_dir(&root).unwrap();
    let cache = root.join("rules.json");
    let alias = directory.path().join("alias.json");
    std::fs::write(&cache, "old").unwrap();
    std::os::unix::fs::symlink(&cache, &alias).unwrap();
    let config = directory.path().join("config.yaml");
    std::fs::write(&config, "config").unwrap();
    let (tx, mut changes) = mpsc::channel(1);
    let mut watches = ConfigWatches::new(&[config.to_str().unwrap().into()], tx, false).unwrap();
    watches.discovered(
        std::slice::from_ref(&alias),
        std::slice::from_ref(&cache),
        Some(&root),
    );
    // FSEvents can deliver fixture-creation events after watch registration.
    tokio::time::timeout(Duration::from_secs(3), async {
        std::fs::write(&config, "ready").unwrap();
        changes.recv().await.unwrap();
        while tokio::time::timeout(Duration::from_millis(100), watches.changed(&mut changes))
            .await
            .is_ok()
        {}
    })
    .await
    .unwrap();
    std::fs::write(&cache, "new").unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), watches.changed(&mut changes))
            .await
            .is_err()
    );
    std::fs::write(&config, "changed").unwrap();
    tokio::time::timeout(Duration::from_secs(3), watches.changed(&mut changes))
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn reload_debounce_includes_candidate_recovery_events() {
    let (tx, mut changes) = mpsc::channel(1);
    let mut watches = ConfigWatches::new(&[], tx.clone(), true).unwrap();
    let recovery = watches.recovery_tx.clone();
    let task = tokio::spawn(async move { watches.debounce(&mut changes).await });
    tokio::task::yield_now().await;
    for sender in [tx, recovery] {
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(!task.is_finished());
        sender.send(()).await.unwrap();
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    task.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn fake_dns_rejected_reload_keeps_inherited_guards_without_freezing_live_pool() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let paths = [path.to_str().unwrap().to_owned()];
    std::fs::write(
        &path,
        r#"[{"dns_group":"fake","dns_servers":"udp://127.0.0.1:9","fake_ip":true}]"#,
    )
    .unwrap();
    let live = prepare(&paths, None).await.unwrap();
    let context = live
        .dns
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    context.allocate("before.example", false).unwrap();
    std::fs::write(
        &path,
        r#"[{"dns_group":"ordinary","dns_servers":"udp://198.18.0.5:53"}]"#,
    )
    .unwrap();
    load_validated(&paths, &mut |_, _, _| {}).await.unwrap();
    let error = prepare(&paths, Some(&live.dns)).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("running configuration until restart")
    );
    context.allocate("after.example", false).unwrap();
}

#[tokio::test]
async fn fake_dns_removed_context_rejects_forwarding_and_override_reload_targets() {
    use serde_json::json;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let paths = [path.to_str().unwrap().to_owned()];
    std::fs::write(
        &path,
        r#"[{"dns_group":"fake","dns_servers":"udp://127.0.0.1:9","fake_ip":true}]"#,
    )
    .unwrap();
    let live = prepare(&paths, None).await.unwrap();
    std::fs::write(&path, "[]").unwrap();
    let removed = prepare(&paths, Some(&live.dns)).await.unwrap();
    assert!(!removed.dns.forbidden_ranges().is_empty());

    for server in [
        json!({"address":"127.0.0.1:1080", "protocol":{"type":"forward", "targets":["198.18.0.5:443"]}}),
        json!({"address":"127.0.0.1:1080", "protocol":{"type":"socks"}, "rules":[{
            "masks":"0.0.0.0/0", "action":"allow", "override_address":"198.18.0.5:443"
        }]}),
    ] {
        std::fs::write(&path, json!([server]).to_string()).unwrap();
        load_validated(&paths, &mut |_, _, _| {}).await.unwrap();
        let error = prepare(&paths, Some(&removed.dns)).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("running configuration until restart")
        );
    }
}

#[tokio::test]
async fn fake_dns_retained_pools_reject_tun_endpoint_reload_collisions() {
    use serde_json::json;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    let paths = [path.to_str().unwrap().to_owned()];
    std::fs::write(
        &path,
        json!([
            {"dns_group":"fake", "dns_servers":"udp://127.0.0.1:9", "fake_ip":{
                "ipv4_range":"198.18.0.0/29", "ipv6_range":"2001:2::/125", "max_entries":5
            }},
            {"device_name":"tun0", "device_fd":42, "address":"10.99.0.1"},
        ])
        .to_string(),
    )
    .unwrap();
    let live = prepare(&paths, None).await.unwrap();
    let context = live
        .dns
        .get_by_name("fake")
        .unwrap()
        .fake_dns_context()
        .unwrap();
    let ip = context.allocate("before.example", false).unwrap();
    for config in [
        json!([{ "dns_group":"fake", "dns_servers":"udp://127.0.0.1:9", "fake_ip":false }]),
        json!([]),
    ] {
        std::fs::write(&path, config.to_string()).unwrap();
        let retained = prepare(&paths, Some(&live.dns)).await.unwrap();
        for field in ["address", "destination"] {
            for (endpoint, allowed) in [
                ("198.18.0.5", false),
                ("::ffff:198.18.0.5", false),
                ("2001:2::5", false),
                ("198.18.0.1", true),
                ("::ffff:198.18.0.1", true),
                ("2001:2::1", true),
                ("10.99.0.1", true),
            ] {
                let mut tun = json!({"device_name":"tun0", "device_fd":42});
                tun[field] = endpoint.into();
                std::fs::write(&path, json!([tun]).to_string()).unwrap();
                load_validated(&paths, &mut |_, _, _| {}).await.unwrap();
                let result = prepare(&paths, Some(&retained.dns)).await;
                if allowed {
                    result.unwrap();
                } else {
                    let error = result.err().expect("retained TUN collision accepted");
                    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                    assert!(
                        error.to_string().contains("TUN interface/gateway"),
                        "{error}"
                    );
                }
            }
        }
    }
    assert_eq!(
        context.restore(ip).unwrap().as_deref(),
        Some("before.example")
    );
    context.allocate("after.example", false).unwrap();
}

#[tokio::test]
async fn fake_dns_terminal_shutdown_closes_all_registries_after_checkpoint_error() {
    let directory = tempfile::tempdir().unwrap();
    let mut registries = Vec::new();
    let mut contexts = Vec::new();
    for index in 0..2 {
        let path = directory.path().join(format!("config-{index}.yaml"));
        let state = directory.path().join(format!("state-{index}.json"));
        std::fs::write(
            &path,
            serde_json::json!([
                {"dns_group":"fake", "dns_servers":"system", "fake_ip":{"state_file":state}}
            ])
            .to_string(),
        )
        .unwrap();
        let prepared = prepare(&[path.to_str().unwrap().to_owned()], None)
            .await
            .unwrap();
        let context = prepared
            .dns
            .get_by_name("fake")
            .unwrap()
            .fake_dns_context()
            .unwrap();
        context.allocate("before.example", false).unwrap();
        contexts.push(context);
        registries.push(prepared);
    }
    let failed_state = directory.path().join("state-0.json");
    std::fs::remove_file(&failed_state).unwrap();
    std::fs::create_dir(&failed_state).unwrap();
    let marker = std::sync::Arc::new(());
    let owned = marker.clone();
    let mut running = RunningServers::default();
    running.listeners.push(tokio::spawn(async move {
        let _owned = owned;
        std::future::pending::<()>().await;
    }));
    assert!(
        running
            .shutdown(&[&registries[0], &registries[1]])
            .await
            .is_err()
    );
    assert_eq!(std::sync::Arc::strong_count(&marker), 1);
    for context in contexts {
        assert!(context.allocate("after.example", false).is_err());
    }
    let snapshot: serde_json::Value = serde_json::from_reader(
        std::fs::File::open(directory.path().join("state-1.json")).unwrap(),
    )
    .unwrap();
    assert!(
        snapshot["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry[0] == "before.example")
    );
}

#[tokio::test]
async fn preparation_preserves_ipv6_scope_ids_and_port_ranges() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(
        &path,
        "- address: '[fe80::1%2]:8080-8081'\n  protocol: {type: http}\n",
    )
    .unwrap();
    let prepared = prepare(&[path.to_str().unwrap().to_owned()], None)
        .await
        .unwrap();
    let crate::config::ResolvedConfig::Server(server) = &prepared.validated.configs[0] else {
        panic!()
    };
    let BindLocation::Address(addresses) = &server.bind_location else {
        panic!()
    };
    let resolved: Vec<_> = addresses
        .iter()
        .flat_map(|address| address.to_socket_addrs().unwrap())
        .collect();
    assert_eq!(
        resolved,
        [
            "[fe80::1%2]:8080".parse().unwrap(),
            "[fe80::1%2]:8081".parse().unwrap()
        ]
    );
}
