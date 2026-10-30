use super::*;

async fn load_validated(
    paths: &[String],
    discovered: &mut (dyn FnMut(&[PathBuf], &[PathBuf]) + Send),
) -> io::Result<ValidatedConfigs> {
    let configs = config::load_configs(&paths.to_vec()).await?;
    validate_configs(paths, configs, discovered).await
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

    let Err(error) = load_validated(&paths, &mut |_, _| {}).await else {
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
                    .rollback(&mut previous, &mut candidate, None)
                    .await
                    .unwrap();
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
        let validated = load_validated(&paths, &mut |reload, recovery| {
            assert!(!reload.contains(&cert) && !reload.contains(&key));
            assert!(recovery.contains(&cert) && recovery.contains(&key));
            watches.discovered(reload, recovery);
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
            watches.discovered(std::slice::from_ref(&trust), &[cert.clone(), key.clone()]);
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
    load_validated(&paths, &mut |_, _| {}).await.unwrap();
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
        load_validated(&paths, &mut |_, _| {}).await.unwrap();
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
                load_validated(&paths, &mut |_, _| {}).await.unwrap();
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
    let Config::Server(server) = &prepared.validated.configs[0] else {
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
