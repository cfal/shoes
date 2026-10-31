use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn diagnostic_contains_path(diagnostic: &str, path: &Path) -> bool {
    let path = path.to_str().unwrap();
    diagnostic.contains(path) || diagnostic.contains(&format!("{path:?}"))
}

#[test]
fn legacy_global_limits_warns_but_canonical_settings_do_not() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("settings.yaml");
    let warning =
        "global_limits will be deprecated in the next version; rename it to global_settings";
    for name in ["global_settings", "global_limits"] {
        std::fs::write(&path, format!("- {name}: {{max_connections: 42}}\n")).unwrap();
        for mode in ["check", "--dry-run"] {
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .env("RUST_LOG", "warn")
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "{diagnostic}");
            assert_eq!(
                diagnostic.contains(warning),
                name == "global_limits",
                "{diagnostic}"
            );
        }
    }
}

#[test]
fn check_diagnostic_paths_accept_display_and_debug_formats() {
    for path in [
        r"C:\tmp\nested.yaml",
        r"/tmp/with\backslash/nested.yaml",
        "/tmp/with\"quote/nested.yaml",
    ] {
        assert!(diagnostic_contains_path(
            &format!("Could not parse config file {path}"),
            Path::new(path)
        ));
        assert!(diagnostic_contains_path(
            &format!("Could not validate config files {:?}", [path]),
            Path::new(path)
        ));
        assert!(!diagnostic_contains_path("other.yaml", Path::new(path)));
    }
}

#[test]
fn check_warns_for_legacy_proxy_aliases_without_changing_alternatives() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.yaml");
    for field in ["client_proxy", "client_proxies"] {
        for legacy in [
            format!("- client_group: out\n  {field}: [direct, direct]\n"),
            format!(
                "- address: '127.0.0.1:0'\n  protocol: {{type: socks}}\n  rules:\n    - masks: '0.0.0.0/0'\n      {field}: [direct, direct]\n"
            ),
        ] {
            std::fs::write(&path, legacy).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .env("RUST_LOG", "warn")
                .args(["check", "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "{diagnostic}");
            assert!(
                diagnostic.contains("client_proxy/client_proxies is deprecated"),
                "{diagnostic}"
            );
            assert!(
                diagnostic.contains("client_chain/client_chains"),
                "{diagnostic}"
            );
            assert!(diagnostic.contains("sequential hops"), "{diagnostic}");
        }
    }
}

#[test]
fn check_diagnostics_include_file_and_nested_context_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested.yaml");
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let valid = format!(
        r#"- address: '{}'
  protocol: {{type: socks}}
"#,
        occupied.local_addr().unwrap()
    );
    for (config, context) in [
        (
            r#"- rule_source_group: imported
  rules:
    - first.srs
    - path: [VALUE_SECRET_SENTINEL]
"#,
            "rules[1]",
        ),
        (
            r#"- global_settings: {unsupported_policy: VALUE_SECRET_SENTINEL}
"#,
            "unknown field `unsupported_policy`",
        ),
        (
            r#"- pem: private
  data: PEM_SECRET_SENTINEL
  unsupported_policy: true
"#,
            "unknown field `unsupported_policy`",
        ),
        (
            r#"- proxy-providers:
    remote:
      url: 'https://user:URL_SECRET_SENTINEL@example.invalid/nodes'
"#,
            "Unable to determine config type",
        ),
        (
            r#"- clash_api_address: '127.0.0.1:9090'
  secret: CONTROLLER_SECRET_SENTINEL
- global_settings: {max_connections: 0}
"#,
            "global_settings.max_connections",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, username: user, password: PASSWORD_SECRET_SENTINEL}
  rules:
    - masks: '0.0.0.0/0'
      client_chain: missing-group
"#,
            "missing-group",
        ),
        (
            r#"- address: '127.0.0.1:1080'
  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}
  tcp_settings: [
"#,
            "line ",
        ),
    ] {
        std::fs::write(&path, format!("{valid}{config}")).unwrap();
        for mode in ["check", "--dry-run", "--no-reload"] {
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.status.code(), Some(1), "{mode}: {diagnostic}");
            assert!(diagnostic_contains_path(&diagnostic, &path), "{diagnostic}");
            assert!(diagnostic.contains(context), "{diagnostic}");
            assert!(!diagnostic.contains("SECRET_SENTINEL"), "{diagnostic}");
            assert!(!diagnostic.contains("Servers ready"), "{diagnostic}");
        }
    }
}

#[test]
fn removed_fallback_groups_fail_before_runtime_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("removed.yaml");
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let base = serde_json::json!([
        {"cache_file_path": directory.path().join("selectors.db")},
        {"address": occupied.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}},
        {"client_group": "removed", "type": "fallback", "client_proxies": ["direct"]}
    ]);
    for check in [
        None,
        Some(serde_json::json!({
            "url": format!("http://{}/", upstream.local_addr().unwrap()),
            "interval_secs": 1
        })),
    ] {
        let mut config = base.clone();
        let expected = if let Some(check) = check {
            config[2]["health_check"] = check;
            "unknown field `health_check`"
        } else {
            "unknown client group type: fallback"
        };
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        for mode in ["check", "--dry-run", "--no-reload"] {
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{mode}: {diagnostic}");
            assert!(diagnostic.contains(expected), "{mode}: {diagnostic}");
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
            assert_eq!(upstream.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        }
    }
}

#[test]
fn check_dry_run_validates_all_files_without_forwarding_or_state_writes() {
    let directory = tempfile::Builder::new()
        .prefix("config'OConnor-")
        .tempdir()
        .unwrap();
    let groups = directory.path().join("groups.yaml");
    let server = directory.path().join("server.yaml");
    let cache = directory.path().join("selectors.db");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    std::fs::write(
        &groups,
        serde_yaml::to_string(&serde_json::json!([
            {"cache_file_path": cache},
            {
                "client_group": "outbound",
                "type": "selector",
                "default": "upstream",
                "client_chains": [{
                    "name": "upstream",
                    "address": upstream.local_addr().unwrap().to_string(),
                    "protocol": {"type": "socks"}
                }]
            }
        ]))
        .unwrap(),
    )
    .unwrap();
    for mode in ["check", "--dry-run"] {
        for (chain, expected) in [("outbound", 0), ("missing-group", 1)] {
            std::fs::write(
                &server,
                format!(
                    r#"- address: '{address}'
  protocol: {{type: socks}}
  rules:
    - masks: '0.0.0.0/0'
      client_chain: {chain}
"#
                ),
            )
            .unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .args([&groups, &server])
                .output()
                .unwrap();
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(expected), "{diagnostic}");
            if expected == 1 {
                assert!(
                    diagnostic_contains_path(&diagnostic, &groups),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic_contains_path(&diagnostic, &server),
                    "{diagnostic}"
                );
                assert!(diagnostic.contains("missing-group"), "{diagnostic}");
            }
            assert!(!cache.exists());
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
            assert_eq!(upstream.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn managed_check_requires_literal_listener_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("managed.yaml");
    let example = include_str!("../../../examples/tun_desktop.yaml");
    let unix = serde_yaml::to_string(&serde_json::json!([{
        "clash_api_path": directory.path().join("api.sock"),
        "secret": "test",
    }]))
    .unwrap();
    for mode in ["check", "--dry-run"] {
        for (listener, valid) in [
            ("", true),
            (
                "- address: 'localhost:1080'\n  protocol: {type: socks}\n",
                false,
            ),
            (
                "- addresses: ['127.0.0.1:1080', 'localhost:1081']\n  protocol: {type: socks}\n",
                false,
            ),
            (
                "- clash_api_address: 'localhost:9090'\n  secret: test\n",
                false,
            ),
            (
                "- addresses: ['127.0.0.1:1080-1081', '[::1]:1080', '[fe80::1%2]:1080']\n  protocol: {type: socks}\n",
                true,
            ),
            (
                "- clash_api_address: '127.0.0.1:9090'\n  secret: test\n",
                true,
            ),
            (unix.as_str(), true),
        ] {
            std::fs::write(&path, format!("{example}\n{listener}")).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .output()
                .unwrap();
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.status.code(),
                Some(if valid { 0 } else { 1 }),
                "{listener}: {diagnostic}"
            );
            if !valid {
                assert!(
                    diagnostic.contains("managed TUN requires literal listener addresses"),
                    "{diagnostic}"
                );
                std::fs::write(&path, listener).unwrap();
                let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
                    .args([mode, "-t", "1"])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "manual listeners must still accept hostnames"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires sudo and util-linux; isolates cleanup dispatch from host networking"]
fn check_dry_run_does_not_dispatch_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cleanup-tun");
    for mode in ["check", "--dry-run"] {
        for (config, expected) in [
            (
                "- address: '127.0.0.1:12345'\n  protocol: {type: socks}\n",
                0,
            ),
            ("invalid configuration", 1),
        ] {
            std::fs::write(&path, config).unwrap();
            let output = Command::new("sudo")
                .current_dir(directory.path())
                .args([
                    "-n", "--", "unshare", "--net", "--mount", "--propagation", "private",
                    "--", "/bin/sh", "-ec",
                    "mount -t tmpfs -o size=1m,mode=755 tmpfs /run\nstatus=0\n\"$@\" || status=$?\ntest ! -e /run/shoes || exit 99\nexit \"$status\"",
                    "sh",
                    env!("CARGO_BIN_EXE_shoes"), mode, "-t", "1", "cleanup-tun",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{mode}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
}

#[cfg(unix)]
async fn config_pipe_writer(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
            {
                Ok(writer) => break writer,
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("open configuration pipe: {error}"),
            }
        }
    })
    .await
    .expect("configuration reader did not open the pipe")
}

#[cfg(unix)]
#[tokio::test]
async fn check_dry_run_keeps_default_signal_actions() {
    use std::os::unix::{ffi::OsStrExt, process::ExitStatusExt};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("blocked.yaml");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for mode in ["check", "--dry-run"] {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let child = Command::new(env!("CARGO_BIN_EXE_shoes"))
                .args([mode, "-t", "1"])
                .arg(&path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut process = super::Process::from_child(child);
            process.wait_for("Starting dry run.").await;
            // Opening the writer proves validation reached the blocking configuration read.
            let writer = config_pipe_writer(&path).await;
            process.signal(signal);
            assert_eq!(process.exit().await.signal(), Some(signal), "{mode}");
            drop(writer);
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn startup_reads_configuration_once_and_remains_interruptible() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("startup.yaml");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for signal in [Some(libc::SIGINT), Some(libc::SIGTERM), None] {
        let mut process = super::Process::start(&path, &["--no-reload"]);
        let mut writer = config_pipe_writer(&path).await;
        if let Some(signal) = signal {
            process.signal(signal);
            assert!(process.exit().await.success());
            drop(writer);
        } else {
            writer
                .write_all(b"- address: '127.0.0.1:0'\n  protocol: {type: socks}\n")
                .unwrap();
            drop(writer);
            process.wait_for("Servers ready").await;
            process.signal(libc::SIGTERM);
            assert!(process.exit().await.success());
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn startup_keeps_configuration_changes_queued_during_initial_read() {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("server.yaml");
    std::fs::write(
        &config,
        "- address: '127.0.0.1:0'\n  protocol: {type: socks}\n",
    )
    .unwrap();
    let pipe = directory.path().join("blocked.yaml");
    let name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let mut process = super::Process::start(&pipe, &[config.to_str().unwrap()]);
    let mut writer = config_pipe_writer(&pipe).await;

    // The second read holds startup open after the first config has been loaded.
    std::fs::write(&config, "invalid configuration").unwrap();
    writer.write_all(b"[]\n").unwrap();
    let replacement = directory.path().join("replacement.yaml");
    std::fs::write(&replacement, "[]\n").unwrap();
    std::fs::rename(&replacement, &pipe).unwrap();
    drop(writer);

    process.wait_for("Servers ready").await;
    process.wait_for("Reload rejected").await;
    process.signal(libc::SIGTERM);
    assert!(process.exit().await.success());
}
