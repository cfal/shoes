use std::io::ErrorKind;
use std::net::TcpListener;
use std::process::Command;

#[test]
fn check_diagnostics_include_file_and_nested_context_without_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested.yaml");
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let valid = format!(
        "- address: '{}'\n  protocol: {{type: socks}}\n",
        occupied.local_addr().unwrap()
    );
    for (config, context) in [
        (
            "- rule_group: imported\n  rules:\n    - first.srs\n    - path: [VALUE_SECRET_SENTINEL]\n",
            "rules[1]",
        ),
        (
            "- global_limits: {unsupported_policy: VALUE_SECRET_SENTINEL}\n",
            "unknown field `unsupported_policy`",
        ),
        (
            "- pem: private\n  data: PEM_SECRET_SENTINEL\n  unsupported_policy: true\n",
            "unknown field `unsupported_policy`",
        ),
        (
            "- proxy-providers:\n    remote:\n      url: 'https://user:URL_SECRET_SENTINEL@example.invalid/nodes'\n",
            "Unable to determine config type",
        ),
        (
            "- clash_api_address: '127.0.0.1:9090'\n  secret: CONTROLLER_SECRET_SENTINEL\n- global_limits: {max_connections: 0}\n",
            "global_limits.max_connections",
        ),
        (
            "- address: '127.0.0.1:1080'\n  protocol: {type: socks, username: user, password: PASSWORD_SECRET_SENTINEL}\n  rules:\n    - masks: '0.0.0.0/0'\n      client_chain: missing-group\n",
            "missing-group",
        ),
        (
            "- address: '127.0.0.1:1080'\n  protocol: {type: socks, password: PASSWORD_SECRET_SENTINEL}\n  tcp_settings: [\n",
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
            assert!(diagnostic.contains(path.to_str().unwrap()), "{diagnostic}");
            assert!(diagnostic.contains(context), "{diagnostic}");
            assert!(!diagnostic.contains("SECRET_SENTINEL"), "{diagnostic}");
            assert!(!diagnostic.contains("Servers ready"), "{diagnostic}");
        }
    }
}

#[test]
fn check_dry_run_validates_all_files_without_forwarding_or_state_writes() {
    let directory = tempfile::tempdir().unwrap();
    let groups = directory.path().join("groups.yaml");
    let server = directory.path().join("server.yaml");
    let cache = directory.path().join("selectors.db");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    std::fs::write(
        &groups,
        format!(
            "- cache_file_path: '{}'\n- client_group: outbound\n  type: selector\n  default: upstream\n  client_proxies:\n    - name: upstream\n      address: '{}'\n      protocol: {{type: socks}}\n",
            cache.display(), upstream.local_addr().unwrap()
        ),
    )
    .unwrap();
    for mode in ["check", "--dry-run"] {
        for (chain, expected) in [("outbound", 0), ("missing-group", 1)] {
            std::fs::write(
                &server,
                format!(
                    "- address: '{address}'\n  protocol: {{type: socks}}\n  rules:\n    - masks: '0.0.0.0/0'\n      client_chain: {chain}\n"
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
                    diagnostic.contains(groups.to_str().unwrap()),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic.contains(server.to_str().unwrap()),
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
