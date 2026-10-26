use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn diagnostic_contains_path(diagnostic: &str, path: &Path) -> bool {
    let path = path.to_str().unwrap();
    diagnostic.contains(path) || diagnostic.contains(&format!("{path:?}"))
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
            r#"- rule_group: imported
  rules:
    - first.srs
    - path: [VALUE_SECRET_SENTINEL]
"#,
            "rules[1]",
        ),
        (
            r#"- global_limits: {unsupported_policy: VALUE_SECRET_SENTINEL}
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
- global_limits: {max_connections: 0}
"#,
            "global_limits.max_connections",
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
                "client_proxies": [{
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
