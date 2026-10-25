use super::*;

#[test]
fn file_logging_check_drains_without_enabling_stderr_or_leaking_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    let log = directory.path().join("check.log");
    let secret = "d55f24e6-5508-4fce-aeaf-858613a97e47";
    std::fs::write(&config, format!("- address: '127.0.0.1:0'\n  protocol:\n    type: vmess\n    cipher: aes-128-gcm\n    user_id: {secret}\n    force_aead: true\n")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .args(["check", "-t", "1", "-l"])
        .arg(&log)
        .arg(&config)
        .env("RUST_LOG", "warn")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let contents = std::fs::read_to_string(log).unwrap();
    assert!(contents.contains("force_aead"));
    assert!(!contents.contains(secret));
}

#[tokio::test]
async fn file_logging_flushes_both_sinks_on_sigterm() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.yaml");
    let first = directory.path().join("first.log");
    let second = directory.path().join("second.log");
    let address = available_address();
    std::fs::write(
        &config,
        format!("- address: {address}\n  protocol:\n    type: socks\n"),
    )
    .unwrap();
    std::fs::write(&first, "previous record\n").unwrap();
    let mut process = Process::start(
        &config,
        &[
            "--no-reload",
            "-l",
            first.to_str().unwrap(),
            "-l",
            second.to_str().unwrap(),
            "-l",
            "-",
        ],
    );
    process.wait_for("Servers ready").await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"\xff\x00").await.unwrap();
    stream.shutdown().await.unwrap();
    process.wait_for("finished with error").await;
    process.signal(libc::SIGTERM);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let pid = process.child.id();
        scope.spawn(|| tx.send(process.child.wait().unwrap()).unwrap());
        let status = rx.recv_timeout(Duration::from_secs(8));
        if status.is_err() {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        assert!(status.expect("CLI shutdown deadline exceeded").success());
    });
    let first = std::fs::read_to_string(first).unwrap();
    let second = std::fs::read_to_string(second).unwrap();
    assert!(first.starts_with("previous record\n"));
    assert_eq!(first.strip_prefix("previous record\n").unwrap(), second);
    assert!(second.contains("finished with error"));
    assert!(second.chars().all(|c| !c.is_control() || c == '\n'));
}

#[test]
fn file_logging_open_error_is_explicit_after_another_sink_started() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.log");
    let output = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .arg("-l")
        .arg(&first)
        .arg("-l")
        .arg(directory.path())
        .arg("check")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to open log file"));
    assert_eq!(std::fs::read(first).unwrap(), b"");
}
