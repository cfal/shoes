use super::*;
use shoes_test_support::{
    curl::{CurlOptions, run_curl},
    test_servers::{TlsVersion, start_local_http_server, start_local_https_server},
};

async fn download(url: &str, proxy: Option<u16>) -> Duration {
    let mut options = CurlOptions::new()
        .insecure(true)
        .http_version("1.1")
        .discard_output(true)
        .fail_on_http_error(true)
        .timeout(180);
    if let Some(port) = proxy {
        options = options.proxy(format!("socks5h://127.0.0.1:{port}"));
    }
    let started = std::time::Instant::now();
    let output = run_curl(url, options).await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    started.elapsed()
}

#[tokio::test]
#[ignore = "sustained 2 GiB downloads; use release Shoes and pinned Xray on an idle host"]
async fn native_sustained_download_without_injected_latency() {
    timeout(Duration::from_secs(1200), sustained_downloads())
        .await
        .unwrap();
}

async fn sustained_downloads() {
    const BYTES: usize = 2 * 1024 * 1024 * 1024;
    let directory = tempfile::Builder::new()
        .prefix("vless-bulk-")
        .tempdir_in(std::env::var_os("HOME").unwrap())
        .unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    for https in [false, true] {
        let target = if https {
            start_local_https_server("0.0.0.0", 0, &cert_path, &key_path, TlsVersion::Tls13Only)
                .await
                .unwrap()
        } else {
            start_local_http_server("0.0.0.0", 0).await.unwrap()
        };
        let scheme = if https { "https" } else { "http" };
        let base = format!("{scheme}://127.0.0.1:{}", target.local_addr().port());
        let url = format!("{base}/bytes/{BYTES}");
        let elapsed = download(&url, None).await;
        eprintln!(
            "direct {scheme} source calibration: {:.2} MiB/s",
            2048.0 / elapsed.as_secs_f64()
        );
        for mode in ["none", "native", "xorpub", "random"] {
            let (encryption, decryption) = if mode == "none" {
                ("none".to_owned(), "none".to_owned())
            } else {
                let (encryption, decryption, _) = credentials(mode, &["mlkem768"]);
                (encryption, decryption)
            };
            let vision = https && mode != "none";
            let server_port = free_port().await;
            let server = start(
                Kind::Xray,
                server_port,
                server_config(Kind::Xray, server_port, &decryption, vision),
            )
            .await;
            for kind in [Kind::Shoes, Kind::Xray] {
                let client_port = free_port().await;
                let client = start(
                    kind,
                    client_port,
                    client_config(kind, client_port, server_port, &encryption, vision),
                )
                .await;
                download(&format!("{base}/bytes/65536"), Some(client_port)).await;
                let mut samples = Vec::new();
                for _ in 0..3 {
                    samples.push(download(&url, Some(client_port)).await);
                }
                report(
                    &format!("sustained {kind:?} {mode} {scheme} vision={vision}"),
                    samples,
                    BYTES,
                    &client,
                );
            }
            drop(server);
        }
    }
}

fn report(label: &str, mut samples: Vec<Duration>, bytes: usize, peer: &Peer) {
    samples.sort_unstable();
    let total: Duration = samples.iter().sum();
    let status =
        std::fs::read_to_string(format!("/proc/{}/status", peer.process.id())).unwrap_or_default();
    let rss = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .unwrap_or("RSS unavailable");
    let stat =
        std::fs::read_to_string(format!("/proc/{}/stat", peer.process.id())).unwrap_or_default();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .map_or("", |(_, rest)| rest)
        .split_whitespace()
        .collect();
    eprintln!(
        "{label}: samples={} p50={:?} p95={:?} MiB/s={:.2} CPU ticks(user/system)={}/{} {rss}",
        samples.len(),
        samples[samples.len() / 2],
        samples[(samples.len() * 95 / 100).min(samples.len() - 1)],
        bytes as f64 * samples.len() as f64 / total.as_secs_f64() / 1048576.0,
        fields.get(11).unwrap_or(&"?"),
        fields.get(12).unwrap_or(&"?")
    );
}

#[tokio::test]
#[ignore = "local performance sampling; requires pinned Xray and SHOES_BASELINE_BINARY"]
async fn native_and_legacy_latency_throughput() {
    timeout(Duration::from_secs(600), samples()).await.unwrap();
}

async fn samples() {
    let baseline: PathBuf = std::env::var_os("SHOES_BASELINE_BINARY")
        .expect("baseline binary required")
        .into();
    let (target, _, mut echo_task) = echo().await;
    for gap in [false, true] {
        for mode in ["native", "xorpub", "random"] {
            for resume in [false, true] {
                let (mut encryption, mut decryption, _) = credentials(mode, &["mlkem768"]);
                // Compare reference shaping rather than the fixed schedule used by correctness tests.
                encryption = encryption.replace(".100-35-35", "");
                decryption = decryption.replace(
                    ".100-35-35",
                    if gap {
                        ".100-35-35.100-1000-1000.100-35-35"
                    } else {
                        ""
                    },
                );
                if !resume {
                    encryption = encryption.replace("0rtt", "1rtt");
                }
                let server_port = free_port().await;
                let server = start(
                    Kind::Xray,
                    server_port,
                    server_config(Kind::Xray, server_port, &decryption, false),
                )
                .await;
                for kind in [Kind::Shoes, Kind::Xray] {
                    let client_port = free_port().await;
                    let client = start(
                        kind,
                        client_port,
                        client_config(kind, client_port, server_port, &encryption, false),
                    )
                    .await;
                    exchange(client_port, target, b"warmup").await.unwrap();
                    let mut setup = Vec::new();
                    let mut bulk = Vec::new();
                    for _ in 0..12 {
                        let started = std::time::Instant::now();
                        exchange(client_port, target, b"latency").await.unwrap();
                        setup.push(started.elapsed());
                        let started = std::time::Instant::now();
                        exchange(client_port, target, &vec![42; 1048576])
                            .await
                            .unwrap();
                        bulk.push(started.elapsed());
                    }
                    report(
                        &format!("{kind:?} {mode} resume={resume} long_gap={gap} TTFB"),
                        setup,
                        7,
                        &client,
                    );
                    report(
                        &format!("{kind:?} {mode} resume={resume} long_gap={gap} bulk"),
                        bulk,
                        2 * 1048576,
                        &client,
                    );
                }
                drop(server);
            }
        }
    }
    echo_task.stop().await;

    let (target, connector, mut target_task) = tls_echo(false).await;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let server_port = free_port().await;
    let server = start(
        Kind::Xray,
        server_port,
        wrap(
            Kind::Xray,
            server_config(Kind::Xray, server_port, "none", true),
            true,
            Transport::Tls,
            &cert_pem,
            &key_pem,
            target,
        ),
    )
    .await;
    // Repeat in reverse order to expose ordering/warm-cache bias.
    for (label, binary) in [
        ("baseline", baseline.clone()),
        ("current", Kind::Shoes.binary()),
        ("current", Kind::Shoes.binary()),
        ("baseline", baseline),
    ] {
        let client_port = free_port().await;
        let mut config = wrap(
            Kind::Shoes,
            client_config(Kind::Shoes, client_port, server_port, "none", false),
            false,
            Transport::Tls,
            &cert_pem,
            &key_pem,
            target,
        );
        config[0]["rules"][0]["client_chain"]["protocol"]["vision"] = json!(true);
        let client = start_binary(Kind::Shoes, client_port, config, binary).await;
        let mut samples = Vec::new();
        for _ in 0..12 {
            let start = std::time::Instant::now();
            let socket = socks_connect(client_port, target).await.unwrap();
            let mut tls = connector
                .connect("localhost".try_into().unwrap(), socket)
                .await
                .unwrap();
            for size in [64, 64].into_iter().chain(std::iter::repeat_n(8192, 128)) {
                let data = vec![42; size];
                tls.write_all(&data).await.unwrap();
                tls.flush().await.unwrap();
                let mut reply = vec![0; size];
                tls.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, data);
            }
            samples.push(start.elapsed());
        }
        report(
            &format!("legacy TLS Vision {label}"),
            samples,
            2 * 1048576,
            &client,
        );
    }
    drop(server);
    target_task.stop().await;
}
