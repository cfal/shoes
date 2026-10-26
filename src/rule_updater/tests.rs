use super::install::FAIL_RENAME;
use super::*;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const STAGE_SUFFIX: &str = ".shoes-update.tmp";
const MAX_HEADERS: usize = 32 * 1024;

fn stamp(m: &Metadata) -> (u64, u64, u64, i64, i64) {
    (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec())
}

fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)
}

const VALID: &[u8] = include_bytes!("../../tests/fixtures/rule_sets/singbox.json");
const OLD: &[u8] = br#"{"version":1,"rules":[{"domain":["old.example"]}]}"#;

#[test]
fn bootstrap_routes_are_inline_tcp_and_preserve_dns_name_precedence() {
    let dir = directory();
    let remote = source(
        "https://example.com/rules.json",
        &dir.path().join("cache.json"),
    );
    let proxy = serde_json::json!({"address": "127.0.0.1:1080", "protocol": {"type": "socks"}});
    for chain in [
        serde_json::json!("direct"),
        proxy.clone(),
        serde_json::json!([{"pool": ["direct", proxy.clone()]}]),
    ] {
        for dns in [
            "system",
            "udp://127.0.0.1",
            "tcp://127.0.0.1",
            "tls://127.0.0.1",
            "https://127.0.0.1/dns-query",
        ] {
            let mut source = remote.clone();
            source.download.as_mut().unwrap().client_chain =
                serde_json::from_value(chain.clone()).unwrap();
            source.download.as_mut().unwrap().bootstrap_url = dns.into();
            crate::config::validate_rule_bootstrap(
                &configs(&source),
                std::slice::from_mut(&mut source),
            )
            .unwrap();
        }
    }
    for chain in [
        serde_json::json!("named"),
        serde_json::json!([{"pool": [proxy.clone(), "named"]}]),
        serde_json::json!({"address": "127.0.0.1:443", "transport": "quic", "protocol": {"type": "socks"}}),
        serde_json::json!([proxy, "direct"]),
    ] {
        let mut source = remote.clone();
        source.download.as_mut().unwrap().client_chain = serde_json::from_value(chain).unwrap();
        assert!(
            crate::config::validate_rule_bootstrap(
                &configs(&source),
                std::slice::from_mut(&mut source)
            )
            .is_err()
        );
    }
    for dns in ["h3://127.0.0.1", "udp://dns.invalid", "named"] {
        let mut source = remote.clone();
        source.download.as_mut().unwrap().bootstrap_url = dns.into();
        assert!(
            crate::config::validate_rule_bootstrap(
                &configs(&source),
                std::slice::from_mut(&mut source)
            )
            .is_err()
        );
    }
    let mut config = configs(&remote);
    config.push(
        serde_json::from_value(
            serde_json::json!({"dns_group": "system", "dns_servers": "tcp://127.0.0.1"}),
        )
        .unwrap(),
    );
    let error = crate::config::validate_rule_bootstrap(&config, &mut [remote]).unwrap_err();
    assert!(error.to_string().contains("named DNS"), "{error}");
}

#[tokio::test]
async fn bootstrap_only_fetches_missing_caches_and_preflights_all_required_routes() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    let (url, fixture) = serve(response(200, "", VALID)).await;
    let remote = source(&url, &path);
    let config = super::bootstrap(configs(&remote), &[]).await.unwrap();
    fixture.await.unwrap();
    crate::config::compile_configs(config).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), VALID);

    write_rule(&path, b"DOWNLOADED_SECRET invalid");
    let mut unsupported = remote.clone();
    unsupported.download.as_mut().unwrap().bootstrap_url = "named".into();
    let config = super::bootstrap(configs(&unsupported), &[]).await.unwrap();
    let error = crate::config::compile_configs(config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("repair or remove"), "{error}");
    assert!(!error.contains("DOWNLOADED_SECRET"), "{error}");
    assert_eq!(std::fs::read(&path).unwrap(), b"DOWNLOADED_SECRET invalid");

    std::fs::remove_file(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = source(
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        &path,
    );
    unsupported.url = remote.url.clone();
    unsupported.path = dir.path().join("second.json");
    let mut config = configs(&remote);
    config.extend(configs(&unsupported).into_iter().skip(1));
    assert!(
        super::bootstrap(config, &[])
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid rule bootstrap_url")
    );
    assert!(!path.exists());
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bootstrap_does_not_replace_a_cache_created_after_probing() {
    let dir = directory();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rules.json", listener.local_addr().unwrap());
    let first = source(&url, &dir.path().join("first.json"));
    let second = source(&url, &dir.path().join("second.json"));
    let mut config = configs(&first);
    config.extend(configs(&second).into_iter().skip(1));
    let task = tokio::spawn(super::bootstrap(config, &[]));
    let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    request(&mut stream).await;
    write_rule(&second.path, OLD);
    stream.write_all(&response(200, "", VALID)).await.unwrap();
    let error = task.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("cache appeared"), "{error}");
    assert_eq!(std::fs::read(&first.path).unwrap(), VALID);
    assert_eq!(std::fs::read(&second.path).unwrap(), OLD);
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert!(!stage_path(&second.path).exists());
}

#[tokio::test]
async fn bootstrap_preserves_inline_tls_names_and_loads_local_pems() {
    let dir = directory();
    let cache = dir.path().join("cache");
    install::create_cache_directory(&cache).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["proxy.invalid".into()]).unwrap();
    let cert_path = dir.path().join("client.pem");
    std::fs::write(&cert_path, certificate.cert.pem()).unwrap();
    let mut remote = source(
        "http://192.0.2.10:8080/rules.json",
        &cache.join("rules.json"),
    );
    remote.download.as_mut().unwrap().client_chain = serde_json::from_value(serde_json::json!({
        "address": listener.local_addr().unwrap().to_string(),
        "protocol": {"type": "tls", "sni_hostname": "proxy.invalid", "verify": false,
            "key": "client-key", "cert": cert_path,
            "protocol": {"type": "socks"}}
    }))
    .unwrap();
    let mut config = configs(&remote);
    config.push(
        serde_json::from_value(serde_json::json!({
            "pem": "client-key", "data": certificate.signing_key.serialize_pem()
        }))
        .unwrap(),
    );
    let (config, _) = crate::config::convert_cert_paths(config).await.unwrap();
    let tls = crate::rustls_config_util::try_create_server_config(
        certificate.cert.pem().as_bytes(),
        certificate.signing_key.serialize_pem().as_bytes(),
        vec![],
        &[],
        &[],
        &Default::default(),
    )
    .unwrap();
    let fixture = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.server_name(), Some("proxy.invalid"));
        let connect = socks_connect(&mut stream).await;
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 10, 31, 144]);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        assert!(request(&mut stream).await.contains("host: 192.0.2.10:8080"));
        stream.write_all(&response(200, "", VALID)).await.unwrap();
        stream.flush().await.unwrap();
    });
    let config = timeout(Duration::from_secs(5), super::bootstrap(config, &[]))
        .await
        .unwrap()
        .unwrap();
    fixture.await.unwrap();
    crate::config::compile_configs(config).await.unwrap();
    assert_eq!(std::fs::read(&remote.path).unwrap(), VALID);
}

#[tokio::test]
async fn bootstrap_preflights_later_synthetic_endpoints_before_any_download() {
    for retained in [false, true] {
        for endpoint in ["destination", "proxy", "DNS"] {
            let dir = directory();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/rules.json", listener.local_addr().unwrap());
            let mut first = source(&url, &dir.path().join("first.json"));
            first.download.as_mut().unwrap().bootstrap_url = "tcp://127.0.0.1:1".into();
            let mut second = first.clone();
            second.path = dir.path().join("second.json");
            match endpoint {
                "destination" => second.url = Some("http://198.18.0.1/rules.json".into()),
                "proxy" => {
                    second.download.as_mut().unwrap().client_chain =
                        serde_json::from_value(serde_json::json!([{"pool": ["direct", {
                            "address": "198.18.0.1:1080", "protocol": {"type": "socks"}
                        }]}]))
                        .unwrap()
                }
                "DNS" => {
                    second.download.as_mut().unwrap().bootstrap_url = "tcp://198.18.0.1".into()
                }
                _ => unreachable!(),
            }
            let mut config = configs(&first);
            config.extend(configs(&second).into_iter().skip(1));
            let ranges = if retained {
                vec!["198.18.0.0/15".parse().unwrap()]
            } else {
                config.push(
                    serde_json::from_value(serde_json::json!({
                        "dns_group": "fake", "dns_servers": "system", "fake_ip": {}
                    }))
                    .unwrap(),
                );
                Vec::new()
            };
            let error = timeout(Duration::from_secs(3), super::bootstrap(config, &ranges))
                .await
                .unwrap()
                .unwrap_err();
            assert!(
                error.to_string().contains("synthetic"),
                "{endpoint}: {error}"
            );
            assert!(error.to_string().contains("second.json"), "{error}");
            assert!(!first.path.exists());
            assert!(!second.path.exists());
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn bootstrap_rejects_retained_synthetic_addresses_before_connecting() {
    let dir = directory();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source = source(
        &format!("http://{}/rules.json", listener.local_addr().unwrap()),
        &dir.path().join("cache.json"),
    );
    let error = super::bootstrap(configs(&source), &["127.0.0.0/8".parse().unwrap()])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("synthetic"), "{error}");
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    assert!(!source.path.exists());
}

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn write_rule(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn source(url: &str, path: &Path) -> RuleSource {
    let mut source = RuleSource::from_path(path.into());
    source.url = Some(url.into());
    source.format = Some(crate::rule_set::Format::SingboxJson);
    source.download = Some(Box::new(crate::rule_set::Download {
        client_chain: crate::config::ClientChain::default(),
        bootstrap_url: "system".into(),
    }));
    source
}

fn configs(source: &RuleSource) -> Vec<Config> {
    serde_json::from_value(
        serde_json::json!([{"rule_cache_dir": source.path.parent()}, {
            "address": "127.0.0.1:0", "protocol": {"type": "socks"},
            "rules": [{"masks": source, "action": "block"}]
        }]),
    )
    .unwrap()
}

async fn update(source: &RuleSource, limits: Limits) -> io::Result<&'static str> {
    let staged = super::stage(
        source,
        Install::open_async(&source.path).await?,
        &DnsRegistry::new(),
        GlobalLimits::default(),
        limits,
        &mut http::DownloadState::default(),
    )
    .await?;
    validate_staged(configs(source), &source.path, &staged.install).await?;
    Ok(
        if staged.install.finish_async(staged.digest).await?.changed() {
            "updated"
        } else {
            "unchanged"
        },
    )
}

fn response(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut result = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    result.extend_from_slice(body);
    result
}

async fn request(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        result.push(stream.read_u8().await.unwrap());
        assert!(result.len() < 16 * 1024);
    }
    String::from_utf8(result).unwrap()
}

async fn socks_connect(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> [u8; 10] {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut connect = [0; 10];
    stream.read_exact(&mut connect).await.unwrap();
    connect
}

async fn serve(bytes: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/rules?token=QUERY_SECRET",
        listener.local_addr().unwrap()
    );
    let task = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let request = request(&mut stream).await;
        assert!(request.starts_with("GET /rules?token=QUERY_SECRET HTTP/1.1\r\n"));
        assert!(request.contains("accept-encoding: identity"));
        let _ = stream.write_all(&bytes).await;
    });
    (url, task)
}

fn stage_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(STAGE_SUFFIX);
    name.into()
}

fn assert_preserved(path: &Path, original: &Metadata) {
    assert_eq!(std::fs::read(path).unwrap(), OLD);
    assert_eq!(stamp(&std::fs::metadata(path).unwrap()), stamp(original));
    assert!(!stage_path(path).exists());
}

#[tokio::test]
async fn validated_fixture_replaces_atomically_and_unchanged_does_not_rename() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let mut held_reader = File::open(&path).unwrap();
    for expected in ["updated", "unchanged"] {
        let before = std::fs::metadata(&path).unwrap();
        let (url, fixture) = serve(response(200, "", VALID)).await;
        let report = update(&source(&url, &path), Limits::default())
            .await
            .unwrap();
        fixture.await.unwrap();
        assert_eq!(report, expected);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.ino() == after.ino(), expected == "unchanged");
        if expected == "unchanged" {
            assert_eq!(stamp(&before), stamp(&after));
        }
        assert_eq!(after.mode() & 0o777, 0o640);
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
        assert!(!stage_path(&path).exists());
    }
    let mut old = Vec::new();
    held_reader.read_to_end(&mut old).unwrap();
    assert_eq!(old, OLD);
}

#[tokio::test]
async fn rejects_http_and_parser_failures_without_touching_last_good() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    for _ in 0..1024 {
        compressed.write_all(&[b' '; 1024]).unwrap();
    }
    let bomb = compressed.finish().unwrap();
    let cases = [
        (response(404, "", VALID), "status 404"),
        (response(500, "", VALID), "status 500"),
        (
            response(302, "Location: http://127.0.0.1/SECRET\r\n", VALID),
            "status 302",
        ),
        (response(206, "", VALID), "status 206"),
        (response(200, "", b"not JSON QUERY_SECRET"), "validation"),
        (
            response(200, "", br#"{"version":1,"rules":["#),
            "validation",
        ),
        (
            response(200, "", br#"{"version":6,"rules":[]}"#),
            "validation",
        ),
        (
            response(200, "", br#"{"version":1,"rules":[{"unknown":true}]}"#),
            "validation",
        ),
        (
            response(200, "", br#"{"version":1,"rules":[]}"#),
            "validation",
        ),
        (
            response(200, "Content-Encoding: gzip\r\n", &bomb),
            "encoding unsupported",
        ),
        (response(200, "", &bomb), "validation"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\n\r\n".to_vec(),
            "size",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
            "truncated",
        ),
        (b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(), "validation"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
            "validation",
        ),
        (
            response(
                200,
                &format!("X-Fill: {}\r\n", "a".repeat(MAX_HEADERS + 1)),
                VALID,
            ),
            "headers",
        ),
        (response(200, &"X-Fill: a\r\n".repeat(65), VALID), "headers"),
    ];
    for (bytes, expected) in cases {
        let (url, fixture) = serve(bytes).await;
        let error = update(&source(&url, &path), Limits::default())
            .await
            .expect_err(expected);
        fixture.await.unwrap();
        let error = error.to_string();
        assert!(error.contains(expected), "expected {expected}: {error}");
        assert!(!error.contains("SECRET"), "{error}");
        assert!(!error.contains(&url), "{error}");
        assert_preserved(&path, &original);
    }
}

#[tokio::test]
async fn empty_download_keeps_the_validation_error_and_last_good_file() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    let (url, fixture) = serve(response(200, "", br#"{"version":1,"rules":[]}"#)).await;
    let error = update(&source(&url, &path), Limits::default())
        .await
        .unwrap_err();
    fixture.await.unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "download failed Shoes rule validation");
    assert_preserved(&path, &original);
}

#[tokio::test]
async fn future_mtime_is_not_freshness_and_offline_fetch_preserves_bytes() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(86400))
        .unwrap();
    let original = std::fs::metadata(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let offline = format!("http://{}/?QUERY_SECRET", listener.local_addr().unwrap());
    drop(listener);
    assert!(
        update(&source(&offline, &path), Limits::default())
            .await
            .is_err()
    );
    assert_preserved(&path, &original);
    let (url, fixture) = serve(response(200, "", OLD)).await;
    let report = update(&source(&url, &path), Limits::default())
        .await
        .unwrap();
    fixture.await.unwrap();
    assert_eq!(report, "unchanged");
    assert_preserved(&path, &original);
}

#[test]
fn ownership_lock_stale_stage_and_unsafe_paths() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let first = Install::open(&path).unwrap();
    assert_eq!(
        Install::open(&path).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(stage_path(&path).exists());
    drop(first);
    assert!(!stage_path(&path).exists());
    std::fs::write(stage_path(&path), "interrupted download").unwrap();
    std::fs::set_permissions(stage_path(&path), std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(Install::open(&path).unwrap());
    assert!(!stage_path(&path).exists());
    let alias = dir.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(Install::open(&alias).is_err());
    std::fs::remove_file(&alias).unwrap();
    symlink(dir.path(), &alias).unwrap();
    assert!(Install::open(&alias.join("rules.json")).is_err());
    assert!(Install::open(&dir.path().join("../rules.json")).is_err());
    drop(Install::open(&dir.path().join("missing.json")).unwrap());
    let link = dir.path().join("hardlink");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(Install::open(&path).is_err());
    std::fs::remove_file(&link).unwrap();
    symlink(&path, stage_path(&path)).unwrap();
    assert!(Install::open(&path).is_err());
    std::fs::remove_file(stage_path(&path)).unwrap();
    let lock = dir.path().join("rules.json.shoes-update.lock");
    std::fs::remove_file(&lock).unwrap();
    symlink(&path, &lock).unwrap();
    assert!(Install::open(&path).is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Install::open(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Install::open(&path).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fifo = dir.path().join("fifo");
    let fifo_name = c_name(fifo.as_os_str()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(Install::open(&fifo).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), OLD);
}

#[tokio::test]
async fn cancellation_removes_stage_and_releases_lock() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rules", listener.local_addr().unwrap());
    let options = source(&url, &path);
    {
        let future = update(&options, Limits::default());
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => panic!("unexpected completion: {result:?}"),
            accepted = listener.accept() => {
                let _stream = accepted.unwrap();
                assert!(stage_path(&path).exists());
            }
        }
    }
    assert_preserved(&path, &original);
    drop(Install::open(&path).unwrap());
}

#[tokio::test]
async fn idle_header_body_connect_and_overall_trickle_deadlines() {
    for (mode, expected) in [
        ("headers", "header deadline"),
        ("idle", "body idle"),
        ("trickle", "overall"),
        ("tls", "connect/DNS/TLS"),
    ] {
        let dir = directory();
        let path = dir.path().join("rules.json");
        write_rule(&path, OLD);
        let original = std::fs::metadata(&path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "{}://{}/rules?SECRET",
            if mode == "tls" { "https" } else { "http" },
            listener.local_addr().unwrap()
        );
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if mode != "tls" {
                request(&mut stream).await;
            }
            if mode == "idle" || mode == "trickle" {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    .await
                    .unwrap();
            }
            if mode == "trickle" {
                for _ in 0..20 {
                    if stream.write_all(b" ").await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } else {
                std::future::pending::<()>().await;
            }
        });
        let limits = Limits {
            bytes: MAX_BYTES,
            connect: Duration::from_millis(150),
            idle: Duration::from_millis(150),
            overall: Duration::from_millis(250),
        };
        let error = update(&source(&url, &path), limits).await.unwrap_err();
        fixture.abort();
        let _ = fixture.await;
        assert!(error.to_string().contains(expected), "{mode}: {error}");
        assert!(!error.to_string().contains("SECRET"));
        assert_preserved(&path, &original);
    }
}

#[tokio::test]
async fn rejects_untrusted_tls_certificate() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let config = crate::rustls_config_util::try_create_server_config(
        certificate.cert.pem().as_bytes(),
        certificate.signing_key.serialize_pem().as_bytes(),
        vec![],
        &[],
        &[],
        &Default::default(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}/rules?QUERY_SECRET",
        listener.local_addr().unwrap().port()
    );
    let fixture = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(stream).await.is_err());
    });
    let error = update(&source(&url, &path), Limits::default())
        .await
        .unwrap_err();
    fixture.await.unwrap();
    assert!(
        error.to_string().contains("TLS certificate verification"),
        "{error}"
    );
    assert!(!error.to_string().contains("SECRET"));
    assert_preserved(&path, &original);
}

#[test]
fn installation_failure_and_concurrent_replacement_preserve_current_file() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    let mut install = Install::open(&path).unwrap();
    install.file.write_all(VALID).unwrap();
    FAIL_RENAME.with(|flag| flag.set(true));
    assert!(install.finish(blake3::hash(VALID)).is_err());
    drop(install);
    assert_preserved(&path, &original);
    let mut install = Install::open(&path).unwrap();
    install.file.write_all(VALID).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(install.finish(blake3::hash(VALID)).is_err());
    assert!(!path.exists());
    std::fs::write(&path, "operator replacement").unwrap();
    assert!(install.finish(blake3::hash(VALID)).is_err());
    drop(install);
    assert_eq!(std::fs::read(&path).unwrap(), b"operator replacement");
}

#[test]
fn post_rename_sync_failure_reports_replacement_not_retention() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let mut install = Install::open(&path).unwrap();
    install.file.write_all(VALID).unwrap();
    super::install::FAIL_AFTER_RENAME.with(|flag| flag.set(true));
    let outcome = install.finish(blake3::hash(VALID)).unwrap();
    assert_eq!(outcome, super::install::Outcome::DurabilityUncertain);
    assert!(outcome.changed());
    assert_eq!(std::fs::read(path).unwrap(), VALID);
}

#[test]
fn replaced_sidecars_are_not_installed_or_removed_by_previous_owner() {
    for replace_lock in [false, true] {
        let dir = directory();
        let path = dir.path().join("rules.json");
        write_rule(&path, OLD);
        let original = std::fs::metadata(&path).unwrap();
        let mut install = Install::open(&path).unwrap();
        install.file.write_all(VALID).unwrap();
        let replaced = if replace_lock {
            dir.path().join("rules.json.shoes-update.lock")
        } else {
            stage_path(&path)
        };
        std::fs::remove_file(&replaced).unwrap();
        write_rule(&replaced, b"replacement must survive");
        assert!(install.finish(blake3::hash(VALID)).is_err());
        drop(install);
        assert_eq!(
            std::fs::read(&replaced).unwrap(),
            b"replacement must survive"
        );
        assert_eq!(std::fs::read(&path).unwrap(), OLD);
        assert_eq!(stamp(&std::fs::metadata(&path).unwrap()), stamp(&original));
    }
}

#[test]
fn directory_descriptor_survives_ancestor_rename_without_following_symlink() {
    let dir = directory();
    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("rules.json");
    write_rule(&path, OLD);
    let mut install = Install::open(&path).unwrap();
    install.file.write_all(VALID).unwrap();
    let moved = dir.path().join("moved");
    std::fs::rename(&parent, &moved).unwrap();
    let decoy = dir.path().join("decoy");
    std::fs::create_dir(&decoy).unwrap();
    std::fs::write(decoy.join("rules.json"), OLD).unwrap();
    symlink(&decoy, &parent).unwrap();
    install.finish(blake3::hash(VALID)).unwrap();
    drop(install);
    assert_eq!(std::fs::read(moved.join("rules.json")).unwrap(), VALID);
    assert_eq!(std::fs::read(decoy.join("rules.json")).unwrap(), OLD);
    assert!(!stage_path(&moved.join("rules.json")).exists());
}

#[test]
fn remote_format_precedence_and_strict_metadata() {
    use crate::rule_set::Format;
    let dir = directory();
    for (url, cache, prefix, expected) in [
        (
            "https://example.com/list.srs?name=x.json",
            "cache.json",
            b"".as_slice(),
            Format::Srs,
        ),
        (
            "https://example.com/list.JSON",
            "cache.srs",
            b"",
            Format::SingboxJson,
        ),
        (
            "https://example.com/download",
            "cache.json",
            b"",
            Format::SingboxJson,
        ),
        (
            "https://example.com/list.json",
            "cache.json",
            b"SRS\x02",
            Format::Srs,
        ),
    ] {
        let mut source = source(url, &dir.path().join(cache));
        source.format = None;
        assert_eq!(source.format(prefix).unwrap(), expected);
        source.format = Some(Format::MihomoText);
        assert_eq!(source.format(prefix).unwrap(), Format::MihomoText);
    }
    for url in [
        "https://USER_SECRET:PASSWORD_SECRET@example.com/?QUERY_SECRET",
        "bad:QUERY_SECRET",
        "https://example.com/#SECRET",
    ] {
        let error = source(url, &dir.path().join("rules.json"))
            .parsed_url()
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SECRET"));
    }
    for interval in [
        "0s",
        "-1d",
        "1",
        "1ms",
        "99999999999999999d",
        "366d",
        "",
        "7D",
    ] {
        let mut source = source(
            "https://example.com/list.json",
            &dir.path().join("rules.json"),
        );
        source.update_interval = Some(interval.into());
        assert!(source.parsed_url().is_err(), "{interval}");
    }
    let mut local = RuleSource::from_path(dir.path().join("local.json"));
    local.update_interval = Some("7d".into());
    assert!(local.parsed_url().is_err());
}

#[tokio::test]
async fn every_existing_decoder_validates_downloads() {
    use crate::rule_set::{Behavior, Format};
    use prost::Message;
    #[derive(Clone, PartialEq, Message)]
    struct Record {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(bytes = "vec", tag = "2")]
        entry: Vec<u8>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Data {
        #[prost(message, repeated, tag = "1")]
        records: Vec<Record>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Domain {
        #[prost(int32, tag = "1")]
        kind: i32,
        #[prost(string, tag = "2")]
        name: String,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Cidr {
        #[prost(bytes = "vec", tag = "1")]
        ip: Vec<u8>,
        #[prost(uint32, tag = "2")]
        prefix: u32,
    }
    let dat = |entry| {
        Data {
            records: vec![Record {
                code: "TEST".into(),
                entry,
            }],
        }
        .encode_to_vec()
    };
    for (format, behavior, code, bytes) in [
        (Format::SingboxJson, None, None, VALID.to_vec()),
        (
            Format::Srs,
            None,
            None,
            include_bytes!("../../tests/fixtures/rule_sets/singbox-v2.srs").to_vec(),
        ),
        (
            Format::Mrs,
            None,
            None,
            include_bytes!("../../tests/fixtures/rule_sets/mihomo-domain.mrs").to_vec(),
        ),
        (
            Format::MihomoText,
            Some(Behavior::Domain),
            None,
            b"example.com\n".to_vec(),
        ),
        (
            Format::MihomoYaml,
            Some(Behavior::Domain),
            None,
            b"payload:\n  - example.com\n".to_vec(),
        ),
        (
            Format::GeositeDat,
            None,
            Some("test"),
            dat(Domain {
                kind: 3,
                name: "example.com".into(),
            }
            .encode_to_vec()),
        ),
        (
            Format::GeoipDat,
            None,
            Some("test"),
            dat(Cidr {
                ip: vec![192, 0, 2, 0],
                prefix: 24,
            }
            .encode_to_vec()),
        ),
    ] {
        let dir = directory();
        let path = dir.path().join("cache");
        let (url, fixture) = serve(response(200, "", &bytes)).await;
        let mut source = source(&url, &path);
        source.format = Some(format);
        source.behavior = behavior;
        source.code = code.map(str::to_owned);
        assert_eq!(
            update(&source, Limits::default()).await.unwrap(),
            "updated",
            "{format:?}"
        );
        fixture.await.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

#[tokio::test]
async fn stalled_url_address_does_not_block_another_guarded_candidate() {
    #[derive(Debug)]
    struct Bootstrap;
    impl crate::resolver::Resolver for Bootstrap {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            assert_eq!(location.address().to_string(), "remote.invalid");
            Box::pin(async {
                Ok(vec![
                    "192.0.2.1:8080".parse().unwrap(),
                    "192.0.2.2:8080".parse().unwrap(),
                ])
            })
        }
    }
    async fn socks(listener: &TcpListener, ip: u8) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        let connect = socks_connect(&mut stream).await;
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, ip, 31, 144]);
        stream
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = directory();
    let mut source = source(
        "http://remote.invalid:8080/rules",
        &dir.path().join("rules.json"),
    );
    let download = source.download.as_mut().unwrap();
    download.bootstrap_url = "bootstrap".into();
    download.client_chain = serde_json::from_value(serde_json::json!({
        "address": listener.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}
    }))
    .unwrap();
    let mut dns = DnsRegistry::new();
    dns.register("bootstrap".into(), Arc::new(Bootstrap));
    let fixture = tokio::spawn(async move {
        let mut stalled = socks(&listener, 1).await;
        let mut working = socks(&listener, 2).await;
        working
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        assert!(
            request(&mut working)
                .await
                .contains("host: remote.invalid:8080")
        );
        working.write_all(&response(200, "", VALID)).await.unwrap();
        assert!(stalled.read_u8().await.is_err());
    });
    drop(
        timeout(
            Duration::from_secs(2),
            stage(
                &source,
                Install::open_async(&source.path).await.unwrap(),
                &dns,
                GlobalLimits::default(),
                Limits::default(),
                &mut http::DownloadState::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap(),
    );
    timeout(Duration::from_secs(2), fixture)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn dangling_sidecar_aliases_and_symlink_cycles_are_rejected() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    let source = source("https://example.invalid/rules.json", &path);
    for suffix in [".shoes-update.lock", ".shoes-update.tmp"] {
        let alias = dir.path().join(format!("alias{suffix}.json"));
        symlink(format!("cache.json{suffix}"), &alias).unwrap();
        let mut config = configs(&source);
        config.push(
            serde_json::from_value(
                serde_json::json!({"rule_source_group": "alias", "rules": [{"path": alias}]}),
            )
            .unwrap(),
        );
        let error = crate::rule_set::validate_remote_paths(&mut config, &[]).unwrap_err();
        assert!(
            error.to_string().contains("overlaps rule_cache_dir"),
            "{error}"
        );
    }
    let cycle = dir.path().join("cycle.json");
    symlink("./cycle.json", &cycle).unwrap();
    assert!(
        crate::rule_set::source_identity(&cycle)
            .unwrap_err()
            .to_string()
            .contains("loop")
    );
}

#[tokio::test]
async fn ipv6_literal_download_reaches_the_exact_url_port() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let url = format!("http://{}/rules", listener.local_addr().unwrap());
    let fixture = tokio::spawn(async move {
        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        request(&mut stream).await;
        stream.write_all(&response(200, "", VALID)).await.unwrap();
    });
    let dir = directory();
    let path = dir.path().join("rules.json");
    assert_eq!(
        update(&source(&url, &path), Limits::default())
            .await
            .unwrap(),
        "updated"
    );
    fixture.await.unwrap();
}

#[tokio::test]
async fn named_download_chain_is_used_and_failure_never_falls_back_to_direct() {
    use crate::control::selection::{SelectionOwner, SelectorDefinition};
    for persisted in [false, true] {
        let dir = directory();
        let cache = dir.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = cache.join("cache.json");
        write_rule(&path, OLD);
        let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let connect = socks_connect(&mut stream).await;
            assert_eq!(&connect[..4], &[5, 1, 0, 1]);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            request(&mut stream).await;
            stream.write_all(&response(200, "", VALID)).await.unwrap();
        });
        let mut source = source(
            &format!("http://{}/rules", trap.local_addr().unwrap()),
            &path,
        );
        source.download.as_mut().unwrap().client_chain =
            serde_json::from_value(serde_json::json!("fetch")).unwrap();
        let mut config = configs(&source);
        let store = dir.path().join("selections.json");
        if persisted {
            let mut owner = SelectionOwner::new(Some(&store)).unwrap();
            let view = owner
                .prepare(std::collections::BTreeMap::from([(
                    "fetch".into(),
                    SelectorDefinition {
                        members: vec!["DIRECT".into(), "working".into()],
                        default: Some("DIRECT".into()),
                    },
                )]))
                .unwrap();
            owner.activate(view).unwrap();
            owner.select("fetch", "working").unwrap();
            drop(owner);
            config.insert(
                0,
                serde_json::from_value(serde_json::json!({"cache_file_path": store})).unwrap(),
            );
        }
        config.insert(0, serde_json::from_value(serde_json::json!({"client_group": "fetch", "type": "selector", "default": if persisted { "DIRECT" } else { "working" }, "client_proxies": [
        "direct",
        {"name": "working", "address": proxy_address.to_string(), "protocol": {"type": "socks"}}
    ]})).unwrap());
        let mut validated = crate::config::compile_configs(config.clone())
            .await
            .unwrap();
        let mut control =
            crate::control::runtime::ControlService::new(validated.control.clone()).unwrap();
        control.runtime.prepare(&mut validated).await.unwrap();
        let remote = &validated.remote_rules[0];
        assert!(
            refresh_source(
                remote,
                &config,
                &DnsRegistry::new(),
                GlobalLimits::default(),
                &mut http::DownloadState::default()
            )
            .await
            .unwrap()
        );
        fixture.await.unwrap();
        assert!(
            refresh_source(
                remote,
                &config,
                &DnsRegistry::new(),
                GlobalLimits::default(),
                &mut http::DownloadState::default()
            )
            .await
            .is_err()
        );
        assert!(
            timeout(Duration::from_millis(50), trap.accept())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
        control.shutdown().await;
    }
}

#[tokio::test]
async fn refresh_noop_remembers_check_time_and_removal_drops_download() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(86400))
        .unwrap();
    let (url, fixture) = serve(response(200, "", OLD)).await;
    let mut source = source(&url, &path);
    source.update_interval = Some("7d".into());
    let mut refresh = Refresh::new(configs(&source), std::slice::from_ref(&source), None).unwrap();
    assert!(refresh.scheduled[0].due <= Instant::now());
    assert!(
        timeout(
            Duration::from_millis(100),
            refresh.changed(&DnsRegistry::new(), GlobalLimits::default())
        )
        .await
        .is_err()
    );
    fixture.await.unwrap();
    assert!(refresh.scheduled[0].due > Instant::now() + Duration::from_secs(3600));
    let next = Refresh::new(configs(&source), &[source], Some(&refresh)).unwrap();
    assert_eq!(next.scheduled[0].due, refresh.scheduled[0].due);
    assert!(
        Refresh::new(Vec::new(), &[], Some(&next))
            .unwrap()
            .scheduled
            .is_empty()
    );
    assert_eq!(std::fs::read(&path).unwrap(), OLD);
}

#[tokio::test]
async fn refresh_pools_rotate_after_success_failure_and_generation_replacement() {
    for first_result in ["success", "failure", "cancelled"] {
        for replace_generation in [false, true] {
            let dir = directory();
            let path = dir.path().join("cache.json");
            write_rule(&path, OLD);
            let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut source = source(
                &format!("http://{}/rules", trap.local_addr().unwrap()),
                &path,
            );
            source.download.as_mut().unwrap().client_chain =
                serde_json::from_value(serde_json::json!([{"pool": [
                    {"address": a.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}},
                    {"address": b.local_addr().unwrap().to_string(), "protocol": {"type": "socks"}}
                ]}]))
                .unwrap();
            let fixture = tokio::spawn(async move {
                let mut selected = Vec::new();
                let mut stalled = None;
                for attempt in 0..3 {
                    let (index, mut stream) = timeout(Duration::from_secs(5), async {
                        tokio::select! {
                            result = a.accept() => (0, result.unwrap().0),
                            result = b.accept() => (1, result.unwrap().0),
                        }
                    })
                    .await
                    .unwrap();
                    selected.push(index);
                    if attempt == 0 {
                        if first_result == "failure" {
                            continue;
                        }
                        if first_result == "cancelled" {
                            stalled = Some(stream);
                            continue;
                        }
                    }
                    socks_connect(&mut stream).await;
                    stream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                        .await
                        .unwrap();
                    request(&mut stream).await;
                    stream.write_all(&response(200, "", VALID)).await.unwrap();
                }
                drop(stalled);
                selected
            });
            let config = configs(&source);
            let sources = crate::config::compile_configs(config.clone())
                .await
                .unwrap()
                .remote_rules;
            let mut refresh = Refresh::new(config.clone(), &sources, None).unwrap();
            for attempt in 0..3 {
                let item = &mut refresh.scheduled[0];
                let dns = DnsRegistry::new();
                let future = refresh_source(
                    &item.source,
                    &config,
                    &dns,
                    GlobalLimits::default(),
                    &mut item.download,
                );
                if first_result == "cancelled" && attempt == 0 {
                    assert!(timeout(Duration::from_millis(100), future).await.is_err());
                    assert_eq!(std::fs::read(&path).unwrap(), OLD);
                } else if first_result == "failure" && attempt == 0 {
                    assert!(
                        future
                            .await
                            .unwrap_err()
                            .to_string()
                            .contains("configured rule download chain failed")
                    );
                    assert_eq!(std::fs::read(&path).unwrap(), OLD);
                } else {
                    future.await.unwrap();
                }
                if replace_generation {
                    refresh = Refresh::new(config.clone(), &sources, Some(&refresh)).unwrap();
                }
            }
            assert_eq!(fixture.await.unwrap(), [0, 1, 0]);
            assert!(
                timeout(Duration::from_millis(20), trap.accept())
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), VALID);
            assert!(!stage_path(&path).exists());
        }
    }
}

#[test]
fn refresh_inherits_schedule_and_backoff_only_for_identical_deliveries() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    write_rule(&path, OLD);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    let mut source = source("https://example.com/first.json", &path);
    let mut previous = Refresh::new(configs(&source), std::slice::from_ref(&source), None).unwrap();
    previous.scheduled[0].due = Instant::now() + Duration::from_secs(3600);
    previous.scheduled[0].failures = 3;

    let next = Refresh::new(
        configs(&source),
        std::slice::from_ref(&source),
        Some(&previous),
    )
    .unwrap();
    assert_eq!(next.scheduled[0].due, previous.scheduled[0].due);
    assert_eq!(next.scheduled[0].failures, 3);

    source.url = Some("https://example.com/second.json".into());
    let changed = Refresh::new(configs(&source), &[source], Some(&previous)).unwrap();
    assert!(changed.scheduled[0].due <= Instant::now());
    assert_eq!(changed.scheduled[0].failures, 0);
}

#[tokio::test]
async fn refresh_validates_the_whole_candidate_only_for_changed_bytes() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, OLD);
    let original = std::fs::metadata(&path).unwrap();
    for body in [OLD, VALID] {
        let (url, fixture) = serve(response(200, "", body)).await;
        let source = source(&url, &path);
        let mut config = configs(&source);
        config.push(
            serde_json::from_value(serde_json::json!({
                "rule_group": "invalid", "rules": [{"masks": {"ip_cidr": ["not an IP"]}}]
            }))
            .unwrap(),
        );
        let result = refresh_source(
            &source,
            &config,
            &DnsRegistry::new(),
            GlobalLimits::default(),
            &mut http::DownloadState::default(),
        )
        .await;
        fixture.await.unwrap();
        if body == OLD {
            assert!(!result.unwrap());
        } else {
            let error = result.unwrap_err().to_string();
            assert!(
                error.starts_with("download rejected by whole configuration validation:"),
                "{error}"
            );
            assert!(error.contains("IP"), "{error}");
            assert!(!error.contains("QUERY_SECRET"), "{error}");
        }
        assert_preserved(&path, &original);
    }
}

#[tokio::test]
async fn staged_validation_reuses_one_input_and_reads_other_caches_normally() {
    let dir = directory();
    let mut first = source(
        "https://example.com/first.json",
        &dir.path().join("first.txt"),
    );
    first.format = None;
    let second = source(
        "https://example.com/second.json",
        &dir.path().join("second.json"),
    );
    write_rule(&first.path, b"SRS invalid old cache");
    write_rule(&second.path, OLD);
    let mut install = Install::open(&first.path).unwrap();
    install.file.write_all(VALID).unwrap();
    let staged = Staged {
        install,
        digest: blake3::hash(VALID),
    };
    let config: Vec<Config> = serde_json::from_value(serde_json::json!([
        {"rule_cache_dir": dir.path()},
        {"rule_source_group": "shared", "rules": [first]},
        {"address": "127.0.0.1:0", "protocol": {"type": "socks"}, "rules": [
            {"masks": first, "action": "block"},
            {"masks": {"rule_source_group": "shared"}, "action": "block"},
            {"masks": second, "action": "block"}
        ]}
    ]))
    .unwrap();
    let validated = validate_staged(config.clone(), &first.path, &staged.install)
        .await
        .unwrap();
    let Config::Server(server) = &validated.configs[0] else {
        panic!("expected server");
    };
    let predicates: Vec<_> = server
        .rules
        .iter()
        .map(|rule| {
            let crate::config::ConfigSelection::Config(rule) = rule else {
                panic!("unexpanded rule");
            };
            rule.criteria.compiled.as_ref().unwrap()
        })
        .collect();
    assert!(Arc::ptr_eq(predicates[0], predicates[1]));
    assert!(!Arc::ptr_eq(predicates[0], predicates[2]));
    assert_eq!(
        std::fs::read(&first.path).unwrap(),
        b"SRS invalid old cache"
    );

    std::fs::remove_file(&second.path).unwrap();
    let error = validate_staged(config, &first.path, &staged.install)
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("remote cache unavailable"),
        "{error}"
    );
}

#[tokio::test]
async fn explicit_bootstrap_resolves_target_without_system_dns() {
    #[derive(Debug)]
    struct Bootstrap {
        port: u16,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl crate::resolver::Resolver for Bootstrap {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            assert_eq!(location.address().to_string(), "remote.invalid");
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
            Box::pin(async move { Ok(vec![address]) })
        }
    }
    let dir = directory();
    let path = dir.path().join("rules.json");
    let (url, fixture) = serve(response(200, "", VALID)).await;
    let url = url::Url::parse(&url).unwrap();
    let resolver = Arc::new(Bootstrap {
        port: url.port().unwrap(),
        calls: Default::default(),
    });
    let mut dns = DnsRegistry::new();
    dns.register("bootstrap".into(), resolver.clone());
    let mut source = source(
        &format!(
            "http://remote.invalid:{}/rules?token=QUERY_SECRET",
            url.port().unwrap()
        ),
        &path,
    );
    source.download.as_mut().unwrap().bootstrap_url = "bootstrap".into();
    let mut staged = super::stage(
        &source,
        Install::open_async(&source.path).await.unwrap(),
        &dns,
        GlobalLimits::default(),
        Limits::default(),
        &mut http::DownloadState::default(),
    )
    .await
    .unwrap();
    staged.install.finish(staged.digest).unwrap();
    fixture.await.unwrap();
    assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn multihop_download_pins_bootstrap_answers_and_preserves_proxy_tls_names() {
    #[derive(Debug)]
    struct Bootstrap {
        first: std::net::SocketAddr,
        calls: std::sync::Mutex<Vec<String>>,
    }
    impl crate::resolver::Resolver for Bootstrap {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            let name = location.address().to_string();
            let address = match name.as_str() {
                "first.invalid" => self.first,
                "second.invalid" => "127.0.0.2:1080".parse().unwrap(),
                "remote.invalid" => "192.0.2.10:8080".parse().unwrap(),
                _ => panic!("unexpected bootstrap lookup: {location}"),
            };
            self.calls.lock().unwrap().push(name);
            Box::pin(async move { Ok(vec![address]) })
        }
    }
    async fn socks(stream: &mut (impl AsyncRead + AsyncWrite + Unpin), expected: [u8; 10]) {
        let connect = socks_connect(stream).await;
        assert_eq!(connect, expected);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
    }
    async fn serve_second(mut stream: impl AsyncRead + AsyncWrite + Unpin) {
        socks(&mut stream, [5, 1, 0, 1, 192, 0, 2, 10, 31, 144]).await;
        assert!(
            request(&mut stream)
                .await
                .contains("host: remote.invalid:8080")
        );
        stream.write_all(&response(200, "", VALID)).await.unwrap();
        stream.flush().await.unwrap();
    }
    for tls in [false, true] {
        let dir = directory();
        let path = dir.path().join("cache.json");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resolver = Arc::new(Bootstrap {
            first: listener.local_addr().unwrap(),
            calls: Default::default(),
        });
        let mut dns = DnsRegistry::new();
        dns.register("bootstrap".into(), resolver.clone());
        let mut source = source("http://remote.invalid:8080/rules", &path);
        let second = if tls {
            serde_json::json!({"type": "tls", "verify": false, "protocol": {"type": "socks"}})
        } else {
            serde_json::json!({"type": "socks"})
        };
        source.download.as_mut().unwrap().bootstrap_url = "bootstrap".into();
        source.download.as_mut().unwrap().client_chain = serde_json::from_value(serde_json::json!([
            {"address": format!("first.invalid:{}", resolver.first.port()), "protocol": {"type": "socks"}},
            {"address": "second.invalid:1080", "protocol": second}
        ])).unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            socks(&mut stream, [5, 1, 0, 1, 127, 0, 0, 2, 4, 56]).await;
            if tls {
                let certificate =
                    rcgen::generate_simple_self_signed(vec!["second.invalid".into()]).unwrap();
                let config = crate::rustls_config_util::try_create_server_config(
                    certificate.cert.pem().as_bytes(),
                    certificate.signing_key.serialize_pem().as_bytes(),
                    vec![],
                    &[],
                    &[],
                    &Default::default(),
                )
                .unwrap();
                let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(stream)
                    .await
                    .unwrap();
                assert_eq!(stream.get_ref().1.server_name(), Some("second.invalid"));
                serve_second(stream).await;
            } else {
                serve_second(stream).await;
            }
        });
        let staged = stage(
            &source,
            Install::open_async(&source.path).await.unwrap(),
            &dns,
            GlobalLimits::default(),
            Limits::default(),
            &mut http::DownloadState::default(),
        )
        .await
        .unwrap();
        drop(staged);
        timeout(Duration::from_secs(5), fixture)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *resolver.calls.lock().unwrap(),
            ["remote.invalid", "second.invalid", "first.invalid"]
        );
    }
}

#[tokio::test]
async fn chunked_body_is_bounded_and_validated() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    let mut bytes = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
        VALID.len()
    )
    .into_bytes();
    bytes.extend_from_slice(VALID);
    bytes.extend_from_slice(b"\r\n0\r\n\r\n");
    let (url, fixture) = serve(bytes).await;
    assert_eq!(
        update(&source(&url, &path), Limits::default())
            .await
            .unwrap(),
        "updated"
    );
    fixture.await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), VALID);
}

#[tokio::test]
async fn first_download_proxy_retains_bootstrap_address_fallback() {
    #[derive(Debug)]
    struct Bootstrap(Vec<std::net::SocketAddr>);
    impl crate::resolver::Resolver for Bootstrap {
        fn resolve_location(
            &self,
            location: &crate::address::NetLocation,
        ) -> crate::resolver::ResolveFuture {
            assert_eq!(location.address().to_string(), "proxy.invalid");
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }
    for direct_first in [false, true] {
        let dir = directory();
        let path = dir.path().join("rules.json");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let refused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_address = refused.local_addr().unwrap();
        drop(refused);
        let mut dns = DnsRegistry::new();
        dns.register(
            "bootstrap".into(),
            Arc::new(Bootstrap(vec![refused_address, address])),
        );
        let mut source = source("http://192.0.2.1:8080/rules", &path);
        let proxy = serde_json::json!({"address": format!("proxy.invalid:{}", address.port()), "protocol": {"type": "socks"}});
        let hops = if direct_first {
            serde_json::json!([{"protocol": {"type": "direct"}}, proxy])
        } else {
            serde_json::json!([proxy])
        };
        source.download.as_mut().unwrap().client_chain = serde_json::from_value(hops).unwrap();
        source.download.as_mut().unwrap().bootstrap_url = "bootstrap".into();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let connect = socks_connect(&mut stream).await;
            assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 1, 31, 144]);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            request(&mut stream).await;
            stream.write_all(&response(200, "", VALID)).await.unwrap();
        });
        drop(
            stage(
                &source,
                Install::open_async(&source.path).await.unwrap(),
                &dns,
                GlobalLimits::default(),
                Limits::default(),
                &mut http::DownloadState::default(),
            )
            .await
            .unwrap(),
        );
        fixture.await.unwrap();
    }
}

#[test]
fn cache_conflicts_and_unknown_download_routes_are_rejected_offline() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, VALID);
    let first = source("https://example.com/a.json", &path);
    let second = source("https://example.com/b.json", &path);
    let mut conflicting = configs(&first);
    conflicting.extend(configs(&second));
    assert!(
        crate::config::create_server_configs(conflicting)
            .err()
            .unwrap()
            .to_string()
            .contains("conflicting remote")
    );
    let mut missing = first.clone();
    missing.download.as_mut().unwrap().client_chain =
        serde_json::from_value(serde_json::json!("missing")).unwrap();
    assert!(crate::config::create_server_configs(configs(&missing)).is_err());
    missing = first;
    missing.download.as_mut().unwrap().bootstrap_url = "missing".into();
    assert!(crate::config::create_server_configs(configs(&missing)).is_err());
}

#[test]
fn remote_bootstrap_literals_reject_active_and_retained_synthetic_ranges() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, VALID);
    let ranges = [
        "100.64.0.0/10".parse().unwrap(),
        "fd00::/64".parse().unwrap(),
    ];
    for scheme in ["udp", "tcp", "tls", "https", "h3"] {
        for host in ["100.64.0.2", "[::ffff:100.64.0.2]", "[fd00::2]"] {
            let mut source = source("https://remote.invalid/rules.json", &path);
            source.download.as_mut().unwrap().bootstrap_url = format!("{scheme}://{host}");
            let mut config = configs(&source);
            config.push(
                serde_json::from_value(serde_json::json!({
                    "dns_group": "fake", "dns_servers": "system",
                    "fake_ip": {"ipv4_range": "100.64.0.0/10", "ipv6_range": "fd00::/64"}
                }))
                .unwrap(),
            );
            let error = crate::config::create_server_configs(config)
                .err()
                .expect("active synthetic bootstrap endpoint accepted");
            assert!(
                error
                    .to_string()
                    .contains("rule download/bootstrap endpoint"),
                "{scheme}://{host}: {error}"
            );

            let mut validated = crate::config::create_server_configs(configs(&source)).unwrap();
            let error = validated.validate_network_endpoints(&ranges).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("rule download/bootstrap endpoint"),
                "{scheme}://{host}: {error}"
            );
            validated
                .validate_network_endpoints(&["192.0.2.0/24".parse().unwrap()])
                .unwrap();
        }
    }
}

#[tokio::test]
async fn remote_bootstrap_group_names_take_precedence_over_url_syntax() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, VALID);
    for name in ["udp://100.64.0.2", "https://100.64.0.2"] {
        let mut source = source("https://remote.invalid/rules.json", &path);
        source.download.as_mut().unwrap().bootstrap_url = name.into();
        let mut config = configs(&source);
        config.push(
            serde_json::from_value(serde_json::json!({
                "dns_group": name, "dns_servers": "udp://127.0.0.1:9",
                "fake_ip": {"ipv4_range": "100.64.0.0/10"}
            }))
            .unwrap(),
        );
        let mut validated = crate::config::create_server_configs(config.clone()).unwrap();
        validated
            .validate_network_endpoints(&["100.64.0.0/10".parse().unwrap()])
            .unwrap();
        let dns = crate::dns::build_dns_registry(validated.dns_groups)
            .await
            .unwrap();
        dns.rule_bootstrap(name).await.unwrap();
    }
}

#[test]
fn remote_sources_work_in_source_groups_policies_and_flat_overrides() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, VALID);
    let remote = source("https://example.com/rules.json", &path);
    let mut flat = serde_json::to_value(&remote).unwrap();
    flat["action"] = "block".into();
    let config = serde_json::from_value(serde_json::json!([
        {"rule_cache_dir": dir.path()},
        {"rule_source_group": "sources", "rules": [remote, {"domain": ["inline.example"]}]},
        {"rule_group": "policies", "rules": [flat]},
        {"address": "127.0.0.1:0", "rules": ["policies", {
            "masks": {"rule_source_group": "sources"}, "action": "block"
        }], "protocol": {"type": "websocket", "targets": [{
            "protocol": {"type": "socks"}, "override_rules": [flat]
        }]}}
    ]))
    .unwrap();
    let mut validated = crate::config::create_server_configs(config).unwrap();
    assert_eq!(validated.remote_rules.len(), 1);
    let mut count = 0;
    crate::config::rule_visit::visit(
        &mut validated.configs,
        &mut |rule| {
            assert!(matches!(
                rule.action,
                crate::config::RuleActionConfig::Block
            ));
            assert!(rule.criteria.compiled.is_some());
            count += 1;
            Ok(())
        },
        &mut |_| panic!("unexpanded policy group"),
    )
    .unwrap();
    assert_eq!(count, 3);
}

#[test]
fn local_source_reuse_does_not_accept_an_empty_remote_cache() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    write_rule(&path, br#"{"version":1,"rules":[]}"#);
    let remote = source("https://example.com/rules.json", &path);
    let local = RuleSource::from_path(path);
    let mut compiler = crate::rules::Compiler::default();
    crate::rule_set::load_source(&local, &mut compiler).unwrap();
    assert!(
        crate::rule_set::load_source(&remote, &mut compiler)
            .err()
            .unwrap()
            .to_string()
            .contains("empty remote")
    );
}

#[tokio::test]
async fn existing_remote_cache_errors_and_local_aliases_redact_payloads() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    let source = source("http://127.0.0.1:1/rules?QUERY_SECRET", &path);
    write_rule(
        &path,
        br#"{"version":1,"rules":[{"DOWNLOADED_SECRET":true}]}"#,
    );
    let error = crate::config::compile_configs(configs(&source))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("remote rule data failed validation"),
        "{error}"
    );
    assert!(error.contains(path.to_str().unwrap()), "{error}");
    assert!(!error.contains("DOWNLOADED_SECRET"), "{error}");
    assert!(!error.contains("QUERY_SECRET"), "{error}");

    write_rule(
        &path,
        br#"{"version":1,"rules":[{"domain_regex":["DOWNLOADED_SECRET"]}]}"#,
    );
    let alias = dir.path().join("alias.json");
    symlink(&path, &alias).unwrap();
    let mut config = configs(&source);
    config.insert(
        0,
        serde_json::from_value(serde_json::json!({
            "rule_source_group": "alias", "rules": [{
                "path": alias, "format": "mihomo_text", "behavior": "ipcidr"
            }]
        }))
        .unwrap(),
    );
    let error = crate::config::compile_configs(config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("local rule source overlaps rule_cache_dir"),
        "{error}"
    );
    assert!(!error.contains("DOWNLOADED_SECRET"), "{error}");
}

#[test]
fn source_identity_resolves_existing_paths_and_missing_leaf_parents() {
    use crate::rule_set::source_identity;

    let dir = directory();
    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let alias = dir.path().join("alias");
    symlink(&parent, &alias).unwrap();
    let canonical_parent = parent.canonicalize().unwrap();

    write_rule(&parent.join("existing.json"), VALID);
    for name in ["existing.json", "missing.json"] {
        assert_eq!(
            source_identity(&alias.join(name)).unwrap(),
            canonical_parent.join(name)
        );
    }
    let missing_parent = alias.join("missing/rules.json");
    assert_eq!(
        source_identity(&missing_parent).unwrap(),
        canonical_parent.join("missing/rules.json")
    );
    assert_eq!(
        source_identity(&parent.join("../parent/existing.json")).unwrap(),
        canonical_parent.join("existing.json")
    );
}

#[tokio::test]
async fn namespace_preflight_rejects_unresolved_parent_traversal_before_creating_resources() {
    let dir = directory();
    let cache = dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let missing = dir.path().join("missing");
    let alias = missing.join("../cache");
    let path = dir.path().join("config.json");
    for extra in [
        serde_json::json!({"certificate_source": "acme", "type": "acme", "domains": ["example.com"],
            "directory_url": "https://ca.invalid/directory", "state_dir": alias.join("acme"),
            "challenge": {"type": "tls_alpn01"}}),
        serde_json::json!({"cache_file_path": alias.join("state")}),
        serde_json::json!({"dns_group": "dns", "dns_servers": "system", "fake_ip": {"state_file": alias.join("fake")}}),
        serde_json::json!({"path": alias.join("socket"), "protocol": {"type": "socks"}}),
    ] {
        std::fs::write(
            &path,
            serde_json::json!([
                {"rule_cache_dir": cache}, extra
            ])
            .to_string(),
        )
        .unwrap();
        let error = crate::config::load_configs(&[path.to_string_lossy().into_owned()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unresolved parent"), "{error}");
        assert!(!missing.exists());
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    }
}

#[test]
fn cache_namespace_is_reserved_even_without_remote_sources() {
    let dir = directory();
    let cache = dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    for extra in [
        serde_json::json!({"cache_file_path": cache.join("state")}),
        serde_json::json!({"dns_group": "dns", "dns_servers": "system", "fake_ip": {"state_file": cache.join("fake")}}),
        serde_json::json!({"pem": "key", "path": cache.join("key.pem")}),
        serde_json::json!({"path": cache.join("socket"), "protocol": {"type": "socks"}}),
        serde_json::json!({"rule_source_group": "local", "rules": [{"path": cache.join("missing.json")}]}),
    ] {
        let mut configs: Vec<Config> = serde_json::from_value(serde_json::json!([
            {"rule_cache_dir": cache}, extra
        ]))
        .unwrap();
        let error = crate::rule_set::validate_remote_paths(&mut configs, &[]).unwrap_err();
        assert!(error.to_string().contains("overlap"), "{error}");
    }
    let mut configs = vec![Config::RuleCacheDirectory(cache.clone())];
    assert!(
        crate::rule_set::validate_remote_paths(&mut configs, &[cache.join("config.yaml")]).is_err()
    );
    let alias = cache.join("outside.json");
    symlink(dir.path().join("outside.json"), &alias).unwrap();
    configs.push(
        serde_json::from_value(serde_json::json!({
            "rule_source_group": "alias", "rules": [{"path": alias}]
        }))
        .unwrap(),
    );
    assert!(crate::rule_set::validate_remote_paths(&mut configs, &[]).is_err());
    let outside_alias = dir.path().join("alias");
    symlink(&cache, &outside_alias).unwrap();
    let mut configs: Vec<Config> = serde_json::from_value(serde_json::json!([
        {"rule_cache_dir": cache},
        {"cache_file_path": outside_alias.join("not-created/state")}
    ]))
    .unwrap();
    assert!(crate::rule_set::validate_remote_paths(&mut configs, &[]).is_err());
}

#[test]
fn remote_declarations_require_one_root_and_direct_unreserved_children() {
    let dir = directory();
    let root = dir.path().join("cache");
    for name in [
        "../outside.json",
        "nested/rules.json",
        "owner.lock",
        "OWNER.LOCK",
        "Owner.Lock",
        "rules.json.shoes-update.lock",
        "rules.json.SHOES-UPDATE.LOCK",
        "rules.json.shoes-update.tmp",
        "rules.json.Shoes-Update.Tmp",
    ] {
        let remote = source("https://example.com/rules.json", &root.join(name));
        let mut config = configs(&remote);
        config[0] = Config::RuleCacheDirectory(root.clone());
        assert!(
            crate::rule_set::validate_remote_paths(&mut config, &[]).is_err(),
            "{name}"
        );
    }
    let remote = source("https://example.com/rules.json", &root.join("rules.json"));
    let mut config = configs(&remote);
    crate::rule_set::validate_remote_paths(&mut config, &[]).unwrap();
    let mut duplicate = config.clone();
    duplicate.push(Config::RuleCacheDirectory(root));
    assert!(crate::rule_set::validate_remote_paths(&mut duplicate, &[]).is_err());
    config.remove(0);
    assert!(
        crate::rule_set::validate_remote_paths(&mut config, &[])
            .unwrap_err()
            .to_string()
            .contains("require a private rule_cache_dir")
    );
}

#[test]
fn managed_root_cannot_intersect_acme_state_in_either_direction() {
    let dir = directory();
    let root = dir.path().join("cache");
    for state in [dir.path().to_path_buf(), root.clone(), root.join("acme")] {
        let mut configs: Vec<Config> = serde_json::from_value(serde_json::json!([
            {"rule_cache_dir": root},
            {"certificate_source": "acme", "type": "acme", "domains": ["example.com"],
             "directory_url": "https://ca.invalid/directory", "state_dir": state,
             "challenge": {"type": "tls_alpn01"}}
        ]))
        .unwrap();
        let error = crate::rule_set::validate_remote_paths(&mut configs, &[]).unwrap_err();
        assert!(
            error.to_string().contains("ACME state directory"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn normalized_sources_preserve_url_format_hints_without_retaining_delivery_secrets() {
    let dir = directory();
    let path = dir.path().join("cache.txt");
    write_rule(&path, VALID);
    let mut remote = source("https://example.com/rules.json?SECRET", &path);
    remote.format = None;
    let mut validated = crate::config::compile_configs(configs(&remote))
        .await
        .unwrap();
    assert_eq!(validated.remote_rules.len(), 1);
    crate::rule_set::visit_sources(&mut validated.configs, &mut |source| {
        assert!(source.url.is_none());
        assert!(source.download.is_none());
        assert!(source.update_interval.is_none());
        Ok(())
    })
    .unwrap();
    assert!(validated.reload_files.is_empty());
}

#[test]
fn bootstrap_guards_include_declared_and_retained_ranges_without_runtime_state() {
    let configs: Vec<Config> = serde_json::from_value(serde_json::json!([
        {"dns_group": "unavailable", "dns_servers": "system", "fake_ip": {"state_file": "/unavailable/state"}},
        {"address": "10.12.0.1", "netmask": "255.255.255.0", "device_name": "tun0", "rules": "allow-all-direct"}
    ])).unwrap();
    let dns = DnsRegistry::for_rule_bootstrap(
        &configs,
        &["203.0.113.0/24".parse().unwrap()],
        GlobalLimits::default(),
    )
    .unwrap();
    assert!(
        dns.forbidden_ranges()
            .iter()
            .any(|range| range.contains("198.18.0.53".parse::<std::net::IpAddr>().unwrap()))
    );
    assert!(dns.get_by_name("unavailable").is_none());
    assert!(
        dns.forbidden_ranges()
            .iter()
            .any(|range| range.contains("203.0.113.1".parse().unwrap()))
    );
}

#[tokio::test]
async fn caches_cannot_overwrite_config_pem_state_or_other_source_files() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    write_rule(&path, VALID);
    let source = source("https://example.com/rules.json", &path);
    for extra in [
        serde_json::json!({"cache_file_path": path}),
        serde_json::json!({"dns_group": "dns", "dns_servers": "system", "fake_ip": {"state_file": path}}),
        serde_json::json!({"path": path, "protocol": {"type": "socks"}}),
        serde_json::json!({"rule_source_group": "other", "rules": [{"path": stage_path(&path)}]}),
    ] {
        let mut config = configs(&source);
        config.push(serde_json::from_value(extra).unwrap());
        assert!(
            crate::config::compile_configs(config)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("overlap")
        );
        assert_eq!(std::fs::read(&path).unwrap(), VALID);
    }
    let mut config = configs(&source);
    config.push(serde_json::from_value(serde_json::json!({"pem": "pem", "path": path})).unwrap());
    assert!(
        crate::config::convert_cert_paths(config)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("overlap")
    );
    // Declaring-file protection runs before any rule decoding or networking.
    std::fs::write(&path, serde_json::to_vec(&configs(&source)).unwrap()).unwrap();
    assert!(
        crate::config::load_configs(&[path.to_str().unwrap().into()])
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("overlap")
    );
}
