use super::install::FAIL_RENAME;
use super::*;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpStream;
const STAGE_SUFFIX: &str = ".shoes-update.tmp";
const MAX_HEADERS: usize = 32 * 1024;
fn stamp(m: &Metadata) -> (u64, u64, u64, i64, i64) {
    (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec())
}
fn c_name(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)
}

use std::os::unix::fs::symlink;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const VALID: &[u8] = include_bytes!("../../tests/fixtures/rule_sets/singbox.json");
const OLD: &[u8] = br#"{"version":1,"rules":[{"domain":["old.example"]}]}"#;

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
    source.download = Some(crate::rule_set::Download {
        client_chain: crate::config::ClientChain::default(),
        bootstrap_url: "system".into(),
    });
    source
}

fn configs(source: &RuleSource) -> Vec<Config> {
    serde_json::from_value(serde_json::json!([{
        "address": "127.0.0.1:0", "protocol": {"type": "socks"},
        "rules": [{"masks": source, "action": "block"}]
    }]))
    .unwrap()
}

async fn update(source: &RuleSource, limits: Limits) -> io::Result<&'static str> {
    let staged = super::stage(
        source,
        &DnsRegistry::new(),
        GlobalLimits::default(),
        limits,
        &mut http::DownloadState::default(),
    )
    .await?;
    validate_staged(configs(source), std::slice::from_ref(&staged)).await?;
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

async fn request(stream: &mut TcpStream) -> String {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        result.push(stream.read_u8().await.unwrap());
        assert!(result.len() < 16 * 1024);
    }
    String::from_utf8(result).unwrap()
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
async fn cold_start_is_validated_as_a_whole_and_offline_checks_do_not_download() {
    let dir = directory();
    let path = dir.path().join("rules.json");
    let (url, fixture) = serve(response(200, "", VALID)).await;
    let source = source(&url, &path);
    assert!(
        crate::config::compile_configs(configs(&source))
            .await
            .is_err()
    );
    let validated = prepare(configs(&source), None, &mut None).await.unwrap();
    fixture.await.unwrap();
    assert_eq!(validated.remote_rules.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), VALID);
    // The fixture is gone; cached startup and offline validation must still work.
    prepare(configs(&source), None, &mut None).await.unwrap();
    crate::config::compile_configs(configs(&source))
        .await
        .unwrap();

    std::fs::remove_file(&path).unwrap();
    let (url, fixture) = serve(response(200, "", VALID)).await;
    let mut invalid = configs(&self::source(&url, &path));
    invalid.push(serde_json::from_value(serde_json::json!({"rule_group": "bad", "rules": [{"masks": {"ip_cidr": ["not an IP"]}}]})).unwrap());
    let error = prepare(invalid, None, &mut None)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("whole configuration validation"), "{error}");
    assert!(error.contains("IP"), "{error}");
    assert!(!error.contains("QUERY_SECRET"), "{error}");
    fixture.await.unwrap();
    assert!(!path.exists());
    assert!(!stage_path(&path).exists());
}

#[tokio::test]
async fn cold_staging_caps_each_download_by_remaining_capacity() {
    let dir = directory();
    for budget in [
        OLD.len() as u64,
        (OLD.len() * 2 - 1) as u64,
        (OLD.len() * 2) as u64,
    ] {
        let a = dir.path().join("a.json");
        let b = dir.path().join("b.json");
        let (url_a, fixture_a) = serve(response(200, "", OLD)).await;
        let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (url_b, fixture_b) = if budget == OLD.len() as u64 {
            (format!("http://{}/rules", trap.local_addr().unwrap()), None)
        } else {
            let (url, fixture) = serve(response(200, "", OLD)).await;
            (url, Some(fixture))
        };
        let sources = [source(&url_a, &a), source(&url_b, &b)];
        let result = stage_sources(
            &sources,
            &DnsRegistry::new(),
            GlobalLimits::default(),
            budget,
        )
        .await;
        fixture_a.await.unwrap();
        if let Some(fixture) = fixture_b {
            fixture.await.unwrap();
        }
        if budget == (OLD.len() * 2) as u64 {
            let staged = result.unwrap();
            assert_eq!(
                staged
                    .iter()
                    .map(|item| item.install.file.metadata().unwrap().len())
                    .sum::<u64>(),
                budget
            );
            drop(staged);
        } else {
            let error = result.err().unwrap().to_string();
            if budget == OLD.len() as u64 {
                assert!(error.contains("staging budget"), "{error}");
                assert!(
                    timeout(Duration::from_millis(20), trap.accept())
                        .await
                        .is_err()
                );
            } else {
                assert!(error.contains("size outside permitted range"), "{error}");
                assert!(error.contains(b.to_str().unwrap()), "{error}");
            }
        }
        for path in [&a, &b] {
            assert!(!path.exists());
            assert!(!stage_path(path).exists());
        }
    }
}

#[tokio::test]
async fn cold_staging_limits_descriptors_before_any_download() {
    for (descriptors, expected) in [
        (64, 0),
        (128, 0),
        (132, 1),
        (512, 96),
        (1024, 128),
        (u64::MAX, 128),
    ] {
        assert_eq!(cold_source_limit(descriptors), expected);
    }
    let dir = directory();
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rules", trap.local_addr().unwrap());
    let sources = (0..129)
        .map(|index| source(&url, &dir.path().join(format!("{index}.json"))))
        .collect::<Vec<_>>();
    let error = stage_sources(
        &sources,
        &DnsRegistry::new(),
        GlobalLimits::default(),
        MAX_STAGED_BYTES,
    )
    .await
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("staging source limit"),
        "{error}"
    );
    assert!(
        timeout(Duration::from_millis(50), trap.accept())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn cold_download_errors_identify_cache_without_exposing_url() {
    let dir = directory();
    let path = dir.path().join("missing-directory/rules.json");
    let source = source("http://127.0.0.1:1/rules?token=QUERY_SECRET", &path);
    let error = prepare(configs(&source), None, &mut None)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains(path.to_str().unwrap()), "{error}");
    assert!(!error.contains("QUERY_SECRET"), "{error}");
    assert!(!stage_path(&path).exists());
}

#[tokio::test]
async fn cold_download_validates_dangling_local_aliases_against_staged_bytes() {
    let dir = directory();
    let path = dir.path().join("cache.json");
    let alias = dir.path().join("alias.json");
    symlink("second.json", &alias).unwrap();
    symlink("cache.json", dir.path().join("second.json")).unwrap();
    let (url, fixture) = serve(response(200, "", VALID)).await;
    let source = source(&url, &path);
    let mut config = configs(&source);
    config.push(
        serde_json::from_value(
            serde_json::json!({"rule_source_group": "alias", "rules": [{"path": alias}]}),
        )
        .unwrap(),
    );
    prepare(config, None, &mut None).await.unwrap();
    fixture.await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), VALID);
    assert_eq!(std::fs::read(alias).unwrap(), VALID);
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
        assert!(error.to_string().contains("sidecar"), "{error}");
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
        let path = dir.path().join("cache.json");
        let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut connect = [0; 10];
            stream.read_exact(&mut connect).await.unwrap();
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
        let mut control = None;
        prepare(config.clone(), None, &mut control).await.unwrap();
        fixture.await.unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(prepare(config, None, &mut control).await.is_err());
        assert!(
            timeout(Duration::from_millis(50), trap.accept())
                .await
                .is_err()
        );
        assert!(!path.exists());
        control.as_mut().unwrap().shutdown().await;
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
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    stream.write_all(&[5, 0]).await.unwrap();
                    let mut connect = [0; 10];
                    stream.read_exact(&mut connect).await.unwrap();
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
    async fn socks(
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        expected: [u8; 10],
    ) {
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0; 10];
        stream.read_exact(&mut connect).await.unwrap();
        assert_eq!(connect, expected);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
    }
    async fn serve_second(mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) {
        socks(&mut stream, [5, 1, 0, 1, 192, 0, 2, 10, 31, 144]).await;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
            assert!(request.len() < 16384);
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
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
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut connect = [0; 10];
            stream.read_exact(&mut connect).await.unwrap();
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

#[tokio::test]
async fn cold_bootstrap_does_not_open_fake_ip_state_and_rejects_synthetic_targets() {
    let dir = directory();
    let state = dir.path().join("fake.json");
    let path = dir.path().join("rules.json");
    let source = source("http://198.18.0.10/rules.json", &path);
    let mut config = configs(&source);
    config.push(serde_json::from_value(serde_json::json!({
        "dns_group": "unrelated", "dns_servers": "system", "fake_ip": {"state_file": state, "max_entries": 16}
    })).unwrap());
    let error = prepare(config, None, &mut None).await.err().unwrap();
    assert!(error.to_string().contains("synthetic"), "{error}");
    assert!(!state.exists());
    assert!(!path.exists());
    assert!(!stage_path(&path).exists());
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
async fn cold_rule_bootstrap_rejects_synthetic_upstreams_before_lookup() {
    let dir = directory();
    let path = dir.path().join("missing.json");
    let state = dir.path().join("fake.json");
    for scheme in ["udp", "tcp", "tls", "https", "h3"] {
        let mut source = source("https://remote.invalid/rules.json", &path);
        let bootstrap = format!("{scheme}://100.64.0.2");
        source.download.as_mut().unwrap().bootstrap_url = bootstrap.clone();
        let mut config = configs(&source);
        config.push(
            serde_json::from_value(serde_json::json!({
                "dns_group": "fake", "dns_servers": "system",
                "fake_ip": {"ipv4_range": "100.64.0.0/10", "state_file": state}
            }))
            .unwrap(),
        );
        let context = crate::config::rule_download_context(config.clone()).unwrap();
        let dns = DnsRegistry::for_rule_downloads(
            context.groups,
            context.limits,
            &context.sources,
            &config,
            None,
        )
        .await
        .unwrap();
        let error = dns
            .rule_bootstrap(&bootstrap)
            .err()
            .expect("cold synthetic bootstrap endpoint accepted");
        assert!(
            error.to_string().contains("synthetic endpoint"),
            "{bootstrap}: {error}"
        );
        for (candidate, previous) in [(config.clone(), None), (configs(&source), Some(&dns))] {
            let error = prepare(candidate, previous, &mut None).await.err().unwrap();
            assert!(
                error.to_string().contains("synthetic endpoint"),
                "{bootstrap}: {error}"
            );
            assert!(!stage_path(&path).exists());
        }
        assert!(!state.exists());
        assert!(!path.exists());
    }
}

#[tokio::test]
async fn synthetic_bootstrap_is_rejected_before_sending_a_dns_packet() {
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dir = directory();
    let path = dir.path().join("missing.json");
    let mut source = source("http://remote.invalid/rules.json", &path);
    source.download.as_mut().unwrap().bootstrap_url =
        format!("udp://{}", udp.local_addr().unwrap());
    let mut config = configs(&source);
    config.push(
        serde_json::from_value(serde_json::json!({
            "dns_group": "fake", "dns_servers": "system", "fake_ip": {"ipv4_range": "127.0.0.0/24"}
        }))
        .unwrap(),
    );
    let error = prepare(config, None, &mut None).await.err().unwrap();
    assert!(error.to_string().contains("synthetic endpoint"), "{error}");
    assert!(
        timeout(Duration::from_millis(20), udp.recv(&mut [0; 512]))
            .await
            .is_err()
    );
    assert!(!path.exists());
    assert!(!stage_path(&path).exists());
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
        let context = crate::config::rule_download_context(config.clone()).unwrap();
        let dns = DnsRegistry::for_rule_downloads(
            context.groups,
            context.limits,
            &context.sources,
            &config,
            None,
        )
        .await
        .unwrap();
        dns.rule_bootstrap(name).unwrap();
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
async fn staged_candidate_uses_normalized_paths_even_before_cache_creation() {
    let dir = directory();
    let path = dir.path().join("./rules.json");
    let stage = dir.path().join("staged");
    write_rule(&stage, VALID);
    let remote = source("https://example.com/rules.json", &path);
    let mut config = configs(&remote);
    config.push(
        serde_json::from_value(serde_json::json!({
            "rule_source_group": "local-alias", "rules": [{
                "path": dir.path().join("rules.json"), "format": "mihomo_text", "behavior": "ipcidr"
            }]
        }))
        .unwrap(),
    );
    let inputs = HashMap::from([(path, File::open(stage).unwrap())]);
    let error = crate::config::compile_configs_with_inputs(config, inputs)
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
    assert!(
        error
            .to_string()
            .contains("staged rule data failed validation"),
        "{error}"
    );
}

#[tokio::test]
async fn staged_alias_errors_redact_downloaded_content_in_cold_and_refresh_paths() {
    const SECRET: &[u8] = br#"{"version":1,"rules":[{"domain_regex":["DOWNLOADED_SECRET"]}]}"#;
    for cold in [true, false] {
        let dir = directory();
        let path = dir.path().join("rules.json");
        if !cold {
            write_rule(&path, OLD);
        }
        let (url, fixture) = serve(response(200, "", SECRET)).await;
        let source = source(&url, &path);
        let mut config = configs(&source);
        config.push(
            serde_json::from_value(serde_json::json!({
                "rule_source_group": "alias", "rules": [{
                    "path": path, "format": "mihomo_text", "behavior": "ipcidr"
                }]
            }))
            .unwrap(),
        );
        let error = if cold {
            prepare(config, None, &mut None).await.err().unwrap()
        } else {
            refresh_source(
                &source,
                &config,
                &DnsRegistry::new(),
                GlobalLimits::default(),
                &mut http::DownloadState::default(),
            )
            .await
            .unwrap_err()
        }
        .to_string();
        fixture.await.unwrap();
        assert!(
            error.contains("staged rule data failed validation"),
            "{error}"
        );
        assert!(error.contains(path.to_str().unwrap()), "{error}");
        assert!(!error.contains("DOWNLOADED_SECRET"), "{error}");
        assert!(!error.contains("QUERY_SECRET"), "{error}");
        if cold {
            assert!(!path.exists());
        } else {
            assert_eq!(std::fs::read(&path).unwrap(), OLD);
        }
        assert!(!stage_path(&path).exists());
        drop(Install::open(&path).unwrap());
    }
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
    for online in [false, true] {
        let result = if online {
            prepare(config.clone(), None, &mut None).await
        } else {
            crate::config::compile_configs(config.clone()).await
        };
        let error = result.err().unwrap().to_string();
        assert!(
            error.contains("remote rule data failed validation"),
            "{error}"
        );
        assert!(error.contains(alias.to_str().unwrap()), "{error}");
        assert!(!error.contains("DOWNLOADED_SECRET"), "{error}");
    }
    config.remove(1);
    let error = crate::config::compile_configs(config)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("invalid CIDR"), "{error}");
    assert!(
        error.contains("DOWNLOADED_SECRET"),
        "ordinary local errors retain detail: {error}"
    );
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
    assert_eq!(source_identity(&missing_parent).unwrap(), missing_parent);
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
            prepare(config, None, &mut None)
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
        crate::config::load_configs(&vec![path.to_str().unwrap().into()])
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("overlap")
    );
}
