use super::{Process, available_address};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

async fn header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    while !data.ends_with(b"\r\n\r\n") {
        data.push(stream.read_u8().await?);
        assert!(data.len() < 4096);
    }
    Ok(data)
}

struct Proxy {
    address: String,
    status: Arc<AtomicU16>,
    probes: mpsc::Receiver<u16>,
    cancel: CancellationToken,
    task: AbortOnDropHandle<()>,
}

impl Proxy {
    async fn start(marker: u8, initial_status: u16) -> Self {
        let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let status = Arc::new(AtomicU16::new(initial_status));
        let current = status.clone();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (tx, probes) = mpsc::channel(64);
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::<io::Result<()>>::new();
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => { result.unwrap().unwrap(); },
                    incoming = listener.accept() => {
                        let (mut stream, _) = incoming.unwrap();
                        let current = current.clone();
                        let tx = tx.clone();
                        tasks.spawn(async move {
                            let request = header(&mut stream).await?;
                            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                            if request.starts_with(b"CONNECT 192.0.2.1:80 ") {
                                assert!(header(&mut stream).await?.starts_with(b"HEAD / HTTP/1.1"));
                                let status = current.load(Ordering::Relaxed);
                                stream.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                                assert_eq!(stream.read(&mut [0;1]).await?, 0);
                                let _ = tx.send(status).await;
                            } else {
                                assert!(request.starts_with(b"CONNECT 198.51.100.99:80 "));
                                stream.write_all(&[marker]).await?;
                                let (mut read, mut write) = stream.into_split();
                                let _ = tokio::io::copy(&mut read, &mut write).await;
                            }
                            Ok::<_, io::Error>(())
                        });
                    }
                }
            }
            tasks.shutdown().await;
        }));
        Self {
            address,
            status,
            probes,
            cancel,
            task,
        }
    }

    async fn observed(&mut self, status: u16) {
        while self.probes.try_recv().is_ok() {}
        // A second completed check proves the preceding result was consumed by the scheduler.
        for _ in 0..2 {
            loop {
                if self.probes.recv().await.unwrap() == status {
                    break;
                }
            }
        }
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        self.task.await.unwrap();
    }
}

async fn flow(address: SocketAddr) -> io::Result<(TcpStream, u8)> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"CONNECT 198.51.100.99:80 HTTP/1.1\r\nHost: 198.51.100.99:80\r\n\r\n")
        .await?;
    let response = header(&mut stream).await?;
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(io::Error::other("CONNECT rejected"));
    }
    let marker = stream.read_u8().await?;
    Ok((stream, marker))
}

#[tokio::test]
async fn health_controller_disabled_fallback_recovery_all_down_reload_and_existing_flow() {
    timeout(Duration::from_secs(25), async {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        let entry = available_address();
        let mut primary = Proxy::start(b'P', 503).await;
        let mut backup = Proxy::start(b'B', 204).await;
        let mut replacement = Proxy::start(b'C', 204).await;
        let mut config = json!([
            {"client_group":"out", "type":"fallback", "health_check":{"url":"http://192.0.2.1/", "interval_secs":1, "timeout_ms":500}, "client_proxies":[
                {"name":"primary", "address":primary.address, "protocol":{"type":"http"}},
                {"name":"backup", "address":backup.address, "protocol":{"type":"http"}}
            ]},
            {"address":entry.to_string(), "protocol":{"type":"http"}, "rules":[{"mask":"0.0.0.0/0", "action":"allow", "client_chain":"out"}]}
        ]);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        let mut process = Process::start(&path, &["--no-reload"]);
        process.wait_for("Servers ready").await;
        tokio::join!(primary.observed(503), backup.observed(204));
        let (mut established, marker) = flow(entry).await.unwrap();
        assert_eq!(marker, b'B');

        primary.status.store(204, Ordering::Relaxed);
        primary.observed(204).await;
        assert_eq!(flow(entry).await.unwrap().1, b'P');
        established.write_all(b"still on backup").await.unwrap();
        let mut echoed = [0;15];
        established.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"still on backup");

        primary.status.store(503, Ordering::Relaxed);
        backup.status.store(503, Ordering::Relaxed);
        tokio::join!(primary.observed(503), backup.observed(503));
        assert!(timeout(Duration::from_secs(2), flow(entry)).await.unwrap().is_err());

        config[0]["client_proxies"][0]["address"] = json!(replacement.address);
        std::fs::write(&path, serde_yaml::to_string(&config).unwrap()).unwrap();
        process.signal(libc::SIGHUP);
        process.wait_for("Servers ready").await;
        replacement.observed(204).await;
        assert_eq!(flow(entry).await.unwrap().1, b'C');
        drop(established);
        process.signal(libc::SIGTERM);
        assert!(process.exit().await.success());
        primary.shutdown().await;
        backup.shutdown().await;
        replacement.shutdown().await;
    }).await.unwrap();
}
