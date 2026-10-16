use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::process::ProcessGuard;

pub const VERSION: &str = "26.10.10";

pub struct Peer {
    _process: ProcessGuard,
    _files: tempfile::TempDir,
}

impl Peer {
    pub fn id(&self) -> u32 {
        self._process.id()
    }
}

pub fn binary() -> io::Result<PathBuf> {
    let path = std::env::var_os("SHOES_TEST_XRAY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("xray"));
    let output = Command::new(&path).arg("version").output()?;
    if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains(VERSION) {
        return Err(io::Error::other(format!(
            "XHTTP tests require Xray {VERSION}; set SHOES_TEST_XRAY_BIN"
        )));
    }
    Ok(path)
}

pub async fn wait_socks(address: SocketAddr) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(address).await {
                stream.write_all(&[5, 1, 0]).await?;
                let mut response = [0; 2];
                stream.read_exact(&mut response).await?;
                if response == [5, 0] {
                    return Ok(());
                }
                return Err(io::Error::other("invalid SOCKS readiness response"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}

pub async fn start(mut config: Value) -> io::Result<Peer> {
    let reservation = loop {
        let socket = std::net::TcpListener::bind("0.0.0.0:0")?;
        let port = socket.local_addr()?.port();
        if !config["inbounds"].as_array().is_some_and(|inbounds| {
            inbounds
                .iter()
                .any(|inbound| inbound["port"].as_u64() == Some(port.into()))
        }) {
            break socket;
        }
    };
    let port = reservation.local_addr()?.port();
    config["inbounds"].as_array_mut().ok_or_else(|| io::Error::other("missing Xray inbounds"))?.push(json!({"listen":"0.0.0.0", "port":port,"protocol":"socks","settings":{"auth":"noauth"},"tag":"readiness"}));
    let files = tempfile::tempdir()?;
    let path = files.path().join("xray.json");
    std::fs::write(&path, serde_json::to_vec(&config)?)?;
    drop(reservation);
    let child = Command::new(binary()?)
        .args(["run", "-config"])
        .arg(path)
        .env("GOMAXPROCS", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut peer = Peer {
        _process: ProcessGuard::new(child, "xray"),
        _files: files,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = peer._process.try_wait()? {
                return Err(io::Error::other(format!(
                    "Xray {VERSION} exited before readiness: {status}"
                )));
            }
            if tokio::time::timeout(
                Duration::from_millis(100),
                wait_socks(([127, 0, 0, 1], port).into()),
            )
            .await
            .is_ok_and(|result| result.is_ok())
            {
                return Ok(());
            }
        }
    })
    .await??;
    Ok(peer)
}

pub async fn connect(socks: SocketAddr, target: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::other("SOCKS authentication rejected"));
    }
    let std::net::IpAddr::V4(ip) = target.ip() else {
        return Err(io::Error::other("test target must be IPv4"));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(ip.octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0; 4];
    stream.read_exact(&mut response).await?;
    if response[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!(
            "SOCKS CONNECT rejected: {response:?}"
        )));
    }
    let length = match response[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err(io::Error::other("invalid SOCKS address")),
    };
    stream.read_exact(&mut vec![0; length + 2]).await?;
    Ok(stream)
}
