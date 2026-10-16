use std::io;

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub fn relay_config(port: u16, proxy_port: u16, protocol: Value) -> Value {
    json!({
        "address": format!("0.0.0.0:{port}"),
        "protocol": {"type": "http"},
        "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": [{
            "address": format!("127.0.0.1:{proxy_port}"), "protocol": protocol
        }]}]
    })
}

pub async fn connect(port: u16, target: &str) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await?);
        if headers.len() > 4096 {
            return Err(io::Error::other("oversized proxy response"));
        }
    }
    if !headers.starts_with(b"HTTP/1.1 200 ") {
        return Err(io::Error::other(format!(
            "CONNECT failed: {}",
            String::from_utf8_lossy(&headers)
        )));
    }
    Ok(stream)
}

pub async fn exchange(mut stream: TcpStream) -> io::Result<()> {
    let payload: Vec<_> = (0..131073).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = stream.split();
    let send = async {
        write.write_all(&payload).await?;
        write.shutdown().await
    };
    let receive = async {
        let mut response = Vec::new();
        read.read_to_end(&mut response).await?;
        assert_eq!(response, payload);
        Ok::<_, io::Error>(())
    };
    tokio::try_join!(send, receive)?;
    Ok(())
}
