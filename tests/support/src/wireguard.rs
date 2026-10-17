use crate::{
    socks5::Socks5UdpAssociation,
    test_servers::{TestServer, start_tcp_stream_echo_server, start_udp_echo_server_with_suffix},
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const ECHO_TCP_BYTES: usize = 256_000;

pub struct EchoTargets {
    tcp: TestServer,
    udp: TestServer,
    ip: IpAddr,
}
impl EchoTargets {
    pub async fn new(ipv6: bool) -> io::Result<Self> {
        let bind = if ipv6 { "::" } else { "0.0.0.0" };
        Ok(Self {
            tcp: start_tcp_stream_echo_server(bind, 0).await?,
            udp: start_udp_echo_server_with_suffix(bind, 0, b"").await?,
            ip: if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap(),
        })
    }
    pub fn tcp(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.tcp.local_addr().port())
    }
    pub fn udp(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.udp.local_addr().port())
    }
    pub async fn check(&self, entry: u16, destination: Option<IpAddr>) -> io::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut tcp = self.tcp();
            let mut udp = self.udp();
            if let Some(ip) = destination {
                tcp.set_ip(ip);
                udp.set_ip(ip);
            }
            let mut stream = connect(entry, tcp).await?;
            let payload: Vec<_> = (0..ECHO_TCP_BYTES).map(|i| (i ^ (i >> 8)) as u8).collect();
            let (mut read, mut write) = stream.split();
            let send = async {
                write.write_all(&payload).await?;
                Ok::<_, io::Error>(())
            };
            let receive = async {
                let mut response = vec![0; payload.len()];
                read.read_exact(&mut response).await?;
                assert_eq!(response, payload);
                Ok::<_, io::Error>(())
            };
            tokio::try_join!(send, receive)?;
            stream.shutdown().await?;
            let association = Socks5UdpAssociation::connect("127.0.0.1", entry).await?;
            for data in [
                &b"wireguard"[..],
                &b"second-datagram"[..],
                &[0x5a; 1200][..],
            ] {
                assert_eq!(association.send_to(udp, data).await?, data);
            }
            Ok(())
        })
        .await?
    }
}

pub async fn connect(entry: u16, target: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", entry)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;
    if response != [5, 0] {
        return Err(io::Error::other("SOCKS authentication rejected"));
    }
    let mut request = vec![5, 1, 0];
    match target.ip() {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(4);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != [5, 0, 0] {
        return Err(io::Error::other(format!(
            "SOCKS CONNECT failed: {header:?}"
        )));
    }
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err(io::Error::other("invalid SOCKS address")),
    };
    stream.read_exact(&mut vec![0; length + 2]).await?;
    Ok(stream)
}
