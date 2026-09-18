//! SOCKS5 client helpers for integration tests.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_PASSWORD: u8 = 2;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksDestination {
    Ip(SocketAddr),
    Hostname(String, u16),
}

impl SocksDestination {
    fn encode(&self, output: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                output.push(ATYP_IPV4);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                output.push(ATYP_IPV6);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Hostname(hostname, port) => {
                let hostname = hostname.as_bytes();
                let length = u8::try_from(hostname.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "SOCKS hostname is too long")
                })?;
                output.extend_from_slice(&[ATYP_DOMAIN, length]);
                output.extend_from_slice(hostname);
                output.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }
}

#[must_use = "dropping the association closes its TCP control connection"]
#[derive(Debug)]
pub struct Socks5UdpAssociation {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

impl Socks5UdpAssociation {
    pub async fn connect(socks_host: &str, socks_port: u16) -> io::Result<Self> {
        Self::connect_inner(socks_host, socks_port, None).await
    }

    pub async fn connect_with_password(
        socks_host: &str,
        socks_port: u16,
        username: &str,
        password: &str,
    ) -> io::Result<Self> {
        Self::connect_inner(socks_host, socks_port, Some((username, password))).await
    }

    async fn connect_inner(
        socks_host: &str,
        socks_port: u16,
        credentials: Option<(&str, &str)>,
    ) -> io::Result<Self> {
        let mut control = TcpStream::connect((socks_host, socks_port)).await?;
        let peer_ip = control.peer_addr()?.ip();
        let auth_method = if credentials.is_some() {
            AUTH_PASSWORD
        } else {
            AUTH_NONE
        };

        control.write_all(&[SOCKS_VERSION, 1, auth_method]).await?;
        let mut greeting = [0; 2];
        control.read_exact(&mut greeting).await?;
        if greeting != [SOCKS_VERSION, auth_method] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SOCKS5 server selected unsupported authentication {greeting:02x?}"),
            ));
        }

        if let Some((username, password)) = credentials {
            authenticate(&mut control, username, password).await?;
        }

        let bind_addr = match peer_ip {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let socket = UdpSocket::bind(bind_addr).await?;

        let mut request = vec![SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0];
        SocksDestination::Ip(bind_addr).encode(&mut request)?;
        control.write_all(&request).await?;

        let mut header = [0; 4];
        control.read_exact(&mut header).await?;
        if header[0] != SOCKS_VERSION || header[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 UDP ASSOCIATE response header {header:02x?}"),
            ));
        }
        if header[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 UDP ASSOCIATE failed with code 0x{:02x}", header[1]),
            ));
        }

        let relay = read_reply_address(&mut control, header[3], peer_ip).await?;
        Ok(Self {
            _control: control,
            socket,
            relay,
        })
    }

    pub fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn close_control(self) -> (UdpSocket, SocketAddr) {
        let Self {
            _control,
            socket,
            relay,
        } = self;
        drop(_control);
        (socket, relay)
    }

    pub async fn send_to(&self, target: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.send_to_with_timeout(
            SocksDestination::Ip(target),
            payload,
            Duration::from_secs(10),
        )
        .await
    }

    pub async fn send_to_hostname(
        &self,
        hostname: &str,
        port: u16,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.send_to_with_timeout(
            SocksDestination::Hostname(hostname.to_string(), port),
            payload,
            Duration::from_secs(10),
        )
        .await
    }

    pub async fn send_to_with_timeout(
        &self,
        target: SocksDestination,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        send_udp_datagram(&self.socket, self.relay, &target, payload, timeout).await
    }
}

pub async fn send_udp_datagram(
    socket: &UdpSocket,
    relay: SocketAddr,
    target: &SocksDestination,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let request = encode_udp_datagram(target, payload)?;
    socket.send_to(&request, relay).await?;

    let mut response = vec![0; 65_536];
    let (length, source) = tokio::time::timeout(timeout, socket.recv_from(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP response timed out"))??;
    if source != relay {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 UDP response came from {source}, expected {relay}"),
        ));
    }
    Ok(decode_udp_datagram(&response[..length])?.to_vec())
}

async fn authenticate(control: &mut TcpStream, username: &str, password: &str) -> io::Result<()> {
    let username = username.as_bytes();
    let password = password.as_bytes();
    let username_len = u8::try_from(username.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SOCKS username is too long"))?;
    let password_len = u8::try_from(password.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SOCKS password is too long"))?;

    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[1, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    control.write_all(&request).await?;

    let mut response = [0; 2];
    control.read_exact(&mut response).await?;
    if response != [1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SOCKS5 username/password authentication failed: {response:02x?}"),
        ));
    }
    Ok(())
}

async fn read_reply_address(
    input: &mut (impl AsyncRead + Unpin),
    atyp: u8,
    fallback_ip: IpAddr,
) -> io::Result<SocketAddr> {
    let address = match atyp {
        ATYP_IPV4 => {
            let mut bytes = [0; 4];
            input.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        ATYP_IPV6 => {
            let mut bytes = [0; 16];
            input.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        ATYP_DOMAIN => {
            let length = input.read_u8().await? as usize;
            let mut bytes = vec![0; length];
            input.read_exact(&mut bytes).await?;
            let hostname = String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let port = input.read_u16().await?;
            return tokio::net::lookup_host((hostname.as_str(), port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "SOCKS relay did not resolve")
                });
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type 0x{atyp:02x}"),
            ));
        }
    };
    let port = input.read_u16().await?;
    let address = if address.is_unspecified() {
        fallback_ip
    } else {
        address
    };
    Ok(SocketAddr::new(address, port))
}

pub fn encode_udp_datagram(target: &SocksDestination, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = vec![0, 0, 0];
    target.encode(&mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_udp_datagram(input: &[u8]) -> io::Result<&[u8]> {
    if input.len() < 4 || input[..2] != [0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP reserved field",
        ));
    }
    if input[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP datagrams are unsupported",
        ));
    }

    let address_length = match input[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let length = *input.get(4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing SOCKS hostname length",
                )
            })? as usize;
            1 + length
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type 0x{atyp:02x}"),
            ));
        }
    };
    let payload_offset = 4 + address_length + 2;
    input.get(payload_offset..).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SOCKS5 UDP destination",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_datagrams_round_trip_all_address_types() {
        let destinations = [
            SocksDestination::Ip("127.0.0.1:53".parse().unwrap()),
            SocksDestination::Ip("[::1]:53".parse().unwrap()),
            SocksDestination::Hostname("resolver.test".to_string(), 53),
        ];

        for destination in destinations {
            let datagram = encode_udp_datagram(&destination, b"payload").unwrap();
            assert_eq!(decode_udp_datagram(&datagram).unwrap(), b"payload");
        }
    }

    #[test]
    fn udp_datagrams_reject_fragments_and_truncation() {
        assert_eq!(
            decode_udp_datagram(&[0, 0, 1, ATYP_IPV4, 127, 0, 0, 1, 0, 53])
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            decode_udp_datagram(&[0, 0, 0, ATYP_IPV6])
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
