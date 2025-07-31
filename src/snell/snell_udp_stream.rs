use futures::ready;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadTargetedMessage,
    AsyncShutdownMessage, AsyncTargetedMessageStream, AsyncWriteMessage, AsyncWriteSourcedMessage,
};

pub struct SnellUdpStream {
    stream: Box<dyn AsyncMessageStream>,
    max_payload_size: usize,

    read_buf: [u8; 65535],

    write_buf: [u8; 65535],
    write_buf_end_offset: usize,

    is_eof: bool,
}

impl SnellUdpStream {
    pub fn new(stream: Box<dyn AsyncMessageStream>, max_payload_size: usize) -> Self {
        Self {
            stream,
            max_payload_size,

            read_buf: [0u8; 65535],

            write_buf: [0u8; 65535],
            write_buf_end_offset: 0,

            is_eof: false,
        }
    }
}

impl AsyncReadTargetedMessage for SnellUdpStream {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();
        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        let mut read_buf = ReadBuf::new(&mut this.read_buf);
        ready!(Pin::new(&mut this.stream).poll_read_message(cx, &mut read_buf))?;

        let len = read_buf.filled().len();
        if len == 0 {
            this.is_eof = true;
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        if len < 4 {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too small")));
        }

        if len > this.max_payload_size {
            return Poll::Ready(Err(std::io::Error::other("snell packet size too big")));
        }

        let cmd = this.read_buf[0];
        if cmd != 1 {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "invalid snell command: {cmd}"
            ))));
        }

        let address_len = this.read_buf[1] as usize;
        let (location, data_offset) = if address_len == 0 {
            let ip_version = this.read_buf[2];
            if ip_version == 4 {
                if len < 9 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv4 target",
                    )));
                }
                let ip_bytes: [u8; 4] = this.read_buf[3..7].try_into().unwrap();
                let ip_addr = Ipv4Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[7..9].try_into().unwrap());
                (NetLocation::new(Address::Ipv4(ip_addr), port), 9)
            } else if ip_version == 6 {
                if len < 21 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "invalid snell packet size for ipv6 target",
                    )));
                }
                let ip_bytes: [u8; 16] = this.read_buf[3..19].try_into().unwrap();
                let ip_addr = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes(this.read_buf[19..21].try_into().unwrap());
                (NetLocation::new(Address::Ipv6(ip_addr), port), 21)
            } else {
                return Poll::Ready(Err(std::io::Error::other(format!(
                    "invalid ip version: {ip_version}"
                ))));
            }
        } else {
            if len < 4 + address_len {
                return Poll::Ready(Err(std::io::Error::other(
                    "invalid snell packet size for host target",
                )));
            }
            let hostname_bytes = &this.read_buf[2..2 + address_len];
            let hostname = std::str::from_utf8(hostname_bytes)
                .map_err(|e| std::io::Error::other(format!("could not parse hostname: {e}")))?;
            let port = u16::from_be_bytes(
                this.read_buf[2 + address_len..4 + address_len]
                    .try_into()
                    .unwrap(),
            );
            (
                NetLocation::new(Address::Hostname(hostname.to_string()), port),
                4 + address_len,
            )
        };

        buf.put_slice(&this.read_buf[data_offset..len]);
        Poll::Ready(Ok(location))
    }
}

impl AsyncWriteSourcedMessage for SnellUdpStream {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        if this.write_buf_end_offset > 0 {
            // it's possible for the buffer to be written, but flush not to be completed.
            // we still want to continue in that scenario.
            if let Poll::Ready(Err(e)) = Pin::new(&mut this).poll_flush_message(cx) {
                return Poll::Ready(Err(e));
            }
            if this.write_buf_end_offset > 0 {
                return Poll::Pending;
            }
        }

        let buf_len = buf.len();
        if buf_len + 19 > this.write_buf.len() {
            // TODO: if it's too big, we need to split up the message into this.max_payload_size chunks.
            panic!("single message is larger than our write buf: {buf_len}");
        }

        let offset = match source {
            SocketAddr::V4(socket_addr) => {
                this.write_buf[0] = 4;
                this.write_buf[1..5].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[5..7].copy_from_slice(&socket_addr.port().to_be_bytes());
                7
            }
            SocketAddr::V6(socket_addr) => {
                this.write_buf[0] = 6;
                this.write_buf[1..17].copy_from_slice(&socket_addr.ip().octets());
                this.write_buf[17..19].copy_from_slice(&socket_addr.port().to_be_bytes());
                19
            }
        };

        this.write_buf[offset..offset + buf_len].copy_from_slice(buf);
        this.write_buf_end_offset = offset + buf_len;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for SnellUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_buf_end_offset > 0 {
            ready!(Pin::new(&mut this.stream)
                .poll_write_message(cx, &this.write_buf[0..this.write_buf_end_offset]))?;
            this.write_buf_end_offset = 0;
        }
        Pin::new(&mut this.stream).poll_flush_message(cx)
    }
}

impl AsyncShutdownMessage for SnellUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown_message(cx)
    }
}

impl AsyncPing for SnellUdpStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    // Write a ping message to the stream, if supported.
    // This should end up calling the highest level stream abstraction that supports
    // pings, and should only result in a single message.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl AsyncTargetedMessageStream for SnellUdpStream {}
