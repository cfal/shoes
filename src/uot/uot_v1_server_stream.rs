//! Packet-address stream implementation shared by UoT V1/V2 non-connect and h2mux.
//!
//! Frame format:
//! ```text
//! | ATYP | address  | port  | length | data     |
//! | u8   | variable | u16be | u16be  | variable |
//! ```
//!
//! The address serializer depends on the transport:
//! - UoT V1 and V2 non-connect use sing `AddrParser`
//! - h2mux `packet_addr` uses SOCKS-style `SocksaddrSerializer`

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use super::socks_addr::{parse_socks_packet_address, write_socks_packet_address};
use super::uot_common::{parse_uot_address, write_uot_address};
use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::slide_buffer::SlideBuffer;
use crate::util::allocate_vec;

/// Buffer size for reading and writing packet-address frames.
const BUFFER_SIZE: usize = u16::MAX as usize + 1 + 1 + u8::MAX as usize + 2 + 2;

type ParseFn = fn(&[u8]) -> std::io::Result<Option<(NetLocation, usize)>>;

struct AddressCodec {
    parse: ParseFn,
    write: fn(&mut [u8], &NetLocation) -> std::io::Result<usize>,
}

const UOT_ADDR_CODEC: AddressCodec = AddressCodec {
    parse: parse_uot_address,
    write: write_uot_address,
};

const SOCKS_ADDR_CODEC: AddressCodec = AddressCodec {
    parse: parse_socks_packet_address,
    write: write_socks_packet_address,
};

/// Packet-address stream for multi-destination UDP transports.
pub struct PacketAddrStream<S> {
    stream: S,
    codec: &'static AddressCodec,

    /// Buffer for reading - accumulates bytes until we have a complete packet
    read_buf: SlideBuffer,

    /// Buffer for writing - holds a complete packet before sending (boxed to avoid stack overflow)
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,

    is_eof: bool,
}

impl<S: AsyncStream> PacketAddrStream<S> {
    fn new_with_codec(stream: S, codec: &'static AddressCodec) -> Self {
        Self {
            stream,
            codec,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            write_buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Create a stream that uses sing UoT `AddrParser` packet addresses.
    pub fn new_uot(stream: S) -> Self {
        Self::new_with_codec(stream, &UOT_ADDR_CODEC)
    }

    /// Create a stream that uses sing-mux SOCKS packet addresses.
    pub fn new_socks(stream: S) -> Self {
        Self::new_with_codec(stream, &SOCKS_ADDR_CODEC)
    }

    /// Feed initial data that was read before the stream was created.
    /// This is needed when a higher-level handshake leaves packet bytes buffered.
    pub fn feed_initial_data(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let len = data.len().min(self.read_buf.remaining_capacity());
            self.read_buf.extend_from_slice(&data[..len]);
        }
    }

    /// Try to parse a complete packet-address frame from the read buffer.
    /// Returns Ok(Some((location, payload_start, payload_len))) if a complete packet is available.
    /// Returns Ok(None) if more data is needed.
    /// Returns Err if the data is malformed (unknown ATYP, invalid UTF-8, etc).
    #[inline]
    fn try_parse_packet(&self) -> std::io::Result<Option<(NetLocation, usize, usize)>> {
        let data = self.read_buf.as_slice();

        // Try to parse the address
        let (location, addr_len) = match (self.codec.parse)(data)? {
            Some(result) => result,
            None => return Ok(None),
        };

        // Need at least address + 2 bytes for length prefix
        if data.len() < addr_len + 2 {
            return Ok(None);
        }

        // Read length prefix
        let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
        let payload_start = addr_len + 2;
        let total_len = payload_start + payload_len;

        // Check if we have the complete packet
        if data.len() < total_len {
            return Ok(None);
        }

        Ok(Some((location, payload_start, payload_len)))
    }
}

impl<S: AsyncStream> AsyncReadTargetedMessage for PacketAddrStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        log::trace!(
            "PacketAddrStream::poll_read_targeted_message: is_eof={}, buf_len={}",
            this.is_eof,
            this.read_buf.len()
        );

        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        loop {
            // Try to parse a complete packet from buffered data
            match this.try_parse_packet()? {
                Some((location, payload_start, payload_len)) => {
                    let data = this.read_buf.as_slice();
                    buf.put_slice(&data[payload_start..payload_start + payload_len]);

                    // Consume the entire packet from the buffer
                    let total_consumed = payload_start + payload_len;
                    this.read_buf.consume(total_consumed);

                    log::trace!(
                        "PacketAddrStream: parsed packet to {}, payload_len={}",
                        location,
                        payload_len
                    );
                    return Poll::Ready(Ok(location));
                }
                None => {
                    let data = this.read_buf.as_slice();
                    let preview: Vec<u8> = data.iter().take(20).copied().collect();
                    log::trace!(
                        "PacketAddrStream: incomplete packet, buf_len={}, first_bytes={:02x?}",
                        this.read_buf.len(),
                        preview
                    );
                    // Need more data - continue below
                }
            }

            // Need more data - compact buffer if needed
            this.read_buf.maybe_compact(4096);

            if this.read_buf.remaining_capacity() == 0 {
                this.read_buf.compact();
            }
            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "packet-address read buffer full but no complete packet",
                )));
            }

            // Read more data from the underlying stream
            let write_slice = this.read_buf.write_slice();
            let mut read_buf = ReadBuf::new(write_slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    log::trace!("PacketAddrStream: read {} bytes from stream", bytes_read);
                    if bytes_read == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                    }
                    this.read_buf.advance_write(bytes_read);
                    // Loop to try parsing again
                }
                Poll::Ready(Err(e)) => {
                    log::trace!("PacketAddrStream: read error: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    log::trace!("PacketAddrStream: poll_read pending");
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for PacketAddrStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // If there's pending data to send, flush it first
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Reset write buffer
        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        // Calculate required space: address + length(2) + payload
        let offset = (this.codec.write)(&mut this.write_buf, source)?;
        let total_len = offset + 2 + buf.len();

        if buf.len() > u16::MAX as usize || total_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "packet-address frame too large: {total_len} > {}",
                this.write_buf.len()
            ))));
        }

        // Write length prefix (u16be)
        let len_bytes = (buf.len() as u16).to_be_bytes();
        this.write_buf[offset..offset + 2].copy_from_slice(&len_bytes);
        let data_start = offset + 2;

        // Write payload
        this.write_buf[data_start..data_start + buf.len()].copy_from_slice(buf);
        this.write_buf_len = data_start + buf.len();

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for PacketAddrStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush any pending write data
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        // Flush the underlying stream
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for PacketAddrStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for PacketAddrStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncTargetedMessageStream for PacketAddrStream<S> {}

pub type UotV1ServerStream<S> = PacketAddrStream<S>;
pub type SocksPacketAddrStream<S> = PacketAddrStream<S>;

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::Ipv4Addr;
    use std::pin::Pin;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn tcp_pair() -> std::io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accept = listener.accept();
        let connect = TcpStream::connect(addr);
        let ((server, _), client) = tokio::try_join!(accept, connect)?;
        Ok((client, server))
    }

    async fn read_packet<S: AsyncStream>(
        stream: &mut PacketAddrStream<S>,
    ) -> std::io::Result<(NetLocation, Vec<u8>)> {
        let mut payload = vec![0u8; 1024];
        let mut read_buf = ReadBuf::new(&mut payload);
        let location =
            poll_fn(|cx| Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut read_buf))
                .await?;
        Ok((location, read_buf.filled().to_vec()))
    }

    async fn write_packet<S: AsyncStream>(
        stream: &mut PacketAddrStream<S>,
        payload: &[u8],
        source: &NetLocation,
    ) -> std::io::Result<()> {
        poll_fn(|cx| Pin::new(&mut *stream).poll_write_sourced_message(cx, payload, source))
            .await?;
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_message(cx)).await
    }

    fn encode_packet(
        write_addr: fn(&mut [u8], &NetLocation) -> std::io::Result<usize>,
        addr: &NetLocation,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = vec![0u8; BUFFER_SIZE];
        let addr_len = write_addr(&mut frame, addr).unwrap();
        frame[addr_len..addr_len + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame[addr_len + 2..addr_len + 2 + payload.len()].copy_from_slice(payload);
        frame.truncate(addr_len + 2 + payload.len());
        frame
    }

    #[tokio::test]
    async fn coalesced_small_frame_does_not_starve_maximum_frame() {
        for socks in [false, true] {
            let source = NetLocation::new(crate::address::Address::Hostname("h".repeat(255)), 9001);
            let payload = vec![7; u16::MAX as usize];
            let codec = if socks {
                &SOCKS_ADDR_CODEC
            } else {
                &UOT_ADDR_CODEC
            };
            let mut frames = encode_packet(codec.write, &NetLocation::UNSPECIFIED, b"first");
            frames.extend_from_slice(&encode_packet(codec.write, &source, &payload));
            let (left, mut right) = tcp_pair().await.unwrap();
            let mut reader = PacketAddrStream::new_with_codec(left, codec);
            reader.feed_initial_data(&frames[..BUFFER_SIZE]);
            right.write_all(&frames[BUFFER_SIZE..]).await.unwrap();
            assert_eq!(read_packet(&mut reader).await.unwrap().1, b"first");
            let mut bytes = vec![0; payload.len()];
            let mut buf = ReadBuf::new(&mut bytes);
            let target =
                poll_fn(|cx| Pin::new(&mut reader).poll_read_targeted_message(cx, &mut buf))
                    .await
                    .unwrap();
            assert_eq!(target, source);
            assert_eq!(buf.filled(), payload);
        }
    }

    #[tokio::test]
    async fn maximum_payload_with_hostname_overhead_roundtrips() {
        for socks in [false, true] {
            let source = NetLocation::new(crate::address::Address::Hostname("h".repeat(255)), 9001);
            let payload = vec![7; u16::MAX as usize];
            let (left, right) = tcp_pair().await.unwrap();
            let mut writer = if socks {
                PacketAddrStream::new_socks(left)
            } else {
                PacketAddrStream::new_uot(left)
            };
            let mut reader = if socks {
                PacketAddrStream::new_socks(right)
            } else {
                PacketAddrStream::new_uot(right)
            };
            let mut bytes = vec![0; payload.len()];
            let mut read_buf = ReadBuf::new(&mut bytes);
            let (write, read) = tokio::join!(
                write_packet(&mut writer, &payload, &source),
                poll_fn(|cx| Pin::new(&mut reader).poll_read_targeted_message(cx, &mut read_buf))
            );
            write.unwrap();
            assert_eq!(read.unwrap(), source);
            assert_eq!(read_buf.filled(), payload);
            let error = poll_fn(|cx| {
                Pin::new(&mut writer).poll_write_sourced_message(cx, &vec![0; 65536], &source)
            })
            .await;
            assert!(error.is_err());
        }
    }

    #[tokio::test]
    async fn test_new_uot_reads_uot_packets() {
        let source = NetLocation::from_ip_addr(Ipv4Addr::new(198, 51, 100, 10).into(), 4444);
        let payload = b"uot payload";
        let frame = encode_packet(write_uot_address, &source, payload);

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_uot(client);

        let writer = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
        });

        let (location, read_payload) = read_packet(&mut stream).await.unwrap();
        writer.await.unwrap();

        assert_eq!(location, source);
        assert_eq!(read_payload, payload);
    }

    #[tokio::test]
    async fn test_new_socks_reads_socks_packets() {
        let source = NetLocation::from_ip_addr(Ipv4Addr::new(203, 0, 113, 20).into(), 5353);
        let payload = b"socks payload";
        let frame = encode_packet(write_socks_packet_address, &source, payload);

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_socks(client);

        let writer = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
        });

        let (location, read_payload) = read_packet(&mut stream).await.unwrap();
        writer.await.unwrap();

        assert_eq!(location, source);
        assert_eq!(read_payload, payload);
    }

    #[tokio::test]
    async fn test_new_uot_rejects_socks_packets() {
        let payload = b"wrong codec";
        let hostname = b"example.com";
        let mut frame = vec![0x03, hostname.len() as u8];
        frame.extend_from_slice(hostname);
        frame.extend_from_slice(&7000u16.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_uot(client);

        let writer = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
        });

        let err = read_packet(&mut stream).await.unwrap_err();
        writer.await.unwrap();

        assert!(err.to_string().contains("unknown UoT ATYP: 3"));
    }

    #[tokio::test]
    async fn test_new_socks_rejects_uot_packets() {
        let source = NetLocation::from_ip_addr(Ipv4Addr::new(198, 51, 100, 11).into(), 7001);
        let frame = encode_packet(write_uot_address, &source, b"wrong codec");

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_socks(client);

        let writer = tokio::spawn(async move {
            server.write_all(&frame).await.unwrap();
        });

        let err = read_packet(&mut stream).await.unwrap_err();
        writer.await.unwrap();

        assert!(err.to_string().contains("unknown SOCKS packet ATYP: 0"));
    }

    #[tokio::test]
    async fn test_new_socks_writes_socks_packets() {
        let source = NetLocation::from_ip_addr(Ipv4Addr::new(203, 0, 113, 22).into(), 9000);
        let payload = b"write socks";
        let expected = encode_packet(write_socks_packet_address, &source, payload);

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_socks(client);

        write_packet(&mut stream, payload, &source).await.unwrap();

        let mut actual = vec![0u8; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_new_uot_writes_uot_packets() {
        let source = NetLocation::from_ip_addr(Ipv4Addr::new(198, 51, 100, 12).into(), 9001);
        let payload = b"write uot";
        let expected = encode_packet(write_uot_address, &source, payload);

        let (client, mut server) = tcp_pair().await.unwrap();
        let mut stream = PacketAddrStream::new_uot(client);

        write_packet(&mut stream, payload, &source).await.unwrap();

        let mut actual = vec![0u8; expected.len()];
        server.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }
}
