//! UDP-over-TCP V1 server stream implementation
//!
//! V1 Packet format (each packet has full address):
//! ```text
//! | ATYP | address  | port  | length | data     |
//! | u8   | variable | u16be | u16be  | variable |
//! ```

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use super::uot_common::{parse_uot_address, write_uot_address};
use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::slide_buffer::SlideBuffer;
use crate::util::allocate_vec;

/// Buffer size for reading/writing UoT packets
const BUFFER_SIZE: usize = 65535;

/// UoT V1 server stream for multi-destination UDP packets
///
/// Each packet includes the full destination address, making it suitable
/// for applications that send UDP packets to multiple destinations.
///
/// This stream wraps an `AsyncStream` (raw byte stream) and handles
/// UoT packet framing internally.
pub struct UotV1ServerStream<S> {
    stream: S,

    /// Buffer for reading - accumulates bytes until we have a complete packet
    read_buf: SlideBuffer,

    /// Buffer for writing - holds a complete packet before sending (boxed to avoid stack overflow)
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,

    is_eof: bool,
}

impl<S: AsyncStream> UotV1ServerStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            write_buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Feed initial data that was read before the stream was created.
    /// This is needed when the first UoT packet arrives in the same TCP segment
    /// as the magic address header.
    pub fn feed_initial_data(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let len = data.len().min(self.read_buf.remaining_capacity());
            self.read_buf.extend_from_slice(&data[..len]);
        }
    }

    /// Try to parse a complete UoT packet from the read buffer.
    /// Returns Ok(Some((location, payload_start, payload_len))) if a complete packet is available.
    /// Returns Ok(None) if more data is needed.
    /// Returns Err if the data is malformed (unknown ATYP, invalid UTF-8, etc).
    #[inline]
    fn try_parse_packet(&self) -> std::io::Result<Option<(NetLocation, usize, usize)>> {
        let data = self.read_buf.as_slice();

        // Try to parse the address
        let (location, addr_len) = match parse_uot_address(data)? {
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

impl<S: AsyncStream> AsyncReadTargetedMessage for UotV1ServerStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        log::trace!(
            "UotV1ServerStream::poll_read_targeted_message: is_eof={}, buf_len={}",
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
                        "UotV1ServerStream: parsed packet to {}, payload_len={}",
                        location,
                        payload_len
                    );
                    return Poll::Ready(Ok(location));
                }
                None => {
                    let data = this.read_buf.as_slice();
                    let preview: Vec<u8> = data.iter().take(20).copied().collect();
                    log::trace!(
                        "UotV1ServerStream: incomplete packet, buf_len={}, first_bytes={:02x?}",
                        this.read_buf.len(),
                        preview
                    );
                    // Need more data - continue below
                }
            }

            // Need more data - compact buffer if needed
            this.read_buf.maybe_compact(4096);

            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "UoT read buffer full but no complete packet",
                )));
            }

            // Read more data from the underlying stream
            let write_slice = this.read_buf.write_slice();
            let mut read_buf = ReadBuf::new(write_slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    log::trace!("UotV1ServerStream: read {} bytes from stream", bytes_read);
                    if bytes_read == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                    }
                    this.read_buf.advance_write(bytes_read);
                    // Loop to try parsing again
                }
                Poll::Ready(Err(e)) => {
                    log::trace!("UotV1ServerStream: read error: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    log::trace!("UotV1ServerStream: poll_read pending");
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for UotV1ServerStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
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
        let addr_len = match source {
            SocketAddr::V4(_) => 7,  // ATYP + IPv4(4) + Port(2)
            SocketAddr::V6(_) => 19, // ATYP + IPv6(16) + Port(2)
        };
        let total_len = addr_len + 2 + buf.len();

        if total_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "UoT packet too large: {total_len} > {}",
                this.write_buf.len()
            ))));
        }

        // Write UoT address format
        let offset = write_uot_address(&mut this.write_buf, source);

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

impl<S: AsyncStream> AsyncFlushMessage for UotV1ServerStream<S> {
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

impl<S: AsyncStream> AsyncShutdownMessage for UotV1ServerStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for UotV1ServerStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncTargetedMessageStream for UotV1ServerStream<S> {}
