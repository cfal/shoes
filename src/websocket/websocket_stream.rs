use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use log::warn;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::config::WebsocketPingType;
use crate::util::allocate_vec;

/// RFC 6455 limits control frame payloads to 125 bytes.
const MAX_CONTROL_PAYLOAD_LEN: usize = 125;

pub struct WebsocketStream {
    stream: Box<dyn AsyncStream>,
    is_client: bool,
    ping_type: WebsocketPingType,
    pending_initial_data: bool,

    read_state: ReadState,
    read_frame_masked: bool,
    read_frame_opcode: OpCode,
    read_frame_length: u64,
    read_frame_mask: [u8; 4],
    read_frame_mask_offset: usize,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,

    write_frame: Box<[u8]>,
    write_frame_start_offset: usize,
    write_frame_end_offset: usize,

    ping_data: Box<[u8]>,
    ping_data_size: usize,
    pending_write_pong: bool,
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadBinaryContent,
    ReadPingContent,
    SkipContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpCode {
    Continue,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Unknown(u8),
}

impl OpCode {
    pub fn from(code: u8) -> Self {
        match code {
            0 => OpCode::Continue,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,
            9 => OpCode::Ping,
            10 => OpCode::Pong,
            _ => OpCode::Unknown(code),
        }
    }

    fn is_control(self) -> bool {
        match self {
            OpCode::Close | OpCode::Ping | OpCode::Pong => true,
            OpCode::Unknown(code) => code >= 8,
            OpCode::Continue | OpCode::Text | OpCode::Binary => false,
        }
    }
}

impl WebsocketStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_client: bool,
        ping_type: WebsocketPingType,
        unprocessed_data: &[u8],
    ) -> Self {
        let mut unprocessed_buf = allocate_vec(16384).into_boxed_slice();
        let mut unprocessed_end_offset = 0;
        let write_frame = allocate_vec(32768).into_boxed_slice();
        let ping_data = allocate_vec(MAX_CONTROL_PAYLOAD_LEN).into_boxed_slice();

        let pending_initial_data = if !unprocessed_data.is_empty() {
            unprocessed_buf[0..unprocessed_data.len()].copy_from_slice(unprocessed_data);
            unprocessed_end_offset = unprocessed_data.len();
            true
        } else {
            false
        };

        Self {
            stream,
            is_client,
            ping_type,
            pending_initial_data,
            read_state: ReadState::Init,
            read_frame_masked: false,
            read_frame_opcode: OpCode::Unknown(99),
            read_frame_length: 0,
            read_frame_mask: [0u8; 4],
            read_frame_mask_offset: 0,
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset,
            write_frame,
            write_frame_start_offset: 0,
            write_frame_end_offset: 0,
            ping_data,
            ping_data_size: 0,
            pending_write_pong: false,
        }
    }

    fn unprocessed_len(&self) -> usize {
        self.unprocessed_end_offset - self.unprocessed_start_offset
    }

    fn consume_unprocessed(&mut self, len: usize) {
        self.unprocessed_start_offset += len;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }
    }

    /// How much of the current frame's remaining payload is buffered.
    fn buffered_payload_len(&self) -> usize {
        std::cmp::min(self.unprocessed_len() as u64, self.read_frame_length) as usize
    }

    fn consume_payload(&mut self, len: usize) {
        self.consume_unprocessed(len);
        self.read_frame_length -= len as u64;
    }

    /// Unmasks the next `len` buffered payload bytes in place and returns their range in
    /// `unprocessed_buf`.
    fn unmask_payload(&mut self, len: usize) -> std::ops::Range<usize> {
        let payload = self.unprocessed_start_offset..self.unprocessed_start_offset + len;
        if self.read_frame_masked {
            apply_mask(
                &mut self.unprocessed_buf[payload.clone()],
                &self.read_frame_mask,
                self.read_frame_mask_offset,
            );
            self.read_frame_mask_offset = (self.read_frame_mask_offset + len) % 4;
        }
        payload
    }

    fn step_init(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
        if self.unprocessed_len() < 2 {
            return Ok(());
        }

        let first = self.unprocessed_buf[self.unprocessed_start_offset];
        let second = self.unprocessed_buf[self.unprocessed_start_offset + 1];
        self.consume_unprocessed(2);

        let read_frame_final = first & 0x80 != 0;

        self.read_frame_masked = second & 0x80 != 0;

        // if we're not the client, then we are reading from the client and we should only accept
        // masked data.
        // this was disabled because shadowrocket seems to send unmasked frames at times.
        // if !self.is_client && !self.read_frame_masked {
        //     return Err(std::io::Error::new(
        //         std::io::ErrorKind::Other,
        //         "client frame was not masked",
        //     ));
        // }

        self.read_frame_opcode = OpCode::from(first & 0x0f);

        if !read_frame_final
            && self.read_frame_opcode != OpCode::Binary
            && self.read_frame_opcode != OpCode::Continue
        {
            return Err(std::io::Error::other(format!(
                "cannot handle non-final frames of type {:?}",
                self.read_frame_opcode
            )));
        }

        let length = second & 0x7f;

        // We don't bother checking max length when it's <= 125,
        // so we do the check in ReadLength.
        if length == 126 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 2,
            };
            self.step_read_length(cx, buf, 2)
        } else if length == 127 {
            self.read_state = ReadState::ReadLength {
                length_bytes_len: 8,
            };
            self.step_read_length(cx, buf, 8)
        } else {
            self.read_frame_length = length as u64;
            if self.read_frame_masked {
                self.read_state = ReadState::ReadMask;
                self.step_read_mask(cx, buf)
            } else {
                self.step_check_content(cx, buf)
            }
        }
    }

    fn step_read_length(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        length_bytes_len: usize,
    ) -> std::io::Result<()> {
        if self.unprocessed_len() < length_bytes_len {
            return Ok(());
        }

        let length_bytes = &self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + length_bytes_len];
        let mut length = 0u64;
        for b in length_bytes {
            length = (length << 8) | (*b as u64);
        }
        self.read_frame_length = length;
        self.consume_unprocessed(length_bytes_len);

        if self.read_frame_length > 0x7fffffffffffffffu64 {
            return Err(std::io::Error::other(format!(
                "Invalid frame length ({})",
                self.read_frame_length
            )));
        }

        if self.read_frame_masked {
            self.read_state = ReadState::ReadMask;
            self.step_read_mask(cx, buf)
        } else {
            self.step_check_content(cx, buf)
        }
    }

    fn step_read_mask(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        if self.unprocessed_len() < 4 {
            return Ok(());
        }

        let mask_bytes =
            &self.unprocessed_buf[self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
        self.read_frame_mask.copy_from_slice(mask_bytes);
        self.read_frame_mask_offset = 0;
        self.consume_unprocessed(4);

        self.step_check_content(cx, buf)
    }

    fn step_check_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        if self.read_frame_opcode.is_control()
            && self.read_frame_length > MAX_CONTROL_PAYLOAD_LEN as u64
        {
            return Err(std::io::Error::other(format!(
                "control frame payload too large ({})",
                self.read_frame_length
            )));
        }
        match self.read_frame_opcode {
            OpCode::Binary | OpCode::Continue => {
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::ReadBinaryContent;
                    self.step_read_binary_content(cx, buf)
                }
            }
            OpCode::Ping => {
                // Reset ping data size, either so that we write
                // the correct pong frame if there's no data, or so
                // that we start from 0 offset in step_read_ping_content.
                self.ping_data_size = 0;

                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.pending_write_pong = true;
                    self.step_init(cx, buf)
                } else {
                    // Make sure we aren't writing pongs when we're reading new ping data.
                    self.pending_write_pong = false;
                    self.read_state = ReadState::ReadPingContent;
                    self.step_read_ping_content(cx, buf)
                }
            }
            OpCode::Pong => {
                // Note that pongs might be delayed, and only written when there's data to write,
                // because copy_bidirectional does not know we need a flush, and wouldn't call
                // poll_write until new data arrives.

                // We don't keep track if we're expecting a pong, because
                // it's allowed for the other side to only respond to the latest
                // ping, ie. we could send 5 pings and only 1 pong response arrives.
                // So it's hard to keep track of if a pong is "valid".
                // https://www.rfc-editor.org/rfc/rfc6455.html#section-5.5.3

                // Unsolicited pongs are heartbeats and may carry any payload; skip it.
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
            // Close frames are skipped like unknown frames, without the reply RFC 6455
            // requires. Xray, sing-box and mihomo close TCP right after sending Close, so
            // reads end at EOF anyway. Replying from this read path would need a deadline
            // for peers that stop reading and wakeups shared by split read and write halves,
            // which is more complexity than the reply is worth.
            _ => {
                warn!("Ignoring unknown frame type: {:?}", self.read_frame_opcode);
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
        }
    }

    fn step_skip_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let skip_amount = self.buffered_payload_len();
        self.consume_payload(skip_amount);
        if self.read_frame_length > 0 {
            return Ok(());
        }

        self.read_state = ReadState::Init;
        self.step_init(cx, buf)
    }

    fn step_read_ping_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let read_amount = self.buffered_payload_len();
        if read_amount == 0 {
            return Ok(());
        }

        let payload = self.unmask_payload(read_amount);
        self.ping_data[self.ping_data_size..self.ping_data_size + read_amount]
            .copy_from_slice(&self.unprocessed_buf[payload]);
        self.ping_data_size += read_amount;
        self.consume_payload(read_amount);

        if self.read_frame_length == 0 {
            self.read_state = ReadState::Init;
            // this previously tried to pack_write_pong_frame right away - but there's no
            // point in doing it, because copy_bidirectional wouldn't know there's anything
            // to flush unless poll_write or poll_write_ping is called anyway.
            self.pending_write_pong = true;
            return self.step_init(cx, buf);
        }

        Ok(())
    }

    fn step_read_binary_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let available_space = buf.remaining();
        if available_space == 0 {
            // it's possible that we looped through all the steps and ended up in read content
            // with no space.
            return Ok(());
        }

        let read_amount = std::cmp::min(self.buffered_payload_len(), available_space);
        if read_amount == 0 {
            return Ok(());
        }

        let payload = self.unmask_payload(read_amount);
        buf.put_slice(&self.unprocessed_buf[payload]);
        self.consume_payload(read_amount);

        if self.read_frame_length == 0 {
            self.read_state = ReadState::Init;
            return self.step_init(cx, buf);
        }

        Ok(())
    }

    fn pack_write_ping_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        let written = pack_frame(
            0x09,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_empty_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;
        if available_space < 6 {
            return false;
        }

        // 0x02 is binary
        let written = pack_frame(
            0x02,
            self.is_client,
            &[],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_pong_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        // up to 14 bytes for header and mask
        if available_space < self.ping_data_size + 14 {
            return false;
        }

        let written = pack_frame(
            0x0a,
            self.is_client,
            &self.ping_data[0..self.ping_data_size],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_write_frame(&mut self, input: &[u8]) -> usize {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        // we need up to 14 bytes just for the header and mask.
        if available_space < 40 {
            return 0;
        }

        let pack_amount = std::cmp::min(input.len(), available_space - 14);

        // 0x02 is binary
        let written = pack_frame(
            0x02,
            self.is_client,
            &input[0..pack_amount],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        pack_amount
    }

    fn do_write_frame(&mut self, cx: &mut Context<'_>) -> std::io::Result<()> {
        loop {
            let remaining_data =
                &self.write_frame[self.write_frame_start_offset..self.write_frame_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        // eof, TODO fix
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write frame eof",
                        ));
                    }
                    self.write_frame_start_offset += written;
                    if self.write_frame_start_offset == self.write_frame_end_offset {
                        self.write_frame_start_offset = 0;
                        self.write_frame_end_offset = 0;
                        break;
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    break;
                }
            }
        }

        Ok(())
    }

    fn reset_unprocessed_buf_offset(&mut self) {
        assert!(
            self.unprocessed_start_offset > 0
                && self.unprocessed_end_offset > self.unprocessed_start_offset
        );

        self.unprocessed_buf.copy_within(
            self.unprocessed_start_offset..self.unprocessed_end_offset,
            0,
        );
        self.unprocessed_end_offset -= self.unprocessed_start_offset;
        self.unprocessed_start_offset = 0;
    }
}

impl AsyncRead for WebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Callers such as tokio's read_to_end pass buffers that already hold data.
        let filled_before = buf.filled().len();

        // If there is unprocessed data and we are reading content, it must be because there
        // is data still to be read, but the passed in `buf` from the previous iteration
        // didn't have enough space to read it all.
        if this.unprocessed_end_offset > 0 && this.read_state == ReadState::ReadBinaryContent {
            let read_result = this.step_read_binary_content(cx, buf);
            if read_result.is_err() {
                return Poll::Ready(read_result);
            }
            assert!(buf.filled().len() > filled_before);
            return Poll::Ready(Ok(()));
        }

        loop {
            // Reset the offset if we have less than half the buffer left to use.
            if this.unprocessed_start_offset * 2 > this.unprocessed_buf.len() {
                this.reset_unprocessed_buf_offset();
            }

            // We need to go through the read_state cycle once if we have initial data,
            // even if poll_read returns pending.
            if !this.pending_initial_data {
                // If we get here, then there is no unprocessed data, or there is unprocessed data
                // and we are not reading content. any unprocessed data that is not content
                // should be smaller than the buffer size.
                assert!(this.unprocessed_start_offset < this.unprocessed_buf.len());

                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);

                match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                    Poll::Ready(res) => {
                        res?;
                        let len = read_buf.filled().len();
                        if len == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        this.unprocessed_end_offset += len;
                    }
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            } else {
                this.pending_initial_data = false;
            }

            let read_result = match this.read_state {
                ReadState::Init => this.step_init(cx, buf),
                ReadState::ReadLength { length_bytes_len } => {
                    this.step_read_length(cx, buf, length_bytes_len)
                }
                ReadState::ReadMask => this.step_read_mask(cx, buf),
                ReadState::SkipContent => this.step_skip_content(cx, buf),
                ReadState::ReadBinaryContent => this.step_read_binary_content(cx, buf),
                ReadState::ReadPingContent => this.step_read_ping_content(cx, buf),
            };

            if read_result.is_err() {
                return Poll::Ready(read_result);
            }

            if buf.filled().len() > filled_before {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for WebsocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.pending_write_pong {
            if this.pack_write_pong_frame() {
                this.pending_write_pong = false;
            } else {
                // Write and try to make space in the write frame,
                // then try again.
                if let Err(e) = this.do_write_frame(cx) {
                    return Poll::Ready(Err(e));
                }
                if this.pack_write_pong_frame() {
                    this.pending_write_pong = false;
                } else {
                    return Poll::Pending;
                }
            }
        }

        let mut written = 0;
        loop {
            let input = &buf[written..];
            if input.is_empty() {
                break;
            }

            written += this.pack_write_frame(input);

            if let Err(e) = this.do_write_frame(cx) {
                return Poll::Ready(Err(e));
            }

            if this.write_frame_end_offset > 0 {
                // Not everything could be written.
                break;
            }
        }

        if written > 0 {
            Poll::Ready(Ok(written))
        } else {
            Poll::Pending
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.write_frame_end_offset > 0 {
            this.do_write_frame(cx)?;
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
            }
        }

        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for WebsocketStream {
    fn supports_ping(&self) -> bool {
        self.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();

        if this.pending_write_pong {
            if this.pack_write_pong_frame() {
                this.pending_write_pong = false;
                return Poll::Ready(Ok(true));
            } else {
                // If pack_write_pong_frame returns false, it means that there's not enough space
                // for the pong frame at the moment - but that also means:
                // 1) we have lots of data to write out
                // 2) a future check of pending_write_pong will still result in a pong being
                // written.
                // This isn't a case where we are pending a write - so don't return Poll::Pending,
                // simply return that no data has been written.
                return Poll::Ready(Ok(false));
            }
        }

        // Don't bother writing a ping if we have other things to write.
        if this.write_frame_end_offset > 0 {
            return Poll::Ready(Ok(false));
        }

        let written = match this.ping_type {
            WebsocketPingType::PingFrame => this.pack_write_ping_frame(),
            WebsocketPingType::EmptyFrame => this.pack_write_empty_frame(),
            _ => {
                panic!("Unexpected ping type: {:?}", this.ping_type);
            }
        };

        // the write frame should be empty so there should always be space.
        assert!(written);

        Poll::Ready(Ok(true))
    }
}

impl AsyncStream for WebsocketStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

#[inline]
fn pack_frame(opcode: u8, use_mask: bool, input: &[u8], output: &mut [u8]) -> usize {
    let input_len = input.len();

    // 0x80 is final
    output[0] = opcode | 0x80;

    let mut offset = if input_len < 126 {
        output[1] = input_len as u8;
        2
    } else if input_len <= 65535 {
        output[1] = 0x7e;
        let size_bytes = (input_len as u16).to_be_bytes();
        output[2..4].copy_from_slice(&size_bytes);
        4
    } else {
        output[1] = 0x7f;
        let size_bytes = (input_len as u64).to_be_bytes();
        output[2..10].copy_from_slice(&size_bytes);
        10
    };

    // Client must be masked, but optional for server.
    let mask = if use_mask {
        // set the masking bit
        output[1] |= 0x80;

        let mut mask_bytes = [0u8; 4];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut mask_bytes);

        output[offset..offset + 4].copy_from_slice(&mask_bytes);
        offset += 4;

        Some(mask_bytes)
    } else {
        None
    };

    if input_len > 0 {
        output[offset..offset + input_len].copy_from_slice(input);
        if let Some(mask_bytes) = mask {
            apply_mask(&mut output[offset..offset + input_len], &mask_bytes, 0);
        }
    }

    offset + input_len
}

/// XORs `bytes` with `mask`, starting `offset` bytes into the mask.
fn apply_mask(bytes: &mut [u8], mask: &[u8; 4], offset: usize) {
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte ^= mask[(offset + i) % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoTlsStream;
    use crate::crypto::tls_deframer::TlsDeframer;
    use futures::task::noop_waker_ref;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn nonempty_ping_preserves_following_payload_and_pong() {
        for masked in [false, true] {
            let ping_payload = b"ping-data";
            let payload = b"application data";
            let mut frames = [0; 128];
            let ping_len = pack_frame(0x09, masked, ping_payload, &mut frames);
            let binary_len = pack_frame(0x02, masked, payload, &mut frames[ping_len..]);
            let frames = &frames[..ping_len + binary_len];
            for split in (0..=ping_len).chain(std::iter::once(frames.len())) {
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let (io, mut peer) = tokio::io::duplex(1024);
                    let mut stream = WebsocketStream::new(
                        Box::new(io),
                        false,
                        WebsocketPingType::PingFrame,
                        &frames[..split],
                    );
                    if split < frames.len() {
                        let mut cx = Context::from_waker(noop_waker_ref());
                        let mut bytes = [0; 1];
                        let mut buf = ReadBuf::new(&mut bytes);
                        assert!(
                            Pin::new(&mut stream)
                                .poll_read(&mut cx, &mut buf)
                                .is_pending()
                        );
                        assert!(buf.filled().is_empty());
                        peer.write_all(&frames[split..]).await.unwrap();
                    }
                    peer.shutdown().await.unwrap();
                    for expected in payload {
                        assert_eq!(stream.read_u8().await.unwrap(), *expected);
                    }
                    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);

                    let wrote_pong =
                        futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_ping(cx))
                            .await
                            .unwrap();
                    assert!(wrote_pong);
                    stream.flush().await.unwrap();
                    let mut pong = vec![0; 2 + ping_payload.len()];
                    peer.read_exact(&mut pong).await.unwrap();
                    assert_eq!(&pong[..2], &[0x8a, ping_payload.len() as u8]);
                    assert_eq!(&pong[2..], ping_payload);
                })
                .await
                .unwrap_or_else(|_| panic!("masked={masked}, split={split}"));
            }
        }
    }

    #[tokio::test]
    async fn idle_tls_transport_flushes_websocket_ping_and_pong() {
        for framed in [false, true] {
            for pong in [false, true] {
                let (io, mut peer) = tokio::io::duplex(4096);
                let websocket = WebsocketStream::new(
                    Box::new(io),
                    false,
                    WebsocketPingType::PingFrame,
                    if pong { &[0x89, 0] } else { &[] },
                );
                let session = crate::reality::established_pair().1;
                let mut tls =
                    CryptoTlsStream::new(websocket, session, framed.then(TlsDeframer::new));
                tls.write_all(b"prior TLS traffic").await.unwrap();
                tls.flush().await.unwrap();

                let mut cx = Context::from_waker(noop_waker_ref());
                let mut bytes = [0; 4096];
                let mut buf = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut peer).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert!(!buf.filled().is_empty());
                buf.clear();
                assert!(
                    Pin::new(&mut peer)
                        .poll_read(&mut cx, &mut buf)
                        .is_pending()
                );

                if pong {
                    assert!(Pin::new(&mut tls).poll_read(&mut cx, &mut buf).is_pending());
                    assert!(buf.filled().is_empty());
                }
                assert!(matches!(
                    Pin::new(&mut tls).poll_write_ping(&mut cx),
                    Poll::Ready(Ok(true))
                ));
                tls.flush().await.unwrap();
                assert!(matches!(
                    Pin::new(&mut peer).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(buf.filled(), &[if pong { 0x8a } else { 0x89 }, 0]);
            }
        }
    }

    fn frame(first: u8, masked: bool, payload: &[u8]) -> Vec<u8> {
        let mut output = vec![0; payload.len() + 14];
        let len = pack_frame(first & 0x0f, masked, payload, &mut output);
        output.truncate(len);
        output[0] = first;
        output
    }

    /// Delivers `frames` through a pipe that holds at most `chunk` bytes, so every read
    /// sees at most `chunk` bytes.
    async fn read_all(frames: Vec<u8>, chunk: usize) -> std::io::Result<Vec<u8>> {
        let (io, mut peer) = tokio::io::duplex(chunk);
        // Rejected frames leave the writer blocked until `stream` drops, so it isn't awaited.
        tokio::spawn(async move {
            if peer.write_all(&frames).await.is_ok() {
                let _ = peer.shutdown().await;
            }
        });
        let mut stream =
            WebsocketStream::new(Box::new(io), false, WebsocketPingType::PingFrame, &[]);
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut received),
        )
        .await
        .expect("WebSocket reads must finish at EOF or on a protocol error")
        .map(|_| received)
    }

    #[tokio::test]
    async fn every_length_encoding_survives_split_delivery() {
        for len in [1, 125, 126, 127, 65535, 65536, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            for masked in [false, true] {
                let frames = frame(0x82, masked, &payload);
                let length_header_len = match len {
                    0..=125 => 2,
                    126..=65535 => 4,
                    _ => 10,
                };
                let mask_len = if masked { 4 } else { 0 };
                assert_eq!(frames.len() - payload.len(), length_header_len + mask_len);
                for chunk in [1, 3, 4096] {
                    // Byte-at-a-time delivery of large frames adds runtime without new states.
                    if chunk == 1 && len > 4096 {
                        continue;
                    }
                    assert_eq!(
                        read_all(frames.clone(), chunk).await.unwrap(),
                        payload,
                        "len={len} masked={masked} chunk={chunk}"
                    );
                }
            }
        }
    }

    /// Later headers arrive in reads that add no payload while `read_to_end`'s buffer already
    /// holds data, which must not look like EOF.
    #[tokio::test]
    async fn fragmented_binary_frames_concatenate() {
        let mut frames = frame(0x02, true, b"first ");
        frames.extend(frame(0x00, true, b"second "));
        frames.extend(frame(0x80, true, b"third"));
        assert_eq!(read_all(frames, 2).await.unwrap(), b"first second third");
    }

    #[tokio::test]
    async fn written_frames_are_readable_in_the_opposite_role() {
        let payload: Vec<u8> = (0..100_000).map(|i| (i % 253) as u8).collect();
        for writer_is_client in [true, false] {
            let (writer_io, reader_io) = tokio::io::duplex(8192);
            let mut writer = WebsocketStream::new(
                Box::new(writer_io),
                writer_is_client,
                WebsocketPingType::PingFrame,
                &[],
            );
            let mut reader = WebsocketStream::new(
                Box::new(reader_io),
                !writer_is_client,
                WebsocketPingType::PingFrame,
                &[],
            );
            let expected = payload.clone();
            let write = tokio::spawn(async move {
                writer.write_all(&expected).await.unwrap();
                writer.flush().await.unwrap();
                writer.shutdown().await.unwrap();
            });
            let mut received = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                reader.read_to_end(&mut received),
            )
            .await
            .unwrap()
            .unwrap();
            write.await.unwrap();
            assert_eq!(received, payload, "writer_is_client={writer_is_client}");
        }
    }

    #[tokio::test]
    async fn control_frames_at_the_size_limit_are_accepted() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for masked in [false, true] {
                let ping = [0x5a; MAX_CONTROL_PAYLOAD_LEN];
                let mut frames = frame(0x89, masked, &ping);
                frames.extend(frame(0x8a, masked, &[0xa5; MAX_CONTROL_PAYLOAD_LEN]));
                frames.extend(frame(0x82, masked, b"data"));
                let (io, mut peer) = tokio::io::duplex(1024);
                peer.write_all(&frames).await.unwrap();
                peer.shutdown().await.unwrap();
                let mut stream =
                    WebsocketStream::new(Box::new(io), false, WebsocketPingType::PingFrame, &[]);
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"data", "masked={masked}");
                let wrote_pong =
                    futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_ping(cx))
                        .await
                        .unwrap();
                assert!(wrote_pong, "masked={masked}");
                stream.flush().await.unwrap();
                let mut pong = vec![0; 2 + ping.len()];
                peer.read_exact(&mut pong).await.unwrap();
                assert_eq!(&pong[..2], &[0x8a, 125], "masked={masked}");
                assert_eq!(&pong[2..], ping, "masked={masked}");
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn full_read_buffers_keep_pending_payload() {
        let (io, mut peer) = tokio::io::duplex(64);
        peer.write_all(&frame(0x82, false, b"abc")).await.unwrap();
        let mut stream =
            WebsocketStream::new(Box::new(io), false, WebsocketPingType::PingFrame, &[]);
        let mut storage = [0; 1];
        let mut buf = ReadBuf::new(&mut storage);
        for _ in 0..2 {
            futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), b"a");
        }
        let mut rest = [0; 2];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"bc");
    }

    #[tokio::test]
    async fn unknown_and_text_frames_are_skipped() {
        let mut frames = frame(0x81, true, b"text is not tunnel data");
        frames.extend(frame(0x83, false, &[1; 300]));
        frames.extend(frame(0x8a, true, b"unsolicited heartbeat"));
        frames.extend(frame(0x82, true, b"binary"));
        assert_eq!(read_all(frames, 5).await.unwrap(), b"binary");
    }

    #[tokio::test]
    async fn invalid_frames_are_rejected() {
        let mut oversized_length = frame(0x82, false, &[]);
        oversized_length[1] = 127;
        oversized_length.extend_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0]);
        for (name, frames) in [
            ("oversized ping", frame(0x89, false, &[0; 126])),
            ("oversized pong", frame(0x8a, true, &[0; 126])),
            ("oversized close", frame(0x88, false, &[0; 126])),
            (
                "oversized reserved control frame",
                frame(0x8b, false, &[0; 126]),
            ),
            ("fragmented ping", frame(0x09, false, b"ping")),
            ("fragmented text", frame(0x01, false, b"text")),
            ("fragmented close", frame(0x08, false, &[])),
            ("64-bit length with the high bit set", oversized_length),
        ] {
            assert!(read_all(frames, 1).await.is_err(), "{name} was accepted");
        }
    }

    #[tokio::test]
    async fn shutdown_sends_buffered_frames_and_keeps_reading() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (io, mut peer) = tokio::io::duplex(64);
            let mut stream =
                WebsocketStream::new(Box::new(io), false, WebsocketPingType::PingFrame, &[]);
            // The pipe holds 64 bytes, so most of this frame is still buffered at shutdown.
            let payload = [0x42; 1000];
            stream.write_all(&payload).await.unwrap();
            let (shutdown, sent) = tokio::join!(stream.shutdown(), async {
                let mut sent = Vec::new();
                peer.read_to_end(&mut sent).await.unwrap();
                sent
            });
            shutdown.unwrap();
            assert_eq!(sent, frame(0x82, false, &payload));

            // The shutdown is a half-close, so replies are still read.
            peer.write_all(&frame(0x82, true, b"reply")).await.unwrap();
            peer.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"reply");
        })
        .await
        .unwrap();
    }
}
