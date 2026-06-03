use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use log::warn;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::config::WebsocketPingType;
use crate::util::allocate_vec;

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
    close_data: Box<[u8]>,
    close_data_size: usize,
    pending_write_close: bool,
    received_close: bool,
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadBinaryContent,
    ReadPingContent,
    ReadCloseContent,
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
        let ping_data = allocate_vec(125).into_boxed_slice();
        let close_data = allocate_vec(125).into_boxed_slice();

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
            close_data,
            close_data_size: 0,
            pending_write_close: false,
            received_close: false,
        }
    }

    fn step_init(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 2 {
            return Ok(());
        }

        let first = self.unprocessed_buf[self.unprocessed_start_offset];
        let second = self.unprocessed_buf[self.unprocessed_start_offset + 1];
        self.unprocessed_start_offset += 2;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

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
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < length_bytes_len {
            return Ok(());
        }

        let length_bytes = &self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + length_bytes_len];
        self.unprocessed_start_offset += length_bytes_len;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let mut length = 0u64;
        for b in length_bytes {
            length = (length << 8) | (*b as u64);
        }
        self.read_frame_length = length;

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
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        if unprocessed_len < 4 {
            return Ok(());
        }

        let mask_bytes =
            &self.unprocessed_buf[self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
        self.read_frame_mask.copy_from_slice(mask_bytes);

        self.unprocessed_start_offset += 4;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.step_check_content(cx, buf)
    }

    fn step_check_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
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
                    if self.read_frame_length > self.ping_data.len() as u64 {
                        return Err(std::io::Error::other(format!(
                            "cannot handle ping data length ({})",
                            self.read_frame_length
                        )));
                    }

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
                if self.read_frame_length > 125 {
                    return Err(std::io::Error::other(format!(
                        "invalid pong data length ({})",
                        self.read_frame_length
                    )));
                }
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.step_init(cx, buf)
                } else {
                    self.read_state = ReadState::SkipContent;
                    self.step_skip_content(cx, buf)
                }
            }
            OpCode::Close => {
                if self.read_frame_length > self.close_data.len() as u64 {
                    return Err(std::io::Error::other(format!(
                        "cannot handle close data length ({})",
                        self.read_frame_length
                    )));
                }

                self.close_data_size = 0;
                self.pending_write_pong = false;
                if self.read_frame_length == 0 {
                    self.read_state = ReadState::Init;
                    self.pending_write_close = true;
                    self.received_close = true;
                    Ok(())
                } else {
                    self.pending_write_close = false;
                    self.read_state = ReadState::ReadCloseContent;
                    self.step_read_close_content(cx, buf)
                }
            }
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
        if self.read_frame_length > 0 {
            let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
            let skip_amount = std::cmp::min(unprocessed_len as u64, self.read_frame_length);
            self.unprocessed_start_offset += skip_amount as usize;
            if self.unprocessed_start_offset == self.unprocessed_end_offset {
                self.unprocessed_start_offset = 0;
                self.unprocessed_end_offset = 0;
            }
            self.read_frame_length -= skip_amount;
            if self.read_frame_length > 0 {
                return Ok(());
            }
        }

        self.read_state = ReadState::Init;
        self.read_frame_mask_offset = 0;
        self.step_init(cx, buf)
    }

    fn step_read_ping_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        let read_amount = std::cmp::min(unprocessed_len, self.read_frame_length as usize);
        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
        }

        self.ping_data[self.ping_data_size..self.ping_data_size + read_amount]
            .copy_from_slice(content_bytes);
        self.ping_data_size += read_amount;
        self.read_frame_length -= read_amount as u64;

        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            // this previously tried to pack_write_pong_frame right away - but there's no
            // point in doing it, because copy_bidirectional wouldn't know there's anything
            // to flush unless poll_write or poll_write_ping is called anyway.
            self.pending_write_pong = true;
            return self.step_init(cx, buf);
        }

        Ok(())
    }

    fn step_read_close_content(
        &mut self,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;
        let read_amount = std::cmp::min(unprocessed_len, self.read_frame_length as usize);
        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
        }

        self.close_data[self.close_data_size..self.close_data_size + read_amount]
            .copy_from_slice(content_bytes);
        self.close_data_size += read_amount;

        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.read_frame_length -= read_amount as u64;

        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
            self.read_state = ReadState::Init;
            self.pending_write_close = true;
            self.received_close = true;
        }

        Ok(())
    }

    fn step_read_binary_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        let unprocessed_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let available_space = buf.remaining();
        if available_space == 0 {
            // it's possible that we looped through all the steps and ended up in read content
            // with no space.
            return Ok(());
        }

        let read_amount = std::cmp::min(
            std::cmp::min(unprocessed_len, self.read_frame_length as usize),
            available_space,
        );

        if read_amount == 0 {
            return Ok(());
        }

        let content_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + read_amount];
        if self.read_frame_masked {
            let iter = content_bytes.iter_mut().zip(
                self.read_frame_mask
                    .iter()
                    .cycle()
                    .skip(self.read_frame_mask_offset),
            );
            for (byte, &key) in iter {
                *byte ^= key
            }
            self.read_frame_mask_offset = (self.read_frame_mask_offset + read_amount) % 4;
        }

        buf.put_slice(content_bytes);

        self.unprocessed_start_offset += read_amount;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.read_frame_length -= read_amount as u64;
        if self.read_frame_length == 0 {
            self.read_frame_mask_offset = 0;
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

    fn pack_write_close_frame(&mut self) -> bool {
        let available_space = self.write_frame.len() - self.write_frame_end_offset;

        // up to 14 bytes for header and mask
        if available_space < self.close_data_size + 14 {
            return false;
        }

        let written = pack_frame(
            0x08,
            self.is_client,
            &self.close_data[0..self.close_data_size],
            &mut self.write_frame[self.write_frame_end_offset..],
        );
        self.write_frame_end_offset += written;

        true
    }

    fn pack_pending_control_frames(&mut self) -> bool {
        if self.pending_write_close {
            if self.pack_write_close_frame() {
                self.pending_write_close = false;
            } else {
                return false;
            }
        }

        if self.pending_write_pong {
            if self.pack_write_pong_frame() {
                self.pending_write_pong = false;
            } else {
                return false;
            }
        }

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

        if this.received_close {
            return Poll::Ready(Ok(()));
        }

        // If there is unprocessed data and we are reading content, it must be because there
        // is data still to be read, but the passed in `buf` from the previous iteration
        // didn't have enough space to read it all.
        if this.unprocessed_end_offset > 0 && this.read_state == ReadState::ReadBinaryContent {
            let read_result = this.step_read_binary_content(cx, buf);
            if read_result.is_err() {
                return Poll::Ready(read_result);
            }
            assert!(!buf.filled().is_empty());
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
                ReadState::ReadCloseContent => this.step_read_close_content(cx, buf),
            };

            if read_result.is_err() {
                return Poll::Ready(read_result);
            }

            if this.received_close {
                return Poll::Ready(Ok(()));
            }

            if !buf.filled().is_empty() {
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

        while !this.pack_pending_control_frames() {
            // Write and try to make space in the write frame, then try again.
            if let Err(e) = this.do_write_frame(cx) {
                return Poll::Ready(Err(e));
            }
            if this.write_frame_end_offset > 0 {
                return Poll::Pending;
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

        while !this.pack_pending_control_frames() {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }

        if this.write_frame_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        // Create a new write frame when flush is called when we don't have one.
        while this.write_frame_end_offset > 0 {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }

        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while !this.pack_pending_control_frames() {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }

        while this.write_frame_end_offset > 0 {
            match this.do_write_frame(cx) {
                Ok(()) => {
                    if this.write_frame_end_offset > 0 {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }

        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl AsyncPing for WebsocketStream {
    fn supports_ping(&self) -> bool {
        self.ping_type != WebsocketPingType::Disabled
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        let this = self.get_mut();

        if this.pending_write_close || this.pending_write_pong {
            if this.pack_pending_control_frames() {
                return Poll::Ready(Ok(true));
            } else {
                // If packing returns false, it means that there's not enough space
                // for the control frame at the moment - but that also means:
                // 1) we have lots of data to write out
                // 2) a future check of pending control frames will still result in one being
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

impl AsyncStream for WebsocketStream {}

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
            let iter = output[offset..offset + input_len]
                .iter_mut()
                .zip(mask_bytes.iter().cycle());
            for (byte, &key) in iter {
                *byte ^= key
            }
        }
    }

    offset + input_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct TestStream {
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for TestStream {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for TestStream {}

    #[test]
    fn non_empty_pong_payload_is_skipped() {
        let stream = TestStream::default();
        let frame = [0x8a, 0x03, b'a', b'b', b'c'];
        let mut websocket =
            WebsocketStream::new(Box::new(stream), false, WebsocketPingType::Disabled, &frame);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut output = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut output);

        let result = Pin::new(&mut websocket).poll_read(&mut cx, &mut read_buf);

        assert!(matches!(result, Poll::Pending));
        assert!(read_buf.filled().is_empty());
        assert_eq!(websocket.read_state, ReadState::Init);
    }

    #[test]
    fn close_frame_is_echoed_with_payload() {
        let stream = TestStream::default();
        let written = stream.written.clone();
        let close_frame = [0x88, 0x02, 0x03, 0xe8];
        let mut websocket = WebsocketStream::new(
            Box::new(stream),
            false,
            WebsocketPingType::Disabled,
            &close_frame,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut output = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut output);

        let read_result = Pin::new(&mut websocket).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(read_result, Poll::Ready(Ok(()))));
        assert!(websocket.pending_write_close);
        assert!(websocket.received_close);

        let flush_result = Pin::new(&mut websocket).poll_flush(&mut cx);
        assert!(matches!(flush_result, Poll::Ready(Ok(()))));

        assert_eq!(&*written.lock().unwrap(), &close_frame);
    }

    #[test]
    fn max_size_ping_is_echoed_as_pong() {
        let stream = TestStream::default();
        let written = stream.written.clone();
        let mut frame = Vec::with_capacity(127);
        frame.extend_from_slice(&[0x89, 125]);
        frame.extend(std::iter::repeat_n(0x42, 125));
        let mut websocket =
            WebsocketStream::new(Box::new(stream), false, WebsocketPingType::Disabled, &frame);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut output = [0u8; 8];
        let mut read_buf = ReadBuf::new(&mut output);

        let read_result = Pin::new(&mut websocket).poll_read(&mut cx, &mut read_buf);
        assert!(matches!(read_result, Poll::Ready(Ok(())) | Poll::Pending));
        assert!(websocket.pending_write_pong);

        let flush_result = Pin::new(&mut websocket).poll_flush(&mut cx);
        assert!(matches!(flush_result, Poll::Ready(Ok(()))));

        let written = written.lock().unwrap();
        assert_eq!(written[0], 0x8a);
        assert_eq!(written[1], 125);
        assert_eq!(&written[2..], &frame[2..]);
    }
}
