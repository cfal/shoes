use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::ready;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncStream;
use crate::util::{allocate_vec, resize_vec};

pub struct WebsocketStream {
    stream: Box<dyn AsyncStream>,
    is_client: bool,
    pending_initial_data: bool,

    read_state: ReadState,
    read_frame_final: bool,
    read_frame_masked: bool,
    read_frame_opcode: OpCode,
    read_frame_length: u64,
    read_frame_mask: [u8; 4],
    read_frame_mask_offset: usize,

    unprocessed_buf: Vec<u8>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,

    write_cache: Box<[u8]>,
    write_cache_size: usize,

    write_frame: Vec<u8>,
    write_frame_start_offset: usize,
    write_frame_end_offset: usize,
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    ReadLength { length_bytes_len: usize },
    ReadMask,
    ReadContent,
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

// if the write cache gets to this size, we'll make a frame and write it out
// first.
const WRITE_CACHE_CREATE_FRAME_THRESHOLD: usize = 4096;

impl WebsocketStream {
    pub fn new(stream: Box<dyn AsyncStream>, is_client: bool, unprocessed_data: &[u8]) -> Self {
        let mut unprocessed_buf = allocate_vec(16384);
        let mut unprocessed_end_offset = 0;
        let write_cache = allocate_vec(65535).into_boxed_slice();
        let write_frame = allocate_vec(65535 + 40);

        let pending_initial_data = if unprocessed_data.len() > 0 {
            unprocessed_buf[0..unprocessed_data.len()].copy_from_slice(unprocessed_data);
            unprocessed_end_offset = unprocessed_data.len();
            true
        } else {
            false
        };

        Self {
            stream,
            is_client,
            pending_initial_data,
            read_state: ReadState::Init,
            read_frame_final: false,
            read_frame_masked: false,
            read_frame_opcode: OpCode::Unknown(99),
            read_frame_length: 0,
            read_frame_mask: [0u8; 4],
            read_frame_mask_offset: 0,
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset,
            write_cache,
            write_cache_size: 0,
            write_frame,
            write_frame_start_offset: 0,
            write_frame_end_offset: 0,
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

        // TODO: we don't check read_frame_final atm
        self.read_frame_final = first & 0x80 != 0;
        self.read_frame_masked = second & 0x80 != 0;

        // // if we're not the client, then we are reading from the client and we should only accept
        // // masked data.
        // if !self.is_client && !self.read_frame_masked {
        //     return Err(std::io::Error::new(
        //         std::io::ErrorKind::Other,
        //         "client frame was not masked",
        //     ));
        // }

        self.read_frame_opcode = OpCode::from(first & 0x0f);

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
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Invalid frame length ({})", self.read_frame_length),
            ));
        }

        if self.read_frame_length > 65535 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Frame length is too large ({})", self.read_frame_length),
            ));
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
        self.unprocessed_start_offset += 4;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                mask_bytes.as_ptr(),
                self.read_frame_mask.as_mut_ptr(),
                4,
            );
        }
        self.step_check_content(cx, buf)
    }

    fn step_check_content(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::io::Result<()> {
        if self.read_frame_length == 0 {
            self.read_state = ReadState::Init;
            self.step_init(cx, buf)
        } else if self.read_frame_opcode != OpCode::Continue
            && self.read_frame_opcode != OpCode::Binary
        {
            self.read_state = ReadState::SkipContent;
            self.step_skip_content(cx, buf)
        } else {
            self.read_state = ReadState::ReadContent;
            self.step_read_content(cx, buf)
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
            self.read_frame_length -= skip_amount;
            if self.read_frame_length > 0 {
                return Ok(());
            }
        }

        self.read_state = ReadState::Init;
        self.step_init(cx, buf)
    }

    fn step_read_content(
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

    fn create_write_frame(&mut self) {
        // 0x80 is final, 0x02 is binary
        self.write_frame[0] = 0x80 | 0x02;

        let mut header_size = if self.write_cache_size < 126 {
            self.write_frame[1] = self.write_cache_size as u8;
            2
        } else if self.write_cache_size <= 65535 {
            self.write_frame[1] = 0x7e;
            self.write_frame[2] = (self.write_cache_size >> 8) as u8;
            self.write_frame[3] = (self.write_cache_size & 0xff) as u8;
            4
        } else {
            self.write_frame[1] = 0x7f;
            self.write_frame[2] = (self.write_cache_size >> 56) as u8;
            self.write_frame[3] = ((self.write_cache_size >> 48) & 0xff) as u8;
            self.write_frame[4] = ((self.write_cache_size >> 40) & 0xff) as u8;
            self.write_frame[5] = ((self.write_cache_size >> 32) & 0xff) as u8;
            self.write_frame[6] = ((self.write_cache_size >> 24) & 0xff) as u8;
            self.write_frame[7] = ((self.write_cache_size >> 16) & 0xff) as u8;
            self.write_frame[8] = ((self.write_cache_size >> 8) & 0xff) as u8;
            self.write_frame[9] = (self.write_cache_size & 0xff) as u8;
            10
        };

        // Client must be masked, but optional for server.
        let mask = if self.is_client {
            // set the masking bit
            self.write_frame[1] |= 0x80;

            let mut mask_bytes = [0u8; 4];
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut mask_bytes);

            self.write_frame[header_size] = mask_bytes[0];
            self.write_frame[header_size + 1] = mask_bytes[1];
            self.write_frame[header_size + 2] = mask_bytes[2];
            self.write_frame[header_size + 3] = mask_bytes[3];
            header_size += 4;

            Some(mask_bytes)
        } else {
            None
        };
        self.write_frame_start_offset = 0;
        self.write_frame_end_offset = header_size + self.write_cache_size;

        if self.write_frame.len() < self.write_frame_end_offset {
            resize_vec(&mut self.write_frame, self.write_frame_end_offset);
        }

        if let Some(mask_bytes) = mask {
            let iter = self.write_cache[0..self.write_cache_size]
                .iter_mut()
                .zip(mask_bytes.iter().cycle());
            for (byte, &key) in iter {
                *byte ^= key
            }
        }

        self.write_frame[header_size..self.write_frame_end_offset]
            .copy_from_slice(&self.write_cache[0..self.write_cache_size]);
        self.write_cache_size = 0;
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
}

impl AsyncRead for WebsocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // It's possible that we have unprocessed data that didn't get read yet, because
        // for example, buf had less space than unprocessed_buf had data.
        if this.unprocessed_end_offset > 0 && this.read_state == ReadState::ReadContent {
            let read_result = this.step_read_content(cx, buf);
            if read_result.is_err() {
                return Poll::Ready(read_result);
            }
            if buf.filled().len() > 0 {
                return Poll::Ready(Ok(()));
            }
        }

        loop {
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
                    // We should only have to resize if we get a huge data packet that's
                    // larger than our buffer size.
                    // TODO: is this even possible?
                    if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                        resize_vec(&mut this.unprocessed_buf, this.unprocessed_end_offset * 2);
                    }
                }
                Poll::Pending => {
                    if this.pending_initial_data {
                        // Don't return immediately, we need to read the pending data in the
                        // unprocessed buf.
                        this.pending_initial_data = false;
                    } else {
                        return Poll::Pending;
                    }
                }
            }

            let read_result = match this.read_state {
                ReadState::Init => this.step_init(cx, buf),
                ReadState::ReadLength { length_bytes_len } => {
                    this.step_read_length(cx, buf, length_bytes_len)
                }
                ReadState::ReadMask => this.step_read_mask(cx, buf),
                ReadState::SkipContent => this.step_skip_content(cx, buf),
                ReadState::ReadContent => this.step_read_content(cx, buf),
            };

            if read_result.is_err() {
                return Poll::Ready(read_result);
            }

            if buf.filled().len() > 0 {
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

        if this.write_frame_end_offset > 0 {
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

        let mut cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);
        if this.write_cache_size >= WRITE_CACHE_CREATE_FRAME_THRESHOLD || cache_space == 0 {
            this.create_write_frame();
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
            cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);
            if cache_space == 0 {
                panic!("no cache space.");
            }
        }

        let write_count = std::cmp::min(cache_space, buf.len());

        this.write_cache[this.write_cache_size..this.write_cache_size + write_count]
            .copy_from_slice(&buf[0..write_count]);
        this.write_cache_size += write_count;

        Poll::Ready(Ok(write_count))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Create a new write frame when flush is called when we don't have one.
        while this.write_cache_size > 0 || this.write_frame_end_offset > 0 {
            if this.write_frame_end_offset == 0 {
                this.create_write_frame();
            }
            if let Err(e) = this.do_write_frame(cx) {
                return Poll::Ready(Err(e));
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[async_trait]
impl AsyncStream for WebsocketStream {}
