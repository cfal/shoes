use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::ready;
use rand::RngCore;
use ring::aead::{Aad, OpeningKey, SealingKey};
use sha3::digest::XofReader;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::nonce::VmessNonceSequence;
use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

const TAG_LEN: usize = 16;

// although the dev docs say that the max data segment is 2^14, it seems like
// many clients send more. so allow the largest value that can be filled.
const MAX_ENCRYPTED_DATA_SIZE: usize = u16::MAX as usize;

const MAX_PACKET_SIZE: usize = 2 + MAX_ENCRYPTED_DATA_SIZE;

const MAX_PADDING_LEN: usize = 64;

const MAX_UNENCRYPTED_DATA_SIZE: usize = MAX_ENCRYPTED_DATA_SIZE - TAG_LEN;

// if the write cache gets to this size, we'll make a packet and write it out
// first.
const WRITE_CACHE_PACKETIZE_THRESHOLD: usize = 4096;

struct LengthMask {
    reader: digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
    mask: [u8; 2],
    enable_padding: bool,
}

impl LengthMask {
    fn new(
        reader: digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
        enable_padding: bool,
    ) -> Self {
        Self {
            reader,
            mask: [0u8; 2],
            enable_padding,
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.reader.read(&mut self.mask);
        ((self.mask[0] as u16) << 8) | (self.mask[1] as u16)
    }

    fn next_values(&mut self) -> (usize, u16) {
        // returns the next padding and length mask
        let padding = if self.enable_padding {
            (self.next_u16() % (MAX_PADDING_LEN as u16)) as usize
        } else {
            0
        };

        (padding, self.next_u16())
    }
}

enum ShutdownState {
    WriteRemainingData,
    CreateEmptyPacket,
    WriteEmptyPacket,
    PollShutdown,
}

pub struct VmessStream {
    stream: Box<dyn AsyncStream>,
    opening_key: OpeningKey<VmessNonceSequence>,
    sealing_key: SealingKey<VmessNonceSequence>,
    read_length_mask: Option<LengthMask>,
    write_length_mask: Option<LengthMask>,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,
    unprocessed_pending_len: Option<(usize, usize)>,

    processed_buf: Box<[u8]>,
    processed_start_offset: usize,
    processed_end_offset: usize,

    write_cache: Box<[u8]>,
    write_cache_size: usize,

    write_packet: Box<[u8]>,
    write_packet_start_offset: usize,
    write_packet_end_offset: usize,

    shutdown_state: ShutdownState,
    is_eof: bool,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
    ReceivedEof,
}

impl VmessStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        opening_key: OpeningKey<VmessNonceSequence>,
        sealing_key: SealingKey<VmessNonceSequence>,
        read_length_shake_reader: Option<
            digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
        >,
        write_length_shake_reader: Option<
            digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
        >,
        enable_global_padding: bool,
    ) -> Self {
        let unprocessed_buf = allocate_vec(MAX_PACKET_SIZE).into_boxed_slice();
        let processed_buf = allocate_vec(MAX_UNENCRYPTED_DATA_SIZE).into_boxed_slice();
        let write_cache =
            allocate_vec(MAX_UNENCRYPTED_DATA_SIZE - MAX_PADDING_LEN).into_boxed_slice();
        let write_packet = allocate_vec(MAX_PACKET_SIZE).into_boxed_slice();

        Self {
            stream,
            opening_key,
            sealing_key,
            read_length_mask: read_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            write_length_mask: write_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,
            write_cache,
            write_cache_size: 0,
            write_packet,
            write_packet_start_offset: 0,
            write_packet_end_offset: 0,
            shutdown_state: ShutdownState::WriteRemainingData,
            is_eof: false,
        }
    }

    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        // returns true if a full packet was decrypted, false if not (ie. more data required)
        let available_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let (padding_len, data_len) = match self.unprocessed_pending_len {
            None => {
                if available_len < 2 {
                    return Ok(DecryptState::NeedData);
                }

                let length_bytes = &mut self.unprocessed_buf
                    [self.unprocessed_start_offset..self.unprocessed_start_offset + 2];

                let mut data_len = ((length_bytes[0] as u16) << 8) | (length_bytes[1] as u16);

                let padding_len = match self.read_length_mask {
                    Some(ref mut mask) => {
                        let (padding_len, length_mask) = mask.next_values();
                        data_len ^= length_mask;
                        padding_len
                    }
                    None => 0,
                };

                let data_len = data_len as usize;

                if data_len > 0x4000 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "data length larger than 2^14",
                    ));
                }

                if data_len - padding_len < TAG_LEN {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "data length ({}) is smaller than tag length ({})",
                            data_len, TAG_LEN
                        ),
                    ));
                }

                if data_len - padding_len == TAG_LEN {
                    // TODO: should we bother to decrypt the eof packet?
                    return Ok(DecryptState::ReceivedEof);
                }

                self.unprocessed_start_offset += 2;

                if available_len - 2 < data_len {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - TAG_LEN;
                if self.processed_end_offset + processed_data_len >= self.processed_buf.len() {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::BufferFull);
                }

                (padding_len, data_len)
            }

            Some((padding_len, data_len)) => {
                if available_len < data_len {
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - TAG_LEN;
                if self.processed_end_offset + processed_data_len >= self.processed_buf.len() {
                    return Ok(DecryptState::BufferFull);
                }

                self.unprocessed_pending_len = None;
                (padding_len, data_len)
            }
        };

        if self
            .opening_key
            .open_in_place(
                Aad::empty(),
                &mut self.unprocessed_buf[self.unprocessed_start_offset
                    ..self.unprocessed_start_offset + data_len - padding_len],
            )
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "open failed for data",
            ));
        }

        let processed_data_len = data_len - padding_len - TAG_LEN;
        self.processed_buf
            [self.processed_end_offset..self.processed_end_offset + processed_data_len]
            .copy_from_slice(
                &self.unprocessed_buf[self.unprocessed_start_offset
                    ..self.unprocessed_start_offset + processed_data_len],
            );

        self.processed_end_offset += processed_data_len;
        self.unprocessed_start_offset += data_len;

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        Ok(DecryptState::Success)
    }

    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) -> () {
        assert!(
            self.processed_end_offset > 0,
            "called without any processed data"
        );

        let available_len = self.processed_end_offset - self.processed_start_offset;

        let unfilled_len = buf.remaining();

        let write_amount = std::cmp::min(unfilled_len, available_len);
        assert!(
            write_amount > 0,
            "no data to write (available_len = {}, unfilled_len = {})",
            available_len,
            unfilled_len,
        );

        buf.put_slice(
            &self.processed_buf
                [self.processed_start_offset..self.processed_start_offset + write_amount],
        );

        let new_processed_start_offset = self.processed_start_offset + write_amount;
        if new_processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    fn create_write_packet(&mut self) {
        // note that this should allow creating an empty packet.

        let (padding_len, length_mask) = match self.write_length_mask {
            Some(ref mut mask) => mask.next_values(),
            None => (0, 0),
        };

        // write packet buffer size must be able to store all the data in the write cache.
        let write_packet_size: usize = self.write_cache_size + padding_len + TAG_LEN;
        assert!(write_packet_size + 2 <= self.write_packet.len());

        let write_packet_size = (write_packet_size as u16) ^ length_mask;
        self.write_packet[0] = (write_packet_size >> 8) as u8;
        self.write_packet[1] = (write_packet_size & 0xff) as u8;

        let mut next_index = 2;
        self.write_packet[next_index..next_index + self.write_cache_size]
            .copy_from_slice(&self.write_cache[0..self.write_cache_size]);
        // TODO: don't unwrap here.
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut self.write_packet[next_index..next_index + self.write_cache_size],
            )
            .unwrap();
        next_index += self.write_cache_size;

        self.write_packet[next_index..next_index + TAG_LEN].copy_from_slice(tag.as_ref());
        next_index += TAG_LEN;

        if padding_len > 0 {
            rand::thread_rng()
                .fill_bytes(&mut self.write_packet[next_index..next_index + padding_len]);
            next_index += padding_len;
        }

        self.write_packet_start_offset = 0;
        self.write_packet_end_offset = next_index;
        self.write_cache_size = 0;
    }

    fn do_write_packet(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        // returns true when everything is written.
        loop {
            let remaining_data =
                &self.write_packet[self.write_packet_start_offset..self.write_packet_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        // eof, TODO fix
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write packet eof",
                        ));
                    }
                    self.write_packet_start_offset += written;
                    if self.write_packet_start_offset == self.write_packet_end_offset {
                        self.write_packet_start_offset = 0;
                        self.write_packet_end_offset = 0;
                        return Ok(true);
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    return Ok(false);
                }
            }
        }
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

impl AsyncRead for VmessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        } else if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                // if we got here, there's no data in processed buf, and we don't have
                // space in unprocessed buf to read more to decrypt.
                // since we know we have enough space for 1 full-sized packet,
                // this must be because start offset has moved forward too much.
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;

            let len = read_buf.filled().len();

            // Make sure we have enough space to store the processed data.
            if len == 0 {
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
                if this.processed_end_offset > 0 {
                    // TODO: I don't think we ever hit this clause.
                    // The only time we read is when processed_end_offset is 0.
                    this.read_processed(buf);
                }
                return Poll::Ready(Ok(()));
            }

            this.unprocessed_end_offset += len;

            // Process some data to free up unprocessed_buf space.
            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => {
                        continue;
                    }
                }
            }

            if this.processed_end_offset > 0 {
                // Return the data we just got.
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.write_packet_end_offset > 0 {
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }

        let mut cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);
        if this.write_cache_size >= WRITE_CACHE_PACKETIZE_THRESHOLD || cache_space == 0 {
            this.create_write_packet();
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);
            assert!(cache_space > 0);
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

        if this.write_cache_size == 0 && this.write_packet_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        // Create a new write frame when flush is called when we don't have one.
        while this.write_cache_size > 0 || this.write_packet_end_offset > 0 {
            if this.write_packet_end_offset == 0 {
                this.create_write_packet();
            }
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
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
        let mut this = self.get_mut();

        loop {
            match this.shutdown_state {
                ShutdownState::WriteRemainingData => {
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                    this.shutdown_state = ShutdownState::CreateEmptyPacket;
                }
                ShutdownState::CreateEmptyPacket => {
                    assert!(this.write_cache_size == 0 && this.write_packet_end_offset == 0);
                    this.create_write_packet();
                    this.shutdown_state = ShutdownState::WriteEmptyPacket;
                }
                ShutdownState::WriteEmptyPacket => {
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                    this.shutdown_state = ShutdownState::PollShutdown;
                }
                ShutdownState::PollShutdown => {
                    ready!(Pin::new(&mut this.stream).poll_shutdown(cx))?;
                    break;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl AsyncStream for VmessStream {}
