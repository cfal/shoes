use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::ready;
use rand::RngCore;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead_util::{create_session_key, TAG_LEN};
use crate::async_stream::AsyncStream;
use crate::util::allocate_vec;

fn generate_iv(buf: &mut [u8]) {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(buf);
}

pub struct IncreasingSequence([u8; NONCE_LEN]);

impl IncreasingSequence {
    fn new() -> IncreasingSequence {
        IncreasingSequence([0u8; NONCE_LEN])
    }
}

impl NonceSequence for IncreasingSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let ret = Nonce::assume_unique_for_key(self.0);
        for i in self.0.iter_mut() {
            *i = i.wrapping_add(1);
            if *i > 0 {
                break;
            }
        }
        Ok(ret)
    }
}

pub struct ShadowsocksStream {
    algorithm: &'static Algorithm,
    stream: Box<dyn AsyncStream>,
    key: Box<[u8]>,
    sealing_key: SealingKey<IncreasingSequence>,
    opening_key: Option<OpeningKey<IncreasingSequence>>,
    salt_len: usize,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,
    unprocessed_pending_len: Option<usize>,
    processed_buf: Box<[u8]>,
    processed_start_offset: usize,
    processed_end_offset: usize,

    write_cache: Box<[u8]>,
    write_cache_start_offset: usize,
    write_cache_end_offset: usize,

    is_eof: bool,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
}

// from https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
// [encrypted payload length][length tag][encrypted payload][payload tag]
// = (2 + 16) + (0x3fff (at most) + 16)
// = 16417
// which means a full single packet can use at most 16417 bytes.
const MAX_DATA_SEGMENT_SIZE: usize = 0x3fff;
const METADATA_SIZE: usize = 2 + (2 * TAG_LEN);
const MAX_PACKET_SIZE: usize = MAX_DATA_SEGMENT_SIZE + METADATA_SIZE;

impl ShadowsocksStream {
    pub fn new(
        algorithm: &'static Algorithm,
        stream: Box<dyn AsyncStream>,
        key: &[u8],
        salt_len: usize,
    ) -> Self {
        let unprocessed_buf = allocate_vec(MAX_PACKET_SIZE).into_boxed_slice();

        // The max processed data from one packet is 0x3fff = 16383, so set it to 2^14
        let processed_buf = allocate_vec(MAX_DATA_SEGMENT_SIZE).into_boxed_slice();

        // Set the write cache to exactly the size of 1 full packet.
        let mut write_cache = allocate_vec(MAX_PACKET_SIZE).into_boxed_slice();

        let mut encrypt_iv = &mut write_cache[0..salt_len];
        generate_iv(&mut encrypt_iv);
        let session_key = create_session_key(key, &encrypt_iv);
        let unbound_key = UnboundKey::new(algorithm, &session_key).unwrap();
        let sealing_key = SealingKey::new(unbound_key, IncreasingSequence::new());

        Self {
            algorithm,
            stream,
            key: key.to_vec().into_boxed_slice(),
            sealing_key,
            opening_key: None,
            salt_len,

            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,

            write_cache,
            write_cache_start_offset: 0,
            write_cache_end_offset: salt_len,

            is_eof: false,
        }
    }

    fn process_opening_key(&mut self) -> std::io::Result<()> {
        let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
        let session_key = create_session_key(&self.key, &decrypt_iv);
        let unbound_key = UnboundKey::new(self.algorithm, &session_key).unwrap();
        let opening_key = OpeningKey::new(unbound_key, IncreasingSequence::new());
        self.opening_key = Some(opening_key);
        Ok(())
    }

    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        // returns true if a full packet was decrypted, false if not (ie. more data required)

        let available_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        let pending_len = match self.unprocessed_pending_len {
            Some(len) => {
                if available_len < len + TAG_LEN {
                    return Ok(DecryptState::NeedData);
                }
                if self.processed_end_offset + len > self.processed_buf.len() {
                    return Ok(DecryptState::BufferFull);
                }
                self.unprocessed_pending_len = None;
                len
            }
            None => {
                let data_length_len = 2 + TAG_LEN;
                if available_len < data_length_len {
                    return Ok(DecryptState::NeedData);
                }

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        Aad::empty(),
                        &mut self.unprocessed_buf[self.unprocessed_start_offset
                            ..self.unprocessed_start_offset + data_length_len],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for length",
                    ));
                }

                let data_len_no_tag: usize =
                    ((self.unprocessed_buf[self.unprocessed_start_offset] as usize) << 8)
                        | (self.unprocessed_buf[self.unprocessed_start_offset + 1] as usize);

                // From https://shadowsocks.org/en/wiki/AEAD-Ciphers.html
                // "Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
                // The higher two bits are reserved and must be set to zero. Payload is
                // therefore limited to 16*1024 - 1 bytes."
                if data_len_no_tag > MAX_DATA_SEGMENT_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "data length larger than max allowed size",
                    ));
                }

                self.unprocessed_start_offset += data_length_len;

                if available_len - data_length_len < data_len_no_tag + TAG_LEN {
                    self.unprocessed_pending_len = Some(data_len_no_tag);
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::NeedData);
                }

                if self.processed_end_offset + data_len_no_tag > self.processed_buf.len() {
                    return Ok(DecryptState::BufferFull);
                }

                data_len_no_tag
            }
        };

        let pending_len_with_tag = pending_len + TAG_LEN;
        if self
            .opening_key
            .as_mut()
            .unwrap()
            .open_in_place(
                Aad::empty(),
                &mut self.unprocessed_buf[self.unprocessed_start_offset
                    ..self.unprocessed_start_offset + pending_len_with_tag],
            )
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "open failed for data",
            ));
        }

        self.processed_buf[self.processed_end_offset..self.processed_end_offset + pending_len]
            .copy_from_slice(
                &self.unprocessed_buf
                    [self.unprocessed_start_offset..self.unprocessed_start_offset + pending_len],
            );

        self.processed_end_offset += pending_len;
        self.unprocessed_start_offset += pending_len_with_tag;

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        // this previously returned a Result<usize> but then we can't tell if it's a
        // 0 sized packet ie. pending_len = 0
        // TODO: check if that's allowed in shadowsocks protocol
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

    fn encrypt_single(&mut self, input: &[u8]) -> std::result::Result<(), Unspecified> {
        let output = &mut self.write_cache[self.write_cache_end_offset..];

        let input_len = input.len();

        output[0] = (input_len >> 8) as u8;
        output[1] = (input_len & 0xff) as u8;

        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut output[0..2])?;

        output[2..2 + TAG_LEN].copy_from_slice(&tag.as_ref()[0..TAG_LEN]);

        let mut written = 2 + TAG_LEN;

        output[written..written + input_len].copy_from_slice(input);

        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut output[written..written + input_len])?;
        written += input_len;

        output[written..written + TAG_LEN].copy_from_slice(&tag.as_ref()[0..TAG_LEN]);

        written += TAG_LEN;

        self.write_cache_end_offset += written;

        Ok(())
    }

    #[inline]
    fn do_write_cache(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        loop {
            match Pin::new(&mut self.stream).poll_write(
                cx,
                &self.write_cache[self.write_cache_start_offset..self.write_cache_end_offset],
            ) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF while writing cached encrypted data",
                        ));
                    }
                    self.write_cache_start_offset += written;
                    if self.write_cache_start_offset == self.write_cache_end_offset {
                        self.write_cache_start_offset = 0;
                        self.write_cache_end_offset = 0;
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

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.opening_key.is_none() {
            loop {
                let mut read_buf = ReadBuf::new(
                    &mut this.unprocessed_buf[this.unprocessed_end_offset..this.salt_len],
                );
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.unprocessed_end_offset += len;
                if this.unprocessed_end_offset == this.salt_len {
                    break;
                }
            }
            this.process_opening_key()?;
            this.unprocessed_end_offset = 0;
        }

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

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        if this.write_cache_start_offset > 0 {
            // Previously, we didn't bother to actually write to the stream when cache space was 0
            // and returned Pending here, but then bidirectional copy would get stuck.
            // For now, try to write when no cache space is remaining.
            // If we don't want to write to stream, we need to configure the
            // context/waker to notify that writes are possible again after flush.
            match this.do_write_cache(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            // if we got here, then everything was written.
            assert!(this.write_cache_start_offset == 0 && this.write_cache_end_offset == 0);
        }

        let max_write_cache_data_size = this.write_cache.len() - METADATA_SIZE;
        let packet_data_size = std::cmp::min(
            std::cmp::min(buf.len(), max_write_cache_data_size),
            MAX_DATA_SEGMENT_SIZE,
        );
        this.encrypt_single(&buf[0..packet_data_size])
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "failed to encrypt packet")
            })?;
        Poll::Ready(Ok(packet_data_size))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_cache_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }
        while this.write_cache_end_offset > 0 {
            match this.do_write_cache(cx) {
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[async_trait]
impl AsyncStream for ShadowsocksStream {}
