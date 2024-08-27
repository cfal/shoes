use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use futures::ready;
use parking_lot::Mutex;
use rand::RngCore;
use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, NONCE_LEN,
};
use ring::error::Unspecified;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead_util::TAG_LEN;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream_type::ShadowsocksStreamType;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::salt_checker::SaltChecker;
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
    stream: Box<dyn AsyncStream>,

    stream_type: ShadowsocksStreamType,
    algorithm: &'static Algorithm,
    salt_len: usize,
    key: Arc<Box<dyn ShadowsocksKey>>,
    salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    encrypt_iv: Box<[u8]>,
    decrypt_iv: Option<Box<[u8]>>,

    sealing_key: SealingKey<IncreasingSequence>,
    opening_key: Option<OpeningKey<IncreasingSequence>>,

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

    is_initial_read: bool,
    is_initial_write: bool,
    is_eof: bool,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
}

const METADATA_SIZE: usize = 2 + (2 * TAG_LEN);

impl ShadowsocksStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        stream_type: ShadowsocksStreamType,
        algorithm: &'static Algorithm,
        salt_len: usize,
        key: Arc<Box<dyn ShadowsocksKey>>,
        salt_checker: Option<Arc<Mutex<dyn SaltChecker>>>,
    ) -> Self {
        let max_payload_len = stream_type.max_payload_len();
        let max_packet_len = max_payload_len + METADATA_SIZE;

        // Be able to store a full packet.
        let unprocessed_buf = allocate_vec(max_packet_len).into_boxed_slice();
        // Be able to store a full payload.
        let processed_buf = allocate_vec(max_payload_len).into_boxed_slice();
        // Set the write cache to exactly the size of 1 full packet.
        let write_cache = allocate_vec(max_packet_len).into_boxed_slice();

        let mut encrypt_iv = allocate_vec(salt_len).into_boxed_slice();
        generate_iv(&mut encrypt_iv);

        let session_key = key.create_session_key(&encrypt_iv);
        let unbound_key = UnboundKey::new(algorithm, &session_key).unwrap();
        let sealing_key = SealingKey::new(unbound_key, IncreasingSequence::new());

        Self {
            stream,

            stream_type,
            algorithm,
            salt_len,
            key,
            salt_checker,
            encrypt_iv,
            // Needed for AEAD2022 server response.
            decrypt_iv: None,

            sealing_key,
            opening_key: None,

            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,

            write_cache,
            write_cache_start_offset: 0,
            write_cache_end_offset: 0,

            is_initial_read: true,
            is_initial_write: true,
            is_eof: false,
        }
    }

    fn process_opening_key(&mut self) -> std::io::Result<()> {
        let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
        let session_key = self.key.create_session_key(&decrypt_iv);
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
                if data_len_no_tag > self.stream_type.max_payload_len() {
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

    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) {
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

    fn encrypt_single(
        &mut self,
        input: &[u8],
        write_length_header: bool,
    ) -> std::result::Result<(), Unspecified> {
        let output = &mut self.write_cache[self.write_cache_end_offset..];
        let input_len = input.len();

        let mut written = if write_length_header {
            output[0] = (input_len >> 8) as u8;
            output[1] = (input_len & 0xff) as u8;

            let tag = self
                .sealing_key
                .seal_in_place_separate_tag(Aad::empty(), &mut output[0..2])?;

            output[2..2 + TAG_LEN].copy_from_slice(&tag.as_ref()[0..TAG_LEN]);

            2 + TAG_LEN
        } else {
            0
        };

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

    fn read_header_len(&self) -> usize {
        match self.stream_type {
            ShadowsocksStreamType::AEAD => self.salt_len,
            ShadowsocksStreamType::AEAD2022Server => {
                // Expect the encrypted client (request) header
                // salt (salt_len) + encrypted packet [type (1) + timestamp (8) + length (2)] + tag (TAG_LEN)
                self.salt_len + 11 + TAG_LEN
            }
            ShadowsocksStreamType::AEAD2022Client => {
                // Expect the server (response) header
                // salt (salt_len) + encrypted packet [type (1) + timestamp (8) + salt (salt_len) + length (2)] + tag (TAG_LEN)
                self.salt_len + 11 + self.salt_len + TAG_LEN
            }
        }
    }

    fn process_read_header(&mut self) -> std::io::Result<()> {
        match self.stream_type {
            ShadowsocksStreamType::AEAD => {
                if let Some(salt_checker) = &self.salt_checker {
                    let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                    if !salt_checker.lock().insert_and_check(&decrypt_iv) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "got duplicate salt",
                        ));
                    }
                }
                self.process_opening_key()?;
                self.unprocessed_start_offset += self.salt_len;
            }
            ShadowsocksStreamType::AEAD2022Server => {
                self.process_opening_key()?;

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        Aad::empty(),
                        &mut self.unprocessed_buf[self.salt_len..self.salt_len + 11 + TAG_LEN],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for fixed length request header",
                    ));
                }

                if self.unprocessed_buf[self.salt_len] != 0 {
                    // HeaderTypeClientStream = 0
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid client header type, got {}",
                            self.unprocessed_buf[self.salt_len]
                        ),
                    ));
                }

                let timestamp_bytes = &self.unprocessed_buf[self.salt_len + 1..self.salt_len + 9];
                let timestamp_secs = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
                let current_time_secs = current_time_secs();
                if current_time_secs >= timestamp_secs {
                    if current_time_secs - timestamp_secs > 30 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "timestamp is greater than 30 seconds",
                        ));
                    }
                } else {
                    // Make sure times aren't too far in the future.
                    if timestamp_secs - current_time_secs > 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "timestamp is {} seconds in the future",
                                timestamp_secs - current_time_secs
                            ),
                        ));
                    }
                }

                let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                if let Some(salt_checker) = &self.salt_checker {
                    if !salt_checker.lock().insert_and_check(&decrypt_iv) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "got duplicate salt",
                        ));
                    }
                }

                // Needed for writing the response
                self.decrypt_iv = Some(decrypt_iv.to_vec().into_boxed_slice());

                let variable_header_len = ((self.unprocessed_buf[self.salt_len + 9] as usize) << 8)
                    | (self.unprocessed_buf[self.salt_len + 10] as usize);

                self.unprocessed_pending_len = Some(variable_header_len);

                self.unprocessed_start_offset += self.salt_len + 11 + TAG_LEN;
            }
            ShadowsocksStreamType::AEAD2022Client => {
                self.process_opening_key()?;

                if self
                    .opening_key
                    .as_mut()
                    .unwrap()
                    .open_in_place(
                        Aad::empty(),
                        &mut self.unprocessed_buf
                            [self.salt_len..self.salt_len + 11 + self.salt_len + TAG_LEN],
                    )
                    .is_err()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "open failed for fixed length request header",
                    ));
                }

                if self.unprocessed_buf[self.salt_len] != 1 {
                    // HeaderTypeServerStream = 1
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "invalid server header type, got {}",
                            self.unprocessed_buf[self.salt_len]
                        ),
                    ));
                }

                let timestamp_bytes = &self.unprocessed_buf[self.salt_len + 1..self.salt_len + 9];
                let timestamp_secs = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
                let current_time_secs = current_time_secs();
                if current_time_secs >= timestamp_secs {
                    if current_time_secs - timestamp_secs > 30 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "timestamp is greater than 30 seconds",
                        ));
                    }
                } else {
                    // Make sure times aren't too far in the future.
                    if timestamp_secs - current_time_secs > 2 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "timestamp is {} seconds in the future",
                                timestamp_secs - current_time_secs
                            ),
                        ));
                    }
                }

                if let Some(salt_checker) = &self.salt_checker {
                    let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                    if !salt_checker.lock().insert_and_check(&decrypt_iv) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "got duplicate salt",
                        ));
                    }
                }

                let request_salt =
                    &self.unprocessed_buf[self.salt_len + 9..self.salt_len + 9 + self.salt_len];

                for (a, b) in request_salt.iter().zip(self.encrypt_iv.iter()) {
                    if a != b {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "server returned request salt does not match",
                        ));
                    }
                }

                let first_chunk_len =
                    ((self.unprocessed_buf[self.salt_len + 9 + self.salt_len] as usize) << 8)
                        | (self.unprocessed_buf[self.salt_len + 9 + self.salt_len + 1] as usize);

                self.unprocessed_pending_len = Some(first_chunk_len);

                self.unprocessed_start_offset = self.salt_len + 11 + self.salt_len + TAG_LEN;
            }
        }

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        Ok(())
    }

    fn process_write_header(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.stream_type {
            ShadowsocksStreamType::AEAD => {
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let handled_len = std::cmp::min(
                    buf.len(),
                    self.write_cache.len() - self.write_cache_end_offset - METADATA_SIZE,
                );
                assert!(handled_len > 0);

                self.encrypt_single(&buf[0..handled_len], true)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "failed to encrypt initial packet",
                        )
                    })?;

                Ok(handled_len)
            }
            ShadowsocksStreamType::AEAD2022Server => {
                assert!(!self.is_initial_read);

                let decrypt_iv = self.decrypt_iv.take().unwrap();

                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let mut response_header = allocate_vec(1 + 8 + self.salt_len + 2);

                // HeaderTypeServerStream = 1
                response_header[0] = 1;
                response_header[1..9].copy_from_slice(&current_time_secs().to_be_bytes());
                response_header[9..9 + self.salt_len].copy_from_slice(&decrypt_iv);

                let handled_len = std::cmp::min(
                    buf.len(),
                    // subtract TAG_LEN and not METADATA_SIZE because we don't need the length header + tag.
                    self.write_cache.len()
                        - self.salt_len
                        - (response_header.len() + TAG_LEN)
                        - TAG_LEN,
                );

                response_header[9 + self.salt_len] = (handled_len >> 8) as u8;
                response_header[9 + self.salt_len + 1] = (handled_len & 0xff) as u8;

                self.encrypt_single(&response_header, false).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to encrypt response header",
                    )
                })?;

                self.encrypt_single(&buf[0..handled_len], false)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "failed to encrypt initial server packet",
                        )
                    })?;

                Ok(handled_len)
            }
            ShadowsocksStreamType::AEAD2022Client => {
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let mut request_header = allocate_vec(1 + 8 + 2);

                // HeaderTypeClientStream = 0
                request_header[0] = 0;
                request_header[1..9].copy_from_slice(&current_time_secs().to_be_bytes());

                // This is a bit hacky. We expect/know that the first packet will be the "variable-length header"
                // with the address and padding, and we need to send it all off in a single packet.
                let buf_len = buf.len();
                assert!(
                    buf_len
                        <= self.write_cache.len()
                        - self.salt_len
                        - (request_header.len() + TAG_LEN)
                        - TAG_LEN
                );

                request_header[9] = (buf_len >> 8) as u8;
                request_header[10] = (buf_len & 0xff) as u8;

                self.encrypt_single(&request_header, false).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to encrypt response header",
                    )
                })?;

                self.encrypt_single(buf, false).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "failed to encrypt initial client packet",
                    )
                })?;

                Ok(buf_len)
            }
        }
    }

    fn poll_read_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        fill_buffer: bool,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.is_initial_read && !this.is_eof {
            loop {
                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.unprocessed_end_offset += len;
                if this.unprocessed_end_offset >= this.read_header_len() {
                    break;
                }
            }

            this.process_read_header()?;
            this.is_initial_read = false;
        }

        loop {
            if this.unprocessed_end_offset > 0 {
                // Process some data to free up unprocessed_buf space.
                loop {
                    match this.try_decrypt()? {
                        DecryptState::NeedData => {
                            break;
                        }
                        DecryptState::BufferFull => {
                            assert!(this.processed_end_offset > 0);
                            break;
                        }
                        DecryptState::Success => {
                            if !fill_buffer && this.processed_end_offset > 0 {
                                break;
                            }
                            continue;
                        }
                    }
                }
            }

            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                // if we got here, there's no data in processed buf, and we don't have
                // space in unprocessed buf to read more to decrypt.
                // since we know we have enough space for 1 full-sized packet,
                // this must be because start offset has moved forward too much.
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            if this.processed_end_offset > 0 {
                // Return the data we just got.
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }

            if this.is_eof {
                return Poll::Ready(Ok(()));
            }

            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;

            let len = read_buf.filled().len();

            // Make sure we have enough space to store the processed data.
            if len == 0 {
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
            } else {
                this.unprocessed_end_offset += len;
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_read_inner(cx, buf, true)
    }
}

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // TODO: This might not be optimal because we always immediately packetize `buf`, should we
        // do something smarter?
        let this = self.get_mut();

        if this.is_initial_write {
            let handled_len = this.process_write_header(buf)?;
            assert!(handled_len > 0 && this.write_cache_end_offset > 0);
            this.is_initial_write = false;

            if let Err(e) = this.do_write_cache(cx) {
                return Poll::Ready(Err(e));
            }

            return Poll::Ready(Ok(handled_len));
        }

        let mut write_cache_space = this.write_cache.len() - this.write_cache_end_offset;

        if write_cache_space <= METADATA_SIZE {
            match this.do_write_cache(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            };
            // if we got here, then everything was written.
            assert!(this.write_cache_start_offset == 0 && this.write_cache_end_offset == 0);
            write_cache_space = this.write_cache.len();
        }

        let max_write_cache_data_size = write_cache_space - METADATA_SIZE;
        let packet_data_size = std::cmp::min(
            std::cmp::min(buf.len(), max_write_cache_data_size),
            this.stream_type.max_payload_len(),
        );
        this.encrypt_single(&buf[0..packet_data_size], true)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "failed to encrypt packet")
            })?;

        if let Err(e) = this.do_write_cache(cx) {
            return Poll::Ready(Err(e));
        }

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

impl AsyncReadMessage for ShadowsocksStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_read_inner(cx, buf, false)
    }
}

impl AsyncWriteMessage for ShadowsocksStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.is_initial_write {
            let handled_len = this.process_write_header(buf)?;
            assert!(handled_len == buf.len());
            this.is_initial_write = false;
            return Poll::Ready(Ok(()));
        }

        let write_cache_space = this.write_cache.len() - this.write_cache_end_offset;
        let packet_size = buf.len() + METADATA_SIZE;
        assert!(packet_size <= this.write_cache.len());

        if packet_size > write_cache_space {
            return Poll::Pending;
        }

        this.encrypt_single(buf, true).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "failed to encrypt packet")
        })?;

        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for ShadowsocksStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncFlushMessage for ShadowsocksStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncShutdownMessage for ShadowsocksStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_shutdown(cx)
    }
}

impl AsyncStream for ShadowsocksStream {}
impl AsyncMessageStream for ShadowsocksStream {}

#[inline]
fn current_time_secs() -> u64 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
}
