use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use log::warn;
use rand::RngCore;
use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM};
use sha3::digest::XofReader;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::typed::Aes128CfbDec;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
// this should be the same as vmess_handler.rs TAG_LEN.
const HEADER_TAG_LEN: usize = 16;
const ENCRYPTION_TAG_LEN: usize = 16;
const MAX_PADDING_LEN: usize = 64;

// should be 2^14, but it's 2^14 - 1 due to a quantumult bug.
// ref: https://www.v2fly.org/en_US/developer/protocols/vmess.html#standard-format
const MAX_ENCRYPTED_WRITE_DATA_SIZE: usize = 2usize.pow(14) - 1;

// although the dev docs say that the max data segment is 2^14, seems like
// some clients (like surge pre-aead) send up to 65535 bytes in a packet.
// we need to be able to handle this much data, even if we always write
// at most MAX_ENCRYPTED_WRITE_DATA_SIZE in a packet.
const MAX_ENCRYPTED_READ_DATA_SIZE: usize = u16::MAX as usize;

const fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

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
    WriteEmptyPacket,
    PollShutdown,
}

pub struct VmessStream {
    stream: Box<dyn AsyncStream>,

    read_header_state: ReadHeaderState,
    read_header_info: Option<ReadHeaderInfo>,

    opening_key: Option<OpeningKey<VmessNonceSequence>>,
    sealing_key: Option<SealingKey<VmessNonceSequence>>,
    tag_len: usize,
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

// Expected VMess header response, when we're a client.
pub struct ReadHeaderInfo {
    pub is_aead: bool,
    pub response_header_key: [u8; 16],
    pub response_header_iv: [u8; 16],
    pub response_authentication_v: u8,
}

#[derive(PartialEq, Eq, Debug)]
enum ReadHeaderState {
    ReadAeadLength,
    ReadAeadContent(usize),
    ReadLegacyContent,
    Done,
}

fn check_header_response(
    response_header_bytes: &[u8],
    response_authentication_v: u8,
) -> std::io::Result<()> {
    if response_header_bytes[0] != response_authentication_v {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid response auth value, expected {}, got {}",
                response_authentication_v, response_header_bytes[0]
            ),
        ));
    }

    // ignore the option byte at response_header_bytes[1], since we don't do reuse of tcp
    // connections.
    if (response_header_bytes[2] & 0x01) == 0x01 {
        warn!("Ignoring unsupported server dynamic port instructions.");
    }

    Ok(())
}

impl VmessStream {
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_udp: bool,
        encryption_keys: Option<(
            OpeningKey<VmessNonceSequence>,
            SealingKey<VmessNonceSequence>,
        )>,
        read_length_shake_reader: Option<
            digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
        >,
        write_length_shake_reader: Option<
            digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>,
        >,
        enable_global_padding: bool,
        prefix_write_bytes: Option<Box<[u8]>>,
        read_header_info: Option<ReadHeaderInfo>,
    ) -> Self {
        let (tag_len, opening_key, sealing_key) = match encryption_keys {
            Some((opening_key, sealing_key)) => {
                (ENCRYPTION_TAG_LEN, Some(opening_key), Some(sealing_key))
            }
            None => (0, None, None),
        };

        let max_unencrypted_read_data_size = MAX_ENCRYPTED_READ_DATA_SIZE - tag_len;
        let max_unencrypted_write_data_size = MAX_ENCRYPTED_WRITE_DATA_SIZE - tag_len;

        const MAX_READ_PACKET_SIZE: usize = MAX_ENCRYPTED_READ_DATA_SIZE + 2;
        let unprocessed_buf = allocate_vec(MAX_READ_PACKET_SIZE).into_boxed_slice();
        let processed_buf = allocate_vec(max_unencrypted_read_data_size).into_boxed_slice();

        let (write_cache, mut write_packet) = if !is_udp {
            let write_cache = allocate_vec(max_unencrypted_write_data_size).into_boxed_slice();

            const MAX_WRITE_PACKET_SIZE: usize = MAX_ENCRYPTED_WRITE_DATA_SIZE + 2;

            // we need to be able to send a full packet, and the prefix (response) data all
            // at once. the response is relatively small, check vmess_handler.
            let write_packet = allocate_vec(MAX_WRITE_PACKET_SIZE + 40).into_boxed_slice();

            (write_cache, write_packet)
        } else {
            // write_message can be called with a full UDP message, which we need to handle,
            // i.e. packetize into multiple packets and store in write_packet.
            let write_cache = allocate_vec(65535).into_boxed_slice();

            let write_packet_size = 65535
                + (div_ceil(65535usize, max_unencrypted_write_data_size)
                    * (MAX_PADDING_LEN * ENCRYPTION_TAG_LEN));
            let write_packet = allocate_vec(write_packet_size + 40).into_boxed_slice();

            (write_cache, write_packet)
        };

        let write_packet_end_offset = match prefix_write_bytes {
            Some(buf) => {
                write_packet[0..buf.len()].copy_from_slice(&buf);
                buf.len()
            }
            None => 0,
        };

        let read_header_state = match read_header_info {
            Some(ref info) => {
                if info.is_aead {
                    ReadHeaderState::ReadAeadLength
                } else {
                    ReadHeaderState::ReadLegacyContent
                }
            }
            None => ReadHeaderState::Done,
        };

        Self {
            stream,
            read_header_state,
            read_header_info,
            opening_key,
            sealing_key,
            tag_len,
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
            write_packet_end_offset,
            shutdown_state: ShutdownState::WriteRemainingData,
            is_eof: false,
        }
    }

    fn process_read_header(&mut self) -> std::io::Result<()> {
        match self.read_header_state {
            ReadHeaderState::ReadAeadLength => self.process_read_header_aead_length(),
            ReadHeaderState::ReadAeadContent(content_len) => {
                self.process_read_header_aead_content(content_len)
            }
            ReadHeaderState::ReadLegacyContent => self.process_read_header_legacy_content(),
            ReadHeaderState::Done => {
                panic!("process_read_header called with Done state");
            }
        }
    }

    fn process_read_header_aead_length(&mut self) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset < 2 + HEADER_TAG_LEN {
            return Ok(());
        }

        let encrypted_response_header_length = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + 2 + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_length_aead_key =
            super::sha2::kdf(&response_header_key[..], &[b"AEAD Resp Header Len Key"]);
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header Len IV"]);

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header_length)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to open encrypted response header length",
            ));
        }

        let response_header_length =
            u16::from_be_bytes(encrypted_response_header_length[0..2].try_into().unwrap()) as usize;

        self.read_header_state = ReadHeaderState::ReadAeadContent(response_header_length);
        self.unprocessed_start_offset += 2 + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.process_read_header_aead_content(response_header_length)
    }

    fn process_read_header_aead_content(&mut self, content_len: usize) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset
            < content_len + HEADER_TAG_LEN
        {
            return Ok(());
        }

        let encrypted_response_header = &mut self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + content_len + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key[..], &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header IV"]);
        let unbound_key = UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header)
            .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to open encrypted response header",
            ));
        }

        let command_len = encrypted_response_header[3];
        if command_len > 0 {
            warn!("Ignoring unused command bytes from AEAD block");
        }

        self.read_header_state = ReadHeaderState::Done;
        self.unprocessed_start_offset += content_len + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        check_header_response(encrypted_response_header, *response_authentication_v)
    }

    fn process_read_header_legacy_content(&mut self) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset < 4 {
            return Ok(());
        }

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_bytes = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
        let response_cipher = Aes128CfbDec::new(
            (&response_header_key[..]).into(),
            (&response_header_iv[..]).into(),
        );
        response_cipher.decrypt(response_header_bytes);

        // do this here, because we would already have read/decrypted it in the aead clause.
        let command_len = response_header_bytes[3];
        if command_len > 0 {
            // if this becomes an issue, we should read the command bytes and ignore them.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "extra command bytes",
            ));
        }

        self.read_header_state = ReadHeaderState::Done;
        self.unprocessed_start_offset += 4;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        check_header_response(response_header_bytes, *response_authentication_v)
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

                if data_len > MAX_ENCRYPTED_READ_DATA_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "encrypted data length larger than {}",
                            MAX_ENCRYPTED_READ_DATA_SIZE
                        ),
                    ));
                }

                if self.tag_len > 0 && (data_len - padding_len) < self.tag_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "data length ({}) is smaller than tag length ({})",
                            data_len, self.tag_len
                        ),
                    ));
                }

                if data_len - padding_len == self.tag_len {
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

                let processed_data_len = data_len - padding_len - self.tag_len;
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

                let processed_data_len = data_len - padding_len - self.tag_len;
                if self.processed_end_offset + processed_data_len >= self.processed_buf.len() {
                    return Ok(DecryptState::BufferFull);
                }

                self.unprocessed_pending_len = None;
                (padding_len, data_len)
            }
        };

        if let Some(ref mut opening_key) = self.opening_key {
            if opening_key
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
        }

        let processed_data_len = data_len - padding_len - self.tag_len;
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

    fn create_write_packet(&mut self) -> bool {
        // note that this should allow creating an empty packet.
        let write_packet_space = self.write_packet.len() - self.write_packet_end_offset;
        let max_padding_len = if self.write_length_mask.is_some() {
            MAX_PADDING_LEN
        } else {
            0
        };

        let max_metadata_size = 2 + max_padding_len + self.tag_len;
        if max_metadata_size >= write_packet_space {
            return false;
        }

        // TODO: allow peeking so that we don't need to use MAX_PADDING_LEN above.
        let (padding_len, length_mask) = match self.write_length_mask {
            Some(ref mut mask) => mask.next_values(),
            None => (0, 0),
        };

        let metadata_size = 2 + padding_len + self.tag_len;
        let max_data_size = std::cmp::min(
            write_packet_space - metadata_size,
            MAX_ENCRYPTED_WRITE_DATA_SIZE - padding_len - self.tag_len,
        );
        let data_size = std::cmp::min(max_data_size, self.write_cache_size);

        let write_packet_size: usize = data_size + padding_len + self.tag_len;
        assert!(write_packet_size + 2 <= self.write_packet.len());

        let mut next_index = self.write_packet_end_offset;

        let write_packet_size = (write_packet_size as u16) ^ length_mask;
        self.write_packet[next_index] = (write_packet_size >> 8) as u8;
        self.write_packet[next_index + 1] = (write_packet_size & 0xff) as u8;

        next_index += 2;
        self.write_packet[next_index..next_index + data_size]
            .copy_from_slice(&self.write_cache[0..data_size]);

        match self.sealing_key {
            Some(ref mut sealing_key) => {
                // TODO: don't unwrap here.
                let tag = sealing_key
                    .seal_in_place_separate_tag(
                        Aad::empty(),
                        &mut self.write_packet[next_index..next_index + data_size],
                    )
                    .unwrap();
                next_index += data_size;

                self.write_packet[next_index..next_index + self.tag_len]
                    .copy_from_slice(tag.as_ref());
                next_index += self.tag_len;
            }
            None => {
                next_index += data_size;
            }
        }

        if padding_len > 0 {
            rand::thread_rng()
                .fill_bytes(&mut self.write_packet[next_index..next_index + padding_len]);
            next_index += padding_len;
        }

        self.write_packet_end_offset = next_index;

        // TODO: keep track of start/stop offset instead?
        if data_size == self.write_cache_size {
            self.write_cache_size = 0;
        } else {
            self.write_cache
                .copy_within(data_size..self.write_cache_size, 0);
            self.write_cache_size -= data_size;
        }

        true
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

        if this.read_header_state != ReadHeaderState::Done && !this.is_eof {
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
                this.process_read_header()?;
                if this.read_header_state == ReadHeaderState::Done {
                    break;
                }
            }

            this.read_header_info.take().unwrap();

            // We probably already have some user data ready to be processed, so we need
            // to do so immediately since we go straight to a poll_read below.
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

            if this.is_eof {
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

        let mut cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);

        if cache_space == 0 {
            while this.write_cache_size > 0 && this.create_write_packet() {}
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
            // now that we've written out all the packet data, create more packets to free up cache
            // space.
            while this.write_cache_size > 0 && this.create_write_packet() {}
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
            while this.write_cache_size > 0 && this.create_write_packet() {}
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
                    if this.write_cache_size > 0 {
                        // create data packets.
                        while this.write_cache_size > 0 && this.create_write_packet() {}
                    }

                    // create the empty packet.
                    // it's possible that the write_packet buffer contains the server response,
                    // and the empty shutdown packet together, ready to send off together.
                    if this.write_cache_size == 0 && this.create_write_packet() {
                        this.shutdown_state = ShutdownState::WriteEmptyPacket;
                        continue;
                    }
                    // if we cannot create the empty packet, the write_packet buffer must
                    // be too full, so flush and try again.
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
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

impl AsyncPing for VmessStream {
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

impl AsyncStream for VmessStream {}

impl AsyncReadMessage for VmessStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        }

        match this.try_decrypt()? {
            DecryptState::NeedData => {}
            DecryptState::ReceivedEof => {
                this.is_eof = true;
            }
            DecryptState::BufferFull => {
                assert!(this.processed_end_offset > 0);
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }
            DecryptState::Success => {
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }
        }

        if this.is_eof {
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
            match this.try_decrypt()? {
                DecryptState::NeedData => {}
                DecryptState::ReceivedEof => {
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                DecryptState::BufferFull => {
                    assert!(this.processed_end_offset > 0);
                    this.read_processed(buf);
                    return Poll::Ready(Ok(()));
                }
                DecryptState::Success => {
                    this.read_processed(buf);
                    return Poll::Ready(Ok(()));
                }
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

impl AsyncWriteMessage for VmessStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        // TODO: clean this up - it's possible we have space and we can add to the write packet
        // without ensuring its all written.
        let this = self.get_mut();

        let max_padding_len = if this.write_length_mask.is_some() {
            MAX_PADDING_LEN
        } else {
            0
        };

        let max_metadata_size = 2 + max_padding_len + this.tag_len;
        let write_packet_space = this.write_packet.len() - this.write_packet_end_offset;
        if max_metadata_size >= write_packet_space {
            return Poll::Pending;
        }

        let min_available_space = write_packet_space - max_metadata_size;

        if buf.len() > min_available_space {
            return Poll::Pending;
        }

        // if we are in message mode, we don't ever use write cache size.
        assert!(this.write_cache_size == 0);

        // TODO: we don't need to copy and call do_write_packet. we can just create a packet
        // directly.
        this.write_cache[0..buf.len()].copy_from_slice(buf);
        this.write_cache_size = buf.len();
        while this.write_cache_size > 0 && this.create_write_packet() {}

        assert!(this.write_cache_size == 0 && this.write_packet_end_offset > 0);

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for VmessStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        assert!(this.write_cache_size == 0);

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

        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for VmessStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_shutdown(cx)
    }
}

impl AsyncMessageStream for VmessStream {}
