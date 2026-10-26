use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use aws_lc_rs::aead::{
    Aad, Algorithm, BoundKey, NONCE_LEN, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
};
use aws_lc_rs::error::Unspecified;
use futures::ready;
use parking_lot::Mutex;
use rand::Rng;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead_util::TAG_LEN;
use super::salt_checker::SaltChecker;
use super::shadowsocks_key::ShadowsocksKey;
use super::shadowsocks_stream_type::ShadowsocksStreamType;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;

fn generate_iv(buf: &mut [u8]) {
    let mut rng = rand::rng();
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

#[cfg(test)]
mod tests {
    use super::super::blake3_key::Blake3Key;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn client_identity_headers_survive_backpressure_and_preserve_responses() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for algorithm in [&aws_lc_rs::aead::AES_128_GCM, &aws_lc_rs::aead::AES_256_GCM] {
                for count in [0, 1, 2] {
                    for capacity in [7, 1024] {
                        let len = algorithm.key_len();
                        let user_key = vec![0x33; len].into_boxed_slice();
                        let client_key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(
                            Blake3Key::new(user_key.clone(), len).with_identity_keys(
                                (0..count)
                                    .map(|i| vec![i + 1; len].into_boxed_slice())
                                    .collect(),
                            ),
                        ));
                        let (client_io, mut peer_io) = tokio::io::duplex(capacity);
                        let mut client = ShadowsocksStream::new(
                            Box::new(client_io),
                            ShadowsocksStreamType::AEAD2022Client,
                            algorithm,
                            len,
                            client_key.clone(),
                            None,
                        );
                        let payload = vec![0x5a; 80_000];
                        let send = async {
                            client.write_all(b"request").await.unwrap();
                            client.write_all(&payload).await.unwrap();
                            client.flush().await.unwrap();
                            client.shutdown().await.unwrap();
                            let mut response = Vec::new();
                            client.read_to_end(&mut response).await.unwrap();
                            assert_eq!(response, b"response");
                        };
                        let receive = async {
                            let mut salt = vec![0; len];
                            peer_io.read_exact(&mut salt).await.unwrap();
                            let mut headers = vec![0; usize::from(count) * 16];
                            peer_io.read_exact(&mut headers).await.unwrap();
                            assert_eq!(headers, client_key.create_identity_headers(&salt).unwrap());
                            let transport = crate::prepend_stream::PrependStream::new(
                                peer_io,
                                Some(salt.into_boxed_slice()),
                            );
                            let mut server = ShadowsocksStream::new(
                                Box::new(transport),
                                ShadowsocksStreamType::AEAD2022Server,
                                algorithm,
                                len,
                                Arc::new(Box::new(Blake3Key::new(user_key, len))),
                                None,
                            );
                            let mut request = Vec::new();
                            server.read_to_end(&mut request).await.unwrap();
                            assert_eq!(&request[..7], b"request");
                            assert_eq!(&request[7..], payload);
                            server.write_all(b"response").await.unwrap();
                            server.flush().await.unwrap();
                            server.shutdown().await.unwrap();
                        };
                        tokio::join!(send, receive);
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn client_identity_responses_require_user_key_and_matching_request_salt() {
        for algorithm in [&aws_lc_rs::aead::AES_128_GCM, &aws_lc_rs::aead::AES_256_GCM] {
            for (response_key, matching_salt) in
                [(0x33, true), (0x11, true), (0x22, true), (0x33, false)]
            {
                let len = algorithm.key_len();
                let (transport, _peer) = tokio::io::duplex(1);
                let mut client = ShadowsocksStream::new(
                    Box::new(transport),
                    ShadowsocksStreamType::AEAD2022Client,
                    algorithm,
                    len,
                    Arc::new(Box::new(
                        Blake3Key::new(vec![0x33; len].into_boxed_slice(), len).with_identity_keys(
                            vec![
                                vec![0x11; len].into_boxed_slice(),
                                vec![0x22; len].into_boxed_slice(),
                            ],
                        ),
                    )),
                    None,
                );
                let (transport, _peer) = tokio::io::duplex(1);
                let mut server = ShadowsocksStream::new(
                    Box::new(transport),
                    ShadowsocksStreamType::AEAD2022Server,
                    algorithm,
                    len,
                    Arc::new(Box::new(Blake3Key::new(
                        vec![response_key; len].into_boxed_slice(),
                        len,
                    ))),
                    None,
                );
                server.is_initial_read = false;
                let mut request_salt = client.encrypt_iv.clone();
                if !matching_salt {
                    request_salt[0] ^= 1;
                }
                server.decrypt_iv = Some(request_salt);
                server.process_write_header(b"response").unwrap();
                let wire = &server.write_cache[..server.write_cache_end_offset];
                client.unprocessed_buf[..wire.len()].copy_from_slice(wire);
                client.unprocessed_end_offset = wire.len();

                if response_key != 0x33 || !matching_salt {
                    let error = client.process_read_header().unwrap_err();
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                    if !matching_salt {
                        assert_eq!(
                            error.to_string(),
                            "server returned request salt does not match"
                        );
                    }
                } else {
                    client.process_read_header().unwrap();
                    assert!(matches!(
                        client.try_decrypt().unwrap(),
                        DecryptState::Success
                    ));
                    assert_eq!(
                        &client.processed_buf[..client.processed_end_offset],
                        b"response"
                    );
                }
            }
        }
    }

    #[test]
    fn client_identity_initial_write_limits_leave_rejected_requests_unqueued() {
        for algorithm in [&aws_lc_rs::aead::AES_128_GCM, &aws_lc_rs::aead::AES_256_GCM] {
            for count in [0, 1, 2, 64] {
                let len = algorithm.key_len();
                let user_key = vec![0x33; len].into_boxed_slice();
                let client_key = Blake3Key::new(user_key.clone(), len).with_identity_keys(
                    (0..count)
                        .map(|i| vec![i as u8; len].into_boxed_slice())
                        .collect(),
                );
                let (transport, _peer) = tokio::io::duplex(1);
                let mut client = ShadowsocksStream::new(
                    Box::new(transport),
                    ShadowsocksStreamType::AEAD2022Client,
                    algorithm,
                    len,
                    Arc::new(Box::new(client_key)),
                    None,
                );
                let max_initial = client.write_cache.len() - len - 11 - 2 * TAG_LEN;
                let oversized = vec![0x5a; max_initial + 1];
                assert_eq!(
                    client.process_write_header(&oversized).unwrap_err().kind(),
                    std::io::ErrorKind::InvalidInput
                );
                assert_eq!(
                    client.write_cache_end_offset, 0,
                    "{len}-byte key, {count} identities"
                );
                assert_eq!(client.write_cache_start_offset, 0);

                let payload = &oversized[..max_initial];
                assert_eq!(client.process_write_header(payload).unwrap(), payload.len());
                assert_eq!(client.write_cache_end_offset, client.write_cache.len());
                let (transport, _peer) = tokio::io::duplex(1);
                let mut server = ShadowsocksStream::new(
                    Box::new(transport),
                    ShadowsocksStreamType::AEAD2022Server,
                    algorithm,
                    len,
                    Arc::new(Box::new(Blake3Key::new(user_key, len))),
                    None,
                );
                server.unprocessed_buf[..len].copy_from_slice(&client.write_cache[..len]);
                let chunks = &client.write_cache[len + count * 16..client.write_cache_end_offset];
                server.unprocessed_buf[len..len + chunks.len()].copy_from_slice(chunks);
                server.unprocessed_end_offset = len + chunks.len();
                server.process_read_header().unwrap();
                assert!(matches!(
                    server.try_decrypt().unwrap(),
                    DecryptState::Success
                ));
                assert_eq!(
                    &server.processed_buf[..server.processed_end_offset],
                    payload
                );
            }
        }
    }

    #[test]
    fn timestamp_window_is_symmetric_and_inclusive() {
        for timestamp in [970, 1000, 1030] {
            assert!(validate_timestamp(timestamp, 1000).is_ok());
        }
        for timestamp in [969, 1031, u64::MAX] {
            assert!(validate_timestamp(timestamp, 1000).is_err());
        }
        assert!(validate_timestamp(0, 0).is_ok());
    }

    #[tokio::test]
    async fn full_output_buffer_preserves_the_decrypted_length_and_nonce() {
        let algorithm = &aws_lc_rs::aead::AES_128_GCM;
        let (transport, _) = tokio::io::duplex(1);
        let mut stream = ShadowsocksStream::new(
            Box::new(transport),
            ShadowsocksStreamType::Aead,
            algorithm,
            16,
            Arc::new(Box::new(super::super::default_key::DefaultKey::new(
                "test", 16,
            ))),
            None,
        );
        let mut seal = SealingKey::new(
            UnboundKey::new(algorithm, &[7; 16]).unwrap(),
            IncreasingSequence::new(),
        );
        stream.opening_key = Some(OpeningKey::new(
            UnboundKey::new(algorithm, &[7; 16]).unwrap(),
            IncreasingSequence::new(),
        ));
        let mut packet = Vec::new();
        for plaintext in [&[0, 3][..], b"abc"] {
            let mut chunk = plaintext.to_vec();
            seal.seal_in_place_append_tag(Aad::empty(), &mut chunk)
                .unwrap();
            packet.extend(chunk);
        }
        stream.unprocessed_buf[..packet.len()].copy_from_slice(&packet);
        stream.unprocessed_end_offset = packet.len();
        stream.processed_end_offset = stream.processed_buf.len();
        assert!(matches!(
            stream.try_decrypt().unwrap(),
            DecryptState::BufferFull
        ));
        assert_eq!(stream.unprocessed_pending_len, Some(3));
        stream.processed_end_offset = 0;
        assert!(matches!(
            stream.try_decrypt().unwrap(),
            DecryptState::Success
        ));
        assert_eq!(&stream.processed_buf[..3], b"abc");
        assert_eq!(stream.unprocessed_pending_len, None);
    }
}

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
        let session_key = self.key.create_session_key(decrypt_iv);
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
                    // The length nonce has already advanced; retry the payload, not its header.
                    self.unprocessed_pending_len = Some(data_len_no_tag);
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

        if matches!(self.stream_type, ShadowsocksStreamType::Aead)
            && let Some(salt) = self.decrypt_iv.take()
            && let Some(checker) = &self.salt_checker
            && !checker.lock().insert_and_check(&salt)
        {
            return Err(std::io::Error::other(
                "salt replay or replay cache capacity exhausted",
            ));
        }

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
            "no data to write (available_len = {available_len}, unfilled_len = {unfilled_len})",
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
            ShadowsocksStreamType::Aead => self.salt_len,
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
            ShadowsocksStreamType::Aead => {
                if self.salt_checker.is_some() {
                    self.decrypt_iv = Some(self.unprocessed_buf[..self.salt_len].into());
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
                validate_timestamp(timestamp_secs, current_time_secs)?;

                let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                if let Some(salt_checker) = &self.salt_checker
                    && !salt_checker.lock().insert_and_check(decrypt_iv)
                {
                    return Err(std::io::Error::other("got duplicate salt"));
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
                validate_timestamp(timestamp_secs, current_time_secs)?;

                if let Some(salt_checker) = &self.salt_checker {
                    let decrypt_iv = &self.unprocessed_buf[0..self.salt_len];
                    if !salt_checker.lock().insert_and_check(decrypt_iv) {
                        return Err(std::io::Error::other("got duplicate salt"));
                    }
                }

                let request_salt =
                    &self.unprocessed_buf[self.salt_len + 9..self.salt_len + 9 + self.salt_len];

                // Use constant-time comparison to prevent timing attacks
                if request_salt.ct_eq(&self.encrypt_iv[..]).unwrap_u8() == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "server returned request salt does not match",
                    ));
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
            ShadowsocksStreamType::Aead => {
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                self.write_cache_end_offset = self.salt_len;

                let handled_len = std::cmp::min(
                    buf.len(),
                    self.write_cache.len() - self.write_cache_end_offset - METADATA_SIZE,
                );
                assert!(handled_len > 0);

                self.encrypt_single(&buf[0..handled_len], true)
                    .map_err(|_| std::io::Error::other("failed to encrypt initial packet"))?;

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

                self.encrypt_single(&response_header, false)
                    .map_err(|_| std::io::Error::other("failed to encrypt response header"))?;

                self.encrypt_single(&buf[0..handled_len], false)
                    .map_err(|_| {
                        std::io::Error::other("failed to encrypt initial server packet")
                    })?;

                Ok(handled_len)
            }
            ShadowsocksStreamType::AEAD2022Client => {
                let mut request_header = [0; 1 + 8 + 2];
                let buf_len = buf.len();
                let base_cache_len = self.stream_type.max_payload_len() + METADATA_SIZE;
                // The complete address/padding header must fit before any handshake bytes are queued.
                if buf_len
                    > base_cache_len - self.salt_len - (request_header.len() + TAG_LEN) - TAG_LEN
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Shadowsocks initial request is too large",
                    ));
                }
                let headers = self.key.create_identity_headers(&self.encrypt_iv)?;
                let cache_len = base_cache_len.checked_add(headers.len()).ok_or_else(|| {
                    std::io::Error::other("Shadowsocks identity headers are too large")
                })?;
                if cache_len != self.write_cache.len() {
                    let mut cache = std::mem::take(&mut self.write_cache).into_vec();
                    cache
                        .try_reserve_exact(cache_len - cache.len())
                        .map_err(std::io::Error::other)?;
                    cache.resize(cache_len, 0);
                    self.write_cache = cache.into_boxed_slice();
                }
                self.write_cache[0..self.salt_len].copy_from_slice(&self.encrypt_iv);
                // EIH precedes the ordinary user-key AEAD chunks and consumes no AEAD nonce.
                self.write_cache[self.salt_len..self.salt_len + headers.len()]
                    .copy_from_slice(&headers);
                self.write_cache_end_offset = self.salt_len + headers.len();

                // HeaderTypeClientStream = 0
                request_header[0] = 0;
                request_header[1..9].copy_from_slice(&current_time_secs().to_be_bytes());
                request_header[9..11].copy_from_slice(&(buf_len as u16).to_be_bytes());

                self.encrypt_single(&request_header, false)
                    .map_err(|_| std::io::Error::other("failed to encrypt response header"))?;

                self.encrypt_single(buf, false).map_err(|_| {
                    std::io::Error::other("failed to encrypt initial client packet")
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
            .map_err(|_| std::io::Error::other("failed to encrypt packet"))?;

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

        this.encrypt_single(buf, true)
            .map_err(|_| std::io::Error::other("failed to encrypt packet"))?;

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

impl AsyncStream for ShadowsocksStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
    fn preferred_write_size(&self) -> Option<std::num::NonZeroUsize> {
        match self.stream_type {
            ShadowsocksStreamType::Aead => {
                std::num::NonZeroUsize::new(self.stream_type.max_payload_len())
            }
            ShadowsocksStreamType::AEAD2022Server | ShadowsocksStreamType::AEAD2022Client => None,
        }
    }
}
impl AsyncMessageStream for ShadowsocksStream {}

#[inline]
fn current_time_secs() -> u64 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs()
}

fn validate_timestamp(timestamp: u64, now: u64) -> std::io::Result<()> {
    if timestamp.abs_diff(now) > 30 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "timestamp outside the 30-second window",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod flush_tests {
    use super::*;
    use crate::copy_bidirectional::tests::{copy_response_with_flush_pressure, quota_test_payload};
    use crate::prepend_stream::PrependStream;
    use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn check_response_flushes(payload: &[u8]) {
        for (algorithm, aead2022) in [
            (&AES_128_GCM, false),
            (&AES_256_GCM, false),
            (&CHACHA20_POLY1305, false),
            (&AES_128_GCM, true),
            (&AES_256_GCM, true),
        ] {
            let salt_len = algorithm.key_len();
            let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(if aead2022 {
                Box::new(super::super::blake3_key::Blake3Key::new(
                    vec![42; salt_len].into_boxed_slice(),
                    salt_len,
                ))
            } else {
                Box::new(super::super::DefaultKey::new("secret", salt_len))
            });
            let (transport, mut peer) = tokio::io::duplex(4096);
            let mut client = ShadowsocksStream::new(
                Box::new(transport),
                if aead2022 {
                    ShadowsocksStreamType::AEAD2022Client
                } else {
                    ShadowsocksStreamType::Aead
                },
                algorithm,
                salt_len,
                key.clone(),
                None,
            );
            let request = b"\x01\x7f\x00\x00\x01\x00\x50\x00\x00";
            client.write_all(request).await.unwrap();
            client.flush().await.unwrap();
            let metadata_len = if aead2022 {
                11 + 2 * TAG_LEN
            } else {
                METADATA_SIZE
            };
            let mut request_wire = vec![0; salt_len + metadata_len + request.len()];
            peer.read_exact(&mut request_wire).await.unwrap();

            let capture = copy_response_with_flush_pressure(
                |stream| async move {
                    let mut server = ShadowsocksStream::new(
                        Box::new(PrependStream::new(
                            stream,
                            Some(request_wire.into_boxed_slice()),
                        )),
                        if aead2022 {
                            ShadowsocksStreamType::AEAD2022Server
                        } else {
                            ShadowsocksStreamType::Aead
                        },
                        algorithm,
                        salt_len,
                        key,
                        None,
                    );
                    let mut received_request = [0; 9];
                    server.read_exact(&mut received_request).await.unwrap();
                    assert_eq!(&received_request, request);
                    server
                },
                payload,
            )
            .await;

            if payload.is_empty() {
                assert!(capture.data.is_empty());
                assert!(capture.first_write_offer.is_empty());
            } else {
                let overhead = if aead2022 {
                    salt_len + 11 + salt_len + 2 * TAG_LEN
                } else {
                    salt_len + METADATA_SIZE
                };
                assert!(capture.first_write_offer.len() > overhead);
                if payload.len() < 1024 {
                    assert_eq!(capture.first_write_offer.len(), overhead + payload.len());
                }
            }

            let (transport, _) = tokio::io::duplex(1);
            client.stream = Box::new(PrependStream::new(
                transport,
                Some(capture.data.into_boxed_slice()),
            ));
            let mut decoded = Vec::new();
            client.read_to_end(&mut decoded).await.unwrap();
            assert_eq!(decoded, payload);
        }
    }

    #[tokio::test]
    async fn response_salt_waits_for_content_across_copier_flushes() {
        check_response_flushes(b"first response").await;
    }

    #[tokio::test]
    async fn response_survives_copier_quota_flushes_and_eof() {
        let payload = quota_test_payload();
        check_response_flushes(&payload).await;
    }

    #[tokio::test]
    async fn empty_response_never_emits_a_salt() {
        check_response_flushes(b"").await;
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingChecker(Arc<AtomicUsize>);
    impl SaltChecker for CountingChecker {
        fn insert_and_check(&mut self, _: &[u8]) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    #[tokio::test]
    async fn legacy_salt_is_admitted_only_after_payload_authentication() {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(
            super::super::default_key::DefaultKey::new("secret", 32),
        ));
        let make_stream = |checker| {
            let (stream, _peer) = tokio::io::duplex(4096);
            ShadowsocksStream::new(
                Box::new(stream),
                ShadowsocksStreamType::Aead,
                &aws_lc_rs::aead::AES_256_GCM,
                32,
                key.clone(),
                checker,
            )
        };
        let mut writer = make_stream(None);
        writer.process_write_header(b"hello").unwrap();
        let wire = writer.write_cache[..writer.write_cache_end_offset].to_vec();
        for corrupt in [true, false] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut reader =
                make_stream(Some(Arc::new(Mutex::new(CountingChecker(calls.clone())))));
            reader.unprocessed_buf[..wire.len()].copy_from_slice(&wire);
            reader.unprocessed_end_offset = wire.len();
            if corrupt {
                reader.unprocessed_buf[wire.len() - 1] ^= 1;
            }
            reader.process_read_header().unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            assert_eq!(reader.try_decrypt().is_ok(), !corrupt);
            assert_eq!(calls.load(Ordering::Relaxed), usize::from(!corrupt));
        }
    }
}
