use std::io;

use aws_lc_rs::{
    aead, cipher,
    rand::{SecureRandom, SystemRandom},
};
use parking_lot::Mutex;
use zeroize::Zeroizing;

pub(crate) const HEADER_LEN: usize = 5;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const WRITE_PLAINTEXT_MAX: usize = 8192;
pub(crate) const READ_CIPHERTEXT_MAX: usize = 16640;
pub(crate) const MAX_NONCE: [u8; 12] = [255; 12];

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("VLESS random generation failed"))?;
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

pub(crate) struct Aead {
    key: aead::LessSafeKey,
    nonce: [u8; 12],
    pub(crate) cipher: Cipher,
}

impl Aead {
    pub(crate) fn new(context: &[u8], material: &[u8], cipher: Cipher) -> io::Result<Self> {
        let key = Zeroizing::new(blake3::derive_key_bytes(context, material));
        let key = aead::UnboundKey::new(cipher.algorithm(), key.as_ref())
            .map_err(|_| invalid("VLESS AEAD key initialization failed"))?;
        Ok(Self {
            key: aead::LessSafeKey::new(key),
            nonce: [0; 12],
            cipher,
        })
    }

    pub(crate) fn wraps_on_next(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        self.nonce
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        self.seal_at(nonce, plaintext, aad)
    }

    pub(crate) fn seal_at(
        &self,
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(plaintext.len() + TAG_LEN);
        output.extend_from_slice(plaintext);
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut output,
            )
            .map_err(|_| invalid("VLESS encryption failed"))?;
        Ok(output)
    }

    pub(crate) fn open<'a>(
        &mut self,
        ciphertext: &'a mut [u8],
        aad: &[u8],
    ) -> io::Result<&'a [u8]> {
        let nonce = self.next_nonce();
        self.open_at(nonce, ciphertext, aad)
    }

    pub(crate) fn open_at<'a>(
        &self,
        nonce: [u8; 12],
        ciphertext: &'a mut [u8],
        aad: &[u8],
    ) -> io::Result<&'a [u8]> {
        self.key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext,
            )
            .map(|plaintext| &*plaintext)
            .map_err(|_| invalid("VLESS authentication failed"))
    }

    pub(crate) fn seal_record(&mut self, plaintext: &[u8], united: &[u8]) -> io::Result<Vec<u8>> {
        let header = record_header(plaintext.len() + TAG_LEN)?;
        let rekey = self.wraps_on_next();
        let ciphertext = self.seal(plaintext, &header)?;
        let mut record = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&ciphertext);
        if rekey {
            *self = Self::new(&record, united, self.cipher)?;
        }
        Ok(record)
    }

    pub(crate) fn open_record<'a>(
        &mut self,
        header: &[u8; HEADER_LEN],
        ciphertext: &'a mut [u8],
        united: &[u8],
    ) -> io::Result<&'a [u8]> {
        let replacement = if self.wraps_on_next() {
            let mut context = Vec::with_capacity(HEADER_LEN + ciphertext.len());
            context.extend_from_slice(header);
            context.extend_from_slice(ciphertext);
            Some(Self::new(&context, united, self.cipher)?)
        } else {
            None
        };
        let plaintext = self.open(ciphertext, header)?;
        if let Some(replacement) = replacement {
            *self = replacement;
        }
        Ok(plaintext)
    }
}

pub(crate) fn record_header(length: usize) -> io::Result<[u8; HEADER_LEN]> {
    if !(TAG_LEN + 1..=READ_CIPHERTEXT_MAX).contains(&length) {
        return Err(invalid("invalid VLESS record length"));
    }
    let [hi, lo] = (length as u16).to_be_bytes();
    Ok([0x17, 3, 3, hi, lo])
}

pub(crate) fn record_length(header: &[u8; HEADER_LEN]) -> io::Result<usize> {
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if header[..3] != [0x17, 3, 3] || record_header(length).is_err() {
        return Err(invalid("invalid VLESS record header"));
    }
    Ok(length)
}

// AWS-LC's persistent context is Send but not Sync. Exclusive stream access
// uses get_mut(), preserving AsyncStream's bounds without locking per update.
pub(crate) struct Ctr(Mutex<cipher::StreamingEncryptingKey>);

impl Ctr {
    pub(crate) fn new(material: &[u8], iv: &[u8; 16]) -> io::Result<Self> {
        let key = Zeroizing::new(blake3::derive_key("VLESS", material));
        let key = cipher::UnboundCipherKey::new(&cipher::AES_256, key.as_ref())
            .map_err(|_| invalid("VLESS CTR key initialization failed"))?;
        let key = cipher::StreamingEncryptingKey::less_safe_ctr(
            key,
            cipher::EncryptionContext::Iv128((*iv).into()),
        )
        .map_err(|_| invalid("VLESS CTR initialization failed"))?;
        Ok(Self(Mutex::new(key)))
    }

    pub(crate) fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        let mut scratch = [0u8; 256 + 15];
        for chunk in bytes.chunks_mut(256) {
            let update = self
                .0
                .get_mut()
                .update(chunk, &mut scratch)
                .map_err(|_| invalid("VLESS CTR update failed"))?;
            if update.written().len() != chunk.len() {
                return Err(invalid("VLESS CTR buffered an incomplete update"));
            }
            chunk.copy_from_slice(update.written());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_and_explicit_nonce_are_independent() {
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let mut writer = Aead::new(b"context", &[9; 96], cipher).unwrap();
            let mut reader = Aead::new(b"context", &[9; 96], cipher).unwrap();
            let mut explicit = writer.seal_at(MAX_NONCE, b"server answer", b"").unwrap();
            assert_eq!(writer.nonce, [0; 12]);
            assert_eq!(
                reader.open_at(MAX_NONCE, &mut explicit, b"").unwrap(),
                b"server answer"
            );
            let mut record = writer.seal(b"data", b"aad").unwrap();
            assert_eq!(writer.nonce[11], 1);
            assert_eq!(reader.open(&mut record, b"aad").unwrap(), b"data");
        }
    }

    #[test]
    fn wrapped_nonce_rekeys_from_original_wire_bytes() {
        let united = [7; 96];
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let mut writer = Aead::new(b"context", &united, cipher).unwrap();
            let mut reader = Aead::new(b"context", &united, cipher).unwrap();
            writer.nonce = MAX_NONCE;
            reader.nonce = MAX_NONCE;
            for _ in 0..3 {
                let mut record = writer.seal_record(b"message", &united).unwrap();
                let header = record[..5].try_into().unwrap();
                assert_eq!(
                    reader
                        .open_record(&header, &mut record[5..], &united)
                        .unwrap(),
                    b"message"
                );
                assert_eq!(writer.nonce, reader.nonce);
            }
            assert_eq!(writer.nonce[11], 2);
        }
    }

    #[test]
    fn wrapped_nonce_records_match_go() {
        use super::super::tests::{bytes, fixtures};

        for v in fixtures()["rekey"].as_array().unwrap() {
            let cipher = if v["aes"].as_bool().unwrap() {
                Cipher::Aes256Gcm
            } else {
                Cipher::ChaCha20Poly1305
            };
            let united = bytes(v, "material");
            let mut writer = Aead::new(&bytes(v, "context"), &united, cipher).unwrap();
            writer.nonce = MAX_NONCE;
            let mut wire = Vec::new();
            for _ in 0..3 {
                wire.extend(writer.seal_record(&bytes(v, "plaintext"), &united).unwrap());
            }
            assert_eq!(wire, bytes(v, "wire"));
        }
    }

    #[test]
    fn header_is_authenticated_and_bounded() {
        for length in [0, 16, 16641, 65535, usize::MAX] {
            assert!(record_header(length).is_err());
        }
        for length in [17, 8208, 16640] {
            assert_eq!(
                record_length(&record_header(length).unwrap()).unwrap(),
                length
            );
        }
        let mut writer = Aead::new(b"context", &[0; 96], Cipher::Aes256Gcm).unwrap();
        let mut reader = Aead::new(b"context", &[0; 96], Cipher::Aes256Gcm).unwrap();
        let mut record = writer.seal_record(b"hello", &[0; 96]).unwrap();
        let mut header: [u8; 5] = record[..5].try_into().unwrap();
        header[4] ^= 1;
        assert!(
            reader
                .open_record(&header, &mut record[5..], &[0; 96])
                .is_err()
        );
    }

    #[test]
    fn persistent_ctr_is_sync_and_fragmentation_independent() {
        fn assert_bounds<T: Send + Sync>() {}
        assert_bounds::<Ctr>();
        for iv in [
            [0; 16],
            [255; 16],
            [
                0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            ],
        ] {
            let mut expected = [9; 1088];
            Ctr::new(&[1; 96], &iv)
                .unwrap()
                .apply(&mut expected)
                .unwrap();
            for split in 0..=32 {
                let mut actual = [9; 1088];
                let mut ctr = Ctr::new(&[1; 96], &iv).unwrap();
                ctr.apply(&mut actual[..split]).unwrap();
                for chunk in actual[split..].chunks_mut(5) {
                    ctr.apply(chunk).unwrap();
                }
                assert_eq!(actual, expected);
            }
        }
    }
}
