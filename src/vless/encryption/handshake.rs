use std::{io, sync::Arc, time::Duration};

use aws_lc_rs::kem;
use rand::RngExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use zeroize::Zeroizing;

use super::{
    ClientEncryption, EncryptionStream, ServerEncryption,
    config::{Mode, PaddingSchedule},
    crypto::{Aead, Cipher, Ctr, MAX_NONCE, invalid, random, record_length},
    keys::{Secret, generate_x25519, import_mlkem_public, x25519_agree},
    mask::HeaderMask,
    session::{ClientSession, ReserveError, ResumeGuard},
    stream::{FreshPadding, InitialRead, StreamKeys},
};
use crate::{async_stream::AsyncStream, util::STREAM_SETUP_TIMEOUT};

fn united(pfs: &[u8; 64], nfs: &[u8; 32]) -> Zeroizing<[u8; 96]> {
    let mut result = Zeroizing::new([0; 96]);
    result[..64].copy_from_slice(pfs);
    result[64..].copy_from_slice(nfs);
    result
}

fn append_padding(
    flight: &mut Vec<u8>,
    aead: &mut Aead,
    schedule: &mut PaddingSchedule,
) -> io::Result<()> {
    let prefix = flight.len();
    let length =
        u16::try_from(schedule.total - 18).map_err(|_| invalid("VLESS padding too large"))?;
    flight.extend_from_slice(&aead.seal(&length.to_be_bytes(), &[])?);
    flight.extend_from_slice(&aead.seal(&vec![0; schedule.total - 34], &[])?);
    schedule.lengths[0] = schedule.lengths[0]
        .checked_add(prefix)
        .ok_or_else(|| invalid("VLESS flight too large"))?;
    Ok(())
}

async fn send_flight<S: AsyncWrite + Unpin>(
    io: &mut S,
    flight: &[u8],
    schedule: PaddingSchedule,
) -> io::Result<()> {
    let mut offset = 0;
    for (index, length) in schedule.lengths.into_iter().enumerate() {
        if length != 0 {
            io.write_all(&flight[offset..offset + length]).await?;
            io.flush().await?;
            offset += length;
        }
        if let Some(gap) = schedule.gaps.get(index) {
            tokio::time::sleep(*gap).await;
        }
    }
    debug_assert_eq!(offset, flight.len());
    io.flush().await
}

async fn read_encrypted_length<S: AsyncRead + Unpin>(
    io: &mut S,
    aead: &mut Aead,
) -> io::Result<usize> {
    let mut bytes = [0; 18];
    io.read_exact(&mut bytes).await?;
    let plain = aead.open(&mut bytes, &[])?;
    Ok(u16::from_be_bytes(
        plain
            .try_into()
            .map_err(|_| invalid("invalid VLESS encrypted length"))?,
    ) as usize)
}

async fn receive_padding<S: AsyncRead + Unpin>(io: &mut S, aead: &mut Aead) -> io::Result<()> {
    let length = read_encrypted_length(io, aead).await?;
    if length < 16 {
        return Err(invalid("short VLESS padding"));
    }
    let mut padding = vec![0; length];
    io.read_exact(&mut padding).await?;
    aead.open(&mut padding, &[])?;
    Ok(())
}

async fn read_padding_progress<S: AsyncRead + Unpin>(
    io: &mut S,
    padding: &mut FreshPadding,
) -> io::Result<()> {
    // The offset survives cancellation when the other local flight completes.
    while padding.filled < padding.ciphertext.len() {
        let n = io.read(&mut padding.ciphertext[padding.filled..]).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        padding.filled += n;
    }
    Ok(())
}

impl ClientEncryption {
    pub(crate) async fn handshake<S: AsyncStream>(&self, io: S) -> io::Result<EncryptionStream<S>> {
        self.handshake_cipher(io, Cipher::Aes256Gcm).await
    }

    pub(super) async fn handshake_cipher<S: AsyncStream>(
        &self,
        mut io: S,
        cipher: Cipher,
    ) -> io::Result<EncryptionStream<S>> {
        let deadline = Instant::now() + STREAM_SETUP_TIMEOUT;
        let iv = random::<16>()?;
        let mut flight = iv.to_vec();
        let nfs = self.encode_relays(&iv, &mut flight)?;
        let mut nfs_aead = Aead::new(&iv, nfs.as_ref(), cipher)?;
        if self.resume
            && let Some(used) = self.cache.snapshot(Instant::now())
        {
            flight.extend_from_slice(&nfs_aead.seal(&32u16.to_be_bytes(), &[])?);
            let encrypted_ticket = nfs_aead.seal(&used.ticket, &[])?;
            flight.extend_from_slice(&encrypted_ticket);
            let united = united(&used.pfs, &nfs);
            let write_aead = Aead::new(&encrypted_ticket, united.as_ref(), cipher)?;
            let random_mode = self.mode == Mode::Random;
            let write_mask = if random_mode {
                Some(HeaderMask::new(united.as_ref(), &iv, flight.len())?)
            } else {
                None
            };
            let keys = StreamKeys {
                united,
                write_aead,
                read_aead: None,
                write_mask,
                read_mask: None,
                random_mode,
            };
            let mut stream = EncryptionStream::new(
                io,
                true,
                keys,
                InitialRead::Resumed {
                    random: [0; 16],
                    filled: 0,
                },
            );
            stream.set_client_prefix(
                flight,
                ResumeGuard {
                    cache: self.cache.clone(),
                    used,
                },
            )?;
            log::debug!("VLESS encryption client: resumed handshake");
            return Ok(stream);
        }
        let mlkem = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
            .map_err(|_| invalid("VLESS ML-KEM generation failed"))?;
        let x25519 = generate_x25519()?;
        let mut offer = mlkem
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(|_| invalid("VLESS ML-KEM public key failed"))?
            .as_ref()
            .to_vec();
        offer.extend_from_slice(
            x25519
                .compute_public_key()
                .map_err(|_| invalid("VLESS X25519 public key failed"))?
                .as_ref(),
        );
        flight.extend_from_slice(&nfs_aead.seal(&1232u16.to_be_bytes(), &[])?);
        flight.extend_from_slice(&nfs_aead.seal(&offer, &[])?);
        let mut schedule = self.padding.sample(&mut rand::rng());
        append_padding(&mut flight, &mut nfs_aead, &mut schedule)?;

        let exchange = async {
            let (mut reader, mut writer) = tokio::io::split(&mut io);
            let send = send_flight(&mut writer, &flight, schedule);
            tokio::pin!(send);
            let ((mut keys, mut padding, ticket), sent) = {
                let receive = async {
                    let mut answer = [0; 1136];
                    reader.read_exact(&mut answer).await?;
                    let answer = nfs_aead.open_at(MAX_NONCE, &mut answer, &[])?;
                    let kem_secret = mlkem
                        .decapsulate(kem::Ciphertext::from(&answer[..1088]))
                        .map_err(|_| invalid("VLESS ML-KEM decapsulation failed"))?;
                    let ec_secret = x25519_agree(&x25519, &answer[1088..1120])?;
                    let mut pfs = Zeroizing::new([0; 64]);
                    pfs[..32].copy_from_slice(kem_secret.as_ref());
                    pfs[32..].copy_from_slice(ec_secret.as_ref());
                    let united = united(&pfs, &nfs);
                    let write_aead = Aead::new(&offer, united.as_ref(), cipher)?;
                    let mut read_aead = Aead::new(answer, united.as_ref(), cipher)?;
                    let mut encrypted_ticket = [0; 32];
                    reader.read_exact(&mut encrypted_ticket).await?;
                    let ticket: [u8; 16] = read_aead
                        .open(&mut encrypted_ticket, &[])?
                        .try_into()
                        .map_err(|_| invalid("invalid VLESS ticket"))?;
                    let seconds = u16::from_be_bytes([ticket[0], ticket[1]]);
                    let expires_at = Instant::now() + Duration::from_secs(u64::from(seconds));
                    let pending_ticket = (self.resume && seconds != 0).then(|| {
                        (
                            self.cache.clone(),
                            Arc::new(ClientSession {
                                ticket,
                                pfs,
                                expires_at,
                            }),
                        )
                    });
                    let length = read_encrypted_length(&mut reader, &mut read_aead).await?;
                    if length < 16 {
                        return Err(invalid("short VLESS server padding"));
                    }
                    let keys = StreamKeys {
                        united,
                        write_aead,
                        read_aead: Some(read_aead),
                        write_mask: None,
                        read_mask: None,
                        random_mode: self.mode == Mode::Random,
                    };
                    Ok((
                        keys,
                        FreshPadding::new(vec![0; length], 0, pending_ticket, deadline),
                        ticket,
                    ))
                };
                tokio::pin!(receive);
                // Poll both flights; after the prefix arrives, help drain padding
                // only while the local flight (including its last gap) is pending.
                tokio::select! {
                    biased;
                    result = &mut send => { result?; (receive.await?, true) }
                    received = &mut receive => (received?, false),
                }
            };
            if !sent {
                tokio::select! {
                    biased;
                    result = &mut send => result?,
                    result = read_padding_progress(&mut reader, &mut padding) => { result?; send.await?; }
                }
            }
            if keys.random_mode {
                keys.write_mask = Some(HeaderMask::new(keys.united.as_ref(), &iv, 0)?);
                keys.read_mask = Some(HeaderMask::new(
                    keys.united.as_ref(),
                    &ticket,
                    padding.ciphertext.len() - padding.filled,
                )?);
            }
            let initial = if padding.filled == padding.ciphertext.len() {
                keys.read_aead
                    .as_mut()
                    .unwrap()
                    .open(&mut padding.ciphertext, &[])?;
                if let Some((cache, ticket)) = padding.ticket {
                    cache.publish(ticket, Instant::now());
                }
                InitialRead::Records
            } else {
                InitialRead::Fresh(padding)
            };
            io::Result::Ok((keys, initial))
        };
        let (keys, initial) =
            tokio::time::timeout_at(deadline, exchange)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "VLESS fresh handshake timed out")
                })??;
        log::debug!("VLESS encryption client: fresh handshake");
        Ok(EncryptionStream::new(io, true, keys, initial))
    }

    fn encode_relays(&self, iv: &[u8; 16], flight: &mut Vec<u8>) -> io::Result<Secret> {
        let mut previous: Option<Ctr> = None;
        let mut nfs = Zeroizing::new([0; 32]);
        for (index, key) in self.keys.iter().enumerate() {
            let (mut relay, secret) = key.exchange()?;
            nfs = secret;
            if self.mode != Mode::Native {
                Ctr::new(&key.public, iv)?.apply(&mut relay)?;
            }
            if let Some(ctr) = &mut previous {
                ctr.apply(&mut relay[..32])?;
            }
            flight.extend_from_slice(&relay);
            if let Some(next) = self.keys.get(index + 1) {
                let mut ctr = Ctr::new(nfs.as_ref(), iv)?;
                let mut hash = next.hash;
                ctr.apply(&mut hash)?;
                flight.extend_from_slice(&hash);
                previous = Some(ctr);
            }
        }
        Ok(nfs)
    }
}

impl ServerEncryption {
    pub(crate) async fn handshake<S: AsyncStream>(
        &self,
        mut io: S,
    ) -> io::Result<EncryptionStream<S>> {
        let deadline = Instant::now() + STREAM_SETUP_TIMEOUT;
        let (keys, random_prefix) = tokio::time::timeout_at(deadline, self.receive(&mut io))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "VLESS server handshake timed out")
            })??;
        let mut stream = EncryptionStream::new(io, false, keys, InitialRead::Records);
        if let Some(random) = random_prefix {
            stream.set_server_random(random);
        }
        log::debug!(
            "VLESS encryption server: {} handshake",
            if random_prefix.is_some() {
                "resumed"
            } else {
                "fresh"
            }
        );
        Ok(stream)
    }

    async fn receive<S: AsyncStream>(
        &self,
        io: &mut S,
    ) -> io::Result<(StreamKeys, Option<[u8; 16]>)> {
        let mut iv = [0; 16];
        io.read_exact(&mut iv).await?;
        let mut relays = vec![0; self.relay_len];
        io.read_exact(&mut relays).await?;
        let nfs = self.decode_relays(&iv, &mut relays)?;
        let mut encrypted_length = [0; 18];
        io.read_exact(&mut encrypted_length).await?;
        let mut nfs_aead = Aead::new(&iv, nfs.as_ref(), Cipher::Aes256Gcm)?;
        // A failed open may overwrite its input; preserve the ChaCha trial's ciphertext.
        let mut trial = encrypted_length;
        let plain = match nfs_aead.open(&mut trial, &[]) {
            Ok(plain) => plain,
            Err(_) => {
                nfs_aead = Aead::new(&iv, nfs.as_ref(), Cipher::ChaCha20Poly1305)?;
                nfs_aead.open(&mut encrypted_length, &[])?
            }
        };
        let length = u16::from_be_bytes(plain.try_into().unwrap()) as usize;
        let cipher = nfs_aead.cipher;
        log::debug!("VLESS encryption server cipher: {cipher:?}");
        let random_mode = self.mode == Mode::Random;
        if length == 32 {
            let mut encrypted_ticket = [0; 32];
            io.read_exact(&mut encrypted_ticket).await?;
            let mut decrypted_ticket = encrypted_ticket;
            let ticket: [u8; 16] = nfs_aead
                .open(&mut decrypted_ticket, &[])?
                .try_into()
                .unwrap();
            let pfs = if self.lifetime.maximum() == 0 {
                Err(ReserveError::Stale)
            } else {
                self.sessions.lock().reserve(&ticket, &nfs, Instant::now())
            };
            let pfs = match pfs {
                Ok(pfs) => pfs,
                Err(ReserveError::Replay) => return Err(invalid("replayed VLESS resumption")),
                Err(ReserveError::Stale) => {
                    send_stale_noise(io).await?;
                    return Err(invalid("stale VLESS ticket"));
                }
                Err(ReserveError::Capacity) => {
                    send_stale_noise(io).await?;
                    return Err(invalid("VLESS resumption replay capacity exceeded"));
                }
            };
            let united = united(&pfs, &nfs);
            let random = random::<16>()?;
            let write_aead = Aead::new(&random, united.as_ref(), cipher)?;
            let read_aead = Some(Aead::new(&encrypted_ticket, united.as_ref(), cipher)?);
            let write_mask = if random_mode {
                Some(HeaderMask::new(united.as_ref(), &random, 16)?)
            } else {
                None
            };
            let read_mask = if random_mode {
                Some(HeaderMask::new(united.as_ref(), &iv, 0)?)
            } else {
                None
            };
            return Ok((
                StreamKeys {
                    united,
                    write_aead,
                    read_aead,
                    write_mask,
                    read_mask,
                    random_mode,
                },
                Some(random),
            ));
        }
        if length < 1232 {
            return Err(invalid("short VLESS ephemeral offer"));
        }
        let mut encrypted_offer = vec![0; length];
        io.read_exact(&mut encrypted_offer).await?;
        let offer = nfs_aead.open(&mut encrypted_offer, &[])?;
        let kem_public = import_mlkem_public(&offer[..1184])?;
        let (kem_ciphertext, kem_secret) = kem_public
            .encapsulate()
            .map_err(|_| invalid("VLESS ML-KEM encapsulation failed"))?;
        let x25519 = generate_x25519()?;
        let ec_secret = x25519_agree(&x25519, &offer[1184..1216])?;
        let mut pfs = Zeroizing::new([0; 64]);
        pfs[..32].copy_from_slice(kem_secret.as_ref());
        pfs[32..].copy_from_slice(ec_secret.as_ref());
        let united = united(&pfs, &nfs);
        let mut answer = kem_ciphertext.as_ref().to_vec();
        answer.extend_from_slice(
            x25519
                .compute_public_key()
                .map_err(|_| invalid("VLESS X25519 public key failed"))?
                .as_ref(),
        );
        let mut write_aead = Aead::new(&answer, united.as_ref(), cipher)?;
        let read_aead = Some(Aead::new(&offer[..1216], united.as_ref(), cipher)?);
        let mut ticket = random::<16>()?;
        let lifetime = self.lifetime.sample(&mut rand::rng());
        ticket[..2].copy_from_slice(&lifetime.to_be_bytes());
        if lifetime != 0
            && !self
                .sessions
                .lock()
                .insert(ticket, pfs, self.lifetime.maximum(), Instant::now())
        {
            ticket[..2].fill(0);
        }
        let mut flight = nfs_aead.seal_at(MAX_NONCE, &answer, &[])?;
        flight.extend_from_slice(&write_aead.seal(&ticket, &[])?);
        let mut schedule = self.padding.sample(&mut rand::rng());
        append_padding(&mut flight, &mut write_aead, &mut schedule)?;
        {
            let (mut reader, mut writer) = tokio::io::split(&mut *io);
            tokio::try_join!(
                send_flight(&mut writer, &flight, schedule),
                receive_padding(&mut reader, &mut nfs_aead)
            )?;
        }
        let write_mask = if random_mode {
            Some(HeaderMask::new(united.as_ref(), &ticket, 0)?)
        } else {
            None
        };
        let read_mask = if random_mode {
            Some(HeaderMask::new(united.as_ref(), &iv, 0)?)
        } else {
            None
        };
        Ok((
            StreamKeys {
                united,
                write_aead,
                read_aead,
                write_mask,
                read_mask,
                random_mode,
            },
            None,
        ))
    }

    fn decode_relays(&self, iv: &[u8; 16], mut relays: &mut [u8]) -> io::Result<Secret> {
        let mut previous: Option<Ctr> = None;
        let mut nfs = Zeroizing::new([0; 32]);
        for (index, key) in self.keys.iter().enumerate() {
            if let Some(ctr) = &mut previous {
                ctr.apply(&mut relays[..32])?;
            }
            let length = key.relay_len();
            if self.mode != Mode::Native {
                Ctr::new(&key.public, iv)?.apply(&mut relays[..length])?;
            }
            nfs = key.exchange(&relays[..length])?;
            relays = &mut relays[length..];
            if let Some(next) = self.keys.get(index + 1) {
                let mut ctr = Ctr::new(nfs.as_ref(), iv)?;
                ctr.apply(&mut relays[..32])?;
                if relays[..32] != next.hash {
                    return Err(invalid("invalid VLESS chain link"));
                }
                relays = &mut relays[32..];
                previous = Some(ctr);
            }
        }
        Ok(nfs)
    }
}

async fn send_stale_noise<S: AsyncWrite + Unpin>(io: &mut S) -> io::Result<()> {
    let length = rand::rng().random_range(1279..2279);
    let mut noise = random::<2279>()?;
    // Reference clients invalidate on a bad header, not on an early EOF.
    while record_length(noise[16..21].try_into().unwrap()).is_ok()
        || record_length(noise[..5].try_into().unwrap()).is_ok()
    {
        noise = random::<2279>()?;
    }
    io.write_all(&noise[..length]).await?;
    io.flush().await
}

#[cfg(test)]
#[path = "tests/handshake.rs"]
mod tests;
