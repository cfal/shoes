use super::*;
use crate::async_stream::AsyncPing;
use crate::vless::encryption::tests::fixture_pair;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{DuplexStream, ReadBuf};
use tokio::sync::Notify;

struct FaultRead {
    inner: DuplexStream,
    offset: usize,
    corrupt: Option<usize>,
    stop: Option<(usize, Arc<Notify>)>,
}

impl FaultRead {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            offset: 0,
            corrupt: None,
            stop: None,
        }
    }
}

impl AsyncRead for FaultRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = if let Some((limit, notify)) = &this.stop {
            if this.offset == *limit {
                notify.notify_one();
                return Poll::Pending;
            }
            (*limit - this.offset).min(buf.remaining())
        } else {
            buf.remaining()
        };
        let mut limited = buf.take(remaining);
        std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut limited))?;
        let n = limited.filled().len();
        if let Some(index) = this.corrupt
            && (this.offset..this.offset + n).contains(&index)
        {
            limited.filled_mut()[index - this.offset] ^= 1;
        }
        // Copying also marks the outer ReadBuf's bytes initialized.
        let bytes = limited.filled().to_vec();
        buf.put_slice(&bytes);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FaultRead {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl AsyncPing for FaultRead {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for FaultRead {}

// Last bytes of each authenticated field, for a single X25519 key and 70 bytes of padding.
const CLIENT_FIELDS: [usize; 4] = [
    16 + 32 + 17,
    16 + 32 + 18 + 1231,
    16 + 32 + 18 + 1232 + 17,
    16 + 32 + 18 + 1232 + 69,
];
const SERVER_FIELDS: [usize; 4] = [1135, 1136 + 31, 1136 + 32 + 17, 1136 + 32 + 69];

#[tokio::test]
async fn every_fresh_control_field_is_authenticated_before_use() {
    for client_receives in [false, true] {
        for field in if client_receives {
            SERVER_FIELDS
        } else {
            CLIENT_FIELDS
        } {
            let (client, server) = fixture_pair("native", true, &[32]);
            let (left, right) = tokio::io::duplex(8192);
            let (mut left, mut right) = (FaultRead::new(left), FaultRead::new(right));
            if client_receives {
                left.corrupt = Some(field);
            } else {
                right.corrupt = Some(field);
            }
            let (c, s) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    async {
                        let mut stream = client.handshake(left).await?;
                        stream.read_u8().await
                    },
                    async {
                        let mut stream = server.handshake(right).await?;
                        stream.write_all(b"x").await?;
                        stream.flush().await
                    }
                )
            })
            .await
            .unwrap();
            if client_receives {
                assert_eq!(c.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert!(
                    client.cache.snapshot(Instant::now()).is_none(),
                    "field {field}"
                );
            } else {
                assert_eq!(s.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }
    }
}

#[tokio::test]
async fn invalid_chain_link_and_wrong_private_key_reject_before_server_flight() {
    for wrong_key in [false, true] {
        let (client, mut server) = fixture_pair("xorpub", true, &[32, 32]);
        if wrong_key {
            server.keys[0] = super::super::keys::ServerKey::new(&[71; 32]).unwrap();
        }
        let (left, right) = tokio::io::duplex(8192);
        let mut right = FaultRead::new(right);
        if !wrong_key {
            right.corrupt = Some(16 + 32);
        }
        let (c, s) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client.handshake(left), server.handshake(right))
        })
        .await
        .unwrap();
        assert_eq!(s.err().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(c.is_err());
        assert!(client.cache.snapshot(Instant::now()).is_none());
    }
}

#[tokio::test]
async fn cancellation_before_authenticating_server_flight_never_publishes_a_ticket() {
    for cancel_client in [false, true] {
        let fields = if cancel_client {
            &SERVER_FIELDS[..]
        } else {
            &CLIENT_FIELDS[..2]
        };
        for &field in fields {
            let (client, server) = fixture_pair("native", true, &[32]);
            let (left, right) = tokio::io::duplex(8192);
            let notify = Arc::new(Notify::new());
            let (mut left, mut right) = (FaultRead::new(left), FaultRead::new(right));
            if cancel_client {
                left.stop = Some((field, notify.clone()));
            } else {
                right.stop = Some((field, notify.clone()));
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                let client_run = async {
                    let mut stream = client.handshake(left).await?;
                    stream.read_u8().await
                };
                let server_run = server.handshake(right);
                let exchange = async {
                    let _ = tokio::join!(client_run, server_run);
                };
                tokio::select! {
                    _ = notify.notified() => {},
                    _ = exchange => panic!("exchange unexpectedly completed"),
                }
            })
            .await
            .unwrap();
            assert!(
                client.cache.snapshot(Instant::now()).is_none(),
                "cancel_client={cancel_client}, field={field}"
            );
        }
    }
}

#[tokio::test]
async fn cancelling_server_padding_read_preserves_authenticated_client_ticket() {
    // The server issues its ticket before consuming client padding. Cancelling
    // that read cannot revoke a reply the client has already authenticated.
    for &field in &CLIENT_FIELDS[2..] {
        let (client, server) = fixture_pair("native", true, &[32]);
        let (left, right) = tokio::io::duplex(8192);
        let (client_stopped, server_stopped) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
        let (mut left, mut right) = (FaultRead::new(left), FaultRead::new(right));
        left.stop = Some((SERVER_FIELDS[3] + 1, client_stopped.clone()));
        right.stop = Some((field, server_stopped.clone()));
        tokio::time::timeout(Duration::from_secs(2), async {
            let client_run = async {
                let mut stream = client.handshake(left).await?;
                stream.read_u8().await
            };
            let server_run = server.handshake(right);
            let exchange = async {
                let _ = tokio::join!(client_run, server_run);
            };
            let both_stopped = async {
                client_stopped.notified().await;
                server_stopped.notified().await;
            };
            tokio::select! {
                _ = both_stopped => {},
                _ = exchange => panic!("exchange unexpectedly completed"),
            }
        })
        .await
        .unwrap();
        assert!(
            client.cache.snapshot(Instant::now()).is_some(),
            "field={field}"
        );

        let (left, right) = tokio::io::duplex(8192);
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                async {
                    let mut stream = client.handshake(left).await.unwrap();
                    assert!(stream.is_resumed(), "field={field}");
                    stream.write_all(b"c").await.unwrap();
                    stream.flush().await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), b's');
                },
                async {
                    let mut stream = server.handshake(right).await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), b'c');
                    stream.write_all(b"s").await.unwrap();
                    stream.flush().await.unwrap();
                }
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn extended_ephemeral_offer_authenticates_but_only_standard_keys_derive_records() {
    for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
        let (client, server) = fixture_pair("native", true, &[32]);
        let (mut left, right) = tokio::io::duplex(8192);
        let iv = [3; 16];
        let (relay, nfs) = client.keys[0].exchange().unwrap();
        let mut aead = Aead::new(&iv, nfs.as_ref(), cipher).unwrap();
        let mlkem = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
        let x25519 = generate_x25519().unwrap();
        let mut offer = mlkem
            .encapsulation_key()
            .unwrap()
            .key_bytes()
            .unwrap()
            .as_ref()
            .to_vec();
        offer.extend_from_slice(x25519.compute_public_key().unwrap().as_ref());
        offer.resize(1284, 0xa5); // 1300 bytes once authenticated, 68 extension bytes.
        let mut flight = iv.to_vec();
        flight.extend_from_slice(&relay);
        flight.extend(aead.seal(&1300u16.to_be_bytes(), &[]).unwrap());
        flight.extend(aead.seal(&offer, &[]).unwrap());
        let mut schedule = client.padding.sample(&mut rand::rng());
        append_padding(&mut flight, &mut aead, &mut schedule).unwrap();
        let client_run = async {
            send_flight(&mut left, &flight, schedule).await.unwrap();
            let mut answer = [0; 1136];
            left.read_exact(&mut answer).await.unwrap();
            let answer = aead.open_at(MAX_NONCE, &mut answer, &[]).unwrap();
            let mut pfs = Zeroizing::new([0; 64]);
            pfs[..32].copy_from_slice(
                mlkem
                    .decapsulate(kem::Ciphertext::from(&answer[..1088]))
                    .unwrap()
                    .as_ref(),
            );
            pfs[32..].copy_from_slice(x25519_agree(&x25519, &answer[1088..]).unwrap().as_ref());
            let united = united(&pfs, &nfs);
            let mut read = Aead::new(answer, united.as_ref(), cipher).unwrap();
            let mut ticket = [0; 32];
            left.read_exact(&mut ticket).await.unwrap();
            read.open(&mut ticket, &[]).unwrap();
            receive_padding(&mut left, &mut read).await.unwrap();
            let mut write = Aead::new(&offer[..1216], united.as_ref(), cipher).unwrap();
            left.write_all(
                &write
                    .seal_record(b"extended offer", united.as_ref())
                    .unwrap(),
            )
            .await
            .unwrap();
            left.flush().await.unwrap();
        };
        let server_run = async {
            let mut stream = server.handshake(right).await.unwrap();
            let mut bytes = [0; 14];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"extended offer");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client_run, server_run);
        })
        .await
        .unwrap();
    }
}
