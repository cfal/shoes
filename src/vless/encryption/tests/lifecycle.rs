use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream, DuplexStream, ReadBuf,
};
use tokio::time::Instant;

use super::{fixture_pair, fixture_settings};
use crate::async_stream::{AsyncPing, AsyncStream};
use crate::vless::encryption::{ClientEncryption, ServerEncryption};

struct Buffered(BufStream<DuplexStream>);

impl AsyncRead for Buffered {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Buffered {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl AsyncPing for Buffered {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Buffered {}

#[tokio::test(start_paused = true)]
async fn buffered_flights_flush_each_fragment_and_short_ticket_expires_during_padding() {
    check_ticket_during_padding("1-1s", false).await;
    check_ticket_during_padding("5-5s", true).await;
}

async fn check_ticket_during_padding(lifetime: &str, published: bool) {
    let (c, s) = fixture_settings("random", true, &[32, 64]);
    let c = c.replace("100-0-0", "100-100-100");
    let s = s
        .replace("600s", lifetime)
        .replace("100-0-0", "100-2000-2000");
    let client = ClientEncryption::new(&c).unwrap();
    let server = ServerEncryption::new(&s, Default::default()).unwrap();
    for connection in 0..2 {
        let (left, right) = tokio::io::duplex(5);
        let wrap = |io| Buffered(BufStream::with_capacity(7, 7, io));
        let start = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let mut stream = client.handshake(wrap(left)).await.unwrap();
                    let resumed = connection == 1 && published;
                    assert_eq!(stream.is_resumed(), resumed);
                    if !resumed {
                        assert!(start.elapsed() >= Duration::from_millis(100));
                    }
                    assert!(
                        start.elapsed() < Duration::from_secs(1),
                        "client must not wait for server padding"
                    );
                    stream.write_all(b"request").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut reply = [0; 7];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(&reply, b"request");
                    assert_eq!(client.cache.snapshot(Instant::now()).is_some(), published);
                },
                async {
                    let mut stream = server.handshake(wrap(right)).await.unwrap();
                    if connection == 0 || !published {
                        assert!(start.elapsed() >= Duration::from_secs(2));
                    }
                    let mut request = [0; 7];
                    stream.read_exact(&mut request).await.unwrap();
                    stream.write_all(&request).await.unwrap();
                    stream.flush().await.unwrap();
                }
            );
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn concurrent_cold_and_warm_connections_transfer_full_duplex_and_half_close() {
    for mode in ["native", "xorpub", "random"] {
        let (client, server) = fixture_pair(mode, true, &[64]);
        let (client, server) = (Arc::new(client), Arc::new(server));
        for warm in [false, true] {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let (client, server) = (client.clone(), server.clone());
                tasks.spawn(async move {
                    let (left, right) = tokio::io::duplex(256);
                    let client = async {
                        let stream = client.handshake(left).await.unwrap();
                        if warm {
                            assert!(stream.is_resumed());
                        }
                        transfer(stream, 42, 43).await;
                    };
                    let server = async {
                        transfer(server.handshake(right).await.unwrap(), 43, 42).await;
                    };
                    tokio::join!(client, server);
                });
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            })
            .await
            .unwrap();
        }
    }
}

async fn transfer<S: AsyncStream>(stream: S, send: u8, receive: u8) {
    let (mut read, mut write) = tokio::io::split(stream);
    tokio::join!(
        async {
            write.write_all(&vec![send; 262144]).await.unwrap();
            write.shutdown().await.unwrap();
        },
        async {
            let mut data = Vec::new();
            read.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, vec![receive; 262144]);
        }
    );
}
