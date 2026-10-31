use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures::future::{BoxFuture, FutureExt};
use futures::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::config::GlobalLimits;
use crate::quic_stream::QuicStream;
use crate::resources::{Budget, BudgetPermit};

use super::{COMMAND_TYPE_AUTHENTICATE, COMMAND_TYPE_DISSOCIATE, COMMAND_TYPE_PACKET};

const MAX_PACKET_LEN: usize = super::MAX_HEADER_LEN + 65535;

#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub uni_streams: usize,
    bi_streams: usize,
    bytes: usize,
}

impl Settings {
    pub fn new(limits: GlobalLimits) -> Self {
        Self {
            uni_streams: limits
                .max_streams_per_connection
                .unwrap_or(super::UNI_STREAM_WINDOW as usize)
                .min(super::UNI_STREAM_WINDOW as usize),
            bi_streams: limits.max_streams_per_connection.unwrap_or(4096),
            bytes: limits.quic_receive_window.max(MAX_PACKET_LEN),
        }
    }
}

struct ChargedBytes {
    bytes: Vec<u8>,
    filled: usize,
    _local: BudgetPermit,
    _global: BudgetPermit,
}

impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.filled]
    }
}

fn allocate(size: usize, budget: &Arc<Budget>) -> Option<ChargedBytes> {
    let local = budget.acquire(size)?;
    let global = crate::resources::try_quic_memory(size)?;
    Some(ChargedBytes {
        bytes: vec![0; size],
        filled: size,
        _local: local,
        _global: global,
    })
}

pub(super) enum UniCommand {
    Authenticate([u8; 48]),
    Data(Bytes),
}

pub(super) type UniReader = BoxFuture<'static, io::Result<Option<UniCommand>>>;
pub(super) type BiReader = BoxFuture<'static, io::Result<Option<BufferedBi>>>;

pub(super) struct Pending {
    pub uni: Vec<UniReader>,
    pub bi: Vec<BiReader>,
}

#[derive(Default)]
struct Readers {
    authenticating: bool,
    #[cfg(test)]
    polls: usize,
    #[cfg(test)]
    accepted: usize,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Only the length prefix is inspected here; semantic packet validation stays in the dispatcher.
fn command_len(prefix: &[u8]) -> io::Result<Option<usize>> {
    if prefix.len() < 2 {
        return Ok(None);
    }
    if prefix[0] != 5 {
        return Err(invalid("invalid TUIC version"));
    }
    Ok(match prefix[1] {
        COMMAND_TYPE_AUTHENTICATE => Some(50),
        COMMAND_TYPE_DISSOCIATE => Some(4),
        COMMAND_TYPE_PACKET => {
            if prefix.len() < 11 {
                return Ok(None);
            }
            let address_len = match prefix[10] {
                0x00 => {
                    let Some(&len) = prefix.get(11) else {
                        return Ok(None);
                    };
                    1 + 1 + len as usize + 2
                }
                0x01 => 7,
                0x02 => 19,
                0xff => 1,
                _ => return Err(invalid("invalid TUIC address type")),
            };
            Some(10 + address_len + u16::from_be_bytes([prefix[8], prefix[9]]) as usize)
        }
        _ => return Err(invalid("invalid TUIC uni command")),
    })
}

pub(super) async fn read_uni_stream(stream: quinn::RecvStream) -> io::Result<Option<UniCommand>> {
    read_uni(stream, None).await
}

async fn read_uni(
    mut stream: quinn::RecvStream,
    staging: Option<(Arc<Budget>, Arc<Mutex<Readers>>)>,
) -> io::Result<Option<UniCommand>> {
    let mut prefix = [0; 12];
    AsyncReadExt::read_exact(&mut stream, &mut prefix[..2]).await?;
    command_len(&prefix[..2])?;
    if prefix[1] == COMMAND_TYPE_AUTHENTICATE {
        if let Some((_, readers)) = &staging {
            let mut readers = readers.lock();
            if readers.authenticating {
                return Err(invalid("duplicate TUIC authentication"));
            }
            readers.authenticating = true;
        }
        let mut credentials = [0; 48];
        AsyncReadExt::read_exact(&mut stream, &mut credentials).await?;
        return Ok(Some(UniCommand::Authenticate(credentials)));
    }
    let mut filled = 2;
    let total = loop {
        if let Some(total) = command_len(&prefix[..filled])? {
            break total;
        }
        let needed = if filled < 11 { 11 } else { 12 };
        AsyncReadExt::read_exact(&mut stream, &mut prefix[filled..needed]).await?;
        filled = needed;
    };
    let data = if let Some((budget, _)) = staging {
        let Some(mut data) = allocate(total, &budget) else {
            log::debug!("Dropping pre-auth TUIC command: staging budget exhausted");
            return Ok(None);
        };
        data.bytes[..filled].copy_from_slice(&prefix[..filled]);
        AsyncReadExt::read_exact(&mut stream, &mut data.bytes[filled..]).await?;
        Bytes::from_owner(data)
    } else {
        let mut data = vec![0; total];
        data[..filled].copy_from_slice(&prefix[..filled]);
        AsyncReadExt::read_exact(&mut stream, &mut data[filled..]).await?;
        Bytes::from(data)
    };
    Ok(Some(UniCommand::Data(data)))
}

struct ResetOnDrop(Option<quinn::SendStream>);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Some(send) = &mut self.0 {
            let _ = send.reset(0u32.into());
        }
    }
}

async fn read_bi(
    send: ResetOnDrop,
    mut recv: quinn::RecvStream,
    peer: std::net::SocketAddr,
    budget: Arc<Budget>,
    authenticated: CancellationToken,
) -> io::Result<Option<BufferedBi>> {
    let mut prefix = VecDeque::new();
    let mut tail: Option<ChargedBytes> = None;
    loop {
        let chunk = tokio::select! {
            biased;
            _ = authenticated.cancelled() => break,
            chunk = recv.read_chunk(4096, true) => match chunk {
                Ok(chunk) => chunk,
                Err(_) => return Ok(None),
            },
        };
        let Some(mut chunk) = chunk else { break };
        while !chunk.bytes.is_empty() {
            if tail.is_none() {
                // Coalesces tiny reads so buffer metadata cannot grow once per received byte.
                let available = budget
                    .limit()
                    .unwrap()
                    .saturating_sub(budget.snapshot().active);
                let Some(mut data) = (available != 0)
                    .then(|| allocate(available.min(4096), &budget))
                    .flatten()
                else {
                    log::debug!("Rejecting pre-auth TUIC TCP stream: staging budget exhausted");
                    return Ok(None);
                };
                data.filled = 0;
                tail = Some(data);
            }
            let data = tail.as_mut().unwrap();
            let len = chunk.bytes.len().min(data.bytes.len() - data.filled);
            data.bytes[data.filled..data.filled + len].copy_from_slice(&chunk.bytes[..len]);
            data.filled += len;
            chunk.bytes.advance(len);
            if data.filled == data.bytes.len() {
                prefix.push_back(Bytes::from_owner(tail.take().unwrap()));
            }
        }
        tokio::task::consume_budget().await;
    }
    if let Some(data) = tail {
        prefix.push_back(Bytes::from_owner(data));
    }
    Ok(Some(BufferedBi {
        send,
        recv,
        peer,
        prefix,
    }))
}

pub(super) struct BufferedBi {
    send: ResetOnDrop,
    recv: quinn::RecvStream,
    peer: std::net::SocketAddr,
    prefix: VecDeque<Bytes>,
}

impl BufferedBi {
    pub fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        peer: std::net::SocketAddr,
    ) -> Self {
        Self {
            send: ResetOnDrop(Some(send)),
            recv,
            peer,
            prefix: VecDeque::new(),
        }
    }

    pub fn into_stream(mut self) -> Box<dyn AsyncStream> {
        Box::new(BufferedStream {
            inner: QuicStream::from(self.send.0.take().unwrap(), self.recv).with_peer(self.peer),
            prefix: self.prefix,
        })
    }
}

struct BufferedStream {
    inner: QuicStream,
    prefix: VecDeque<Bytes>,
}

impl AsyncRead for BufferedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = self.prefix.front_mut() {
            let len = prefix.len().min(buf.remaining());
            buf.put_slice(&prefix[..len]);
            prefix.advance(len);
            if prefix.is_empty() {
                self.prefix.pop_front();
            }
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for BufferedStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for BufferedStream {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

pub(super) async fn authenticate(
    connection: &quinn::Connection,
    uuid: &[u8],
    password: &str,
    settings: Settings,
) -> io::Result<Pending> {
    let budget = Arc::new(Budget::new(Some(settings.bytes)));
    collect(
        connection,
        uuid,
        password,
        settings,
        budget,
        Arc::new(Mutex::new(Readers::default())),
    )
    .await
}

async fn collect(
    connection: &quinn::Connection,
    uuid: &[u8],
    password: &str,
    settings: Settings,
    budget: Arc<Budget>,
    readers: Arc<Mutex<Readers>>,
) -> io::Result<Pending> {
    use subtle::ConstantTimeEq;
    let mut token = [0; 32];
    connection
        .export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| io::Error::other(format!("Failed to export keying material: {e:?}")))?;
    let mut uni_reads: FuturesUnordered<UniReader> = FuturesUnordered::new();
    let mut bi_reads: FuturesUnordered<BiReader> = FuturesUnordered::new();
    let mut uni = Vec::new();
    let mut bi = Vec::new();
    let authenticated = CancellationToken::new();
    loop {
        tokio::select! {
            biased;
            Some(result) = uni_reads.next(), if !uni_reads.is_empty() => {
                match result? {
                    Some(UniCommand::Authenticate(credentials)) => {
                        if !bool::from(credentials[..16].ct_eq(uuid) & credentials[16..].ct_eq(&token)) {
                            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "incorrect credentials"));
                        }
                        authenticated.cancel();
                        connection.set_max_concurrent_uni_streams((settings.uni_streams as u32).into());
                        let uni = uni.into_iter().map(|command| futures::future::ready(Ok(Some(command))).boxed())
                            .chain(uni_reads).collect();
                        let bi = bi.into_iter().map(|stream| futures::future::ready(Ok(Some(stream))).boxed())
                            .chain(bi_reads).collect();
                        return Ok(Pending { uni, bi });
                    }
                    Some(command) if uni.len() < settings.uni_streams => uni.push(command),
                    _ => {},
                }
            },
            Some(result) = bi_reads.next(), if !bi_reads.is_empty() => {
                if let Some(stream) = result? { bi.push(stream); }
            },
            stream = connection.accept_uni(), if uni_reads.len() <= settings.uni_streams => {
                let stream = stream?;
                // An unread stream may be AUTH whose first bytes were delayed; only complete
                // commands or budget-denied bodies are discarded before the auth deadline.
                let reader = read_uni(stream, Some((budget.clone(), readers.clone()))).boxed();
                #[cfg(test)]
                let reader = {
                    readers.lock().accepted += 1;
                    let mut reader = reader;
                    let counter = readers.clone();
                    std::future::poll_fn(move |cx| {
                        counter.lock().polls += 1;
                        reader.as_mut().poll(cx)
                    }).boxed()
                };
                uni_reads.push(reader);
            },
            stream = connection.accept_bi(), if bi_reads.len() + bi.len() < settings.bi_streams => {
                let (send, recv) = stream?;
                let reader = read_bi(ResetOnDrop(Some(send)), recv, connection.remote_address(), budget.clone(), authenticated.clone());
                bi_reads.push(reader.boxed());
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    const UUID: [u8; 16] = [9; 16];
    const PASSWORD: &str = "pre-auth";

    async fn pair(
        limits: GlobalLimits,
    ) -> (
        quinn::Connection,
        quinn::Connection,
        (quinn::Endpoint, quinn::Endpoint),
    ) {
        let (server, client) = crate::quic_endpoint::test_endpoints_with_config(|config| {
            super::super::configure_transport(config, limits);
        });
        let (client_conn, server_conn) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await },
        );
        (client_conn.unwrap(), server_conn.unwrap(), (server, client))
    }

    async fn send_auth(client: &quinn::Connection) {
        let mut auth = [0; 50];
        auth[..2].copy_from_slice(&[5, COMMAND_TYPE_AUTHENTICATE]);
        auth[2..18].copy_from_slice(&UUID);
        client
            .export_keying_material(&mut auth[18..], &UUID, PASSWORD.as_bytes())
            .unwrap();
        let mut stream = client.open_uni().await.unwrap();
        stream.write_all(&auth).await.unwrap();
    }

    #[test]
    fn length_scanner_bounds_every_partial_address_prefix() {
        for payload in [0u16, 65535] {
            for address in [vec![0, 0], vec![0, 255], vec![1], vec![2], vec![0xff]] {
                let mut prefix = vec![5, COMMAND_TYPE_PACKET, 0, 1, 0, 1, 1, 0];
                prefix.extend_from_slice(&payload.to_be_bytes());
                prefix.extend_from_slice(&address);
                for end in 0..prefix.len() {
                    assert_eq!(command_len(&prefix[..end]).unwrap(), None);
                }
                let expected_header = match address[..] {
                    [0, length] => 14 + length as usize,
                    [1] => 17,
                    [2] => 29,
                    [0xff] => 11,
                    _ => unreachable!(),
                };
                assert_eq!(
                    command_len(&prefix).unwrap(),
                    Some(expected_header + payload as usize)
                );
            }
        }
        assert_eq!(command_len(&[5, 0]).unwrap(), Some(50));
        assert_eq!(command_len(&[5, 3]).unwrap(), Some(4));
        for invalid in [&[4, 0][..], &[5, 1], &[5, 2, 0, 0, 0, 0, 0, 0, 0, 0, 3]] {
            assert!(command_len(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn stalled_readers_have_linear_polling_cost() {
        timeout(Duration::from_secs(10), async {
            let mut counts = Vec::new();
            for count in [64, 128] {
                let limits = GlobalLimits::default();
                let settings = Settings::new(limits);
                let (client, server, _endpoints) = pair(limits).await;
                let readers = Arc::new(Mutex::new(Readers::default()));
                let budget = Arc::new(Budget::new(Some(settings.bytes)));
                let task = tokio::spawn({
                    let readers = readers.clone();
                    let budget = budget.clone();
                    async move { collect(&server, &UUID, PASSWORD, settings, budget, readers).await }
                });
                let mut streams = Vec::new();
                for index in 0..count {
                    let mut stream = client.open_uni().await.unwrap();
                    stream.write_all(&[5]).await.unwrap();
                    streams.push(stream);
                    while readers.lock().accepted != index + 1 {
                        tokio::task::yield_now().await;
                    }
                }
                send_auth(&client).await;
                let pending = task.await.unwrap().unwrap();
                assert_eq!(pending.uni.len(), count);
                let polls = readers.lock().polls;
                assert!(polls <= count * 4 + 16, "{polls} polls for {count} readers");
                counts.push(polls);
                drop(pending);
                assert_eq!(budget.snapshot().active, 0);
                client.close(0u32.into(), b"done");
            }
            assert!(counts[1] <= 2 * counts[0] + 16);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn staging_budget_drops_excess_and_releases_retained_allocations() {
        timeout(Duration::from_secs(5), async {
            let limits = GlobalLimits {
                quic_receive_window: 65536,
                quic_stream_window: 16384,
                ..Default::default()
            };
            let settings = Settings::new(limits);
            let (client, server, _endpoints) = pair(limits).await;
            let budget = Arc::new(Budget::new(Some(settings.bytes)));
            let task = tokio::spawn({
                let budget = budget.clone();
                async move {
                    collect(
                        &server,
                        &UUID,
                        PASSWORD,
                        settings,
                        budget,
                        Arc::new(Mutex::new(Readers::default())),
                    )
                    .await
                }
            });
            let mut packet = vec![5, 2, 0, 1, 0, 1, 1, 0];
            packet.extend_from_slice(&40000u16.to_be_bytes());
            packet.extend_from_slice(&[1, 127, 0, 0, 1, 0, 53]);
            packet.resize(40017, 42);
            for _ in 0..2 {
                let mut stream = client.open_uni().await.unwrap();
                let _ = stream.write_all(&packet).await;
                assert_eq!(stream.stopped().await.unwrap(), Some(0u32.into()));
            }
            assert_eq!(budget.snapshot().active, packet.len());
            assert!(budget.snapshot().peak <= settings.bytes);
            assert!(budget.snapshot().rejected > 0);
            send_auth(&client).await;
            let mut pending = task.await.unwrap().unwrap();
            assert_eq!(pending.uni.len(), 1);
            let Some(UniCommand::Data(data)) = pending.uni.pop().unwrap().await.unwrap() else {
                panic!("expected packet")
            };
            assert_eq!(data, packet);
            assert_eq!(budget.snapshot().active, packet.len());
            drop(data);
            assert_eq!(budget.snapshot().active, 0);
            client.close(0u32.into(), b"done");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tiny_tcp_reads_share_capacity_charged_buffers() {
        timeout(Duration::from_secs(5), async {
            let (client, server, _endpoints) = pair(GlobalLimits::default()).await;
            let budget = Arc::new(Budget::new(Some(65804)));
            let task = tokio::spawn({
                let budget = budget.clone();
                async move {
                    let (send, recv) = server.accept_bi().await.unwrap();
                    read_bi(
                        ResetOnDrop(Some(send)),
                        recv,
                        server.remote_address(),
                        budget,
                        CancellationToken::new(),
                    )
                    .await
                }
            });
            let (mut send, _recv) = client.open_bi().await.unwrap();
            for _ in 0..128 {
                send.write_all(&[42]).await.unwrap();
                tokio::task::yield_now().await;
            }
            send.finish().unwrap();
            let buffered = task.await.unwrap().unwrap().unwrap();
            assert_eq!(buffered.prefix.len(), 1);
            assert_eq!(budget.snapshot().active, 4096);
            let mut stream = buffered.into_stream();
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, vec![42; 128]);
            assert_eq!(budget.snapshot().active, 0);
            client.close(0u32.into(), b"done");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_unpolled_tcp_readers_resets_both_directions() {
        timeout(Duration::from_secs(5), async {
            let (client, server, _endpoints) = pair(GlobalLimits::default()).await;
            let (mut send, mut recv) = client.open_bi().await.unwrap();
            send.write_all(&[5]).await.unwrap();
            let (server_send, server_recv) = server.accept_bi().await.unwrap();
            let budget = Arc::new(Budget::new(Some(65804)));
            let reader = read_bi(
                ResetOnDrop(Some(server_send)),
                server_recv,
                server.remote_address(),
                budget.clone(),
                CancellationToken::new(),
            );
            drop(reader);
            assert!(matches!(
                recv.read_chunk(1, true).await,
                Err(quinn::ReadError::Reset(_))
            ));
            assert_eq!(send.stopped().await.unwrap(), Some(0u32.into()));
            assert_eq!(budget.snapshot().active, 0);
            client.close(0u32.into(), b"done");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn authentication_hands_off_a_partially_read_body_without_loss() {
        timeout(Duration::from_secs(5), async {
            let limits = GlobalLimits::default();
            let settings = Settings::new(limits);
            let (client, server, _endpoints) = pair(limits).await;
            let budget = Arc::new(Budget::new(Some(settings.bytes)));
            let task = tokio::spawn({
                let budget = budget.clone();
                async move {
                    collect(
                        &server,
                        &UUID,
                        PASSWORD,
                        settings,
                        budget,
                        Arc::new(Mutex::new(Readers::default())),
                    )
                    .await
                }
            });
            let mut packet = vec![5, 2, 0, 1, 0, 1, 1, 0, 64, 0, 0xff];
            packet.extend((0..16384).map(|index| (index % 251) as u8));
            let mut stream = client.open_uni().await.unwrap();
            stream.write_all(&packet[..139]).await.unwrap();
            while budget.snapshot().active == 0 {
                tokio::task::yield_now().await;
            }
            send_auth(&client).await;
            let mut pending = task.await.unwrap().unwrap();
            assert_eq!(pending.uni.len(), 1);
            let reader = tokio::spawn(pending.uni.pop().unwrap());
            stream.write_all(&packet[139..]).await.unwrap();
            let Some(UniCommand::Data(data)) = reader.await.unwrap().unwrap() else {
                panic!("expected packet");
            };
            assert_eq!(data, packet);
            assert_eq!(budget.snapshot().active, packet.len());
            drop(data);
            assert_eq!(budget.snapshot().active, 0);
            client.close(0u32.into(), b"done");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_partial_bodies_releases_staging_memory() {
        timeout(Duration::from_secs(5), async {
            let limits = GlobalLimits::default();
            let settings = Settings::new(limits);
            let (client, server, _endpoints) = pair(limits).await;
            let budget = Arc::new(Budget::new(Some(settings.bytes)));
            let task = tokio::spawn({
                let budget = budget.clone();
                async move {
                    collect(
                        &server,
                        &UUID,
                        PASSWORD,
                        settings,
                        budget,
                        Arc::new(Mutex::new(Readers::default())),
                    )
                    .await
                }
            });
            let mut stream = client.open_uni().await.unwrap();
            stream
                .write_all(&[5, 2, 0, 1, 0, 1, 1, 0, 255, 255, 0xff])
                .await
                .unwrap();
            while budget.snapshot().active == 0 {
                tokio::task::yield_now().await;
            }
            assert_eq!(budget.snapshot().active, 65546);
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
            assert_eq!(budget.snapshot().active, 0);
            client.close(0u32.into(), b"done");
        })
        .await
        .unwrap();
    }
}
