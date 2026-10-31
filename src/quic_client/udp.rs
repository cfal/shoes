use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use tokio::{io::ReadBuf, sync::mpsc};

use super::{Protocol, hysteria2, session::Generation, tuic};
use crate::{
    address::NetLocation,
    async_stream::*,
    config::quic_client::TuicUdpMode,
    udp_fragments::{MAX_UDP_PAYLOAD, UdpFragments},
};

const QUEUE_SIZE: usize = 64;

pub(super) struct Fragment<'a> {
    pub session: u32,
    pub packet: u16,
    pub index: u8,
    pub count: u8,
    pub location: Option<NetLocation>,
    pub payload: &'a [u8],
}

pub(super) struct Registry {
    next: u64,
    maximum: u64,
    closed: bool,
    entries: HashMap<u32, mpsc::Sender<Bytes>>,
    fragments: UdpFragments<(u32, u16)>,
}

impl Registry {
    pub fn new(maximum: u64) -> Self {
        Self {
            next: 0,
            maximum,
            closed: false,
            entries: HashMap::new(),
            fragments: UdpFragments::new(),
        }
    }
    pub fn exhausted(&self) -> bool {
        self.next > self.maximum
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.entries.clear();
        self.fragments = UdpFragments::new();
    }
    fn register(&mut self) -> io::Result<Option<(u32, mpsc::Receiver<Bytes>)>> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "QUIC connection closed",
            ));
        }
        if self.exhausted() {
            return Ok(None);
        }
        let id = self.next as u32;
        self.next += 1;
        let (sender, receiver) = mpsc::channel(QUEUE_SIZE);
        self.entries.insert(id, sender);
        Ok(Some((id, receiver)))
    }
    fn remove(&mut self, id: u32) {
        self.entries.remove(&id);
        self.fragments.retain(|(session, _)| *session != id);
    }
    fn deliver(&mut self, fragment: Fragment<'_>) {
        let Some(sender) = self.entries.get(&fragment.session) else {
            return;
        };
        if let Ok(Some((_, data))) = self.fragments.push(
            (fragment.session, fragment.packet),
            fragment.count,
            fragment.index,
            fragment.location,
            fragment.payload,
        ) {
            let _ = sender.try_send(data);
        }
    }
}

pub(super) async fn receive(
    connection: quinn::Connection,
    registry: Arc<parking_lot::Mutex<Registry>>,
    protocol: Protocol,
) {
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    let mut streams = tokio::task::JoinSet::new();
    let is_tuic = matches!(protocol, Protocol::Tuic(_));
    loop {
        tokio::select! {
            packet = connection.read_datagram() => {
                let Ok(packet) = packet else { break };
                let fragment = match protocol {
                    Protocol::Hysteria2(_) => hysteria2::decode(&packet),
                    Protocol::Tuic(_) => tuic::decode(&packet),
                };
                if let Ok(fragment) = fragment { registry.lock().deliver(fragment); }
            }
            stream = connection.accept_uni(), if is_tuic && streams.len() < QUEUE_SIZE => {
                let Ok(mut stream) = stream else { break };
                streams.spawn(async move {
                    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(tuic::MAX_PACKET)).await
                });
            }
            Some(packet) = streams.join_next(), if !streams.is_empty() => {
                if let Ok(Ok(Ok(packet))) = packet {
                    if let Ok(fragment) = tuic::decode(&packet) { registry.lock().deliver(fragment); }
                }
            }
            _ = expiry.tick() => registry.lock().fragments.expire(),
        }
    }
    registry.lock().close();
}

pub(super) struct Association {
    generation: Arc<Generation>,
    target: NetLocation,
    id: u32,
    packet: u16,
    receiver: mpsc::Receiver<Bytes>,
    closed: bool,
    write: Option<PendingIo>,
    shutdown: Option<PendingIo>,
}

type PendingIo = Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + Sync>>;

impl Association {
    pub fn new(generation: Arc<Generation>, target: NetLocation) -> io::Result<Option<Self>> {
        let registration = generation.registry.lock().register()?;
        Ok(registration.map(|(id, receiver)| Self {
            generation,
            target,
            id,
            receiver,
            packet: 0,
            closed: false,
            write: None,
            shutdown: None,
        }))
    }
    fn close(&mut self) -> bool {
        if !self.closed {
            self.closed = true;
            self.generation.registry.lock().remove(self.id);
            self.receiver.close();
            return true;
        }
        false
    }
    fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(write) = &mut self.write {
            let result = std::task::ready!(write.as_mut().poll(cx));
            self.write = None;
            return Poll::Ready(result);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        if self.close() {
            if let Some(sender) = &self.generation.dissociate {
                let _ = sender.try_send(tuic::Dissociate {
                    id: self.id as u16,
                    completed: None,
                });
            }
        }
    }
}

impl AsyncReadMessage for Association {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || self.generation.connection().close_reason().is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "QUIC association closed",
            )));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(data)) if data.len() <= buf.remaining() => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP read buffer too small",
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "QUIC association closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWriteMessage for Association {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.write.is_some() {
            return self.poll_write(cx);
        }
        if data.len() > MAX_UDP_PAYLOAD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds 65535 bytes",
            )));
        }
        let connection = self.generation.connection();
        let mtu = connection.max_datagram_size().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "QUIC datagrams unavailable")
        })?;
        let packets = match &self.generation.protocol {
            Protocol::Hysteria2(_) => {
                hysteria2::encode(self.id, self.packet, &self.target, data, mtu)?
            }
            Protocol::Tuic(config) => tuic::encode(
                self.id,
                self.packet,
                &self.target,
                data,
                if config.udp_relay_mode == TuicUdpMode::Quic {
                    tuic::MAX_PACKET
                } else {
                    mtu
                },
            )?,
        };
        self.packet = self.packet.wrapping_add(1);
        if matches!(&self.generation.protocol, Protocol::Tuic(config) if config.udp_relay_mode == TuicUdpMode::Quic)
        {
            let connection = self.generation.connection().clone();
            self.write = Some(Box::pin(async move {
                tuic::send_command(&connection, &packets[0]).await
            }));
            return self.poll_write(cx);
        }
        for packet in packets {
            self.generation
                .connection()
                .send_datagram(packet)
                .map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncFlushMessage for Association {
    fn poll_flush_message(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write(cx)
    }
}
impl AsyncShutdownMessage for Association {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_write(cx))?;
        if self.close() {
            if let Some(sender) = self.generation.dissociate.clone() {
                let id = self.id as u16;
                self.shutdown = Some(Box::pin(async move {
                    tokio::time::timeout(Duration::from_secs(5), async move {
                        let (completed, result) = tokio::sync::oneshot::channel();
                        sender
                            .send(tuic::Dissociate {
                                id,
                                completed: Some(completed),
                            })
                            .await
                            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
                        result
                            .await
                            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?
                    })
                    .await?
                }));
            }
        }
        if let Some(shutdown) = &mut self.shutdown {
            let result = std::task::ready!(shutdown.as_mut().poll(cx));
            self.shutdown = None;
            return Poll::Ready(result);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Association {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for Association {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(id: u32, packet: u16, count: u8, index: u8, payload: &[u8]) -> Fragment<'_> {
        Fragment {
            session: id,
            packet,
            count,
            index,
            location: Some(NetLocation::from_str("127.0.0.1:53", None).unwrap()),
            payload,
        }
    }

    #[tokio::test]
    async fn ids_never_reuse_and_closed_registrations_fail() {
        let mut registry = Registry::new(1);
        let (first, mut receiver) = registry.register().unwrap().unwrap();
        registry.remove(first);
        assert!(receiver.recv().await.is_none());
        let (second, _) = registry.register().unwrap().unwrap();
        assert_ne!(first, second);
        assert!(registry.register().unwrap().is_none());
        registry.close();
        assert!(registry.register().is_err());
    }

    #[tokio::test]
    async fn demux_drops_unknown_full_and_retired_sessions_without_blocking() {
        let mut registry = Registry::new(u16::MAX.into());
        let (a, mut ra) = registry.register().unwrap().unwrap();
        let (b, mut rb) = registry.register().unwrap().unwrap();
        for _ in 0..QUEUE_SIZE + 10 {
            registry.deliver(fragment(a, 0, 1, 0, b"a"));
        }
        registry.deliver(fragment(b, 0, 1, 0, b"b"));
        assert_eq!(rb.recv().await.unwrap().as_ref(), b"b");
        for _ in 0..QUEUE_SIZE {
            assert_eq!(ra.recv().await.unwrap().as_ref(), b"a");
        }
        assert!(ra.try_recv().is_err());
        for id in 100..200 {
            registry.deliver(fragment(id, 0, 2, 0, b"unknown"));
        }
        registry.deliver(fragment(b, 1, 2, 0, b"head"));
        registry.deliver(fragment(b, 1, 2, 1, b"tail"));
        assert_eq!(rb.recv().await.unwrap().as_ref(), b"headtail");
        registry.close();
        assert!(ra.recv().await.is_none());
        assert!(rb.recv().await.is_none());
    }
}
