//! One Hysteria2 UDP session as an AsyncMessageStream.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use log::debug;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

use super::frame::{build_datagrams, parse_datagram};

/// How many reassembled payloads may queue up before the reader blocks.
const INCOMING_CAPACITY: usize = 64;

/// Fragments waiting for their siblings, keyed by packet id.
///
/// A packet whose fragments never all arrive is dropped when its id is reused,
/// which is the protocol's own rule: a lost fragment loses the whole packet,
/// and UDP was never going to guarantee otherwise.
struct Reassembly {
    packets: HashMap<u16, Vec<Option<Vec<u8>>>>,
}

impl Reassembly {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    /// Feed one datagram; returns a complete payload when the last piece lands.
    fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_datagram(data)?;
        if parsed.fragment_count == 0 || parsed.fragment_id >= parsed.fragment_count {
            return None;
        }
        if parsed.fragment_count == 1 {
            return Some(parsed.payload.to_vec());
        }

        let slots = self
            .packets
            .entry(parsed.packet_id)
            .or_insert_with(|| vec![None; parsed.fragment_count as usize]);
        if slots.len() != parsed.fragment_count as usize {
            // The id was reused with a different fragment count, so the older
            // packet can never complete. Start over rather than mixing them.
            *slots = vec![None; parsed.fragment_count as usize];
        }
        slots[parsed.fragment_id as usize] = Some(parsed.payload.to_vec());

        if slots.iter().all(|slot| slot.is_some()) {
            let slots = self.packets.remove(&parsed.packet_id)?;
            Some(slots.into_iter().flatten().flatten().collect())
        } else {
            None
        }
    }
}

pub struct Hysteria2UdpSession {
    connection: quinn::Connection,
    session_id: u32,
    address: String,
    next_packet_id: AtomicU16,
    incoming: mpsc::Receiver<Vec<u8>>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Hysteria2UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2UdpSession")
            .field("session_id", &self.session_id)
            .field("address", &self.address)
            .finish()
    }
}

impl Hysteria2UdpSession {
    pub fn new(connection: quinn::Connection, session_id: u32, address: String) -> Self {
        let (tx, rx) = mpsc::channel(INCOMING_CAPACITY);
        let reader_connection = connection.clone();

        // One task reads this connection's datagrams. It filters by session id
        // and drops the rest, which is only correct because an outbound holds
        // at most one UDP session per connection: a second session would need
        // this to demultiplex instead, or its packets would vanish here.
        let reader_task = tokio::spawn(async move {
            let mut reassembly = Reassembly::new();
            loop {
                let datagram: Bytes = match reader_connection.read_datagram().await {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        debug!("Hysteria2 UDP reader for session {session_id} stopping: {e}");
                        return;
                    }
                };
                let Some(parsed) = parse_datagram(&datagram) else {
                    continue;
                };
                if parsed.session_id != session_id {
                    continue;
                }
                if let Some(payload) = reassembly.push(&datagram)
                    && tx.send(payload).await.is_err()
                {
                    return;
                }
            }
        });

        Self {
            connection,
            session_id,
            address,
            next_packet_id: AtomicU16::new(0),
            incoming: rx,
            reader_task,
        }
    }
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        // The protocol has no way to close a session; the server releases the
        // port on its own idle timer. All we owe is our own reader.
        self.reader_task.abort();
    }
}

impl Unpin for Hysteria2UdpSession {}

impl AsyncWriteMessage for Hysteria2UdpSession {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let max_datagram = this
            .connection
            .max_datagram_size()
            .ok_or_else(|| std::io::Error::other("peer does not accept QUIC datagrams"))?;

        let packet_id = this.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let datagrams =
            build_datagrams(this.session_id, packet_id, &this.address, buf, max_datagram)?;

        for datagram in datagrams {
            this.connection
                .send_datagram(Bytes::from(datagram))
                .map_err(|e| std::io::Error::other(format!("failed to send a datagram: {e}")))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for Hysteria2UdpSession {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.incoming.poll_recv(cx) {
            Poll::Ready(Some(payload)) => {
                if payload.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "UDP payload of {} bytes does not fit a {} byte buffer",
                            payload.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&payload);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the Hysteria2 UDP session ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for Hysteria2UdpSession {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for Hysteria2UdpSession {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for Hysteria2UdpSession {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for Hysteria2UdpSession {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hysteria2::frame::build_datagrams;

    #[test]
    fn test_reassembly_passes_an_unfragmented_packet_straight_through() {
        let mut reassembly = Reassembly::new();
        let datagrams = build_datagrams(1, 1, "a:1", b"hello", 1200).unwrap();
        assert_eq!(reassembly.push(&datagrams[0]).unwrap(), b"hello");
    }

    #[test]
    fn test_reassembly_waits_for_every_fragment() {
        let mut reassembly = Reassembly::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let datagrams = build_datagrams(1, 1, "a:1", &payload, 1200).unwrap();
        assert!(datagrams.len() >= 3);

        for datagram in &datagrams[..datagrams.len() - 1] {
            assert!(
                reassembly.push(datagram).is_none(),
                "an incomplete packet must not be delivered"
            );
        }
        assert_eq!(
            reassembly.push(datagrams.last().unwrap()).unwrap(),
            payload,
            "the last fragment completes the packet"
        );
    }

    #[test]
    fn test_reassembly_accepts_fragments_out_of_order() {
        let mut reassembly = Reassembly::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let mut datagrams = build_datagrams(1, 1, "a:1", &payload, 1200).unwrap();
        datagrams.reverse();

        let mut completed = None;
        for datagram in &datagrams {
            if let Some(done) = reassembly.push(datagram) {
                completed = Some(done);
            }
        }
        assert_eq!(completed.unwrap(), payload);
    }

    #[test]
    fn test_reassembly_drops_a_malformed_datagram() {
        let mut reassembly = Reassembly::new();
        assert!(reassembly.push(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_reassembly_drops_a_fragment_id_past_its_count() {
        let mut reassembly = Reassembly::new();
        let mut datagrams = build_datagrams(1, 1, "a:1", b"hello", 1200).unwrap();
        // fragment_count stays 1 while fragment_id claims to be the second.
        datagrams[0][6] = 1;
        assert!(reassembly.push(&datagrams[0]).is_none());
    }
}
