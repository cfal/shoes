//! One Hysteria2 UDP session as an AsyncMessageStream.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use log::debug;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::quic_outbound::datagram_router::DatagramRouter;
use crate::quic_transport::fragments::FragmentTable;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

use super::frame::{build_datagrams, parse_datagram};

/// Where the session id sits in a Hysteria2 datagram: the first four bytes,
/// before the packet id and the fragment numbers
/// (`core/internal/protocol/proxy.go:151-223`).
///
/// This is all the connection's demultiplexer needs to read. The rest of the
/// header is parsed by the session itself, which is where that session's
/// reassembly table lives.
pub fn session_id_of(datagram: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(datagram.get(0..4)?.try_into().ok()?))
}

pub struct Hysteria2UdpSession {
    connection: quinn::Connection,
    router: Arc<DatagramRouter>,
    session_id: u32,
    address: String,
    next_packet_id: AtomicU16,
    incoming: mpsc::Receiver<Bytes>,
    fragments: FragmentTable,
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
    /// Open a session on a connection, taking its id from the connection's
    /// demultiplexer.
    ///
    /// Registering here rather than in the caller keeps the registration and
    /// the deregistration in `Drop` as one pair that cannot come apart.
    pub fn new(
        connection: quinn::Connection,
        router: Arc<DatagramRouter>,
        address: String,
    ) -> Self {
        let (session_id, incoming) = router.register();
        debug!("Hysteria2: UDP session {session_id} to {address}");

        Self {
            connection,
            router,
            session_id,
            address,
            next_packet_id: AtomicU16::new(0),
            incoming,
            fragments: FragmentTable::new(),
        }
    }
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        // The protocol has no way to close a session; the server releases the
        // port on its own idle timer. All we owe is our seat in the router, so
        // that its datagrams stop being queued for nobody.
        self.router.deregister(self.session_id);
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

        // The router has already established that these datagrams are ours.
        // What is left - the header past the session id, and the reassembly -
        // is per-session work and belongs here rather than on the reader shared
        // by every session on the connection.
        loop {
            let datagram = match this.incoming.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => datagram,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "the Hysteria2 UDP session ended",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            };

            let Some(parsed) = parse_datagram(&datagram) else {
                continue;
            };
            let Some(payload) = this.fragments.push(
                parsed.packet_id,
                parsed.fragment_id,
                parsed.fragment_count,
                parsed.payload,
            ) else {
                // A fragment that completes nothing. Not a read.
                continue;
            };

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
            return Poll::Ready(Ok(()));
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

    /// Parse a wire datagram and feed its fragment in, exactly as the reader
    /// task does. Keeps these tests on the encoder's real output rather than on
    /// hand-written fragment numbers.
    fn push_wire(table: &mut FragmentTable, datagram: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_datagram(datagram)?;
        table.push(
            parsed.packet_id,
            parsed.fragment_id,
            parsed.fragment_count,
            parsed.payload,
        )
    }

    #[test]
    fn test_reassembly_passes_an_unfragmented_packet_straight_through() {
        let mut table = FragmentTable::new();
        let datagrams = build_datagrams(1, 1, "a:1", b"hello", 1200).unwrap();
        assert_eq!(push_wire(&mut table, &datagrams[0]).unwrap(), b"hello");
    }

    #[test]
    fn test_reassembly_waits_for_every_fragment() {
        let mut table = FragmentTable::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let datagrams = build_datagrams(1, 1, "a:1", &payload, 1200).unwrap();
        assert!(datagrams.len() >= 3);

        for datagram in &datagrams[..datagrams.len() - 1] {
            assert!(
                push_wire(&mut table, datagram).is_none(),
                "an incomplete packet must not be delivered"
            );
        }
        assert_eq!(
            push_wire(&mut table, datagrams.last().unwrap()).unwrap(),
            payload,
            "the last fragment completes the packet"
        );
    }

    #[test]
    fn test_reassembly_accepts_fragments_out_of_order() {
        let mut table = FragmentTable::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let mut datagrams = build_datagrams(1, 1, "a:1", &payload, 1200).unwrap();
        datagrams.reverse();

        let mut completed = None;
        for datagram in &datagrams {
            if let Some(done) = push_wire(&mut table, datagram) {
                completed = Some(done);
            }
        }
        assert_eq!(completed.unwrap(), payload);
    }

    #[test]
    fn test_reassembly_drops_a_malformed_datagram() {
        let mut table = FragmentTable::new();
        assert!(push_wire(&mut table, &[0u8; 4]).is_none());
    }

    #[test]
    fn test_reassembly_drops_a_fragment_id_past_its_count() {
        let mut table = FragmentTable::new();
        let mut datagrams = build_datagrams(1, 1, "a:1", b"hello", 1200).unwrap();
        // fragment_count stays 1 while fragment_id claims to be the second.
        datagrams[0][6] = 1;
        assert!(push_wire(&mut table, &datagrams[0]).is_none());
    }
}
