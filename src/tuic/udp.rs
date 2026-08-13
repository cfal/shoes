//! One TUIC UDP association as an AsyncMessageStream.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use log::debug;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};
use crate::config::TuicUdpRelayMode;

use super::frame::{
    ADDRESS_TYPE_NONE, COMMAND_TYPE_PACKET, MAX_HEADER_LEN, TUIC_VERSION, encode_dissociate,
    encode_heartbeat, encode_packet_header,
};

/// How many reassembled payloads may queue up before the reader blocks.
const INCOMING_CAPACITY: usize = 64;

/// Ceiling on a single Packet command read from a unidirectional stream: the
/// two command bytes, the largest header the protocol allows, and a maximal
/// UDP payload.
const MAX_COMMAND_BYTES: usize = 2 + MAX_HEADER_LEN + u16::MAX as usize;

/// Build the datagrams for one outgoing UDP packet.
///
/// Only the first fragment carries the address; the rest use address type 0xff,
/// which is what the specification defines that value for.
pub(crate) fn build_packets(
    assoc_id: u16,
    packet_id: u16,
    target: &NetLocation,
    payload: &[u8],
    max_packet: usize,
) -> std::io::Result<Vec<Vec<u8>>> {
    let first_header = encode_packet_header(assoc_id, packet_id, 1, 0, 0, Some(target)).len();
    let later_header = encode_packet_header(assoc_id, packet_id, 1, 1, 0, None).len();

    let (first_capacity, later_capacity) = match (
        max_packet.checked_sub(first_header).filter(|c| *c > 0),
        max_packet.checked_sub(later_header).filter(|c| *c > 0),
    ) {
        (Some(first), Some(later)) => (first, later),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("packet limit of {max_packet} is smaller than a TUIC packet header"),
            ));
        }
    };

    // The count goes into every header, so it has to be known before the first
    // fragment is built.
    let fragment_count = if payload.len() <= first_capacity {
        1usize
    } else {
        1 + (payload.len() - first_capacity).div_ceil(later_capacity)
    };
    if fragment_count > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes needs {fragment_count} fragments, over the 255 the protocol allows",
                payload.len()
            ),
        ));
    }

    let mut packets = Vec::with_capacity(fragment_count);
    let mut offset = 0;
    for index in 0..fragment_count {
        let capacity = if index == 0 {
            first_capacity
        } else {
            later_capacity
        };
        let end = (offset + capacity).min(payload.len());
        let chunk = &payload[offset..end];
        let address = if index == 0 { Some(target) } else { None };
        let mut packet = encode_packet_header(
            assoc_id,
            packet_id,
            fragment_count as u8,
            index as u8,
            chunk.len() as u16,
            address,
        );
        packet.extend_from_slice(chunk);
        packets.push(packet);
        offset = end;
    }
    Ok(packets)
}

/// Fragments waiting for their siblings, keyed by packet id.
struct Reassembly {
    packets: HashMap<u16, Vec<Option<Vec<u8>>>>,
}

impl Reassembly {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    /// Feed a whole Packet command, starting at the version byte.
    fn push(&mut self, command: &[u8]) -> Option<Vec<u8>> {
        if command.len() < 2 || command[0] != TUIC_VERSION || command[1] != COMMAND_TYPE_PACKET {
            return None;
        }
        let body = &command[2..];
        if body.len() < 8 {
            return None;
        }
        let packet_id = u16::from_be_bytes([body[2], body[3]]);
        let fragment_total = body[4];
        let fragment_id = body[5];
        let size = u16::from_be_bytes([body[6], body[7]]) as usize;

        if fragment_total == 0 || fragment_id >= fragment_total {
            return None;
        }

        // Skip the address to reach the payload; its encoding is what tells us
        // where the payload starts.
        let address_len = match body.get(8)? {
            &ADDRESS_TYPE_NONE => 1,
            0x00 => 1 + 1 + *body.get(9)? as usize + 2,
            0x01 => 1 + 4 + 2,
            0x02 => 1 + 16 + 2,
            _ => return None,
        };
        let payload_start = 8 + address_len;
        let payload_end = payload_start.checked_add(size)?;
        if body.len() < payload_end {
            return None;
        }
        let payload = body[payload_start..payload_end].to_vec();

        if fragment_total == 1 {
            return Some(payload);
        }

        let slots = self
            .packets
            .entry(packet_id)
            .or_insert_with(|| vec![None; fragment_total as usize]);
        if slots.len() != fragment_total as usize {
            *slots = vec![None; fragment_total as usize];
        }
        slots[fragment_id as usize] = Some(payload);

        if slots.iter().all(|slot| slot.is_some()) {
            let slots = self.packets.remove(&packet_id)?;
            Some(slots.into_iter().flatten().flatten().collect())
        } else {
            None
        }
    }

    /// The association id a Packet command carries, without parsing the rest.
    fn assoc_id_of(command: &[u8]) -> Option<u16> {
        if command.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([command[2], command[3]]))
    }
}

pub struct TuicUdpSession {
    connection: quinn::Connection,
    assoc_id: u16,
    target: NetLocation,
    mode: TuicUdpRelayMode,
    next_packet_id: AtomicU16,
    incoming: mpsc::Receiver<Vec<u8>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for TuicUdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicUdpSession")
            .field("assoc_id", &self.assoc_id)
            .field("target", &self.target)
            .finish()
    }
}

impl TuicUdpSession {
    pub fn new(
        connection: quinn::Connection,
        assoc_id: u16,
        target: NetLocation,
        mode: TuicUdpRelayMode,
        heartbeat_interval: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::channel(INCOMING_CAPACITY);
        let mut tasks = Vec::with_capacity(3);

        // The server replies in whichever mode the association's first packet
        // used, so only that reader is started. Heartbeats travel as datagrams
        // in both modes, but they carry no payload and the reader ignores
        // anything that is not a Packet for us.
        match mode {
            TuicUdpRelayMode::Native => {
                let datagram_connection = connection.clone();
                let tx = tx.clone();
                tasks.push(tokio::spawn(async move {
                    let mut reassembly = Reassembly::new();
                    loop {
                        let datagram: Bytes = match datagram_connection.read_datagram().await {
                            Ok(datagram) => datagram,
                            Err(e) => {
                                debug!(
                                    "TUIC datagram reader for association {assoc_id} stopping: {e}"
                                );
                                return;
                            }
                        };
                        if Reassembly::assoc_id_of(&datagram) != Some(assoc_id) {
                            continue;
                        }
                        if let Some(payload) = reassembly.push(&datagram)
                            && tx.send(payload).await.is_err()
                        {
                            return;
                        }
                    }
                }));
            }
            TuicUdpRelayMode::Quic => {
                let stream_connection = connection.clone();
                let tx = tx.clone();
                tasks.push(tokio::spawn(async move {
                    let mut reassembly = Reassembly::new();
                    loop {
                        let mut recv = match stream_connection.accept_uni().await {
                            Ok(recv) => recv,
                            Err(e) => {
                                debug!(
                                    "TUIC uni stream reader for association {assoc_id} stopping: {e}"
                                );
                                return;
                            }
                        };
                        // One command per stream, which is what the reference
                        // sends and what our server now sends.
                        let command = match recv.read_to_end(MAX_COMMAND_BYTES).await {
                            Ok(command) => command,
                            Err(e) => {
                                debug!("TUIC uni stream dropped: {e}");
                                continue;
                            }
                        };
                        if Reassembly::assoc_id_of(&command) != Some(assoc_id) {
                            continue;
                        }
                        if let Some(payload) = reassembly.push(&command)
                            && tx.send(payload).await.is_err()
                        {
                            return;
                        }
                    }
                }));
            }
        }

        // The specification asks for heartbeats only while a relaying task is
        // in flight, which is exactly the lifetime of this session. An idle
        // connection is left to quinn's own keep-alive.
        let heartbeat_connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(heartbeat_interval);
            ticker.tick().await; // the first tick fires immediately
            loop {
                ticker.tick().await;
                if heartbeat_connection
                    .send_datagram(Bytes::from(encode_heartbeat()))
                    .is_err()
                {
                    return;
                }
            }
        }));

        Self {
            connection,
            assoc_id,
            target,
            mode,
            next_packet_id: AtomicU16::new(0),
            incoming: rx,
            tasks,
        }
    }
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        // Best effort: tell the server the association is over so it can free
        // the socket rather than waiting out its idle timeout.
        let connection = self.connection.clone();
        let assoc_id = self.assoc_id;
        tokio::spawn(async move {
            if let Ok(mut stream) = connection.open_uni().await {
                let _ = stream.write_all(&encode_dissociate(assoc_id)).await;
                let _ = stream.finish();
            }
        });
    }
}

impl Unpin for TuicUdpSession {}

impl AsyncWriteMessage for TuicUdpSession {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let packet_id = this.next_packet_id.fetch_add(1, Ordering::Relaxed);

        match this.mode {
            TuicUdpRelayMode::Native => {
                let max_packet = this
                    .connection
                    .max_datagram_size()
                    .ok_or_else(|| std::io::Error::other("peer does not accept QUIC datagrams"))?;
                let packets =
                    build_packets(this.assoc_id, packet_id, &this.target, buf, max_packet)?;
                for packet in packets {
                    this.connection
                        .send_datagram(Bytes::from(packet))
                        .map_err(|e| {
                            std::io::Error::other(format!("failed to send a datagram: {e}"))
                        })?;
                }
            }
            TuicUdpRelayMode::Quic => {
                // A stream has no size limit of its own, so the only bound is
                // the packet's own 16-bit length field. The reference passes
                // the same ceiling, which means a real UDP payload never
                // fragments in this mode.
                let packets = build_packets(
                    this.assoc_id,
                    packet_id,
                    &this.target,
                    buf,
                    u16::MAX as usize,
                )?;
                let connection = this.connection.clone();
                // Opening a stream is async and this is a poll, so the send is
                // handed to a task. Ordering within a packet is preserved
                // because one task writes all of its fragments in turn.
                tokio::spawn(async move {
                    for packet in packets {
                        match connection.open_uni().await {
                            Ok(mut stream) => {
                                if stream.write_all(&packet).await.is_err() {
                                    return;
                                }
                                let _ = stream.finish();
                            }
                            Err(e) => {
                                debug!("TUIC uni send failed: {e}");
                                return;
                            }
                        }
                    }
                });
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for TuicUdpSession {
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
                "the TUIC UDP association ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for TuicUdpSession {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for TuicUdpSession {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for TuicUdpSession {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for TuicUdpSession {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::net::Ipv4Addr;

    fn target() -> NetLocation {
        NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53)
    }

    #[test]
    fn test_single_fragment_carries_the_address() {
        let packets = build_packets(1, 2, &target(), &[0u8; 100], 1200).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][6], 1, "fragment total");
        assert_ne!(
            packets[0][10], ADDRESS_TYPE_NONE,
            "the first fragment carries the address"
        );
    }

    #[test]
    fn test_later_fragments_use_the_none_address() {
        let packets = build_packets(1, 2, &target(), &[0u8; 5000], 1200).unwrap();
        assert!(packets.len() > 1);
        assert_ne!(packets[0][10], ADDRESS_TYPE_NONE);
        for packet in &packets[1..] {
            assert_eq!(packet[10], ADDRESS_TYPE_NONE);
        }
    }

    #[test]
    fn test_every_fragment_fits_the_limit() {
        let packets = build_packets(1, 2, &target(), &[0u8; 5000], 1200).unwrap();
        assert!(packets.iter().all(|p| p.len() <= 1200));
    }

    #[test]
    fn test_refuses_more_than_255_fragments() {
        assert!(build_packets(1, 2, &target(), &[0u8; 100_000], 200).is_err());
    }

    #[test]
    fn test_refuses_a_limit_below_the_header() {
        assert!(build_packets(1, 2, &target(), b"x", 8).is_err());
    }

    #[test]
    fn test_reassembly_round_trips_an_unfragmented_packet() {
        let mut reassembly = Reassembly::new();
        let packets = build_packets(1, 2, &target(), b"hello", 1200).unwrap();
        assert_eq!(reassembly.push(&packets[0]).unwrap(), b"hello");
    }

    #[test]
    fn test_reassembly_waits_for_every_fragment() {
        let mut reassembly = Reassembly::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let packets = build_packets(1, 2, &target(), &payload, 1200).unwrap();
        assert!(packets.len() >= 3);

        for packet in &packets[..packets.len() - 1] {
            assert!(reassembly.push(packet).is_none());
        }
        assert_eq!(reassembly.push(packets.last().unwrap()).unwrap(), payload);
    }

    #[test]
    fn test_reassembly_rejects_a_foreign_command() {
        let mut reassembly = Reassembly::new();
        let mut packets = build_packets(1, 2, &target(), b"hello", 1200).unwrap();
        packets[0][1] = 0x04; // Heartbeat, not Packet
        assert!(reassembly.push(&packets[0]).is_none());
    }

    #[test]
    fn test_assoc_id_is_read_without_parsing_the_rest() {
        let packets = build_packets(0xbeef, 2, &target(), b"hello", 1200).unwrap();
        assert_eq!(Reassembly::assoc_id_of(&packets[0]), Some(0xbeef));
        assert_eq!(Reassembly::assoc_id_of(&[0u8; 3]), None);
    }
}
