use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::time::Instant;

use crate::address::NetLocation;

pub const MAX_UDP_PAYLOAD: usize = 65535;
const MAX_PACKETS: usize = 64;
const MAX_BYTES: usize = 1024 * 1024;
const FRAGMENT_TTL: Duration = Duration::from_secs(5);

struct Packet {
    created: Instant,
    location: Option<NetLocation>,
    fragments: Vec<Option<Bytes>>,
    received: usize,
    bytes: usize,
}

pub struct UdpFragments<K> {
    packets: HashMap<K, Packet>,
    bytes: usize,
}

impl<K: Eq + Hash + Clone> UdpFragments<K> {
    pub fn new() -> Self {
        Self {
            packets: HashMap::new(),
            bytes: 0,
        }
    }

    pub fn expire(&mut self) {
        self.packets
            .retain(|_, packet| packet.created.elapsed() < FRAGMENT_TTL);
        self.bytes = self.packets.values().map(|packet| packet.bytes).sum();
    }

    fn remove(&mut self, key: &K) -> Option<Packet> {
        let packet = self.packets.remove(key)?;
        self.bytes -= packet.bytes;
        Some(packet)
    }

    pub fn push(
        &mut self,
        key: K,
        count: u8,
        index: u8,
        location: Option<NetLocation>,
        data: &[u8],
    ) -> io::Result<Option<(NetLocation, Bytes)>> {
        self.expire();
        if count == 0 || index >= count || data.len() > MAX_UDP_PAYLOAD {
            self.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP fragment",
            ));
        }
        if count == 1 {
            self.remove(&key);
            return location
                .map(|location| Some((location, Bytes::copy_from_slice(data))))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing UDP address"));
        }
        if !self.packets.contains_key(&key) && self.packets.len() >= MAX_PACKETS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP fragment packet budget exhausted",
            ));
        }
        if self.bytes + data.len() > MAX_BYTES {
            self.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP fragment byte budget exhausted",
            ));
        }
        let packet = self.packets.entry(key.clone()).or_insert_with(|| Packet {
            created: Instant::now(),
            location: None,
            fragments: vec![None; count as usize],
            received: 0,
            bytes: 0,
        });
        if packet.fragments.len() != count as usize
            || packet.fragments[index as usize].is_some()
            || packet.bytes + data.len() > MAX_UDP_PAYLOAD
            || location
                .as_ref()
                .zip(packet.location.as_ref())
                .is_some_and(|(a, b)| a != b)
        {
            self.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent or oversized UDP fragments",
            ));
        }
        if packet.location.is_none() {
            packet.location = location;
        }
        packet.bytes += data.len();
        self.bytes += data.len();
        packet.received += 1;
        // Own only the admitted payload, not an arbitrarily large parent datagram.
        packet.fragments[index as usize] = Some(Bytes::copy_from_slice(data));
        if packet.received != count as usize {
            return Ok(None);
        }
        let packet = self.remove(&key).unwrap();
        let location = packet.location.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing UDP fragment address")
        })?;
        let mut data = BytesMut::with_capacity(packet.bytes);
        for fragment in packet.fragments {
            data.extend_from_slice(&fragment.unwrap());
        }
        Ok(Some((location, data.freeze())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> NetLocation {
        NetLocation::from_str("127.0.0.1:53", None).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn out_of_order_packets_are_isolated_and_expire() {
        let mut cache = UdpFragments::new();
        assert!(cache.push((1, 1), 2, 1, None, b"tail").unwrap().is_none());
        assert!(
            cache
                .push((2, 1), 2, 0, Some(address()), b"other")
                .unwrap()
                .is_none()
        );
        let (_, data) = cache
            .push((1, 1), 2, 0, Some(address()), b"head")
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"headtail");
        assert_eq!(cache.bytes, 5);
        tokio::time::advance(FRAGMENT_TTL).await;
        cache.expire();
        assert!(cache.packets.is_empty());
        assert_eq!(cache.bytes, 0);
    }

    #[tokio::test]
    async fn packet_budget_is_independent_and_completion_releases_capacity() {
        let mut cache = UdpFragments::new();
        for key in 0..MAX_PACKETS {
            assert!(
                cache
                    .push(key, 2, 0, Some(address()), b"x")
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(cache.packets.len(), MAX_PACKETS);
        assert_eq!(cache.bytes, MAX_PACKETS);
        assert_eq!(
            cache
                .push(MAX_PACKETS, 2, 0, None, b"x")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            cache.push(0, 2, 1, None, b"y").unwrap().unwrap().1.as_ref(),
            b"xy"
        );
        assert_eq!(cache.packets.len(), MAX_PACKETS - 1);
        assert_eq!(cache.bytes, MAX_PACKETS - 1);
        assert!(cache.push(MAX_PACKETS, 2, 0, None, b"z").unwrap().is_none());
        assert_eq!(cache.packets.len(), MAX_PACKETS);
        assert_eq!(cache.bytes, MAX_PACKETS);
    }

    #[tokio::test]
    async fn byte_budget_is_exact_and_rejection_releases_affected_packet() {
        let mut cache = UdpFragments::new();
        let payload = vec![0; MAX_UDP_PAYLOAD];
        let full_packets = MAX_BYTES / MAX_UDP_PAYLOAD;
        for key in 0..full_packets {
            cache.push(key, 2, 0, Some(address()), &payload).unwrap();
        }
        let remainder = MAX_BYTES % MAX_UDP_PAYLOAD;
        cache
            .push(full_packets, 2, 0, Some(address()), &payload[..remainder])
            .unwrap();
        assert_eq!(cache.bytes, MAX_BYTES);
        assert_eq!(cache.packets.len(), full_packets + 1);
        assert!(cache.packets.len() < MAX_PACKETS);
        assert_eq!(
            cache
                .push(full_packets + 1, 2, 0, None, b"x")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(cache.bytes, MAX_BYTES);
        assert_eq!(
            cache
                .push(full_packets, 2, 1, None, b"x")
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(cache.bytes, MAX_BYTES - remainder);
        assert_eq!(cache.packets.len(), full_packets);
        cache
            .push(full_packets, 2, 0, Some(address()), &payload[..remainder])
            .unwrap();
        assert_eq!(cache.bytes, MAX_BYTES);
    }

    #[tokio::test]
    async fn invalid_fragments_clean_only_the_affected_packet_and_allow_reuse() {
        let oversized = vec![0; MAX_UDP_PAYLOAD];
        let other_address = NetLocation::from_str("127.0.0.2:53", None).unwrap();
        for (count, index, location, data) in [
            (0, 0, None, &b"x"[..]),
            (2, 2, None, &b"x"[..]),
            (2, 0, None, &b"duplicate"[..]),
            (3, 2, None, &b"changed count"[..]),
            (2, 1, Some(other_address), &b"conflict"[..]),
            (2, 1, None, oversized.as_slice()),
        ] {
            let mut cache = UdpFragments::new();
            cache.push(1, 2, 0, Some(address()), b"head").unwrap();
            cache.push(2, 2, 0, Some(address()), b"other").unwrap();
            assert_eq!(
                cache
                    .push(1, count, index, location, data)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert!(!cache.packets.contains_key(&1));
            assert_eq!(cache.packets.len(), 1);
            assert_eq!(cache.bytes, 5);
            cache.push(1, 2, 1, None, b"tail").unwrap();
            assert_eq!(
                cache
                    .push(1, 2, 0, Some(address()), b"head")
                    .unwrap()
                    .unwrap()
                    .1
                    .as_ref(),
                b"headtail"
            );
            assert_eq!(cache.packets.len(), 1);
            assert_eq!(cache.bytes, 5);
        }
    }

    #[tokio::test]
    async fn exact_payload_limit_and_missing_address_release_state() {
        let mut cache = UdpFragments::new();
        let payload = vec![7; MAX_UDP_PAYLOAD - 1];
        cache.push(1, 2, 0, Some(address()), &payload).unwrap();
        let (location, result) = cache.push(1, 2, 1, None, &[7]).unwrap().unwrap();
        assert_eq!(location, address());
        assert_eq!(result.as_ref(), vec![7; MAX_UDP_PAYLOAD]);
        assert_eq!(cache.bytes, 0);
        assert!(cache.packets.is_empty());
        cache.push(1, 2, 0, Some(address()), &payload).unwrap();
        assert_eq!(
            cache.push(1, 2, 1, None, &[7, 7]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(cache.bytes, 0);
        assert!(cache.packets.is_empty());
        cache.push(1, 2, 0, None, b"head").unwrap();
        assert_eq!(
            cache.push(1, 2, 1, None, b"tail").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(cache.bytes, 0);
        assert!(cache.packets.is_empty());
        cache.push(1, 2, 0, Some(address()), b"old").unwrap();
        assert_eq!(
            cache
                .push(1, 1, 0, Some(address()), b"new")
                .unwrap()
                .unwrap()
                .1
                .as_ref(),
            b"new"
        );
        assert_eq!(cache.bytes, 0);
        assert!(cache.packets.is_empty());
        cache.push(1, 2, 0, None, b"old").unwrap();
        assert_eq!(
            cache.push(1, 1, 0, None, b"new").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(cache.bytes, 0);
        assert!(cache.packets.is_empty());
        assert!(
            cache
                .push(1, 2, 0, Some(address()), b"reused")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn later_fragments_do_not_extend_creation_deadline() {
        let mut cache = UdpFragments::new();
        cache.push(1, 3, 0, Some(address()), b"first").unwrap();
        tokio::time::advance(Duration::from_secs(4)).await;
        cache.push(1, 3, 1, None, b"second").unwrap();
        assert_eq!(cache.bytes, 11);
        tokio::time::advance(Duration::from_secs(1)).await;
        cache.expire();
        assert!(cache.packets.is_empty());
        assert_eq!(cache.bytes, 0);
        cache.push(1, 2, 0, Some(address()), b"new").unwrap();
        assert_eq!(
            cache
                .push(1, 2, 1, None, b"tail")
                .unwrap()
                .unwrap()
                .1
                .as_ref(),
            b"newtail"
        );
        assert!(cache.packets.is_empty());
        assert_eq!(cache.bytes, 0);
    }
}
