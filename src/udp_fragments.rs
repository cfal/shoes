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
    async fn rejects_bad_indices_and_caps_packet_and_total_bytes() {
        let mut cache = UdpFragments::new();
        assert!(cache.push(1, 0, 0, Some(address()), b"x").is_err());
        assert!(cache.push(1, 2, 2, Some(address()), b"x").is_err());
        assert!(
            cache
                .push(1, 2, 0, Some(address()), &vec![0; MAX_UDP_PAYLOAD])
                .unwrap()
                .is_none()
        );
        assert!(cache.push(1, 2, 1, None, b"x").is_err());
        for key in 2..1000 {
            let _ = cache.push(key, 255, 0, Some(address()), &vec![0; 60000]);
        }
        assert!(cache.bytes <= MAX_BYTES);
        assert!(cache.packets.len() <= MAX_PACKETS);
    }
}
