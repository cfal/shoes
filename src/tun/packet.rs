use std::{
    mem,
    ops::{Deref, DerefMut, Range},
    sync::{LazyLock, Mutex},
};

const BUFFER_POOL_MAX_SIZE: usize = 64;
const BUFFER_POOL_MAX_CAPACITY: usize = 65_539;
static BUFFER_POOL: LazyLock<Mutex<Vec<Vec<u8>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Owns packet storage independently of the visible IP packet or UDP payload range.
#[derive(Debug)]
pub struct PacketBuffer {
    storage: Vec<u8>,
    range: Range<usize>,
    pooled: bool,
}

impl PacketBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut storage = BUFFER_POOL
            .lock()
            .ok()
            .and_then(|mut pool| pool.pop())
            .unwrap_or_default();
        storage.reserve(capacity);
        Self {
            storage,
            range: 0..0,
            pooled: true,
        }
    }

    pub fn copy_from_slice(data: &[u8]) -> Self {
        Self {
            storage: data.to_vec(),
            range: 0..data.len(),
            pooled: false,
        }
    }

    pub fn resize(&mut self, length: usize) {
        assert_eq!(self.range.start, 0);
        self.storage.resize(length, 0);
        self.range.end = length;
    }

    pub fn truncate(&mut self, length: usize) {
        self.range.end = self.range.start + self.len().min(length);
    }

    pub fn retain_range(&mut self, range: Range<usize>) {
        assert!(range.start <= range.end && range.end <= self.len());
        self.range = self.range.start + range.start..self.range.start + range.end;
    }

    pub fn into_payload(self, compact: bool) -> Self {
        let capacity = self.storage.capacity();
        let payload_len = self.len();
        // Tiny datagrams must not pin jumbo/MTU storage in per-flow queues.
        if (compact && capacity != payload_len) || capacity > payload_len.saturating_mul(2) {
            Self::copy_from_slice(&self)
        } else {
            self
        }
    }
}

impl Deref for PacketBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.storage[self.range.clone()]
    }
}

impl DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storage[self.range.clone()]
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        if self.pooled
            && self.storage.capacity() <= BUFFER_POOL_MAX_CAPACITY
            && let Ok(mut pool) = BUFFER_POOL.lock()
            && pool.len() < BUFFER_POOL_MAX_SIZE
        {
            let mut storage = mem::take(&mut self.storage);
            storage.clear();
            pool.push(storage);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_view_preserves_the_original_allocation() {
        let mut packet = PacketBuffer::copy_from_slice(&[7; 1504]);
        let pointer = packet.as_ptr();
        packet.retain_range(4..1504);
        packet.retain_range(28..1500);
        let payload = packet.into_payload(false);
        assert_eq!(payload.as_ptr(), pointer.wrapping_add(32));
        assert_eq!(payload.len(), 1472);
        assert_eq!(payload.storage.capacity(), 1504);
        assert_eq!(&*payload, &[7; 1472]);
    }

    #[test]
    fn tiny_payload_does_not_retain_oversized_storage() {
        let mut packet = PacketBuffer::copy_from_slice(&[9; 65539]);
        packet.retain_range(32..96);
        let payload = packet.into_payload(false);
        assert_eq!(payload.storage.capacity(), 64);
        assert_eq!(&*payload, &[9; 64]);
        assert!(!payload.pooled);
    }

    #[test]
    fn explicit_payload_allowance_uses_compact_storage_even_for_large_packets() {
        let mut packet = PacketBuffer::copy_from_slice(&[5; 1504]);
        packet.retain_range(32..1504);
        let payload = packet.into_payload(true);
        assert_eq!(payload.storage.capacity(), 1472);
        assert_eq!(payload.len(), 1472);
    }

    #[test]
    fn empty_payload_releases_its_backing_storage() {
        let mut packet = PacketBuffer::copy_from_slice(&[0; 1504]);
        packet.retain_range(32..32);
        let payload = packet.into_payload(false);
        assert_eq!(payload.len(), 0);
        assert_eq!(payload.storage.capacity(), 0);
    }
}
