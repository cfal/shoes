#[cfg(not(target_has_atomic = "64"))]
pub(crate) use portable_atomic::{AtomicI64, AtomicU64};
#[cfg(target_has_atomic = "64")]
pub(crate) use std::sync::atomic::{AtomicI64, AtomicU64};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::Ordering;

    #[test]
    fn concurrent_counter_crosses_32_bit_boundary() {
        let start = u64::from(u32::MAX) - 100;
        let counter = AtomicU64::new(start);
        let barrier = Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let counter = &counter;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..100_000 {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Relaxed), start + 400_000);
    }

    #[test]
    fn signed_offset_preserves_values_outside_32_bits() {
        let offset = AtomicI64::new(-(1i64 << 40));
        assert_eq!(offset.load(Ordering::Acquire), -(1i64 << 40));
        offset.store(1i64 << 40, Ordering::Release);
        assert_eq!(offset.load(Ordering::Acquire), 1i64 << 40);
    }
}
