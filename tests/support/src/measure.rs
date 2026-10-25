//! Process-wide measurements require an isolated test executable or child process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Allocations {
    pub live_bytes: usize,
    pub live_allocations: usize,
    pub allocations: usize,
    pub peak_bytes: usize,
}

/// Requested Rust heap, not allocator arenas, foreign allocations, or RSS.
pub struct CountingAllocator {
    live_bytes: AtomicUsize,
    live_allocations: AtomicUsize,
    allocations: AtomicUsize,
    peak_bytes: AtomicUsize,
}

impl CountingAllocator {
    pub const fn new() -> Self {
        Self {
            live_bytes: AtomicUsize::new(0),
            live_allocations: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            peak_bytes: AtomicUsize::new(0),
        }
    }

    fn allocated(&self, size: usize) {
        let live = self.live_bytes.fetch_add(size, Relaxed) + size;
        self.peak_bytes.fetch_max(live, Relaxed);
        self.allocations.fetch_add(1, Relaxed);
    }

    pub fn snapshot(&self) -> Allocations {
        Allocations {
            live_bytes: self.live_bytes.load(Relaxed),
            live_allocations: self.live_allocations.load(Relaxed),
            allocations: self.allocations.load(Relaxed),
            peak_bytes: self.peak_bytes.load(Relaxed),
        }
    }

    pub fn reset_peak(&self) {
        self.peak_bytes
            .store(self.live_bytes.load(Relaxed), Relaxed);
    }
}

impl Default for CountingAllocator {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.allocated(layout.size());
            self.live_allocations.fetch_add(1, Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.live_bytes.fetch_sub(layout.size(), Relaxed);
        self.live_allocations.fetch_sub(1, Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            // Preserve rule_allocation's conservative peak even for in-place realloc.
            self.allocated(size);
            self.live_bytes.fetch_sub(layout.size(), Relaxed);
        }
        result
    }
}

/// Wait for a known lifecycle state, not merely two identical (possibly leaked) samples.
pub async fn settle<T: Debug>(
    label: &str,
    limit: Duration,
    mut sample: impl FnMut() -> T,
    ready: impl Fn(&T) -> bool,
) -> T {
    let deadline = Instant::now() + limit;
    loop {
        let value = sample();
        if ready(&value) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: cleanup deadline: {value:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub struct ProcessUsage {
    pub fds: usize,
    pub rss_kib: usize,
}

#[cfg(target_os = "linux")]
pub fn process_usage(pid: u32) -> std::io::Result<ProcessUsage> {
    let mut fds = 0;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        entry?;
        fds += 1;
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| std::io::Error::other("missing or invalid VmRSS in proc status"))?;
    Ok(ProcessUsage { fds, rss_kib })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_counts_zeroed_and_reallocated_blocks() {
        let allocator = CountingAllocator::new();
        let layout = Layout::from_size_align(32, 8).unwrap();
        unsafe {
            let ptr = allocator.alloc_zeroed(layout);
            assert!(!ptr.is_null());
            assert_eq!(std::slice::from_raw_parts(ptr, 32), &[0; 32]);
            let ptr = allocator.realloc(ptr, layout, 64);
            assert!(!ptr.is_null());
            let sample = allocator.snapshot();
            assert_eq!(sample.live_bytes, 64);
            assert_eq!(sample.live_allocations, 1);
            assert_eq!(sample.allocations, 2);
            assert_eq!(sample.peak_bytes, 96);
            allocator.reset_peak();
            assert_eq!(allocator.snapshot().peak_bytes, 64);
            allocator.dealloc(ptr, Layout::from_size_align(64, 8).unwrap());
        }
        assert_eq!(allocator.snapshot().live_bytes, 0);
        assert_eq!(allocator.snapshot().live_allocations, 0);
    }

    #[tokio::test]
    #[should_panic(expected = "cleanup deadline")]
    async fn stable_but_wrong_samples_do_not_pass_cleanup() {
        settle(
            "retained task",
            Duration::from_millis(20),
            || 1,
            |&n| n == 0,
        )
        .await;
    }
}
