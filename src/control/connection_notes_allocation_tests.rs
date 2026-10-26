use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use super::connection_notes::{self, BUFFER_BYTES, MAX_EVENTS, MAX_FLOWS, Phase};
use super::flows::FlowRegistry;

struct CountingAllocator;

#[derive(Clone, Copy, Default)]
struct Counts {
    allocations: usize,
    live_bytes: isize,
}

// Debug-only, thread-local counting leaves release benchmark allocation unchanged.
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}

fn count(allocations: usize, bytes: isize) {
    let _ = COUNTS.try_with(|counts| {
        if let Some(mut current) = counts.get() {
            current.allocations += allocations;
            current.live_bytes += bytes;
            counts.set(Some(current));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            count(1, layout.size() as isize);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(0, -(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            count(1, size as isize - layout.size() as isize);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn disabled_notes_allocate_nothing_and_enabled_buffers_fit_budget() {
    let disabled = FlowRegistry::default();
    let resolver: Arc<dyn crate::resolver::Resolver> = Arc::new(crate::resolver::NativeResolver);
    COUNTS.set(Some(Counts::default()));
    for _ in 0..10_000 {
        let notes = std::hint::black_box(&disabled).start_notes();
        assert!(notes.is_none());
        let wrapped = connection_notes::resolver(&resolver, notes.as_ref(), Phase::Dial);
        assert!(Arc::ptr_eq(&resolver, &wrapped));
    }
    let disabled_allocations = COUNTS.replace(None).unwrap().allocations;
    assert_eq!(disabled_allocations, 0);

    let mut buffers = Vec::with_capacity(MAX_FLOWS);
    COUNTS.set(Some(Counts::default()));
    let registry = FlowRegistry::new(true);
    for _ in 0..MAX_FLOWS {
        let notes = registry.start_notes().unwrap();
        for _ in 0..MAX_EVENTS + 1 {
            notes.event(Phase::Routing, format_args!("fixture"));
        }
        buffers.push(notes);
    }
    assert!(registry.start_notes().is_none());
    let retained = COUNTS.replace(None).unwrap().live_bytes as usize;
    let budget = MAX_FLOWS * BUFFER_BYTES;
    assert!(retained <= budget, "retained {retained} exceeds {budget}");
    eprintln!(
        "disabled attempts=10000 allocations={disabled_allocations}; enabled buffers={MAX_FLOWS} retained_bytes={retained} budget={budget}"
    );
}
