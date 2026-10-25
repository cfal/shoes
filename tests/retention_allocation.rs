use std::sync::Arc;

use shoes::rules::{Compiler, Expression, Outcome, Predicate};
use shoes_test_support::measure::{Allocations, CountingAllocator};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator::new();

fn generation(index: usize) -> Arc<Predicate> {
    Compiler::default()
        .compile(Expression::Domain(
            (0..256)
                .map(|n| format!("host-{n:03}-{index:04}.test"))
                .collect(),
        ))
        .unwrap()
}

fn failed_compilation() {
    let error = Compiler::default()
        .compile(Expression::All(vec![
            Expression::Domain((0..256).map(|n| format!("host-{n:03}.test")).collect()),
            Expression::DestinationPort(vec![0]),
        ]))
        .unwrap_err();
    assert!(error.to_string().contains("ports must be"));
}

fn assert_same_live_allocations(before: Allocations, after: Allocations) {
    assert_eq!(after.live_bytes, before.live_bytes, "requested live bytes");
    assert_eq!(
        after.live_allocations, before.live_allocations,
        "live allocation count"
    );
}

// One test per executable: a mutex would not isolate libtest's other allocations.
#[test]
fn compiled_generations_and_rejected_partial_builds_release_their_allocations() {
    println!("allocator=System; requested Rust heap only; warmup=8; cycles=64; pinned=4");
    for index in 0..8 {
        drop(generation(index));
        failed_compilation();
    }
    let empty = ALLOCATOR.snapshot();
    let mut current = generation(0);
    let baseline = ALLOCATOR.snapshot();
    assert!(baseline.live_bytes > empty.live_bytes);
    assert!(baseline.live_allocations > empty.live_allocations);
    let mut samples = [baseline; 64];
    ALLOCATOR.reset_peak();
    for (index, sample) in samples.iter_mut().enumerate() {
        failed_compilation();
        assert_same_live_allocations(baseline, ALLOCATOR.snapshot());

        let previous_owner = Arc::downgrade(&current);
        let pins: [Arc<Predicate>; 4] =
            std::array::from_fn(|offset| generation(index * 4 + offset));
        let weak_pins = pins.each_ref().map(Arc::downgrade);
        current = generation(index + 1);
        assert!(
            previous_owner.upgrade().is_none(),
            "replaced owner retained"
        );
        for (offset, predicate) in pins.iter().enumerate() {
            assert_eq!(
                predicate.evaluate(
                    Some(&format!("host-042-{:04}.test", index * 4 + offset)),
                    None,
                    443
                ),
                Outcome::Match
            );
        }
        assert!(ALLOCATOR.snapshot().live_bytes > baseline.live_bytes);
        drop(pins);
        assert!(weak_pins.iter().all(|pin| pin.upgrade().is_none()));
        drop(weak_pins);
        drop(previous_owner);
        *sample = ALLOCATOR.snapshot();
        assert_same_live_allocations(baseline, *sample);
    }
    drop(current);
    let destroyed = ALLOCATOR.snapshot();
    assert_same_live_allocations(empty, destroyed);
    for (cycle, sample) in samples.iter().enumerate() {
        println!(
            "cycle={cycle} state=one_owner live_bytes={} live_allocations={} allocations={} peak_bytes={}",
            sample.live_bytes, sample.live_allocations, sample.allocations, sample.peak_bytes
        );
    }
    println!("state=owner_destroyed before={empty:?} after={destroyed:?}");
}
