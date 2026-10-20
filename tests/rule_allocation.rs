use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use shoes::config::Config;
use shoes::rule_set::{Behavior, Format, RuleSetConfig};
use shoes::rules::{Compiler, Expression};

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(ptr, layout, size) };
        if !result.is_null() {
            // Conservatively count both buffers even when realloc is in place.
            allocated(size);
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn peak<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    let result = run();
    (result, PEAK.load(Relaxed).saturating_sub(baseline))
}

fn load_peak(bytes: &[u8], format: Format) -> (std::io::Result<()>, usize) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source");
    std::fs::write(&path, bytes).unwrap();
    let configs = [Config::RuleSet(RuleSetConfig {
        rule_set: "test".into(),
        path,
        format: Some(format),
        behavior: (format == Format::MihomoYaml).then_some(Behavior::Domain),
        code: (format == Format::GeositeDat).then(|| "TEST".into()),
        attributes: vec![],
    })];
    peak(|| shoes::rule_set::load(&configs, &mut Compiler::default()))
}

fn message(tag: u32, bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    prost::encoding::encode_key(tag, prost::encoding::WireType::LengthDelimited, &mut output);
    prost::encoding::encode_varint(bytes.len() as u64, &mut output);
    output.extend_from_slice(bytes);
    output
}

// A separate test executable keeps allocator measurements isolated from parallel
// library tests. Inputs are allocated before measuring compiler-owned memory.
#[test]
fn adversarial_inputs_stay_within_their_compilation_reserves() {
    for yaml in [
        format!("payload: [{}]", "[],".repeat(350_000)),
        format!("{{[{}]: a}}", "a,".repeat(350_000)),
        format!("[[{}]]", ":,".repeat(350_000)),
    ] {
        let (result, used) = load_peak(yaml.as_bytes(), Format::MihomoYaml);
        assert!(result.is_err());
        assert!(
            used < 32 * 1024 * 1024 + yaml.len() * 2,
            "YAML peak: {used}"
        );
        println!("YAML bytes={}, peak={used}", yaml.len());
    }
    let json = format!(r#"{{"{}\n":0}}"#, "a".repeat(1024 * 1024));
    let (result, used) = load_peak(json.as_bytes(), Format::SingboxJson);
    assert!(result.is_err());
    assert!(used < json.len() * 4 + 4096, "JSON peak: {used}");
    println!("JSON bytes={}, peak={used}", json.len());

    let count = 100_000;
    let mut domain = message(2, b"example.com");
    domain.extend_from_slice(&[0x1a, 0].repeat(count));
    let mut category = message(1, b"TEST");
    category.extend(message(2, &domain));
    let dat = message(1, &category);
    let (result, used) = load_peak(&dat, Format::GeositeDat);
    result.unwrap();
    assert!(
        used < dat.len() * 10 + count * 160 + 4096,
        "DAT peak: {used}"
    );
    println!("DAT attributes={count}, peak={used}");

    let patterns = vec![format!("(?i){}", "a".repeat(60_000)); 8];
    let bytes: usize = patterns.iter().map(String::len).sum();
    let (_, used) = peak(|| Compiler::default().compile(Expression::DomainRegex(patterns)));
    let reserve = bytes * 512 + 64 * 1024 * 1024;
    assert!(used < reserve, "regex peak: {used}, reserve: {reserve}");
    println!("regex bytes={bytes}, peak={used}, reserve={reserve}");
}
