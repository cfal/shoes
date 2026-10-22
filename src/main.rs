#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    shoes::cli::main();
}
