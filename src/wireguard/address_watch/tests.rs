use super::*;
use parking_lot::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct FakeProbe(Arc<Mutex<io::Result<Option<IpAddr>>>>);

impl SourceProbe for FakeProbe {
    fn source(&self, _target: SocketAddr) -> io::Result<Option<IpAddr>> {
        match &*self.0.lock() {
            Ok(ip) => Ok(*ip),
            Err(error) => Err(io::Error::new(error.kind(), "probe could not run")),
        }
    }
}

struct Harness {
    state: Arc<Mutex<io::Result<Option<IpAddr>>>>,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

async fn start(initial: &str) -> Harness {
    let state = Arc::new(Mutex::new(Ok(Some(ip(initial)))));
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let task = tokio::spawn(run(
        vec!["203.0.113.1:51820".parse().unwrap()],
        FakeProbe(state.clone()),
        WATCH_INTERVAL,
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
        },
    ));
    // Let the first snapshot finish. Paused time does not auto-advance while a blocking probe
    // runs, so this is deterministic.
    tokio::time::sleep(Duration::from_millis(100)).await;
    Harness { state, count, task }
}

impl Harness {
    async fn ticks(&self, n: u32) {
        // Ticks fire 100 ms before each wake-up, and auto-advance waits for the blocking probe.
        for _ in 0..n {
            tokio::time::sleep(WATCH_INTERVAL).await;
        }
    }
    fn fired(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

#[tokio::test(start_paused = true)]
async fn unchanged_source_never_fires() {
    let h = start("192.0.2.1").await;
    h.ticks(10).await;
    assert_eq!(h.fired(), 0);
    h.task.abort();
}

#[tokio::test(start_paused = true)]
async fn source_change_fires_once() {
    let h = start("192.0.2.1").await;
    h.ticks(2).await;
    *h.state.lock() = Ok(Some(ip("198.51.100.1")));
    h.ticks(1).await;
    assert_eq!(h.fired(), 1);
    h.ticks(5).await;
    assert_eq!(h.fired(), 1);
    h.task.abort();
}

#[tokio::test(start_paused = true)]
async fn losing_and_regaining_the_route_are_changes() {
    let h = start("192.0.2.1").await;
    *h.state.lock() = Ok(None);
    h.ticks(1).await;
    assert_eq!(h.fired(), 1);
    *h.state.lock() = Ok(Some(ip("192.0.2.1")));
    h.ticks(1).await;
    assert_eq!(h.fired(), 2);
    h.ticks(3).await;
    assert_eq!(h.fired(), 2);
    h.task.abort();
}

/// Descriptor exhaustion or a socket-protector error is not a network change.
#[tokio::test(start_paused = true)]
async fn a_probe_that_cannot_run_is_not_a_change() {
    let h = start("192.0.2.1").await;
    *h.state.lock() = Err(io::Error::other("too many open files"));
    h.ticks(3).await;
    assert_eq!(h.fired(), 0);
    *h.state.lock() = Ok(Some(ip("192.0.2.1")));
    h.ticks(2).await;
    assert_eq!(h.fired(), 0);
    // A real change is still seen after the probe recovers.
    *h.state.lock() = Ok(Some(ip("198.51.100.1")));
    h.ticks(1).await;
    assert_eq!(h.fired(), 1);
    h.task.abort();
}

#[test]
fn os_probe_reports_loopback_for_loopback_target() {
    let probe = OsProbe { interface: None };
    assert_eq!(
        probe.source("127.0.0.1:9".parse().unwrap()).unwrap(),
        Some(ip("127.0.0.1"))
    );
}

/// Inside a VPN app the probe must be protected like the real WireGuard socket, or the OS
/// answers with the tunnel address. A protector that refuses this thread makes the probe fail.
#[cfg(feature = "ffi")]
#[test]
fn os_probe_goes_through_socket_protection() {
    struct Restore(Arc<dyn crate::tun::SocketProtector>);
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::tun::set_global_socket_protector(self.0.clone());
        }
    }
    let _restore = Restore(crate::tun::get_global_socket_protector());
    let owner = std::thread::current().id();
    let protected = Arc::new(AtomicUsize::new(0));
    let seen = protected.clone();
    crate::tun::set_global_socket_protector(Arc::new(crate::tun::FnSocketProtector::new(
        move |_| {
            if std::thread::current().id() == owner {
                seen.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "protection denied",
                ))
            } else {
                Ok(())
            }
        },
    )));
    let probe = OsProbe { interface: None };
    let error = probe.source("127.0.0.1:9".parse().unwrap()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(protected.load(Ordering::SeqCst), 1);
}
