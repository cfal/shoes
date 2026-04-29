//! Traffic statistics tracking for the TUN server.
//!
//! Provides global atomic byte counters and a callback mechanism for reporting
//! traffic statistics to the host application (iOS/Android) via FFI.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;

/// Cumulative upload bytes (device → proxy).
static UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cumulative download bytes (proxy → device).
static DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// Optional callback invoked with (upload_bytes, download_bytes).
type TrafficCallback = Arc<dyn Fn(u64, u64) + Send + Sync>;
static TRAFFIC_CALLBACK: OnceLock<RwLock<Option<TrafficCallback>>> = OnceLock::new();

/// Add bytes to the upload counter.
pub fn add_upload_bytes(bytes: u64) {
    UPLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Add bytes to the download counter.
pub fn add_download_bytes(bytes: u64) {
    DOWNLOAD_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Reset traffic counters (called on service start).
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn reset_traffic_counters() {
    UPLOAD_BYTES.store(0, Ordering::Relaxed);
    DOWNLOAD_BYTES.store(0, Ordering::Relaxed);
}

/// Set the traffic callback function.
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn set_traffic_callback(callback: Arc<dyn Fn(u64, u64) + Send + Sync>) {
    let lock = TRAFFIC_CALLBACK.get_or_init(|| RwLock::new(None));
    *lock.write() = Some(callback);
}

/// Clear the traffic callback.
/// Called from platform FFI modules (ios.rs / android.rs).
#[allow(dead_code)]
pub fn clear_traffic_callback() {
    if let Some(lock) = TRAFFIC_CALLBACK.get() {
        *lock.write() = None;
    }
}

/// Invoke the traffic callback with current counter values.
pub fn report_traffic() {
    let Some(lock) = TRAFFIC_CALLBACK.get() else {
        return;
    };
    let guard = lock.read();
    if let Some(ref cb) = *guard {
        let upload = UPLOAD_BYTES.load(Ordering::Relaxed);
        let download = DOWNLOAD_BYTES.load(Ordering::Relaxed);
        cb(upload, download);
    }
}

// Wrapper around an `AsyncRead + AsyncWrite` stream that counts bytes
// transferred through the traffic counters in real time.
//
// Bytes read from the inner stream are counted as upload (device → proxy).
// Bytes written to the inner stream are counted as download (proxy → device).
//
// This is used instead of post-hoc counting so that long-lived TCP connections
// (large downloads, persistent streams) report traffic incrementally.
pin_project_lite::pin_project! {
    pub struct TrafficCountingStream<S> {
        #[pin]
        inner: S,
    }
}

impl<S> TrafficCountingStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: tokio::io::AsyncRead> tokio::io::AsyncRead for TrafficCountingStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                add_upload_bytes(n as u64);
            }
        }
        result
    }
}

impl<S: tokio::io::AsyncWrite> tokio::io::AsyncWrite for TrafficCountingStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n @ 1..)) = &result {
            add_download_bytes(*n as u64);
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Get current traffic counters.
#[cfg(test)]
pub fn get_traffic_counters() -> (u64, u64) {
    (
        UPLOAD_BYTES.load(Ordering::Relaxed),
        DOWNLOAD_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    // Serialize tests that mutate shared global state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_add_and_reset_counters() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_traffic_counters();

        add_upload_bytes(100);
        add_download_bytes(200);
        add_upload_bytes(50);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 150);
        assert_eq!(down, 200);

        reset_traffic_counters();
        let (up, down) = get_traffic_counters();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }

    #[test]
    fn test_callback_invoked_with_current_counters() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_traffic_counters();

        let captured_up = Arc::new(AtomicU64::new(0));
        let captured_down = Arc::new(AtomicU64::new(0));
        let up_clone = captured_up.clone();
        let down_clone = captured_down.clone();

        set_traffic_callback(Arc::new(move |up, down| {
            up_clone.store(up, Ordering::Relaxed);
            down_clone.store(down, Ordering::Relaxed);
        }));

        add_upload_bytes(1000);
        add_download_bytes(2000);
        report_traffic();

        assert_eq!(captured_up.load(Ordering::Relaxed), 1000);
        assert_eq!(captured_down.load(Ordering::Relaxed), 2000);

        clear_traffic_callback();
    }

    #[test]
    fn test_clear_callback_stops_reporting() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_traffic_counters();

        let call_count = Arc::new(AtomicU64::new(0));
        let count_clone = call_count.clone();

        set_traffic_callback(Arc::new(move |_, _| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        }));

        report_traffic();
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        clear_traffic_callback();
        report_traffic();
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            1,
            "callback should not fire after clear"
        );
    }

    #[tokio::test]
    async fn test_counting_stream_reports_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_traffic_counters();

        let data = b"hello world";
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut stream = TrafficCountingStream::new(cursor);

        // Read from the stream — counted as upload
        let mut buf = vec![0u8; 32];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(n, 11);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 11, "bytes read should be counted as upload");
        assert_eq!(down, 0, "no writes yet");
    }

    #[tokio::test]
    async fn test_counting_stream_reports_write_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_traffic_counters();

        let buf = Vec::new();
        let mut stream = TrafficCountingStream::new(std::io::Cursor::new(buf));

        // Write to the stream — counted as download
        let n = tokio::io::AsyncWriteExt::write(&mut stream, b"response data")
            .await
            .unwrap();
        assert_eq!(n, 13);

        let (up, down) = get_traffic_counters();
        assert_eq!(up, 0, "no reads yet");
        assert_eq!(down, 13, "bytes written should be counted as download");
    }

    #[test]
    fn test_report_without_callback_does_not_panic() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_traffic_callback();
        report_traffic(); // should be a no-op
    }
}
