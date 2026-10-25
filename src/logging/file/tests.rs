use super::*;
use std::sync::mpsc;

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Stalled {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    output: Output,
    stall_flush: bool,
}

impl Stalled {
    fn wait(&mut self) {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
            self.release.recv().unwrap();
        }
    }
}

impl Write for Stalled {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.stall_flush {
            self.wait();
        }
        self.output.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.stall_flush {
            self.wait();
        }
        Ok(())
    }
}

struct Release(mpsc::Sender<()>);

impl Drop for Release {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn stalled(stall_flush: bool) -> (Arc<FileLogWriter>, mpsc::Receiver<()>, Release, Output) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let output = Output::default();
    let writer = FileLogWriter::with_writer(Stalled {
        entered: Some(entered_tx),
        release: release_rx,
        output: output.clone(),
        stall_flush,
    })
    .unwrap();
    (Arc::new(writer), entered_rx, Release(release_tx), output)
}

fn emit(writer: &FileLogWriter, text: &str) {
    writer.write_log(&log::Record::builder().build(), text);
}

#[test]
fn stalled_storage_does_not_block_current_thread_relay_and_drops_newest_in_order() {
    let (writer, entered, release, output) = stalled(false);
    emit(&writer, "first");
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let producer = writer.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let relay = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut left, mut right) = tokio::io::duplex(16);
                tokio::join!(
                    async {
                        for n in 0..1000 {
                            emit(&producer, &n.to_string());
                        }
                        left.write_all(b"relay").await.unwrap();
                    },
                    async {
                        let mut bytes = [0; 5];
                        right.read_exact(&mut bytes).await.unwrap();
                        assert_eq!(&bytes, b"relay");
                    }
                );
            });
        done_tx.send(()).unwrap();
    });
    let completed = done_rx.recv_timeout(Duration::from_secs(2));
    let stats = writer.stats();
    drop(release);
    relay.join().unwrap();
    completed.unwrap();
    assert_eq!(stats.pending_records, MAX_RECORDS);
    assert!(stats.pending_bytes <= MAX_BYTES);
    assert_eq!(stats.dropped_records, 1001 - MAX_RECORDS as u64);
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
    let expected = format!(
        "first\n{}",
        (0..255).map(|n| format!("{n}\n")).collect::<String>()
    );
    assert_eq!(*output.0.lock(), expected.as_bytes());
    assert_eq!(writer.stats().pending_bytes, 0);
}

#[test]
fn byte_limit_includes_inflight_record_and_escaping_expansion() {
    let (writer, entered, release, _) = stalled(false);
    let large = "\u{202e}".repeat(MAX_RECORD_BYTES);
    emit(&writer, &large);
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    for _ in 0..MAX_RECORDS {
        emit(&writer, &large);
    }
    let stats = writer.stats();
    assert!(stats.pending_records < MAX_RECORDS);
    assert!(stats.pending_bytes <= MAX_BYTES);
    assert!(stats.pending_bytes > MAX_BYTES - MAX_RECORD_BYTES);
    assert!(stats.dropped_records > 0);
    assert_eq!(stats.truncated_records, stats.accepted_records);
    drop(release);
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn escaped_records_are_bounded_valid_unicode_and_single_line() {
    for input in ["\u{1b}\n\r\0".repeat(20000), "\u{65e5}".repeat(20000)] {
        let (line, truncated) = escaped_record(&input);
        assert!(truncated);
        assert!(line.len() <= MAX_RECORD_BYTES);
        assert!(line.ends_with(" [truncated]\n"));
        assert_eq!(line.lines().count(), 1);
        assert!(line.chars().all(|c| !c.is_control() || c == '\n'));
    }
}

#[test]
fn shutdown_deadline_discards_backlog_and_does_not_wait_again_on_drop() {
    let (writer, entered, release, _) = stalled(false);
    emit(&writer, "blocked");
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    emit(&writer, "queued");
    let started = Instant::now();
    assert_eq!(
        writer
            .shutdown_timeout(Duration::from_millis(30))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!writer.is_finished());
    assert!(writer.worker.lock().is_some());
    let stats = writer.stats();
    assert_eq!(stats.pending_records, 1);
    assert_eq!(stats.dropped_records, 1);
    emit(&writer, "after close");
    assert_eq!(writer.stats().dropped_records, 2);
    let worker = writer.worker.lock().take().unwrap();
    let started = Instant::now();
    drop(writer);
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(release);
    worker.join().unwrap();
}

#[test]
fn stalled_flush_is_bounded_and_recoverable() {
    let (writer, entered, release, _) = stalled(true);
    emit(&writer, "written");
    assert_eq!(
        writer
            .flush_timeout(Duration::from_millis(30))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    emit(&writer, "after flush timeout");
    drop(release);
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(writer.stats().written_records, 2);
}

struct FailingWriter {
    fail_on_flush: bool,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_on_flush {
            Ok(bytes.len())
        } else {
            Err(io::Error::other("private write error"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("private flush error"))
    }
}

#[test]
fn write_and_flush_errors_close_sink_without_recursive_logging() {
    for fail_on_flush in [false, true] {
        let writer = FileLogWriter::with_writer(FailingWriter { fail_on_flush }).unwrap();
        emit(&writer, "test");
        assert!(writer.shutdown_timeout(Duration::from_secs(2)).is_err());
        emit(&writer, "after failure");
        let stats = writer.stats();
        assert_eq!(stats.io_errors, 1);
        assert_eq!(stats.pending_records, 0);
        assert_eq!(stats.pending_bytes, 0);
        assert!(stats.dropped_records > 0);
        assert!(writer.is_finished());
    }
}

#[test]
fn flush_barrier_and_drop_drain_normal_writer() {
    let output = Output::default();
    let writer = FileLogWriter::with_writer(output.clone()).unwrap();
    emit(&writer, "first");
    writer.flush_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(*output.0.lock(), b"first\n");
    emit(&writer, "second");
    drop(writer);
    assert_eq!(*output.0.lock(), b"first\nsecond\n");
}

#[test]
fn open_failure_is_explicit() {
    let directory = tempfile::tempdir().unwrap();
    assert!(FileLogWriter::new(directory.path().to_str().unwrap()).is_err());
}
