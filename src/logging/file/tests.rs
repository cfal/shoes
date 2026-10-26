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
    if completed.is_err() {
        drop(release);
        relay.join().unwrap();
        panic!("logging blocked relay progress: {completed:?}");
    }
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
    let escaped_len = escaped_record(&large).0.len();
    assert_eq!(writer.stats().pending_records, 1);
    assert_eq!(writer.stats().pending_bytes, escaped_len);
    for _ in 0..MAX_RECORDS {
        emit(&writer, &large);
    }
    let stats = writer.stats();
    assert!(stats.pending_records < MAX_RECORDS);
    assert!(stats.pending_bytes <= MAX_BYTES);
    assert!(stats.pending_bytes > MAX_BYTES - MAX_RECORD_BYTES);
    assert!(stats.dropped_records > 0);
    assert_eq!(stats.accepted_records as usize, MAX_BYTES / escaped_len);
    assert_eq!(stats.pending_records as u64, stats.accepted_records);
    assert_eq!(stats.pending_bytes, stats.pending_records * escaped_len);
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
        if self.fail_on_flush {
            Err(io::Error::other("private flush error"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn write_and_flush_errors_close_sink_without_recursive_logging() {
    for fail_on_flush in [false, true] {
        let writer = FileLogWriter::with_writer(FailingWriter { fail_on_flush }).unwrap();
        emit(&writer, "test");
        if fail_on_flush {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut state = writer.shared.state.lock();
            while state.stats.written_records != 1 {
                assert!(Instant::now() < deadline);
                writer.shared.changed.wait_until(&mut state, deadline);
            }
        }
        assert!(writer.shutdown_timeout(Duration::from_secs(2)).is_err());
        let failed = writer.stats();
        assert_eq!(failed.accepted_records, 1);
        assert_eq!(failed.written_records, u64::from(fail_on_flush));
        assert_eq!(failed.dropped_records, u64::from(!fail_on_flush));
        emit(&writer, "after failure");
        let stats = writer.stats();
        assert_eq!(stats.io_errors, 1);
        assert_eq!(stats.pending_records, 0);
        assert_eq!(stats.pending_bytes, 0);
        assert_eq!(stats.dropped_records, failed.dropped_records + 1);
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

struct GatedBufferedWriter {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    buffered: Vec<u8>,
    output: Output,
}

impl Write for GatedBufferedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let _ = self.entered.send(());
        // Disconnection releases every gate during failed-test cleanup.
        let _ = self.release.recv_timeout(Duration::from_secs(5));
        self.buffered.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.write_all(&self.buffered)?;
        self.buffered.clear();
        Ok(())
    }
}

#[test]
fn earlier_flush_completes_before_later_flush_or_shutdown_target() {
    for shutdown in [false, true] {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let output = Output::default();
        let writer = Arc::new(
            FileLogWriter::with_writer(GatedBufferedWriter {
                entered: entered_tx,
                release: release_rx,
                buffered: Vec::new(),
                output: output.clone(),
            })
            .unwrap(),
        );
        emit(&writer, "A");
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let first_writer = writer.clone();
        let (first_tx, first_rx) = mpsc::channel();
        let first = std::thread::spawn(move || {
            let result = first_writer.flush_timeout(Duration::from_secs(2));
            let _ = first_tx.send(result);
        });
        let request_deadline = Instant::now() + Duration::from_secs(1);
        let mut state = writer.shared.state.lock();
        while state.flush_target != Some(1) {
            assert!(Instant::now() < request_deadline);
            writer
                .shared
                .changed
                .wait_until(&mut state, request_deadline);
        }
        drop(state);
        emit(&writer, "B");

        // Hold the state lock until parked: only the second lifecycle request
        // can notify us while A is gated and the first flusher is waiting.
        let mut state = writer.shared.state.lock();
        let second_writer = writer.clone();
        let (second_tx, second_rx) = mpsc::channel();
        let second = std::thread::spawn(move || {
            let result = if shutdown {
                second_writer.shutdown_timeout(Duration::from_secs(2))
            } else {
                second_writer.flush_timeout(Duration::from_secs(2))
            };
            let _ = second_tx.send(result);
        });
        let notified = writer
            .shared
            .changed
            .wait_for(&mut state, Duration::from_secs(1));
        assert!(!notified.timed_out());
        assert_eq!(state.flush_target, Some(2));
        drop(state);
        assert!(matches!(
            first_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        release_tx.send(()).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let first_result = first_rx.recv_timeout(Duration::from_secs(1));
        let first_output = output.0.lock().clone();
        let second_pending = matches!(second_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
        // Release before inspecting results so assertion failures cannot strand B.
        drop(release_tx);
        first.join().unwrap();
        let second_result = second_rx.recv_timeout(Duration::from_secs(2));
        second.join().unwrap();
        writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
        if let Some(worker) = writer.worker.lock().take() {
            worker.join().unwrap();
        }

        first_result.unwrap().unwrap();
        assert_eq!(first_output, b"A\n");
        assert!(second_pending);
        second_result.unwrap().unwrap();
        assert_eq!(*output.0.lock(), b"A\nB\n");
    }
}

#[test]
fn finished_sink_flush_returns_immediately_after_timeout_discards_records() {
    let (writer, entered, release, _) = stalled(false);
    emit(&writer, "A");
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    emit(&writer, "B");
    assert_eq!(
        writer.shutdown_timeout(Duration::ZERO).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    drop(release);
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
    assert!(writer.is_finished());
    let stats = writer.stats();
    assert_eq!(stats.accepted_records, 2);
    assert_eq!(stats.written_records, 1);
    assert_eq!(stats.dropped_records, 1);
    let began = Instant::now();
    assert_eq!(
        writer
            .flush_timeout(Duration::from_secs(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(began.elapsed() < Duration::from_secs(1));
}

#[test]
fn fresh_sink_flush_completes_without_accepting_records() {
    let writer = FileLogWriter::with_writer(Output::default()).unwrap();
    assert_eq!(writer.shared.state.lock().flushed_through, None);
    let began = Instant::now();
    writer.flush_timeout(Duration::from_secs(2)).unwrap();
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(writer.shared.state.lock().flushed_through, Some(0));
    let stats = writer.stats();
    assert_eq!(stats.accepted_records, 0);
    assert_eq!(stats.written_records, 0);
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn finished_sink_flush_succeeds_after_clean_shutdown() {
    let writer = FileLogWriter::with_writer(Output::default()).unwrap();
    emit(&writer, "A");
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
    assert!(writer.is_finished());
    writer.flush_timeout(Duration::ZERO).unwrap();
    assert_eq!(writer.shared.state.lock().flushed_through, Some(1));
}

#[test]
fn concurrent_producers_preserve_bounds_and_each_producers_order() {
    for large in [false, true] {
        let (writer, entered, release, output) = stalled(false);
        emit(&writer, "prime");
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        let start = Arc::new(std::sync::Barrier::new(4));
        let mut producers = Vec::new();
        for producer in 0..4 {
            let writer = writer.clone();
            let start = start.clone();
            producers.push(std::thread::spawn(move || {
                let payload = if large {
                    "peer\u{1b}\n".repeat(1300)
                } else {
                    String::new()
                };
                start.wait();
                for sequence in 0..128 {
                    emit(&writer, &format!("{producer}:{sequence}:{payload}"));
                }
            }));
        }
        for producer in producers {
            producer.join().unwrap();
        }
        let pending = writer.stats();
        drop(release);
        writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(pending.accepted_records + pending.dropped_records, 513);
        assert_eq!(pending.pending_records as u64, pending.accepted_records);
        assert_eq!(pending.written_records, 0);
        assert!(pending.pending_records <= MAX_RECORDS);
        assert!(pending.pending_bytes <= MAX_BYTES);
        assert!(pending.dropped_records > 0);

        let contents = String::from_utf8(output.0.lock().clone()).unwrap();
        assert_eq!(contents.len(), pending.pending_bytes);
        assert_eq!(contents.lines().count() as u64, pending.accepted_records);
        let mut previous = [None; 4];
        for line in contents.lines().skip(1) {
            let mut fields = line.splitn(3, ':');
            let producer: usize = fields.next().unwrap().parse().unwrap();
            let sequence: usize = fields.next().unwrap().parse().unwrap();
            assert!(sequence < 128);
            assert!(previous[producer].is_none_or(|last| last < sequence));
            previous[producer] = Some(sequence);
        }
        let finished = writer.stats();
        assert_eq!(finished.written_records, pending.accepted_records);
        assert_eq!(finished.pending_records, 0);
        assert_eq!(finished.pending_bytes, 0);
    }
}

#[test]
fn concurrent_producers_racing_shutdown_leave_no_pending_records() {
    let writer = Arc::new(FileLogWriter::with_writer(Output::default()).unwrap());
    let start = Arc::new(std::sync::Barrier::new(5));
    let mut producers = Vec::new();
    emit(&writer, "prime");
    for _ in 0..4 {
        let writer = writer.clone();
        let start = start.clone();
        producers.push(std::thread::spawn(move || {
            let text = "peer\u{1b}\n".repeat(1300);
            start.wait();
            for _ in 0..128 {
                emit(&writer, &text);
            }
        }));
    }
    start.wait();
    writer.shutdown_timeout(Duration::from_secs(2)).unwrap();
    for producer in producers {
        producer.join().unwrap();
    }
    let stats = writer.stats();
    assert_eq!(stats.accepted_records + stats.dropped_records, 513);
    assert_eq!(stats.written_records, stats.accepted_records);
    assert_eq!(stats.pending_records, 0);
    assert_eq!(stats.pending_bytes, 0);
}
