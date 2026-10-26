use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use super::LogWriter;

const MAX_RECORDS: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const FILE_LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Process-local sink identity and cumulative health counters. Pending bounds
/// include the record currently being written; no paths or record contents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileLogStats {
    pub sink_id: u64,
    pub pending_records: usize,
    pub pending_bytes: usize,
    pub accepted_records: u64,
    pub written_records: u64,
    pub dropped_records: u64,
    pub truncated_records: u64,
    pub io_errors: u64,
}

struct State {
    queue: VecDeque<Box<str>>,
    stats: FileLogStats,
    closing: bool,
    finished: bool,
    flush_target: Option<u64>,
    flushed_through: Option<u64>,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

/// Dedicated blocking writer with drop-newest overload handling. Admission and
/// accounting share a mutex; escaping and filesystem I/O run outside it.
pub struct FileLogWriter {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl FileLogWriter {
    pub fn new(path: &str) -> io::Result<Self> {
        Self::from_file(OpenOptions::new().create(true).append(true).open(path)?)
    }

    pub(crate) fn from_file(file: File) -> io::Result<Self> {
        Self::with_writer(file)
    }

    #[cfg(all(test, any(target_os = "ios", all(unix, feature = "ffi"))))]
    pub(crate) fn with_test_writer(writer: impl Write + Send + 'static) -> io::Result<Self> {
        Self::with_writer(writer)
    }

    fn with_writer(writer: impl Write + Send + 'static) -> io::Result<Self> {
        static NEXT_SINK: AtomicU64 = AtomicU64::new(1);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                stats: FileLogStats {
                    sink_id: NEXT_SINK.fetch_add(1, Ordering::Relaxed),
                    ..FileLogStats::default()
                },
                closing: false,
                finished: false,
                flush_target: None,
                flushed_through: None,
            }),
            changed: Condvar::new(),
        });
        let worker_shared = shared.clone();
        let worker = std::thread::Builder::new()
            .name("shoes-file-log".into())
            .spawn(move || run_worker(worker_shared, writer))?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub fn stats(&self) -> FileLogStats {
        self.shared.state.lock().stats
    }

    /// True once the worker has released its writer, including after I/O failure.
    pub fn is_finished(&self) -> bool {
        self.shared.state.lock().finished
    }

    /// Wait for records accepted before this call, without closing the sink.
    /// This lifecycle operation must not be called from a relay worker.
    pub fn flush_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.wait_until(Instant::now() + timeout, false)
    }

    /// Stop admissions and drain until the deadline. On timeout, discard queued
    /// records and retain the worker handle: an in-flight OS write is not cancellable.
    pub fn shutdown_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.wait_until(Instant::now() + timeout, true)
    }

    fn wait_until(&self, deadline: Instant, shutdown: bool) -> io::Result<()> {
        let mut state = self.shared.state.lock();
        let target = state.stats.accepted_records;
        if shutdown {
            state.closing = true;
        }
        if state.flushed_through.is_none_or(|count| count < target) {
            state.flush_target = Some(state.flush_target.unwrap_or(0).max(target));
        }
        self.shared.changed.notify_all();
        loop {
            if state.stats.io_errors != 0 && (!shutdown || state.finished) {
                return Err(io::Error::other("file log worker failed"));
            }
            let completed = if shutdown {
                state.finished
            } else {
                state.flushed_through.is_some_and(|count| count >= target)
            };
            if completed {
                drop(state);
                let mut worker = self.worker.lock();
                if worker.as_ref().is_some_and(JoinHandle::is_finished) {
                    let _ = worker.take().unwrap().join();
                }
                return Ok(());
            }
            if state.finished {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "file log worker closed before flush target",
                ));
            }
            if Instant::now() >= deadline {
                if shutdown {
                    discard_queue(&mut state);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "file log deadline expired",
                ));
            }
            self.shared.changed.wait_until(&mut state, deadline);
        }
    }
}

impl LogWriter for FileLogWriter {
    fn write_log(&self, _: &log::Record, formatted: &str) {
        {
            let mut state = self.shared.state.lock();
            if state.closing || state.finished || state.stats.pending_records == MAX_RECORDS {
                state.stats.dropped_records += 1;
                return;
            }
        }
        // Escape only a bounded prefix, including expansion and the line delimiter.
        let (line, truncated) = escaped_record(formatted);
        let mut state = self.shared.state.lock();
        if state.closing
            || state.finished
            || state.stats.pending_records == MAX_RECORDS
            || state.stats.pending_bytes + line.len() > MAX_BYTES
        {
            state.stats.dropped_records += 1;
            return;
        }
        state.stats.truncated_records += u64::from(truncated);
        state.stats.accepted_records += 1;
        state.stats.pending_records += 1;
        state.stats.pending_bytes += line.len();
        state.queue.push_back(line.into_boxed_str());
        self.shared.changed.notify_all();
    }

    fn flush(&self) {
        let _ = self.flush_timeout(FILE_LOG_FLUSH_TIMEOUT);
    }
}

impl Drop for FileLogWriter {
    fn drop(&mut self) {
        // Do not spend a second deadline after an explicit shutdown timed out.
        if !self.shared.state.lock().closing {
            let _ = self.shutdown_timeout(FILE_LOG_FLUSH_TIMEOUT);
        }
        // Dropping a still-running JoinHandle detaches it. It retains at most one
        // bounded record and the OS handle until that blocking call returns.
    }
}

fn escaped_record(formatted: &str) -> (String, bool) {
    const TRUNCATED_SUFFIX: &str = " [truncated]\n";
    let mut line = String::with_capacity((formatted.len().saturating_add(1)).min(MAX_RECORD_BYTES));
    let mut truncated = false;
    for c in formatted.chars() {
        let escape = c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        let encoded_len = if escape {
            c.escape_default().count()
        } else {
            c.len_utf8()
        };
        if line.len() + encoded_len > MAX_RECORD_BYTES - TRUNCATED_SUFFIX.len() {
            truncated = true;
            break;
        }
        if escape {
            line.extend(c.escape_default());
        } else {
            line.push(c);
        }
    }
    line.push_str(if truncated { TRUNCATED_SUFFIX } else { "\n" });
    (line, truncated)
}

fn discard_queue(state: &mut State) {
    while let Some(line) = state.queue.pop_front() {
        state.stats.pending_records -= 1;
        state.stats.pending_bytes -= line.len();
        state.stats.dropped_records += 1;
    }
}

fn report_health(stats: FileLogStats) {
    // Never recurse through log:: or expose paths, errors, payloads, or credentials.
    let _ = writeln!(
        std::io::stderr(),
        "event=file_log_health version=1 sink_id={} dropped_records={} truncated_records={} io_errors={}",
        stats.sink_id,
        stats.dropped_records,
        stats.truncated_records,
        stats.io_errors,
    );
}

fn run_worker(shared: Arc<Shared>, mut writer: impl Write) {
    let mut reported_health = (0, 0, 0);
    let mut last_report = Instant::now();
    loop {
        let mut state = shared.state.lock();
        // Acknowledge progress before the next write can stall. Keeping only
        // the highest target must not postpone earlier callers' barriers.
        let flush_progress = state.flush_target.is_some()
            && state
                .flushed_through
                .is_none_or(|count| count < state.stats.written_records);
        let shutting_down = state.closing && state.queue.is_empty();
        let line = if flush_progress || shutting_down {
            None
        } else if let Some(line) = state.queue.pop_front() {
            Some(line)
        } else {
            shared.changed.wait(&mut state);
            continue;
        };
        drop(state);

        let result = match &line {
            Some(line) => writer.write_all(line.as_bytes()),
            None => writer.flush(),
        };
        let mut state = shared.state.lock();
        let flush_completed = line.is_none()
            && state
                .flush_target
                .is_some_and(|target| target <= state.stats.written_records);
        if let Some(line) = line {
            state.stats.pending_records -= 1;
            state.stats.pending_bytes -= line.len();
            if result.is_ok() {
                state.stats.written_records += 1;
            } else {
                state.stats.dropped_records += 1;
            }
        } else if result.is_ok() {
            state.flushed_through = Some(state.stats.written_records);
            if flush_completed {
                state.flush_target = None;
            }
        }
        if result.is_err() {
            state.stats.io_errors += 1;
            state.closing = true;
            discard_queue(&mut state);
        }
        let should_finish = shutting_down || result.is_err();
        let stats = state.stats;
        let health = (
            stats.dropped_records,
            stats.truncated_records,
            stats.io_errors,
        );
        let report = health != reported_health
            && (should_finish
                || flush_completed
                || last_report.elapsed() >= Duration::from_secs(1));
        shared.changed.notify_all();
        drop(state);
        if report {
            report_health(stats);
            reported_health = health;
            last_report = Instant::now();
        }
        if should_finish {
            drop(writer);
            shared.state.lock().finished = true;
            shared.changed.notify_all();
            return;
        }
    }
}

#[cfg(test)]
mod tests;
