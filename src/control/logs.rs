//! A log sink a host can subscribe to.
//!
//! `MultiLogger` already dispatches each formatted line to a list of
//! `LogWriter`s, so this is one more sink rather than a change to logging.
//!
//! Note what this sink is not: a privileged view. It sees exactly what the
//! `Directive` filtering lets every other sink see, and enabling it must not
//! raise the global level. Anything that must not reach a log file must not
//! reach a log line at all — redaction belongs at the call site, not here.
//! This fork has already had to fix REALITY key material reaching the log, so
//! that is a demonstrated risk rather than a hypothetical one, and streaming
//! lines to a user-session GUI is a new way for it to escape.

use std::collections::VecDeque;

use log::{Level, Record};
use parking_lot::Mutex;
use tokio::sync::broadcast;

/// One log line, already formatted, with its metadata kept separate so a host
/// can filter by level without parsing the text back apart.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub level: Level,
    pub target: String,
    pub message: String,
    pub at: std::time::SystemTime,
}

/// Retains a bounded backlog and broadcasts to live subscribers.
pub struct BroadcastLogWriter {
    ring: Mutex<VecDeque<LogLine>>,
    capacity: usize,
    tx: broadcast::Sender<LogLine>,
}

impl BroadcastLogWriter {
    /// `capacity` lines are retained for subscribers that attach later, and it
    /// is what makes the memory cost a number the host picked rather than a
    /// leak.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            tx,
        }
    }

    /// The retained backlog, and a receiver for everything after it.
    ///
    /// A GUI that attaches after the tunnel started still needs to see why it
    /// failed, which is why the backlog comes back rather than only the stream.
    pub fn subscribe(&self) -> (Vec<LogLine>, broadcast::Receiver<LogLine>) {
        // Subscribe while holding the ring lock, so a line written between the
        // two steps lands on the receiver instead of falling in the gap
        // between the snapshot and the subscription.
        let ring = self.ring.lock();
        let rx = self.tx.subscribe();
        let backlog = ring.iter().cloned().collect();
        (backlog, rx)
    }

    fn push(&self, line: LogLine) {
        {
            let mut ring = self.ring.lock();
            if ring.len() == self.capacity {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        // Ignored deliberately: no subscribers, or one that has fallen behind,
        // must not stall a thread that is moving packets.
        let _ = self.tx.send(line);
    }
}

impl crate::logging::LogWriter for BroadcastLogWriter {
    fn write_log(&self, record: &Record, formatted: &str) {
        self.push(LogLine {
            level: record.level(),
            target: record.target().to_string(),
            message: formatted.to_string(),
            at: std::time::SystemTime::now(),
        });
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(message: &str) -> LogLine {
        LogLine {
            level: Level::Info,
            target: "shoes".to_string(),
            message: message.to_string(),
            at: std::time::SystemTime::now(),
        }
    }

    #[test]
    fn test_a_late_subscriber_receives_the_backlog() {
        let writer = BroadcastLogWriter::new(4);
        writer.push(line("first"));
        writer.push(line("second"));

        let (backlog, _rx) = writer.subscribe();
        assert_eq!(backlog.len(), 2);
        assert_eq!(backlog[0].message, "first");
        assert_eq!(backlog[1].message, "second");
    }

    #[test]
    fn test_the_ring_does_not_grow_past_its_capacity() {
        let writer = BroadcastLogWriter::new(2);
        for i in 0..10 {
            writer.push(line(&format!("line {i}")));
        }

        let (backlog, _rx) = writer.subscribe();
        assert_eq!(backlog.len(), 2);
        assert_eq!(backlog[1].message, "line 9");
    }

    /// write_log runs on arbitrary threads, including inside the packet path.
    /// A subscriber that stops reading must lose lines rather than stall it.
    #[test]
    fn test_a_stalled_subscriber_does_not_block_the_writer() {
        let writer = BroadcastLogWriter::new(2);
        let (_backlog, _rx) = writer.subscribe();
        for i in 0..1000 {
            writer.push(line(&format!("line {i}")));
        }
        // Returning at all is the assertion.
    }

    #[test]
    fn test_a_subscriber_receives_lines_written_after_it_attached() {
        let writer = BroadcastLogWriter::new(4);
        let (_backlog, mut rx) = writer.subscribe();
        writer.push(line("after"));
        assert_eq!(rx.try_recv().unwrap().message, "after");
    }

    /// A zero capacity would panic inside broadcast::channel, and a host
    /// passing one means "do not retain", not "crash".
    #[test]
    fn test_a_zero_capacity_is_clamped_rather_than_fatal() {
        let writer = BroadcastLogWriter::new(0);
        writer.push(line("only"));
        let (backlog, _rx) = writer.subscribe();
        assert_eq!(backlog.len(), 1);
    }
}
