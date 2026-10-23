use std::sync::{Arc, Weak};

use parking_lot::RwLock;
use tokio::sync::broadcast;

static SUBSCRIBER: RwLock<Option<Weak<LogHub>>> = RwLock::new(None);

#[derive(Clone)]
pub struct LogEvent {
    pub level: log::Level,
    pub time: String,
    pub message: String,
}

pub struct LogHub {
    pub sender: broadcast::Sender<LogEvent>,
}

impl LogHub {
    pub fn new() -> Self {
        Self {
            sender: broadcast::channel(1024).0,
        }
    }
    pub fn install(self: &Arc<Self>) {
        *SUBSCRIBER.write() = Some(Arc::downgrade(self));
    }
}

pub struct Writer;
impl crate::logging::LogWriter for Writer {
    fn write_log(&self, record: &log::Record, _: &str) {
        let Some(hub) = SUBSCRIBER.read().as_ref().and_then(Weak::upgrade) else {
            return;
        };
        if hub.sender.receiver_count() == 0 {
            return;
        }
        let mut message = record.args().to_string();
        // JSON escaping can expand each input byte sixfold; keep either DTO below 16 KiB.
        message.truncate(message.floor_char_boundary(2600));
        let _ = hub.sender.send(LogEvent {
            level: record.level(),
            time: chrono::Utc::now().to_rfc3339(),
            message,
        });
    }
    fn flush(&self) {}
}

pub fn level_name(level: log::LevelFilter) -> &'static str {
    match level {
        log::LevelFilter::Off => "silent",
        log::LevelFilter::Error => "error",
        log::LevelFilter::Warn => "warning",
        log::LevelFilter::Info => "info",
        log::LevelFilter::Debug => "debug",
        log::LevelFilter::Trace => "trace",
    }
}
