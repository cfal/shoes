pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod stream;
pub(crate) mod transport;

pub(crate) const STREAM_WINDOW: u32 = 256 * 1024;
pub(crate) const CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;

// Bounds late-frame tracking independently of advertised live-stream limits.
const RESET_STREAM_MAX: usize = 50;
const RESET_STREAM_DURATION: std::time::Duration = std::time::Duration::from_secs(1);

pub(crate) fn client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .max_concurrent_reset_streams(RESET_STREAM_MAX)
        .reset_stream_duration(RESET_STREAM_DURATION);
    builder
}

pub(crate) fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_reset_streams(RESET_STREAM_MAX)
        .reset_stream_duration(RESET_STREAM_DURATION);
    builder
}
