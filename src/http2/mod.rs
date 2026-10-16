pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod stream;

pub(crate) const STREAM_WINDOW: u32 = 256 * 1024;
pub(crate) const CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;
