use std::time::Duration;

use tokio::io::AsyncRead;

use super::{Sniffed, SniffedProtocol};

pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;

pub struct PeekResult {
    pub sniffed: Option<Sniffed>,
    pub buffered: Vec<u8>,
}

pub async fn peek_stream<S>(
    _stream: &mut S,
    _prefix: &[u8],
    _protocols: &[SniffedProtocol],
    _timeout: Duration,
    _max_bytes: usize,
) -> PeekResult
where
    S: AsyncRead + Unpin + ?Sized,
{
    PeekResult {
        sniffed: None,
        buffered: Vec::new(),
    }
}
