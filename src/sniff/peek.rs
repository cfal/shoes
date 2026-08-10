use std::time::Duration;

use tokio::io::AsyncRead;

use super::{SniffOutcome, Sniffed, SniffedProtocol};

/// Ceiling on how much is buffered before sniffing gives up. Well above any
/// real ClientHello even with post-quantum key shares, and far below the
/// 65540-byte record the format allows.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;

const INITIAL_CAPACITY: usize = 1024;
const READ_CHUNK: usize = 2048;

pub struct PeekResult {
    pub sniffed: Option<Sniffed>,
    /// Everything that was read, `prefix` included. This must reach the remote
    /// unchanged whatever the outcome.
    pub buffered: Vec<u8>,
}

/// Read until a sniffer recognises the traffic, the deadline passes, the cap
/// is reached, or the peer stops talking.
///
/// This never fails. A sniff that goes wrong is not a connection that goes
/// wrong: the caller routes by address instead, and the bytes read so far are
/// handed back intact.
pub async fn peek_stream<S>(
    stream: &mut S,
    prefix: &[u8],
    protocols: &[SniffedProtocol],
    timeout: Duration,
    max_bytes: usize,
) -> PeekResult
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffered = Vec::with_capacity(INITIAL_CAPACITY.max(prefix.len()));
    buffered.extend_from_slice(prefix);

    let sniffed = tokio::time::timeout(timeout, run(stream, &mut buffered, protocols, max_bytes))
        .await
        .unwrap_or(None);

    PeekResult { sniffed, buffered }
}

async fn run<S>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    protocols: &[SniffedProtocol],
    max_bytes: usize,
) -> Option<Sniffed>
where
    S: AsyncRead + Unpin + ?Sized,
{
    use tokio::io::AsyncReadExt;

    let mut live: Vec<SniffedProtocol> = protocols.to_vec();

    loop {
        let mut still_live = Vec::with_capacity(live.len());
        for protocol in &live {
            match protocol.sniff(buffered) {
                SniffOutcome::Found(sniffed) => return Some(sniffed),
                SniffOutcome::NeedMore => still_live.push(*protocol),
                SniffOutcome::NotThisOne => {}
            }
        }
        live = still_live;

        // Nobody is still interested, so no amount of reading will help.
        if live.is_empty() || buffered.len() >= max_bytes {
            return None;
        }

        // Read into a fixed buffer rather than the Vec's spare capacity, so
        // the cap is exact and a cancelled read cannot leave a partly-grown
        // Vec behind.
        let mut chunk = [0u8; READ_CHUNK];
        let want = READ_CHUNK.min(max_bytes - buffered.len());
        match stream.read(&mut chunk[..want]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    /// Yields the given chunks one read at a time, then either EOF or, if
    /// `stall` is set, nothing at all — the shape a connection has when the
    /// client is waiting for the server to speak first.
    struct ChunkedStream {
        chunks: VecDeque<Vec<u8>>,
        stall: bool,
    }

    impl ChunkedStream {
        fn new(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                stall: false,
            }
        }

        fn stalling(chunks: Vec<&[u8]>) -> Self {
            Self {
                chunks: chunks.into_iter().map(<[u8]>::to_vec).collect(),
                stall: true,
            }
        }
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.chunks.push_front(chunk[n..].to_vec());
                    }
                    Poll::Ready(Ok(()))
                }
                None if self.stall => Poll::Pending,
                None => Poll::Ready(Ok(())), // EOF
            }
        }
    }

    #[tokio::test]
    async fn finds_the_name_in_the_prefix_without_reading() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let mut stream = ChunkedStream::stalling(vec![]);
        let result = peek_stream(
            &mut stream,
            &hello,
            &[SniffedProtocol::Tls],
            Duration::from_millis(300),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert_eq!(result.sniffed.unwrap().domain.as_deref(), Some("ex.com"));
        assert_eq!(result.buffered, hello);
    }

    #[tokio::test]
    async fn reassembles_a_name_split_across_reads() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let (head, tail) = hello.split_at(9);
        let mut stream = ChunkedStream::new(vec![head, tail]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_millis(300),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert_eq!(result.sniffed.unwrap().domain.as_deref(), Some("ex.com"));
        assert_eq!(result.buffered, hello);
    }

    #[tokio::test]
    async fn returns_early_when_every_sniffer_rejects() {
        let mut stream = ChunkedStream::stalling(vec![b"SSH-2.0-OpenSSH_9.6\r\n"]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls, SniffedProtocol::Http],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, b"SSH-2.0-OpenSSH_9.6\r\n");
    }

    #[tokio::test]
    async fn keeps_what_it_read_when_the_deadline_passes() {
        // A real deadline rather than tokio's paused clock, which needs the
        // test-util feature and would pull it into the production build.
        let hello = crate::sniff::test_client_hello("ex.com");
        let partial = &hello[..9];
        let mut stream = ChunkedStream::stalling(vec![partial]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_millis(50),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, partial);
    }

    #[tokio::test]
    async fn stops_at_eof() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let mut stream = ChunkedStream::new(vec![&hello[..9]]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert_eq!(result.buffered, &hello[..9]);
    }

    #[tokio::test]
    async fn never_buffers_past_the_cap() {
        // A record header claiming 65535 bytes, so the TLS sniffer keeps
        // asking for more until the cap stops it.
        let filler = vec![0x16u8, 0x03, 0x01, 0xff, 0xff];
        let mut chunks: Vec<&[u8]> = Vec::new();
        for _ in 0..64 {
            chunks.push(&filler);
        }
        let mut stream = ChunkedStream::new(chunks);
        let result = peek_stream(
            &mut stream,
            &[],
            &[SniffedProtocol::Tls],
            Duration::from_secs(30),
            32,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert!(
            result.buffered.len() <= 32,
            "buffered {} bytes, cap was 32",
            result.buffered.len()
        );
    }

    #[tokio::test]
    async fn reads_nothing_when_no_protocols_are_enabled() {
        let hello = crate::sniff::test_client_hello("ex.com");
        let mut stream = ChunkedStream::stalling(vec![&hello]);
        let result = peek_stream(
            &mut stream,
            &[],
            &[],
            Duration::from_secs(30),
            DEFAULT_MAX_BYTES,
        )
        .await;

        assert!(result.sniffed.is_none());
        assert!(result.buffered.is_empty());
    }
}
