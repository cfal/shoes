//! `MieruStream` — one mieru session as an `AsyncStream`.
//!
//! Over TCP the session has no ARQ: `pkg/protocol/session.go:1144-1148` makes
//! ACK handling a no-op for the stream transport, and TCP already provides
//! ordering and retransmission. So this is framing plus an open/close state
//! machine.

use std::pin::Pin;
use std::task::{Context, Poll};

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};
use crate::mieru::crypto::{DirectionCipher, derive_key, round_to_interval};
use crate::mieru::frame::{decode_segment, encode_data_segment, encode_session_segment};
use crate::mieru::metadata::{
    CLOSE_SESSION_REQUEST, CLOSE_SESSION_RESPONSE, Metadata, OPEN_SESSION_REQUEST,
    OPEN_SESSION_RESPONSE, SESSION_STATUS_OK, SessionMetadata,
};
use crate::mieru::padding::PaddingStrategy;
use crate::mieru::{MAX_FRAGMENT_LEN, MAX_PADDING_LEN, METADATA_LEN, NONCE_LEN, TAG_LEN};
use crate::util::write_all;

/// Bytes read from the socket in one go.
const READ_CHUNK_LEN: usize = 8192;

/// The largest segment a peer may legally send: nonce, sealed metadata, both
/// paddings at their maximum, and a full fragment with its tag. Upstream caps
/// the fragment at `maxPDU = 32 * 1024` (`pkg/protocol/segment.go:36`).
const MAX_SEGMENT_LEN: usize = NONCE_LEN
    + METADATA_LEN
    + TAG_LEN
    + MAX_PADDING_LEN
    + MAX_FRAGMENT_LEN
    + TAG_LEN
    + MAX_PADDING_LEN;

/// How many bytes to buffer while looking for a segment boundary.
///
/// A whole segment must fit *and* leave room for the read that completes it,
/// or a stream of maximum-size segments trips the guard and the connection
/// dies mid-download. The guard is a defence against a peer claiming a length
/// it never sends, not a tuning knob, so it is sized from the protocol's own
/// limits rather than a round number.
const READ_BUFFER_LEN: usize = MAX_SEGMENT_LEN + READ_CHUNK_LEN;

pub struct MieruStream {
    inner: Box<dyn AsyncStream>,
    send: DirectionCipher,
    recv: DirectionCipher,
    session_id: u32,
    next_seq: u32,

    /// Bytes read from the socket that have not yet formed a whole segment.
    pending: Vec<u8>,
    /// Decoded payload the caller has not yet read.
    ready: Vec<u8>,
    ready_at: usize,

    /// Bytes staged for the socket by `poll_write`.
    outgoing: Vec<u8>,
    outgoing_at: usize,

    /// Set when the peer closed the session. The underlay may stay open, so
    /// this is what turns a close into EOF for the caller.
    session_closed: bool,
}

impl std::fmt::Debug for MieruStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruStream")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl MieruStream {
    /// Derive the key, open a session and wait for the server's response.
    ///
    /// The response is awaited here rather than lazily, so a wrong password
    /// surfaces as a failed connection instead of a stream that silently
    /// carries nothing.
    pub async fn open(
        mut inner: Box<dyn AsyncStream>,
        password: &[u8],
        username: &[u8],
        unix_secs: u64,
    ) -> std::io::Result<Self> {
        let key = derive_key(password, username, round_to_interval(unix_secs));
        let mut send = DirectionCipher::new(&key, username);
        let mut recv = DirectionCipher::new(&key, username);
        // The strategy shapes the session segments only; data segments use
        // plain random padding, so it is not kept past the handshake.
        let strategy = PaddingStrategy::for_user(username);

        // Session ids are the peer's bookkeeping; any value works as long as
        // it is consistent for the connection.
        // Upstream reserves 0: onOpenSessionRequest fails with "reserved
        // session ID 0 is used" (pkg/protocol/underlay_stream.go).
        let session_id: u32 = rand::rng().random_range(1..=u32::MAX);

        let request = encode_session_segment(
            &mut send,
            &SessionMetadata {
                protocol: OPEN_SESSION_REQUEST,
                timestamp_minutes: 0,
                session_id,
                seq: 0,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            },
            strategy,
        )?;
        write_all(&mut inner, &request).await?;
        inner.flush().await?;

        let mut pending = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let n = inner.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the mieru server closed the connection before answering the session request",
                ));
            }
            pending.extend_from_slice(&buf[..n]);
            if let Some((meta, _, consumed)) = decode_segment(&mut recv, &pending)? {
                match meta {
                    Metadata::Session(session)
                        if session.protocol == OPEN_SESSION_RESPONSE
                            && session.status == SESSION_STATUS_OK
                            && session.session_id == session_id =>
                    {
                        pending.drain(..consumed);
                        break;
                    }
                    // The server answers with the id it was given
                    // (`pkg/protocol/session.go:1123`). A different one means
                    // we are not looking at our own session, and carrying on
                    // would send data segments the peer cannot place. Checked
                    // after the status, so a refusal is still reported as one.
                    Metadata::Session(session)
                        if session.protocol == OPEN_SESSION_RESPONSE
                            && session.status == SESSION_STATUS_OK =>
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "the mieru server opened session {} while we asked for {session_id}",
                                session.session_id
                            ),
                        ));
                    }
                    // A close, or an open response carrying a status, is the
                    // server refusing us - upstream sends statusQuotaExhausted
                    // this way. Treating any session segment as success gives
                    // the caller a stream that then stalls.
                    Metadata::Session(session) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "the mieru server refused the session: protocol type {}, status {}",
                                session.protocol, session.status
                            ),
                        ));
                    }
                    Metadata::Data(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "the mieru server sent data before opening the session",
                        ));
                    }
                }
            }
        }

        Ok(Self {
            inner,
            send,
            recv,
            session_id,
            next_seq: 1,
            pending,
            ready: Vec::new(),
            ready_at: 0,
            outgoing: Vec::new(),
            outgoing_at: 0,
            session_closed: false,
        })
    }

    /// Move every complete segment out of `pending` and into `ready`.
    fn drain_pending(&mut self) -> std::io::Result<()> {
        while let Some((meta, payload, consumed)) = decode_segment(&mut self.recv, &self.pending)? {
            self.pending.drain(..consumed);
            match meta {
                Metadata::Data(_) => {
                    if !payload.is_empty() {
                        self.ready.extend_from_slice(&payload);
                    }
                }
                // The server closes a session while keeping the TCP underlay
                // open, so a close has to become EOF here. Without the flag
                // the reader goes back to the socket and the connection hangs
                // until an outer timeout.
                Metadata::Session(session)
                    if session.protocol == CLOSE_SESSION_REQUEST
                        || session.protocol == CLOSE_SESSION_RESPONSE =>
                {
                    self.session_closed = true;
                    break;
                }
                Metadata::Session(_) => {}
            }
        }
        Ok(())
    }
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Hand back anything already decoded.
            if this.ready_at < this.ready.len() {
                let available = &this.ready[this.ready_at..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.ready_at += n;
                if this.ready_at == this.ready.len() {
                    this.ready.clear();
                    this.ready_at = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if this.session_closed {
                // Closed and drained: EOF.
                return Poll::Ready(Ok(()));
            }

            let mut chunk = [0u8; READ_CHUNK_LEN];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut chunk_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = chunk_buf.filled();
                    if filled.is_empty() {
                        // EOF, and nothing decoded is waiting.
                        return Poll::Ready(Ok(()));
                    }
                    if this.pending.len() + filled.len() > READ_BUFFER_LEN {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "mieru segment exceeded the maximum size",
                        )));
                    }
                    this.pending.extend_from_slice(filled);
                    this.drain_pending()?;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Finish any staged bytes first, so a segment is never interleaved
        // with the next one.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru transport accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.outgoing.clear();
        this.outgoing_at = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // The payload length field is 16 bits and the protocol caps a fragment
        // at 32768 bytes, so a larger write becomes several segments.
        let take = buf.len().min(MAX_FRAGMENT_LEN);
        let segment =
            encode_data_segment(&mut this.send, this.session_id, this.next_seq, &buf[..take])?;
        this.next_seq = this.next_seq.wrapping_add(1);
        this.outgoing = segment;
        this.outgoing_at = 0;

        // Push what we can now; the rest goes out on the next call or flush.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru transport accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.outgoing.clear();
        this.outgoing_at = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Shutting down on top of a half-written segment would put a truncated
        // one on the wire; the peer cannot decrypt it and the last of the
        // caller's data is lost.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru transport accepted no bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.outgoing.clear();
        this.outgoing_at = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for MieruStream {
    fn supports_ping(&self) -> bool {
        // mieru has no keepalive of its own on the stream transport; the
        // underlying connection's own is what keeps a session alive.
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for MieruStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mieru::testing::{ScriptedPeer, TEST_PASSWORD, TEST_USERNAME, connect};

    #[tokio::test]
    async fn test_open_completes_the_session_handshake() {
        let (_stream, _server, _peer) = connect().await;
    }

    #[tokio::test]
    async fn test_written_data_arrives_as_a_data_segment() {
        let (mut stream, mut server, mut peer) = connect().await;
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = server.read(&mut buf).await.unwrap();
        let (_, payload, _) = decode_segment(&mut peer.recv, &buf[..n]).unwrap().unwrap();
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn test_a_data_segment_is_readable_as_bytes() {
        let (mut stream, mut server, mut peer) = connect().await;
        let segment = peer.data(1, 1, b"from the server");
        server.write_all(&segment).await.unwrap();

        let mut buf = [0u8; 15];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from the server");
    }

    #[tokio::test]
    async fn test_a_payload_larger_than_one_fragment_is_split() {
        let (mut stream, mut server, mut peer) = connect().await;
        let payload: Vec<u8> = (0..MAX_FRAGMENT_LEN + 1000).map(|i| i as u8).collect();
        let sent = payload.clone();
        tokio::spawn(async move {
            stream.write_all(&sent).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut received = Vec::new();
        let mut pending = Vec::new();
        let mut segments = 0;
        let mut buf = vec![0u8; 65536];
        while received.len() < payload.len() {
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0, "the server end closed early");
            pending.extend_from_slice(&buf[..n]);
            while let Some((meta, body, consumed)) =
                decode_segment(&mut peer.recv, &pending).unwrap()
            {
                received.extend_from_slice(&body);
                pending.drain(..consumed);
                segments += 1;
                // Every segment must respect the fragment ceiling. Without
                // this the test would pass on a single oversized segment,
                // since the payload length field is wide enough to hold one.
                if let Metadata::Data(data) = meta {
                    assert!(
                        data.payload_len as usize <= MAX_FRAGMENT_LEN,
                        "a segment carried {} bytes, over the {MAX_FRAGMENT_LEN} limit",
                        data.payload_len
                    );
                }
            }
        }
        assert_eq!(received, payload);
        assert!(
            segments >= 2,
            "a payload of {} bytes must span more than one segment, got {segments}",
            payload.len()
        );
    }

    /// A server sending back-to-back maximum-size segments must not trip the
    /// read guard. The guard has to hold a whole segment *and* the read that
    /// completes it, or a bulk download dies partway through.
    #[tokio::test]
    async fn test_back_to_back_full_size_segments_are_readable() {
        let (mut stream, mut server, mut peer) = connect().await;

        let chunk: Vec<u8> = (0..MAX_FRAGMENT_LEN).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        for seq in 1..=3u32 {
            wire.extend_from_slice(&peer.data(1, seq, &chunk));
        }
        tokio::spawn(async move {
            let _ = server.write_all(&wire).await;
            let _ = server.flush().await;
        });

        let mut received = vec![0u8; MAX_FRAGMENT_LEN * 3];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received[..MAX_FRAGMENT_LEN], chunk.as_slice());
        assert_eq!(&received[MAX_FRAGMENT_LEN * 2..], chunk.as_slice());
    }

    /// A segment split across two reads must reassemble, which it cannot if a
    /// partial read advanced the nonce.
    #[tokio::test]
    async fn test_a_segment_split_across_reads_reassembles() {
        let (mut stream, mut server, mut peer) = connect().await;
        let segment = peer.data(1, 1, b"split me");
        let (first, second) = segment.split_at(segment.len() / 2);
        server.write_all(first).await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.write_all(second).await.unwrap();

        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"split me");
    }

    /// The server refuses a session by answering with a close, or with a
    /// non-zero status. Accepting any session segment as success hands the
    /// caller a stream that then stalls instead of an error naming the cause.
    #[tokio::test]
    async fn test_a_refused_session_is_an_error_not_a_stream() {
        use crate::mieru::frame::encode_session_segment;
        use crate::mieru::metadata::{
            CLOSE_SESSION_RESPONSE, OPEN_SESSION_RESPONSE, SESSION_STATUS_QUOTA_EXHAUSTED,
            SessionMetadata,
        };
        use crate::mieru::padding::PaddingStrategy;

        // Two refusals: a close, and an open response carrying a status.
        for (protocol, status) in [
            (CLOSE_SESSION_RESPONSE, 0),
            (OPEN_SESSION_RESPONSE, SESSION_STATUS_QUOTA_EXHAUSTED),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let client = tokio::spawn(async move {
                let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
                MieruStream::open(Box::new(tcp), TEST_PASSWORD, TEST_USERNAME, 1000).await
            });

            let (mut server_tcp, _) = listener.accept().await.unwrap();
            let mut peer = ScriptedPeer::new(1000);
            let mut buf = vec![0u8; 4096];
            let _ = server_tcp.read(&mut buf).await.unwrap();

            let refusal = encode_session_segment(
                &mut peer.send,
                &SessionMetadata {
                    protocol,
                    timestamp_minutes: 0,
                    session_id: 1,
                    seq: 0,
                    status,
                    payload_len: 0,
                    suffix_len: 0,
                },
                PaddingStrategy::Ascii,
            )
            .unwrap();
            server_tcp.write_all(&refusal).await.unwrap();

            let err = client.await.unwrap().unwrap_err();
            assert!(
                err.to_string().contains("refused"),
                "protocol {protocol} status {status} should be refused: {err}"
            );
        }
    }

    /// The server can close a session while keeping the TCP underlay open, so
    /// a close segment has to become EOF. Without that the reader goes back to
    /// the socket and the proxied connection hangs.
    #[tokio::test]
    async fn test_a_close_segment_ends_the_stream() {
        use crate::mieru::frame::encode_session_segment;
        use crate::mieru::metadata::{CLOSE_SESSION_REQUEST, SessionMetadata};
        use crate::mieru::padding::PaddingStrategy;

        let (mut stream, mut server, mut peer) = connect().await;

        // Some data, then a close, and the underlay stays open.
        let data = peer.data(1, 1, b"last words");
        server.write_all(&data).await.unwrap();
        let close = encode_session_segment(
            &mut peer.send,
            &SessionMetadata {
                protocol: CLOSE_SESSION_REQUEST,
                timestamp_minutes: 0,
                session_id: 1,
                seq: 2,
                status: 0,
                payload_len: 0,
                suffix_len: 0,
            },
            PaddingStrategy::Ascii,
        )
        .unwrap();
        server.write_all(&close).await.unwrap();
        server.flush().await.unwrap();

        // The buffered data arrives, then EOF - not a hang.
        let mut all = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut all),
        )
        .await;
        assert!(read.is_ok(), "reading after a close must not hang");
        read.unwrap().unwrap();
        assert_eq!(all, b"last words");
    }

    /// The server echoes back the id it was given. A different one means the
    /// response belongs to some other session, and data segments we send would
    /// land nowhere - so the handshake must fail rather than hand back a
    /// stream that silently carries nothing.
    #[tokio::test]
    async fn test_a_response_for_another_session_fails_the_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            MieruStream::open(Box::new(tcp), TEST_PASSWORD, TEST_USERNAME, 1000).await
        });

        let (mut server_tcp, _) = listener.accept().await.unwrap();
        let mut peer = ScriptedPeer::new(1000);
        let mut buf = vec![0u8; 4096];
        let n = server_tcp.read(&mut buf).await.unwrap();
        let (meta, _, _) = decode_segment(&mut peer.recv, &buf[..n]).unwrap().unwrap();
        let asked_for = match meta {
            Metadata::Session(session) => session.session_id,
            Metadata::Data(_) => panic!("the first segment opens the session"),
        };

        // Answer with a well-formed OK response for a different session.
        let response = peer.open_session_response(asked_for.wrapping_add(1).max(1));
        server_tcp.write_all(&response).await.unwrap();

        let err = client.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("while we asked for"),
            "unexpected error: {err}"
        );
    }

    /// A wrong password must fail at open, not at the first read: the caller
    /// gets a verdict rather than a connection that mysteriously carries
    /// nothing.
    #[tokio::test]
    async fn test_a_wrong_password_fails_the_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            MieruStream::open(Box::new(tcp), b"the wrong password", TEST_USERNAME, 1000).await
        });

        let (mut server_tcp, _) = listener.accept().await.unwrap();
        let mut peer = ScriptedPeer::new(1000);
        let mut buf = vec![0u8; 4096];
        let _ = server_tcp.read(&mut buf).await.unwrap();
        // The peer answers with its own key, which the client cannot open.
        let response = peer.open_session_response(1);
        let _ = server_tcp.write_all(&response).await;

        assert!(client.await.unwrap().is_err());
    }
}
