//! The mieru client handler: a session, with socks5 inside it.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::address::ResolvedLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::mieru::stream::MieruStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

/// The marker bytes framing a UDP datagram inside the session.
/// `docs/protocol.md`, "UDP Associate Encapsulation".
const UDP_MARKER_START: u8 = 0x00;
const UDP_MARKER_END: u8 = 0xff;

/// socks5 command values. RFC 1928, which mieru ships as `docs/rfc/rfc1928.txt`.
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_SUCCESS: u8 = 0x00;

/// Frame a datagram as `[0x00][u16 len][data][0xff]`, preserving the packet
/// boundary a stream would otherwise lose.
pub fn try_encapsulate_udp(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "UDP datagram of {} bytes exceeds the {} the encapsulation allows",
                payload.len(),
                u16::MAX
            ),
        ));
    }
    let mut out = Vec::with_capacity(1 + 2 + payload.len() + 1);
    out.push(UDP_MARKER_START);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.push(UDP_MARKER_END);
    Ok(out)
}

#[cfg(test)]
fn encapsulate_udp(payload: &[u8]) -> Vec<u8> {
    try_encapsulate_udp(payload).expect("the test payload fits")
}

/// Recover one datagram. `Ok(None)` means more bytes are needed.
#[allow(clippy::type_complexity)]
pub fn decapsulate_udp(input: &[u8]) -> std::io::Result<Option<(Vec<u8>, usize)>> {
    if input.len() < 3 {
        return Ok(None);
    }
    if input[0] != UDP_MARKER_START {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mieru UDP encapsulation has a wrong start marker",
        ));
    }
    let len = u16::from_be_bytes([input[1], input[2]]) as usize;
    let total = 1 + 2 + len + 1;
    if input.len() < total {
        return Ok(None);
    }
    if input[total - 1] != UDP_MARKER_END {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mieru UDP encapsulation has a wrong end marker",
        ));
    }
    Ok(Some((input[3..3 + len].to_vec(), total)))
}

/// `[0x05][cmd][0x00][address][u16 port]`, reusing the socks5 address encoder
/// the rest of this crate already has.
fn encode_socks5_request(command: u8, location: &crate::address::NetLocation) -> Vec<u8> {
    let address = crate::socks_handler::write_location_to_vec(location);
    let mut request = Vec::with_capacity(3 + address.len());
    request.push(SOCKS5_VERSION);
    request.push(command);
    request.push(0x00);
    request.extend_from_slice(&address);
    request
}

/// Read and check a socks5 reply from inside the session.
async fn read_socks5_reply(session: &mut MieruStream) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut head = [0u8; 3];
    session.read_exact(&mut head).await?;
    if head[0] != SOCKS5_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the mieru server sent a reply that is not socks5",
        ));
    }
    if head[1] != SOCKS5_SUCCESS {
        return Err(std::io::Error::other(format!(
            "the mieru server refused the request with socks5 status {}",
            head[1]
        )));
    }

    // Consume the bound address the reply carries; its value is unused, but
    // its bytes have to leave the stream before payload starts.
    //
    // read_location_direct, not read_location: the buffered reader reads
    // greedily, so when the reply and the target's first response bytes arrive
    // in one decoded segment it would swallow the payload into a buffer that
    // is then dropped. This one reads exactly the address.
    crate::socks_handler::read_location_direct(session).await?;
    Ok(())
}

/// The mieru client handler.
///
/// A connection is one mieru session carrying one socks5 request, which is
/// what `MULTIPLEXING_OFF` looks like on the wire.
#[derive(Debug)]
pub struct MieruTcpHandler {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl MieruTcpHandler {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
        }
    }

    async fn open_session(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<MieruStream> {
        let now = crate::util::unix_time_secs().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mieru derives its key from the current time, and this clock is unusable: {e}"
                ),
            )
        })?;
        MieruStream::open(client_stream, &self.password, &self.username, now).await
    }
}

#[async_trait]
impl TcpClientHandler for MieruTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        use tokio::io::AsyncWriteExt;

        let mut session = self.open_session(client_stream).await?;
        let request = encode_socks5_request(SOCKS5_CONNECT, &remote_location.into_location());
        session.write_all(&request).await?;
        session.flush().await?;
        read_socks5_reply(&mut session).await?;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(session) as Box<dyn AsyncStream>,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        true
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use tokio::io::AsyncWriteExt;

        let mut session = self.open_session(client_stream).await?;
        let target_location = target.into_location();
        let request = encode_socks5_request(SOCKS5_UDP_ASSOCIATE, &target_location);
        session.write_all(&request).await?;
        session.flush().await?;
        read_socks5_reply(&mut session).await?;

        Ok(Box::new(MieruUdpStream::new(session, target_location)))
    }
}

/// A mieru session carrying socks5 UDP-associate traffic.
pub struct MieruUdpStream {
    session: MieruStream,
    /// The associated destination. Every datagram we send carries it in the
    /// socks5 UDP header, because that header is how the server learns where
    /// to forward the payload.
    target: crate::address::NetLocation,
    pending: Vec<u8>,
    /// A framed datagram being written out. The session writes at most one
    /// fragment per call, so a large datagram takes several, and the frame has
    /// to survive across them.
    outgoing: Vec<u8>,
    outgoing_at: usize,
}

impl std::fmt::Debug for MieruUdpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruUdpStream")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl MieruUdpStream {
    pub fn new(session: MieruStream, target: crate::address::NetLocation) -> Self {
        Self {
            session,
            target,
            pending: Vec::new(),
            outgoing: Vec::new(),
            outgoing_at: 0,
        }
    }
}

impl AsyncReadMessage for MieruUdpStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some((framed, consumed)) = decapsulate_udp(&this.pending)? {
                this.pending.drain(..consumed);
                // The server prepends the socks5 UDP header naming where the
                // datagram came from. shoes' AsyncMessageStream carries bare
                // payloads, so the header comes off here.
                let (_source, payload) = crate::socks5_udp_relay::parse_socks5_udp_packet(&framed)?;
                if payload.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "mieru UDP datagram is larger than the read buffer",
                    )));
                }
                buf.put_slice(payload);
                return Poll::Ready(Ok(()));
            }

            let mut chunk = [0u8; 8192];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.session).poll_read(cx, &mut chunk_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = chunk_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.pending.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWriteMessage for MieruUdpStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // A frame left over from a call that returned Pending is resumed as-is.
        // Re-encoding it would duplicate the part already on the wire, and the
        // caller is required to re-poll with the same datagram anyway.
        if this.outgoing_at >= this.outgoing.len() {
            // The server reads each frame with parseSocks5UDPDatagram and
            // expects RSV RSV FRAG ATYP ADDR PORT before the payload; that
            // header is how it learns the destination. pkg/socks5/udp.go:335.
            let with_header = crate::socks5_udp_relay::encode_socks5_udp_packet(&this.target, buf);
            this.outgoing = try_encapsulate_udp(&with_header)?;
            this.outgoing_at = 0;
        }

        // Frames legitimately span segments: upstream's Session.Write splits at
        // maxPDU and PacketOverStreamTunnel.Read reassembles with io.ReadFull
        // (pkg/protocol/packet.go). So a short write is normal and the frame
        // must be finished, not rejected - stopping half way would leave a
        // truncated frame on the wire and the peer would tear the session down
        // on the missing 0xff.
        while this.outgoing_at < this.outgoing.len() {
            match Pin::new(&mut this.session).poll_write(cx, &this.outgoing[this.outgoing_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "mieru session accepted no bytes of the UDP frame",
                    )));
                }
                Poll::Ready(Ok(n)) => this.outgoing_at += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.outgoing.clear();
        this.outgoing_at = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for MieruUdpStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.session).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for MieruUdpStream {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.session).poll_shutdown(cx)
    }
}

impl AsyncPing for MieruUdpStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for MieruUdpStream {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_encapsulation_frames_a_datagram() {
        let framed = encapsulate_udp(b"payload");
        assert_eq!(framed[0], UDP_MARKER_START);
        assert_eq!(&framed[1..3], &7u16.to_be_bytes());
        assert_eq!(&framed[3..10], b"payload");
        assert_eq!(framed[10], UDP_MARKER_END);
        assert_eq!(framed.len(), 1 + 2 + 7 + 1);
    }

    #[test]
    fn test_udp_decapsulation_round_trips() {
        let framed = encapsulate_udp(b"round trip");
        let (payload, consumed) = decapsulate_udp(&framed).unwrap().unwrap();
        assert_eq!(payload, b"round trip");
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn test_udp_decapsulation_waits_for_the_whole_datagram() {
        let framed = encapsulate_udp(b"incomplete");
        for cut in 0..framed.len() {
            assert!(
                decapsulate_udp(&framed[..cut]).unwrap().is_none(),
                "a {cut}-byte prefix is incomplete"
            );
        }
    }

    #[test]
    fn test_udp_decapsulation_rejects_bad_markers() {
        let mut framed = encapsulate_udp(b"payload");
        framed[0] = 0x01;
        assert!(decapsulate_udp(&framed).is_err());

        let mut framed = encapsulate_udp(b"payload");
        let last = framed.len() - 1;
        framed[last] = 0x00;
        assert!(decapsulate_udp(&framed).is_err());
    }

    #[test]
    fn test_a_datagram_too_large_to_frame_is_refused() {
        let oversized = vec![0u8; u16::MAX as usize + 1];
        assert!(try_encapsulate_udp(&oversized).is_err());
    }

    #[test]
    fn test_two_datagrams_decapsulate_in_sequence() {
        let mut wire = encapsulate_udp(b"first");
        wire.extend_from_slice(&encapsulate_udp(b"second"));

        let (first, consumed) = decapsulate_udp(&wire).unwrap().unwrap();
        assert_eq!(first, b"first");
        let (second, _) = decapsulate_udp(&wire[consumed..]).unwrap().unwrap();
        assert_eq!(second, b"second");
    }

    /// The frame the server reads is not the bare payload: it is a socks5 UDP
    /// datagram, `RSV RSV FRAG ATYP ADDR PORT payload`, which is how the
    /// server learns where to forward it. `pkg/socks5/udp.go:335`.
    #[test]
    fn test_a_udp_frame_carries_the_socks5_header() {
        let target = crate::address::NetLocation::from_str("1.2.3.4:53", None).unwrap();
        let with_header = crate::socks5_udp_relay::encode_socks5_udp_packet(&target, b"query");
        let framed = encapsulate_udp(&with_header);

        let (inner, _) = decapsulate_udp(&framed).unwrap().unwrap();
        assert_eq!(&inner[..3], &[0x00, 0x00, 0x00], "RSV RSV FRAG");
        assert_eq!(inner[3], 0x01, "address type is ipv4");
        assert_eq!(&inner[4..8], &[1, 2, 3, 4], "the destination address");
        assert_eq!(&inner[8..10], &53u16.to_be_bytes(), "the destination port");
        assert_eq!(&inner[10..], b"query", "then the payload");

        // And it parses back to what we put in.
        let (parsed_target, payload) =
            crate::socks5_udp_relay::parse_socks5_udp_packet(&inner).unwrap();
        assert_eq!(parsed_target, target);
        assert_eq!(payload, b"query");
    }

    /// A datagram larger than one fragment still has to reach the peer whole.
    /// Upstream splits at maxPDU on write and reassembles with io.ReadFull on
    /// read (`pkg/protocol/packet.go`), so a frame spanning segments is normal
    /// traffic - refusing it, or stopping at the first short write, drops the
    /// datagram and leaves a truncated frame the peer cannot parse.
    #[tokio::test]
    async fn test_a_datagram_larger_than_a_fragment_is_written_whole() {
        use crate::mieru::frame::decode_segment;
        use crate::mieru::testing::connect;
        use tokio::io::AsyncReadExt;

        let (session, mut server, mut peer) = connect().await;
        let target = crate::address::NetLocation::from_str("1.2.3.4:53", None).unwrap();
        let mut udp = MieruUdpStream::new(session, target.clone());

        let payload: Vec<u8> = (0..crate::mieru::MAX_FRAGMENT_LEN + 5000)
            .map(|i| i as u8)
            .collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            std::future::poll_fn(|cx| Pin::new(&mut udp).poll_write_message(cx, &sent)).await?;
            std::future::poll_fn(|cx| Pin::new(&mut udp).poll_flush_message(cx)).await
        });

        // Collect segments until the whole frame is on the wire.
        let expected = try_encapsulate_udp(&crate::socks5_udp_relay::encode_socks5_udp_packet(
            &target, &payload,
        ))
        .unwrap();
        let mut wire = Vec::new();
        let mut pending = Vec::new();
        let mut buf = vec![0u8; 65536];
        while wire.len() < expected.len() {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), server.read(&mut buf))
                .await
                .expect("the writer stalled on a short write")
                .unwrap();
            assert!(n > 0, "the session closed before the frame was complete");
            pending.extend_from_slice(&buf[..n]);
            while let Some((_, body, consumed)) = decode_segment(&mut peer.recv, &pending).unwrap()
            {
                wire.extend_from_slice(&body);
                pending.drain(..consumed);
            }
        }

        writer.await.unwrap().unwrap();
        assert_eq!(wire, expected, "the frame must arrive byte for byte");

        // And it parses back to the datagram we asked to send.
        let (inner, _) = decapsulate_udp(&wire).unwrap().unwrap();
        let (parsed_target, parsed_payload) =
            crate::socks5_udp_relay::parse_socks5_udp_packet(&inner).unwrap();
        assert_eq!(parsed_target, target);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_a_socks5_connect_request_has_the_documented_shape() {
        let location = crate::address::NetLocation::from_str("example.com:443", None).unwrap();
        let request = encode_socks5_request(SOCKS5_CONNECT, &location);
        assert_eq!(request[0], 0x05, "version");
        assert_eq!(request[1], SOCKS5_CONNECT, "command");
        assert_eq!(request[2], 0x00, "reserved");
        assert_eq!(request[3], 0x03, "address type is domain");
        assert_eq!(request[4], 11, "domain length");
        assert_eq!(&request[5..16], b"example.com");
        assert_eq!(&request[16..18], &443u16.to_be_bytes());
    }

    #[test]
    fn test_a_udp_associate_request_uses_its_own_command() {
        let location = crate::address::NetLocation::from_str("1.2.3.4:53", None).unwrap();
        let request = encode_socks5_request(SOCKS5_UDP_ASSOCIATE, &location);
        assert_eq!(request[1], SOCKS5_UDP_ASSOCIATE);
        assert_eq!(request[3], 0x01, "address type is ipv4");
    }
}
