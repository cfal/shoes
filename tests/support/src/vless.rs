//! Minimal VLESS UDP and XUDP clients for integration tests.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

const VLESS_VERSION: u8 = 0;
const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
const NETWORK_UDP: u8 = 2;
const MAX_RECEIVE_BUFFER: usize = 2 + u8::MAX as usize + 4 + 2 * u16::MAX as usize;

pub const XUDP_STATUS_NEW: u8 = 1;
pub const XUDP_STATUS_KEEP: u8 = 2;
pub const XUDP_STATUS_END: u8 = 3;
pub const XUDP_STATUS_KEEPALIVE: u8 = 4;
pub const XUDP_OPTION_DATA: u8 = 1;
pub const XUDP_OPTION_ERROR: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VlessDestination {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl VlessDestination {
    fn encode(&self, output: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Ip(SocketAddr::V4(address)) => {
                output.extend_from_slice(&address.port().to_be_bytes());
                output.push(ADDRESS_IPV4);
                output.extend_from_slice(&address.ip().octets());
            }
            Self::Ip(SocketAddr::V6(address)) => {
                output.extend_from_slice(&address.port().to_be_bytes());
                output.push(ADDRESS_IPV6);
                output.extend_from_slice(&address.ip().octets());
            }
            Self::Domain(hostname, port) => {
                let hostname = hostname.as_bytes();
                let length = u8::try_from(hostname.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "VLESS hostname is too long")
                })?;
                output.extend_from_slice(&port.to_be_bytes());
                output.extend_from_slice(&[ADDRESS_DOMAIN, length]);
                output.extend_from_slice(hostname);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XudpFrame {
    pub session_id: u16,
    pub status: u8,
    pub options: u8,
    pub destination: Option<VlessDestination>,
    pub payload: Option<Vec<u8>>,
}

pub struct VlessUdpClient<S> {
    stream: S,
    response: ResponseBuffer,
}

impl<S> VlessUdpClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect(
        mut stream: S,
        uuid: [u8; 16],
        destination: VlessDestination,
    ) -> io::Result<Self> {
        stream
            .write_all(&encode_vless_udp_request(uuid, &destination)?)
            .await?;
        Ok(Self {
            stream,
            response: ResponseBuffer::default(),
        })
    }

    pub async fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        self.stream
            .write_all(&encode_vless_udp_packet(payload)?)
            .await
    }

    pub async fn recv_packet(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            self.response.consume_header()?;
            if self.response.header_consumed
                && let Some(payload) = parse_udp_packet(&mut self.response.bytes)?
            {
                return Ok(payload);
            }
            self.response.read_more(&mut self.stream, deadline).await?;
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

pub struct XudpClient<S> {
    stream: S,
    response: ResponseBuffer,
}

impl<S> XudpClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn connect(mut stream: S, uuid: [u8; 16]) -> io::Result<Self> {
        stream.write_all(&encode_vless_xudp_request(uuid)).await?;
        Ok(Self {
            stream,
            response: ResponseBuffer::default(),
        })
    }

    pub async fn send_frame(&mut self, frame: &XudpFrame) -> io::Result<()> {
        self.stream.write_all(&encode_xudp_frame(frame)?).await
    }

    pub async fn recv_frame(&mut self, timeout: Duration) -> io::Result<XudpFrame> {
        let deadline = Instant::now() + timeout;
        loop {
            self.response.consume_header()?;
            if self.response.header_consumed
                && let Some(frame) = parse_xudp_frame(&mut self.response.bytes)?
            {
                return Ok(frame);
            }
            self.response.read_more(&mut self.stream, deadline).await?;
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[derive(Default)]
struct ResponseBuffer {
    bytes: Vec<u8>,
    header_consumed: bool,
}

impl ResponseBuffer {
    fn consume_header(&mut self) -> io::Result<()> {
        if self.header_consumed || self.bytes.len() < 2 {
            return Ok(());
        }
        if self.bytes[0] != VLESS_VERSION {
            return Err(invalid_data(format!(
                "unsupported VLESS response version {}",
                self.bytes[0]
            )));
        }
        let header_length = 2 + self.bytes[1] as usize;
        if self.bytes.len() >= header_length {
            self.bytes.drain(..header_length);
            self.header_consumed = true;
        }
        Ok(())
    }

    async fn read_more<S>(&mut self, stream: &mut S, deadline: Instant) -> io::Result<()>
    where
        S: AsyncRead + Unpin,
    {
        if self.bytes.len() >= MAX_RECEIVE_BUFFER {
            return Err(invalid_data("VLESS response exceeds the receive limit"));
        }

        let mut chunk = [0; 8192];
        let length = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VLESS response timed out"))??;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated VLESS response",
            ));
        }
        self.bytes.extend_from_slice(&chunk[..length]);
        Ok(())
    }
}

pub fn parse_uuid(uuid: &str) -> io::Result<[u8; 16]> {
    let compact: String = uuid.chars().filter(|character| *character != '-').collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS UUID must contain 32 hexadecimal digits",
        ));
    }

    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    Ok(result)
}

pub fn encode_vless_udp_request(
    uuid: [u8; 16],
    destination: &VlessDestination,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32);
    output.push(VLESS_VERSION);
    output.extend_from_slice(&uuid);
    output.push(0);
    output.push(COMMAND_UDP);
    destination.encode(&mut output)?;
    Ok(output)
}

pub fn encode_vless_xudp_request(uuid: [u8; 16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(19);
    output.push(VLESS_VERSION);
    output.extend_from_slice(&uuid);
    output.extend_from_slice(&[0, COMMAND_MUX]);
    output
}

pub fn encode_vless_udp_packet(payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS UDP payload is too large",
        )
    })?;
    let mut output = Vec::with_capacity(payload.len() + 2);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn encode_xudp_frame(frame: &XudpFrame) -> io::Result<Vec<u8>> {
    validate_xudp_status(frame.status)?;
    let has_data = frame.options & XUDP_OPTION_DATA != 0;
    if has_data != frame.payload.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP DATA option and payload presence must agree",
        ));
    }

    let destination_allowed = matches!(frame.status, XUDP_STATUS_NEW | XUDP_STATUS_KEEP);
    if frame.destination.is_some() && !destination_allowed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP control frames cannot contain a destination",
        ));
    }
    if frame.status == XUDP_STATUS_NEW && frame.destination.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP New frames require a destination",
        ));
    }

    let mut metadata = Vec::with_capacity(32);
    metadata.extend_from_slice(&frame.session_id.to_be_bytes());
    metadata.extend_from_slice(&[frame.status, frame.options]);
    if let Some(destination) = &frame.destination {
        metadata.push(NETWORK_UDP);
        destination.encode(&mut metadata)?;
    }
    let metadata_length = u16::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XUDP metadata is too large"))?;

    let payload_length = frame
        .payload
        .as_ref()
        .map(|payload| {
            u16::try_from(payload.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "XUDP payload is too large")
            })
        })
        .transpose()?;
    let mut output =
        Vec::with_capacity(metadata.len() + frame.payload.as_deref().map_or(2, |p| p.len() + 4));
    output.extend_from_slice(&metadata_length.to_be_bytes());
    output.extend_from_slice(&metadata);
    if let (Some(length), Some(payload)) = (payload_length, &frame.payload) {
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(payload);
    }
    Ok(output)
}

fn parse_udp_packet(input: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if input.len() < 2 {
        return Ok(None);
    }
    let payload_length = u16::from_be_bytes([input[0], input[1]]) as usize;
    let frame_length = 2 + payload_length;
    if input.len() < frame_length {
        return Ok(None);
    }
    let payload = input[2..frame_length].to_vec();
    input.drain(..frame_length);
    Ok(Some(payload))
}

fn parse_xudp_frame(input: &mut Vec<u8>) -> io::Result<Option<XudpFrame>> {
    if input.len() < 2 {
        return Ok(None);
    }
    let metadata_length = u16::from_be_bytes([input[0], input[1]]) as usize;
    if metadata_length < 4 {
        return Err(invalid_data("XUDP metadata is shorter than its header"));
    }
    let metadata_end = 2 + metadata_length;
    if input.len() < metadata_end {
        return Ok(None);
    }

    let session_id = u16::from_be_bytes([input[2], input[3]]);
    let status = input[4];
    let options = input[5];
    validate_xudp_status(status)?;
    let mut metadata_offset = 6;
    let has_destination = status == XUDP_STATUS_NEW
        || (status == XUDP_STATUS_KEEP
            && metadata_offset < metadata_end
            && input[metadata_offset] == NETWORK_UDP);
    let destination = if has_destination {
        let (destination, consumed) =
            parse_xudp_destination(&input[metadata_offset..metadata_end])?;
        metadata_offset += consumed;
        Some(destination)
    } else {
        None
    };
    let _extension = &input[metadata_offset..metadata_end];

    let payload = if options & XUDP_OPTION_DATA != 0 {
        if input.len() < metadata_end + 2 {
            return Ok(None);
        }
        let payload_length =
            u16::from_be_bytes([input[metadata_end], input[metadata_end + 1]]) as usize;
        let frame_end = metadata_end + 2 + payload_length;
        if input.len() < frame_end {
            return Ok(None);
        }
        let payload = input[metadata_end + 2..frame_end].to_vec();
        input.drain(..frame_end);
        Some(payload)
    } else {
        input.drain(..metadata_end);
        None
    };

    Ok(Some(XudpFrame {
        session_id,
        status,
        options,
        destination,
        payload,
    }))
}

fn parse_xudp_destination(input: &[u8]) -> io::Result<(VlessDestination, usize)> {
    if input.first() != Some(&NETWORK_UDP) {
        return Err(invalid_data("XUDP destination is not UDP"));
    }
    if input.len() < 4 {
        return Err(unexpected_eof("truncated XUDP destination"));
    }
    let port = u16::from_be_bytes([input[1], input[2]]);
    match input[3] {
        ADDRESS_IPV4 => {
            let address = input
                .get(4..8)
                .ok_or_else(|| unexpected_eof("truncated XUDP IPv4 address"))?;
            Ok((
                VlessDestination::Ip(SocketAddr::from((
                    [address[0], address[1], address[2], address[3]],
                    port,
                ))),
                8,
            ))
        }
        ADDRESS_IPV6 => {
            let address: [u8; 16] = input
                .get(4..20)
                .ok_or_else(|| unexpected_eof("truncated XUDP IPv6 address"))?
                .try_into()
                .expect("slice length is checked");
            Ok((VlessDestination::Ip(SocketAddr::from((address, port))), 20))
        }
        ADDRESS_DOMAIN => {
            let hostname_length = *input
                .get(4)
                .ok_or_else(|| unexpected_eof("missing XUDP hostname length"))?
                as usize;
            let hostname = input
                .get(5..5 + hostname_length)
                .ok_or_else(|| unexpected_eof("truncated XUDP hostname"))?;
            let hostname = String::from_utf8(hostname.to_vec())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Ok((
                VlessDestination::Domain(hostname, port),
                5 + hostname_length,
            ))
        }
        address_type => Err(invalid_data(format!(
            "unsupported XUDP address type 0x{address_type:02x}"
        ))),
    }
}

fn validate_xudp_status(status: u8) -> io::Result<()> {
    if matches!(
        status,
        XUDP_STATUS_NEW | XUDP_STATUS_KEEP | XUDP_STATUS_END | XUDP_STATUS_KEEPALIVE
    ) {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "unsupported XUDP status 0x{status:02x}"
        )))
    }
}

fn invalid_data(error: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.into())
}

fn unexpected_eof(error: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    const UUID: [u8; 16] = [0; 16];

    struct ChunkedStream {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkedStream {
        fn split_at(bytes: &[u8], split: usize) -> Self {
            let chunks = [&bytes[..split], &bytes[split..]]
                .into_iter()
                .filter(|chunk| !chunk.is_empty())
                .map(<[u8]>::to_vec)
                .collect();
            Self { chunks }
        }
    }

    impl AsyncRead for ChunkedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let length = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..length]);
            if length < chunk.len() {
                chunk.drain(..length);
                self.chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ChunkedStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn request_vectors_cover_every_address_type() {
        let ipv4 = encode_vless_udp_request(
            UUID,
            &VlessDestination::Ip("127.0.0.1:4660".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(
            ipv4,
            [
                vec![0],
                vec![0; 16],
                vec![0, 2, 0x12, 0x34, 1, 127, 0, 0, 1]
            ]
            .concat()
        );

        let domain =
            encode_vless_udp_request(UUID, &VlessDestination::Domain("a.test".to_string(), 53))
                .unwrap();
        assert_eq!(
            domain,
            [
                vec![0],
                vec![0; 16],
                vec![0, 2, 0, 53, 2, 6],
                b"a.test".to_vec()
            ]
            .concat()
        );

        let ipv6 =
            encode_vless_udp_request(UUID, &VlessDestination::Ip("[::1]:443".parse().unwrap()))
                .unwrap();
        assert_eq!(
            ipv6,
            [
                vec![0],
                vec![0; 16],
                vec![0, 2, 1, 0xbb, 3],
                vec![0; 15],
                vec![1],
            ]
            .concat()
        );
    }

    #[test]
    fn xudp_new_vector_matches_the_reference_format() {
        let frame = XudpFrame {
            session_id: 1,
            status: XUDP_STATUS_NEW,
            options: XUDP_OPTION_DATA,
            destination: Some(VlessDestination::Ip("127.0.0.1:4660".parse().unwrap())),
            payload: Some(b"x".to_vec()),
        };
        assert_eq!(
            encode_xudp_frame(&frame).unwrap(),
            [
                0x00, 0x0c, 0x00, 0x01, 0x01, 0x01, 0x02, 0x12, 0x34, 0x01, 0x7f, 0, 0, 1, 0, 1,
                b'x'
            ]
        );

        let domain = XudpFrame {
            destination: Some(VlessDestination::Domain("a.test".to_string(), 53)),
            ..frame.clone()
        };
        assert_eq!(
            encode_xudp_frame(&domain).unwrap(),
            [
                0, 15, 0, 1, 1, 1, 2, 0, 53, 2, 6, b'a', b'.', b't', b'e', b's', b't', 0, 1, b'x',
            ]
        );

        let ipv6 = XudpFrame {
            destination: Some(VlessDestination::Ip("[::1]:443".parse().unwrap())),
            ..frame
        };
        assert_eq!(
            encode_xudp_frame(&ipv6).unwrap(),
            [
                vec![0, 24, 0, 1, 1, 1, 2, 1, 0xbb, 3],
                vec![0; 15],
                vec![1, 0, 1, b'x'],
            ]
            .concat()
        );
    }

    #[test]
    fn xudp_encoding_distinguishes_empty_and_absent_data() {
        let empty = XudpFrame {
            session_id: 7,
            status: XUDP_STATUS_KEEPALIVE,
            options: XUDP_OPTION_DATA,
            destination: None,
            payload: Some(Vec::new()),
        };
        assert_eq!(encode_xudp_frame(&empty).unwrap(), [0, 4, 0, 7, 4, 1, 0, 0]);

        let absent = XudpFrame {
            options: 0,
            payload: None,
            ..empty
        };
        assert_eq!(encode_xudp_frame(&absent).unwrap(), [0, 4, 0, 7, 4, 0]);
    }

    #[test]
    fn payload_lengths_are_checked() {
        assert_eq!(
            encode_vless_udp_packet(&vec![0; 65_535]).unwrap().len(),
            65_537
        );
        assert_eq!(
            encode_vless_udp_packet(&vec![0; 65_536])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let oversized = XudpFrame {
            session_id: 1,
            status: XUDP_STATUS_KEEP,
            options: XUDP_OPTION_DATA,
            destination: None,
            payload: Some(vec![0; 65_536]),
        };
        assert_eq!(
            encode_xudp_frame(&oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn udp_reader_handles_every_split_with_coalesced_packets() {
        let response = [
            &[0, 2, 0xaa, 0xbb][..],
            &[0, 3, b'o', b'n', b'e'][..],
            &[0, 3, b't', b'w', b'o'][..],
        ]
        .concat();

        for split in 0..=response.len() {
            let mut client = VlessUdpClient::connect(
                ChunkedStream::split_at(&response, split),
                UUID,
                VlessDestination::Ip("127.0.0.1:53".parse().unwrap()),
            )
            .await
            .unwrap();

            assert_eq!(
                client.recv_packet(Duration::from_secs(1)).await.unwrap(),
                b"one"
            );
            assert_eq!(
                client.recv_packet(Duration::from_secs(1)).await.unwrap(),
                b"two"
            );
        }
    }

    #[tokio::test]
    async fn xudp_reader_handles_extensions_control_frames_and_coalescing() {
        let response = [
            &[0, 0][..],
            &[0, 4, 0, 1, XUDP_STATUS_KEEP, 0][..],
            &[0, 4, 0, 1, XUDP_STATUS_END, XUDP_OPTION_ERROR][..],
            &[0, 4, 0, 1, XUDP_STATUS_KEEPALIVE, 0][..],
            &[0, 4, 0, 1, XUDP_STATUS_KEEPALIVE, XUDP_OPTION_DATA, 0, 0][..],
            &[
                0,
                12,
                0,
                2,
                XUDP_STATUS_NEW,
                XUDP_OPTION_DATA,
                NETWORK_UDP,
                0,
                53,
                ADDRESS_IPV4,
                127,
                0,
                0,
                1,
                0,
                1,
                b'x',
            ][..],
            &[
                0,
                20,
                0,
                2,
                XUDP_STATUS_KEEP,
                XUDP_OPTION_DATA,
                NETWORK_UDP,
                0,
                53,
                ADDRESS_IPV4,
                127,
                0,
                0,
                1,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                0,
                1,
                b'y',
            ][..],
        ]
        .concat();
        let (client_stream, mut peer) = duplex(512);
        let mut client = XudpClient::connect(client_stream, UUID).await.unwrap();
        let peer_task = tokio::spawn(async move {
            let mut request = [0; 19];
            peer.read_exact(&mut request).await.unwrap();
            peer.write_all(&response).await.unwrap();
        });

        let first = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(first.status, XUDP_STATUS_KEEP);
        assert_eq!(first.destination, None);
        assert_eq!(first.payload, None);
        let second = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(second.status, XUDP_STATUS_END);
        assert_eq!(second.options, XUDP_OPTION_ERROR);
        let third = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(third.status, XUDP_STATUS_KEEPALIVE);
        assert_eq!(third.payload, None);
        let fourth = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(fourth.payload, Some(Vec::new()));
        let fifth = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(fifth.payload, Some(b"x".to_vec()));
        assert_eq!(
            fifth.destination,
            Some(VlessDestination::Ip("127.0.0.1:53".parse().unwrap()))
        );
        let sixth = client.recv_frame(Duration::from_secs(1)).await.unwrap();
        assert_eq!(sixth.payload, Some(b"y".to_vec()));
        assert_eq!(
            sixth.destination,
            Some(VlessDestination::Ip("127.0.0.1:53".parse().unwrap()))
        );
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn xudp_reader_handles_every_split_boundary() {
        let response = [
            0,
            1,
            0xaa,
            0,
            12,
            0,
            1,
            XUDP_STATUS_NEW,
            XUDP_OPTION_DATA,
            NETWORK_UDP,
            0,
            53,
            ADDRESS_IPV4,
            127,
            0,
            0,
            1,
            0,
            3,
            b'o',
            b'n',
            b'e',
        ];

        for split in 0..=response.len() {
            let mut client = XudpClient::connect(ChunkedStream::split_at(&response, split), UUID)
                .await
                .unwrap();

            let frame = client.recv_frame(Duration::from_secs(1)).await.unwrap();
            assert_eq!(frame.session_id, 1);
            assert_eq!(frame.payload, Some(b"one".to_vec()));
        }
    }

    #[tokio::test]
    async fn partial_response_survives_timeout() {
        let (client_stream, mut peer) = duplex(256);
        let mut client = VlessUdpClient::connect(
            client_stream,
            UUID,
            VlessDestination::Ip("127.0.0.1:53".parse().unwrap()),
        )
        .await
        .unwrap();
        let peer_task = tokio::spawn(async move {
            let mut request = [0; 26];
            peer.read_exact(&mut request).await.unwrap();
            peer.write_all(&[0, 0, 0, 3, b'o']).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            peer.write_all(b"ne").await.unwrap();
        });

        assert_eq!(
            client
                .recv_packet(Duration::from_millis(10))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            client.recv_packet(Duration::from_secs(1)).await.unwrap(),
            b"one"
        );
        peer_task.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_and_truncated_responses_are_rejected() {
        async fn failure(response: &[u8]) -> io::ErrorKind {
            let (client_stream, mut peer) = duplex(256);
            let mut client = XudpClient::connect(client_stream, UUID).await.unwrap();
            let response = response.to_vec();
            let peer_task = tokio::spawn(async move {
                let mut request = [0; 19];
                peer.read_exact(&mut request).await.unwrap();
                peer.write_all(&response).await.unwrap();
            });
            let kind = client
                .recv_frame(Duration::from_secs(1))
                .await
                .unwrap_err()
                .kind();
            peer_task.await.unwrap();
            kind
        }

        assert_eq!(failure(&[1, 0]).await, io::ErrorKind::InvalidData);
        assert_eq!(
            failure(&[0, 0, 0, 3, 0, 1, 1]).await,
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            failure(&[0, 0, 0, 12, 0, 1, 1, 1, 2, 0, 53, 1, 127]).await,
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            failure(&[0, 0, 0, 12, 0, 1, 1, 1, 2, 0, 53, 0xff, 0, 0, 0, 0]).await,
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn uuid_parser_rejects_non_hex_input() {
        assert_eq!(
            parse_uuid("not-a-uuid").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            parse_uuid("b85798ef-e9dc-46a4-9a87-8da4499d36d0").unwrap(),
            [
                0xb8, 0x57, 0x98, 0xef, 0xe9, 0xdc, 0x46, 0xa4, 0x9a, 0x87, 0x8d, 0xa4, 0x49, 0x9d,
                0x36, 0xd0,
            ]
        );
    }
}
