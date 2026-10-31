use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn_proto::coding::Codec;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_util::task::AbortOnDropHandle;

use super::{
    session::{Generation, SETUP_TIMEOUT},
    udp::Fragment,
};
use crate::{
    address::{Address, NetLocation, ResolvedLocation},
    async_stream::{AsyncPing, AsyncStream},
    config::quic_client::Hysteria2ClientConfig,
    tcp::tcp_handler::TcpClientSetupResult,
};

fn padding(min: usize, max: usize) -> String {
    let mut rng = rand::rng();
    (0..rng.random_range(min..=max))
        .map(|_| char::from(rng.random_range(b'a'..=b'z')))
        .collect()
}

fn auth_request(password: &str) -> io::Result<http::Request<()>> {
    let mut auth = http::HeaderValue::from_str(password)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HY2 auth header"))?;
    auth.set_sensitive(true);
    http::Request::builder()
        .method("POST")
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", auth)
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", padding(256, 2047))
        .body(())
        .map_err(io::Error::other)
}

fn auth_response(response: &http::Response<()>) -> io::Result<bool> {
    if response.status().as_u16() != 233 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("HY2 authentication status {}", response.status()),
        ));
    }
    // Adaptive-only clients advertise RX=0 and never infer Brutal from a rate.
    if let Some(rate) = response.headers().get("Hysteria-CC-RX") {
        let rate = rate.to_str().map_err(io::Error::other)?;
        if rate != "auto" {
            rate.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid HY2 receive rate")
            })?;
        }
    }
    Ok(matches!(
        response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|v| v.to_str().ok()),
        Some("1" | "t" | "T" | "TRUE" | "true" | "True")
    ))
}

pub(super) async fn authenticate(
    connection: &quinn::Connection,
    config: &Hysteria2ClientConfig,
) -> io::Result<(bool, AbortOnDropHandle<()>)> {
    let (mut driver, mut sender) = h3::client::builder()
        .max_field_section_size(16 * 1024)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(io::Error::other)?;
    let hold = sender.clone();
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        // Both the driver and at least one SendRequest must survive authentication.
        let _hold = hold;
        let _ = driver.wait_idle().await;
    }));
    let mut request = sender
        .send_request(auth_request(&config.password.0)?)
        .await
        .map_err(io::Error::other)?;
    request.finish().await.map_err(io::Error::other)?;
    let response = request.recv_response().await.map_err(io::Error::other)?;
    let enabled = auth_response(&response)?;
    request.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    Ok((enabled, task))
}

fn authority(location: &NetLocation) -> io::Result<String> {
    let address = match location.address() {
        Address::Ipv6(ip) => format!("[{ip}]:{}", location.port()),
        address => format!("{address}:{}", location.port()),
    };
    if address.len() > 2048 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HY2 address too long",
        ));
    }
    Ok(address)
}

fn put_varint(out: &mut BytesMut, value: usize) -> io::Result<()> {
    let value = quinn::VarInt::from_u64(value as u64).map_err(io::Error::other)?;
    value.encode(out);
    Ok(())
}

fn take_varint(input: &mut &[u8]) -> io::Result<usize> {
    quinn::VarInt::decode(input)
        .map_err(|_| invalid("truncated HY2 varint"))?
        .into_inner()
        .try_into()
        .map_err(|_| invalid("HY2 length overflow"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn request(target: &NetLocation) -> io::Result<Bytes> {
    let address = authority(target)?;
    let padding = padding(64, 512);
    let mut bytes = BytesMut::new();
    put_varint(&mut bytes, 0x401)?;
    put_varint(&mut bytes, address.len())?;
    bytes.extend_from_slice(address.as_bytes());
    put_varint(&mut bytes, padding.len())?;
    bytes.extend_from_slice(padding.as_bytes());
    Ok(bytes.freeze())
}

async fn read_varint(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<usize> {
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes[..1]).await?;
    let size = 1 << (bytes[0] >> 6);
    stream.read_exact(&mut bytes[1..size]).await?;
    take_varint(&mut &bytes[..size])
}

async fn response(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let status = stream.read_u8().await?;
    let length = read_varint(stream).await?;
    if length > 2048 {
        return Err(invalid("HY2 response message too long"));
    }
    let mut message = vec![0; length];
    stream.read_exact(&mut message).await?;
    let length = read_varint(stream).await?;
    if length > 4096 {
        return Err(invalid("HY2 response padding too long"));
    }
    let mut padding = vec![0; length];
    stream.read_exact(&mut padding).await?;
    if status != 0 {
        return Err(io::Error::other(format!(
            "HY2 target refused: {}",
            String::from_utf8_lossy(&message)
        )));
    }
    Ok(())
}

type Response = Pin<Box<dyn Future<Output = io::Result<quinn::RecvStream>> + Send + Sync>>;

struct Stream {
    send: quinn::SendStream,
    recv: Option<quinn::RecvStream>,
    response: Option<Response>,
    _generation: Arc<Generation>,
}

pub(super) async fn connect(
    generation: Arc<Generation>,
    target: &ResolvedLocation,
) -> io::Result<TcpClientSetupResult> {
    let header = request(target.location())?;
    let (mut send, mut recv) =
        tokio::time::timeout(SETUP_TIMEOUT, generation.connection().open_bi()).await??;
    tokio::time::timeout(SETUP_TIMEOUT, send.write_all(&header)).await??;
    let response = Box::pin(async move {
        tokio::time::timeout(SETUP_TIMEOUT, response(&mut recv)).await??;
        Ok(recv)
    });
    Ok(TcpClientSetupResult {
        client_stream: Box::new(Stream {
            send,
            recv: None,
            response: Some(response),
            _generation: generation,
        }),
        early_data: None,
    })
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut self.response {
            let result = ready!(response.as_mut().poll(cx));
            self.response = None;
            self.recv = Some(result?);
        }
        match &mut self.recv {
            Some(recv) => Pin::new(recv).poll_read(cx, buf),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "HY2 response failed",
            ))),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(Into::into)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Stream {}

pub(super) fn decode(mut input: &[u8]) -> io::Result<Fragment<'_>> {
    if input.len() < 9 {
        return Err(invalid("short HY2 packet"));
    }
    let session = input.get_u32();
    let packet = input.get_u16();
    let index = input.get_u8();
    let count = input.get_u8();
    let length = take_varint(&mut input)?;
    if length == 0 || length > 2048 || input.len() < length {
        return Err(invalid("invalid HY2 UDP address"));
    }
    let address = std::str::from_utf8(&input[..length]).map_err(io::Error::other)?;
    let location = NetLocation::from_str(address, None)?;
    Ok(Fragment {
        session,
        packet,
        // HY2 assigns no meaning to fragment IDs on unfragmented packets.
        index: if count == 1 { 0 } else { index },
        count,
        location: Some(location),
        payload: &input[length..],
    })
}

pub(super) fn encode(
    session: u32,
    packet: u16,
    target: &NetLocation,
    payload: &[u8],
    mtu: usize,
) -> io::Result<Vec<Bytes>> {
    let address = authority(target)?;
    let mut suffix = BytesMut::new();
    put_varint(&mut suffix, address.len())?;
    suffix.extend_from_slice(address.as_bytes());
    let chunk = mtu
        .checked_sub(8 + suffix.len())
        .filter(|n| *n > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "HY2 datagram MTU too small"))?;
    let count = payload.len().div_ceil(chunk).max(1);
    if count > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many HY2 fragments",
        ));
    }
    let mut packets = Vec::with_capacity(count);
    for index in 0..count {
        let mut data = BytesMut::new();
        data.put_u32(session);
        data.put_u16(packet);
        data.put_u8(index as u8);
        data.put_u8(count as u8);
        data.extend_from_slice(&suffix);
        data.extend_from_slice(&payload[index * chunk..payload.len().min((index + 1) * chunk)]);
        packets.push(data.freeze());
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::quic_client::Secret, quic_client::test_connection_pair};
    use tokio::io::AsyncWriteExt;

    fn config(password: &str) -> Hysteria2ClientConfig {
        Hysteria2ClientConfig {
            password: Secret(password.into()),
            udp_enabled: true,
            obfs: None,
            hopping: None,
        }
    }

    fn auth_headers(padding: usize) -> Bytes {
        let mut block = BytesMut::new();
        h3::qpack::encode_stateless(
            &mut block,
            [
                h3::qpack::HeaderField::new(":status", "233"),
                h3::qpack::HeaderField::new("hysteria-padding", vec![b'x'; padding]),
            ],
        )
        .unwrap();
        let mut frame = BytesMut::new();
        put_varint(&mut frame, 1).unwrap();
        put_varint(&mut frame, block.len()).unwrap();
        frame.extend_from_slice(&block);
        frame.freeze()
    }

    fn oversized_frame() -> Bytes {
        let mut frame = BytesMut::new();
        put_varint(&mut frame, 1).unwrap();
        put_varint(&mut frame, 1 << 30).unwrap();
        frame.freeze()
    }

    async fn rejects_h3_input(input: Bytes, after_auth: bool) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (server, endpoint) = crate::quic_endpoint::test_endpoints();
            let (client, peer) = test_connection_pair(&server, &endpoint).await;
            let (authenticated, ready) = tokio::sync::oneshot::channel();
            let peer = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut control = peer.open_uni().await.unwrap();
                control.write_all(&[0, 4, 0]).await.unwrap();
                let (mut response, mut request) = peer.accept_bi().await.unwrap();
                request.read_to_end(16 * 1024).await.unwrap();
                if after_auth {
                    response.write_all(&auth_headers(0)).await.unwrap();
                    response.finish().unwrap();
                    ready.await.unwrap();
                    let _ = control.write_all(&input).await;
                } else {
                    let _ = response.write_all(&input).await;
                }
                let closed = peer.closed().await;
                if after_auth {
                    assert!(matches!(
                        closed,
                        quinn::ConnectionError::ApplicationClosed(error)
                            if error.error_code.into_inner() == h3::error::Code::H3_EXCESSIVE_LOAD.value()
                    ));
                }
            }));
            let result = authenticate(&client, &config("password")).await;
            if after_auth {
                let (_, _driver) = result.unwrap();
                authenticated.send(()).unwrap();
                client.closed().await;
            } else {
                let error = result.expect_err("oversized authentication response accepted");
                assert!(matches!(
                    error.get_ref().and_then(|error| error.downcast_ref::<h3::error::StreamError>()),
                    Some(h3::error::StreamError::HeaderTooBig { .. })
                ), "unexpected authentication error: {error}");
                client.close(0u32.into(), b"done");
            }
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn auth_headers_have_a_decoded_size_limit() {
        rejects_h3_input(auth_headers(32 * 1024), false).await;
    }

    #[tokio::test]
    async fn auth_rejects_oversized_headers_before_payload() {
        rejects_h3_input(oversized_frame(), false).await;
    }

    #[tokio::test]
    async fn retained_h3_control_stream_rejects_oversized_frames_before_payload() {
        rejects_h3_input(oversized_frame(), true).await;
    }

    #[tokio::test]
    async fn unknown_h3_frames_do_not_exhaust_a_lifetime_budget() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (server, endpoint) = crate::quic_endpoint::test_endpoints();
            let (client, peer) = test_connection_pair(&server, &endpoint).await;
            let (authenticated, ready) = tokio::sync::oneshot::channel();
            let peer = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut unknown = BytesMut::new();
                put_varint(&mut unknown, 0x21).unwrap();
                put_varint(&mut unknown, 2 * 1024 * 1024).unwrap();
                unknown.resize(unknown.len() + 2 * 1024 * 1024, 0xff);
                let mut control = peer.open_uni().await.unwrap();
                control.write_all(&[0, 4, 0]).await.unwrap();
                let (mut response, mut request) = peer.accept_bi().await.unwrap();
                request.read_to_end(16 * 1024).await.unwrap();
                response.write_all(&unknown).await.unwrap();
                response.write_all(&auth_headers(0)).await.unwrap();
                response.finish().unwrap();
                ready.await.unwrap();
                control.write_all(&unknown).await.unwrap();
                // The error proves the control decoder reached the next frame.
                control.write_all(&[0, 0]).await.unwrap();
                assert!(matches!(
                    peer.closed().await,
                    quinn::ConnectionError::ApplicationClosed(error)
                        if error.error_code.into_inner() == h3::error::Code::H3_FRAME_UNEXPECTED.value()
                ));
            }));
            let (_, _driver) = authenticate(&client, &config("password")).await.unwrap();
            authenticated.send(()).unwrap();
            client.closed().await;
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn authentication_headers_are_sensitive_and_permission_fails_closed() {
        let request = auth_request("secret").unwrap();
        assert_eq!(request.uri(), "https://hysteria/auth");
        assert!(request.headers()["hysteria-auth"].is_sensitive());
        assert!(!format!("{request:?}").contains("secret"));
        assert!(auth_request("bad\r\nheader").is_err());
        let password = "p\u{e4}ssword";
        let request = auth_request(password).unwrap();
        assert_eq!(
            request.headers()["hysteria-auth"].as_bytes(),
            password.as_bytes()
        );
        assert!(config(password).validate().is_ok());
        for (header, expected) in [
            (None, false),
            (Some("true"), true),
            (Some("1"), true),
            (Some("false"), false),
            (Some("garbage"), false),
            (Some("tRuE"), false),
        ] {
            let mut response = http::Response::builder().status(233);
            if let Some(header) = header {
                response = response.header("Hysteria-UDP", header);
            }
            assert_eq!(
                auth_response(&response.body(()).unwrap()).unwrap(),
                expected
            );
        }
        assert!(auth_response(&http::Response::builder().status(200).body(()).unwrap()).is_err());
        for rate in ["auto", "0", "1000000"] {
            assert!(
                auth_response(
                    &http::Response::builder()
                        .status(233)
                        .header("Hysteria-CC-RX", rate)
                        .body(())
                        .unwrap()
                )
                .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn response_bounds_and_exact_consumption() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer
            .write_all(&[0, 0, 3, 1, 2, 3, b'h', b'i'])
            .await
            .unwrap();
        response(&mut reader).await.unwrap();
        let mut greeting = [0; 2];
        reader.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"hi");
        for field in [2049, 4097] {
            let mut bytes = BytesMut::new();
            bytes.put_u8(0);
            if field == 4097 {
                bytes.put_u8(0);
            }
            put_varint(&mut bytes, field).unwrap();
            assert!(response(&mut bytes.as_ref()).await.is_err());
        }
        assert!(
            response(&mut &[1, 3, b'b', b'a', b'd', 0][..])
                .await
                .is_err()
        );
        assert!(response(&mut &[0, 3, b'a'][..]).await.is_err());
    }

    #[test]
    fn udp_fragments_repeat_address_and_reassemble_out_of_order() {
        for address in ["example.com:53", "127.0.0.1:53", "[::1]:53"] {
            let target = NetLocation::from_str(address, None).unwrap();
            for length in [0, 1, 1200, 4096, 65535] {
                let payload = vec![17; length];
                let packets = encode(23, 37, &target, &payload, 1200).unwrap();
                let mut fragments = crate::udp_fragments::UdpFragments::new();
                let mut result = None;
                for packet in packets.iter().rev() {
                    assert!(packet.len() <= 1200);
                    let frame = decode(packet).unwrap();
                    assert_eq!(frame.location.as_ref(), Some(&target));
                    result = fragments
                        .push(
                            (frame.session, frame.packet),
                            frame.count,
                            frame.index,
                            frame.location,
                            frame.payload,
                        )
                        .unwrap()
                        .or(result);
                }
                assert_eq!(result.unwrap().1.as_ref(), payload);
            }
        }
        assert!(decode(&[0; 8]).is_err());
        assert!(decode(&[0, 0, 0, 0, 0, 0, 0, 1, 0xff]).is_err());
        let target = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let mut packet = encode(0, 0, &target, b"single", 1200)
            .unwrap()
            .remove(0)
            .to_vec();
        packet[6] = 255;
        assert_eq!(decode(&packet).unwrap().index, 0);
    }
}
