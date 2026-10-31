use std::{io, sync::Arc, time::Duration};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::{Semaphore, mpsc, oneshot};

use super::{
    session::{Generation, SETUP_TIMEOUT},
    udp::Fragment,
};
use crate::{
    address::{Address, NetLocation, ResolvedLocation},
    config::quic_client::TuicClientConfig,
    quic_stream::QuicStream,
    tcp::tcp_handler::TcpClientSetupResult,
};

pub(super) const MAX_PACKET: usize = 10 + 259 + 65535;
const MAX_COMMAND_WRITERS: usize = 64;

#[derive(Clone)]
pub(super) struct CommandWriter {
    connection: quinn::Connection,
    slots: Arc<Semaphore>,
}

impl CommandWriter {
    pub fn new(connection: quinn::Connection) -> Self {
        Self {
            connection,
            slots: Arc::new(Semaphore::new(MAX_COMMAND_WRITERS)),
        }
    }

    pub async fn send(&self, bytes: Bytes) -> io::Result<()> {
        let (permit, mut stream) = tokio::time::timeout(Duration::from_secs(5), async {
            let permit = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .map_err(io::Error::other)?;
            let stream = self.connection.open_uni().await?;
            Ok::<_, io::Error>((permit, stream))
        })
        .await??;
        // Dropping a partial command sends FIN, which peers treat as a fatal
        // protocol error. Once admitted, finish independently of caller cancellation.
        // The permit bounds detached writers; connection closure releases them.
        tokio::spawn(async move {
            let _permit = permit;
            stream.write_all(&bytes).await?;
            stream.finish()?;
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(io::Error::other)?
    }
}

pub(super) async fn authenticate(
    commands: &CommandWriter,
    config: &TuicClientConfig,
) -> io::Result<()> {
    let uuid = config.uuid_bytes()?;
    let mut token = [0; 32];
    commands
        .connection
        .export_keying_material(&mut token, &uuid, config.password.0.as_bytes())
        .map_err(|_| io::Error::other("TUIC TLS exporter failed"))?;
    let mut request = BytesMut::from(&[5, 0][..]);
    request.extend_from_slice(&uuid);
    request.extend_from_slice(&token);
    commands.send(request.freeze()).await
}

pub(super) struct Dissociate {
    pub id: u16,
    pub completed: Option<oneshot::Sender<io::Result<()>>>,
}

pub(super) async fn request_dissociate(
    sender: mpsc::Sender<Dissociate>,
    id: u16,
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async move {
        let (completed, result) = oneshot::channel();
        sender
            .send(Dissociate {
                id,
                completed: Some(completed),
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
        result
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?
    })
    .await?
}

pub(super) async fn dissociate_loop(
    writer: CommandWriter,
    mut commands: mpsc::Receiver<Dissociate>,
) {
    loop {
        let command = tokio::select! {
            _ = writer.connection.closed() => return,
            command = commands.recv() => command,
        };
        let Some(command) = command else { return };
        let id = command.id.to_be_bytes();
        let result = writer
            .send(Bytes::copy_from_slice(&[5, 3, id[0], id[1]]))
            .await;
        if let Some(completed) = command.completed {
            let _ = completed.send(result);
        }
    }
}

pub(super) async fn heartbeat(connection: quinn::Connection, seconds: u64) {
    let mut tick = tokio::time::interval(Duration::from_secs(seconds));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = connection.closed() => return,
            _ = tick.tick() => if connection.send_datagram(Bytes::from_static(&[5, 4])).is_err() {
                connection.close(0u32.into(), b"heartbeat failed");
                return;
            },
        }
    }
}

pub(super) async fn connect(
    generation: Arc<Generation>,
    target: &ResolvedLocation,
) -> io::Result<TcpClientSetupResult> {
    let mut request = BytesMut::from(&[5, 1][..]);
    encode_address(&mut request, target.location())?;
    let (mut send, recv) =
        tokio::time::timeout(SETUP_TIMEOUT, generation.connection().open_bi()).await??;
    tokio::time::timeout(SETUP_TIMEOUT, send.write_all(&request)).await??;
    Ok(TcpClientSetupResult {
        client_stream: Box::new(QuicStream::from(send, recv).with_owner(generation)),
        early_data: None,
    })
}

fn encode_address(out: &mut BytesMut, location: &NetLocation) -> io::Result<()> {
    match location.address() {
        Address::Hostname(name) => {
            let length: u8 = name.len().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TUIC hostname exceeds 255 bytes",
                )
            })?;
            if length == 0 {
                return Err(invalid("empty TUIC hostname"));
            }
            out.put_u8(0);
            out.put_u8(length);
            out.extend_from_slice(name.as_bytes());
        }
        Address::Ipv4(ip) => {
            out.put_u8(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ipv6(ip) => {
            out.put_u8(2);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.put_u16(location.port());
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    if input.len() < count {
        return Err(invalid("truncated TUIC packet"));
    }
    let (value, rest) = input.split_at(count);
    *input = rest;
    Ok(value)
}

fn decode_address(input: &mut &[u8]) -> io::Result<Option<NetLocation>> {
    let kind = take(input, 1)?[0];
    let address = match kind {
        0xff => return Ok(None),
        0 => {
            let length = take(input, 1)?[0] as usize;
            if length == 0 {
                return Err(invalid("empty TUIC hostname"));
            }
            let name = std::str::from_utf8(take(input, length)?).map_err(io::Error::other)?;
            Address::from(name)?
        }
        1 => Address::Ipv4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(take(input, 4)?).unwrap(),
        )),
        2 => Address::Ipv6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(take(input, 16)?).unwrap(),
        )),
        _ => return Err(invalid("invalid TUIC address type")),
    };
    let port = u16::from_be_bytes(take(input, 2)?.try_into().unwrap());
    Ok(Some(NetLocation::new(address, port)))
}

pub(super) fn decode(mut input: &[u8]) -> io::Result<Fragment<'_>> {
    if take(&mut input, 2)? != [5, 2] {
        return Err(invalid("invalid TUIC packet command"));
    }
    if input.len() < 8 {
        return Err(invalid("short TUIC packet"));
    }
    let session = input.get_u16() as u32;
    let packet = input.get_u16();
    let count = input.get_u8();
    let index = input.get_u8();
    let size = input.get_u16() as usize;
    let location = decode_address(&mut input)?;
    if input.len() != size {
        return Err(invalid("TUIC payload size mismatch"));
    }
    if index == 0 && location.is_none() {
        return Err(invalid("TUIC first fragment has no address"));
    }
    Ok(Fragment {
        session,
        packet,
        count,
        index,
        location,
        payload: input,
    })
}

pub(super) fn encode(
    session: u32,
    packet: u16,
    target: &NetLocation,
    payload: &[u8],
    mtu: usize,
) -> io::Result<Vec<Bytes>> {
    let mut address = BytesMut::new();
    encode_address(&mut address, target)?;
    let chunk = mtu
        .checked_sub(10 + address.len())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "TUIC datagram MTU too small")
        })?;
    let count = payload.len().div_ceil(chunk).max(1);
    if count > 255 || payload.len() > 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC packet too large",
        ));
    }
    let mut packets = Vec::with_capacity(count);
    for index in 0..count {
        let part = &payload[index * chunk..payload.len().min((index + 1) * chunk)];
        let mut data = BytesMut::from(&[5, 2][..]);
        data.put_u16(session as u16);
        data.put_u16(packet);
        data.put_u8(count as u8);
        data.put_u8(index as u8);
        data.put_u16(part.len() as u16);
        if index == 0 {
            data.extend_from_slice(&address);
        } else {
            data.put_u8(0xff);
        }
        data.extend_from_slice(part);
        packets.push(data.freeze());
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{quic_client::test_connection_pair, udp_fragments::UdpFragments};

    #[tokio::test]
    async fn cancelled_command_finishes_without_truncating_the_stream() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (server, client) = crate::quic_endpoint::test_endpoints();
            let (client, peer) = test_connection_pair(&server, &client).await;
            client.set_send_window(32);
            let commands = CommandWriter::new(client.clone());
            let payload = Bytes::from(vec![42; 1024]);
            let mut write = Box::pin(commands.send(payload.clone()));
            assert!(futures::poll!(&mut write).is_pending());
            drop(write);
            let mut stream = peer.accept_uni().await.unwrap();
            assert_eq!(stream.read_to_end(payload.len()).await.unwrap(), payload);
            assert!(peer.close_reason().is_none());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_commands_keep_their_slots_until_connection_close() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (server, endpoint) = crate::quic_endpoint::test_endpoints();
            let (client, _peer) = test_connection_pair(&server, &endpoint).await;
            client.set_send_window(0);
            let commands = CommandWriter::new(client.clone());
            for _ in 0..MAX_COMMAND_WRITERS {
                let mut write = Box::pin(commands.send(Bytes::from_static(b"pending")));
                assert!(futures::poll!(&mut write).is_pending());
            }
            assert_eq!(commands.slots.available_permits(), 0);
            let mut blocked = Box::pin(commands.send(Bytes::from_static(b"not admitted")));
            assert!(futures::poll!(&mut blocked).is_pending());
            drop(blocked);
            client.close(0u32.into(), b"done");
            while commands.slots.available_permits() != MAX_COMMAND_WRITERS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn packets_reassemble_out_of_order_with_empty_and_full_payloads() {
        for target in ["127.0.0.1:53", "[::1]:53", "example.com:53"] {
            let target = NetLocation::from_str(target, None).unwrap();
            for length in [0, 1, 1200, 4096, 65535] {
                let payload = vec![42; length];
                let packets = encode(65535, 42, &target, &payload, 1200).unwrap();
                let mut fragments = UdpFragments::new();
                let mut result = None;
                for packet in packets.iter().rev() {
                    let fragment = decode(packet).unwrap();
                    result = fragments
                        .push(
                            (fragment.session, fragment.packet),
                            fragment.count,
                            fragment.index,
                            fragment.location,
                            fragment.payload,
                        )
                        .unwrap()
                        .or(result);
                }
                let (address, data) = result.unwrap();
                assert_eq!(address, target);
                assert_eq!(data.as_ref(), payload);
            }
        }
    }

    #[test]
    fn parser_rejects_trailing_truncated_and_addressless_first_packets() {
        let target = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        let packet = encode(1, 2, &target, b"data", 1200).unwrap().remove(0);
        for length in 0..packet.len() {
            assert!(decode(&packet[..length]).is_err());
        }
        let mut extra = packet.to_vec();
        extra.push(0);
        assert!(decode(&extra).is_err());
        assert!(decode(&[5, 2, 0, 0, 0, 0, 1, 0, 0, 0, 255]).is_err());
        assert!(
            encode_address(
                &mut BytesMut::new(),
                &NetLocation::new(Address::Hostname("x".repeat(256)), 1)
            )
            .is_err()
        );
    }
}
