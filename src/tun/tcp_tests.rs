use super::*;
use etherparse::PacketBuilder;
use futures::FutureExt;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixDatagram as AsyncDatagram};
use tokio::time::timeout;

fn packet(sequence: u32, ack: Option<u32>, fin: bool, data: &[u8]) -> Vec<u8> {
    let builder =
        PacketBuilder::ipv4([10, 23, 0, 2], [198, 51, 100, 9], 64).tcp(12001, 8080, sequence, 8192);
    let mut builder = match ack {
        Some(ack) => builder.ack(ack),
        None => builder.syn(),
    };
    if fin {
        builder = builder.fin();
    }
    let mut bytes = Vec::new();
    builder.write(&mut bytes, data).unwrap();
    bytes
}

fn reply(bytes: &[u8]) -> TcpPacket<&[u8]> {
    let ip = Ipv4Packet::new_checked(bytes).unwrap();
    assert_eq!(ip.src_addr().octets(), [198, 51, 100, 9]);
    assert_eq!(ip.dst_addr().octets(), [10, 23, 0, 2]);
    assert_eq!(ip.next_header(), IpProtocol::Tcp);
    assert!(ip.verify_checksum());
    let tcp = TcpPacket::new_checked(&bytes[usize::from(ip.header_len())..]).unwrap();
    assert_eq!(tcp.src_port(), 8080);
    assert_eq!(tcp.dst_port(), 12001);
    assert!(tcp.verify_checksum(
        &IpAddress::from(ip.src_addr()),
        &IpAddress::from(ip.dst_addr())
    ));
    assert!(!tcp.rst());
    tcp
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_fd_tcp_sniffs_http_and_replays_through_packet_ingress() {
    let (wire, tun) = UnixDatagram::pair().unwrap();
    wire.set_nonblocking(true).unwrap();
    let wire = AsyncDatagram::from_std(wire).unwrap();
    let exit = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let rule = serde_yaml::from_str(&format!(
        "masks: sniff.example\naction: allow\noverride_address: 127.0.0.1:{}",
        exit.local_addr().unwrap().port(),
    ))
    .unwrap();
    let selector = Arc::new(
        create_tcp_client_proxy_selector(vec![rule], resolver.clone())
            .unwrap()
            .with_sniff(true),
    );
    let config = TunServerConfig::new()
        .raw_fd(tun.as_raw_fd())
        .close_fd_on_drop(false)
        .packet_information(false);
    let (shutdown, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(run_tun_server(config, selector, resolver, shutdown_rx));
    let outcome = AssertUnwindSafe(timeout(Duration::from_secs(10), async {
        let payload = crate::sniff::tests::http_request();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let upstream = async {
            let (mut stream, _) = exit.accept().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let client = async {
            wire.send(&packet(100, None, false, &[])).await.unwrap();
            let mut buffer = [0; 2048];
            let length = wire.recv(&mut buffer).await.unwrap();
            let syn_ack = reply(&buffer[..length]);
            assert!(syn_ack.syn() && syn_ack.ack());
            assert_eq!(syn_ack.ack_number().0, 101);
            let mut ack = (syn_ack.seq_number().0 as u32).wrapping_add(1);
            let mut sequence = 101;
            wire.send(&packet(sequence, Some(ack), false, &[]))
                .await
                .unwrap();
            for fragment in [&payload[..5], &payload[5..]] {
                wire.send(&packet(sequence, Some(ack), false, fragment))
                    .await
                    .unwrap();
                sequence += fragment.len() as u32;
            }
            wire.send(&packet(sequence, Some(ack), true, &[]))
                .await
                .unwrap();
            sequence += 1;
            let mut received = Vec::new();
            loop {
                let length = wire.recv(&mut buffer).await.unwrap();
                let tcp = reply(&buffer[..length]);
                if tcp.payload().is_empty() && !tcp.fin() {
                    continue;
                }
                let offset = tcp.seq_number().0.wrapping_sub(ack as i32);
                if offset < 0 {
                    // A delayed runner may observe a retransmission before its ACK is processed.
                    wire.send(&packet(sequence, Some(ack), false, &[]))
                        .await
                        .unwrap();
                    continue;
                }
                assert_eq!(offset, 0);
                received.extend_from_slice(tcp.payload());
                ack = ack.wrapping_add(tcp.payload().len() as u32 + u32::from(tcp.fin()));
                wire.send(&packet(sequence, Some(ack), false, &[]))
                    .await
                    .unwrap();
                if tcp.fin() {
                    break;
                }
            }
            assert_eq!(received, response);
        };
        tokio::join!(upstream, client);
    }))
    .catch_unwind()
    .await;
    let _ = shutdown.send(());
    timeout(Duration::from_secs(10), server)
        .await
        .expect("TUN shutdown stalled")
        .unwrap()
        .unwrap();
    match outcome {
        Ok(result) => result.expect("raw-FD TCP pipeline stalled"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
