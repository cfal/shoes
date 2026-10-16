use std::{collections::BTreeMap, time::Duration};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::naive_client_session::NaiveClientSession;
use crate::address::NetLocation;

#[tokio::test(start_paused = true)]
async fn existing_settings_and_idle_policy_are_unchanged() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let session = NaiveClientSession::new(Box::new(client)).await.unwrap();
    let mut settings = BTreeMap::new();
    let mut connection_window = 65_535;
    let mut acknowledged = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();

        while !acknowledged || connection_window == 65_535 {
            let mut header = [0; 9];
            peer.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; length];
            peer.read_exact(&mut payload).await.unwrap();
            match header[3] {
                4 if header[4] == 1 => acknowledged = true,
                4 => {
                    for setting in payload.as_chunks::<6>().0 {
                        settings.insert(
                            u16::from_be_bytes(setting[..2].try_into().unwrap()),
                            u32::from_be_bytes(setting[2..].try_into().unwrap()),
                        );
                    }
                }
                8 => {
                    assert_eq!(&header[5..], &[0; 4]);
                    connection_window += u32::from_be_bytes(payload.try_into().unwrap());
                }
                frame_type => panic!("unexpected frame type {frame_type}"),
            }
        }
    })
    .await
    .expect("Naive handshake did not advertise its connection window");
    assert_eq!(connection_window, 256 * 1024);
    assert_eq!(settings.get(&4), Some(&(256 * 1024)));
    assert_eq!(settings.get(&5), Some(&(16 * 1024)));
    assert_eq!(settings.get(&3), Some(&1024));
    assert!(!settings.contains_key(&2), "push policy changed");
    assert!(!settings.contains_key(&6), "header limit changed");

    assert!(
        tokio::time::timeout(Duration::from_secs(360), peer.read_u8())
            .await
            .is_err(),
        "an idle Naive carrier must not originate PINGs or shut down"
    );
    assert!(session.is_ready());
}

#[tokio::test(start_paused = true)]
async fn unresponsive_idle_peer_does_not_retire_naive_session() {
    let (client, peer) = tokio::io::duplex(8192);
    let session = NaiveClientSession::new(Box::new(client)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(360)).await;
    assert!(session.is_ready());
    drop(peer);
}

#[tokio::test]
async fn response_headers_larger_than_16_kib_remain_accepted() {
    let (client, peer) = tokio::io::duplex(8192);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(peer).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.headers()["proxy-authorization"], "Basic dTpw");
        let response = http::Response::builder()
            .header("x-front-end-metadata", "x".repeat(32 * 1024))
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(b"ok"), true).unwrap();
        while connection.accept().await.is_some() {}
    });
    let mut session = NaiveClientSession::new(Box::new(client)).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = session
            .open_stream(
                &NetLocation::from_str("example.com:443", None).unwrap(),
                "Basic dTpw",
                false,
            )
            .await?;
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await?;
        assert_eq!(data, b"ok");
        Ok::<_, std::io::Error>(())
    })
    .await;
    server.abort();
    let _ = server.await;
    result.unwrap().unwrap();
}

#[tokio::test]
async fn peer_stream_limit_queues_without_dropping_existing_tunnel() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::h2_multi_stream::H2MultiStream;

    let (client, peer) = tokio::io::duplex(8192);
    let count = Arc::new(AtomicUsize::new(0));
    let accepted = count.clone();
    let server = tokio::spawn(async move {
        let mut connection = h2::server::Builder::new()
            .max_concurrent_streams(1)
            .handshake(peer)
            .await
            .unwrap();
        let mut streams = tokio::task::JoinSet::new();
        while let Some(incoming) = connection.accept().await {
            let (request, mut respond) = incoming.unwrap();
            accepted.fetch_add(1, Ordering::SeqCst);
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            streams.spawn(async move {
                let mut stream = H2MultiStream::new(send, request.into_body());
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let mut session = NaiveClientSession::new(Box::new(client)).await.unwrap();
    let target = NetLocation::from_str("example.com:443", None).unwrap();
    let mut first = tokio::time::timeout(
        Duration::from_secs(5),
        session.open_stream(&target, "Basic dTpw", false),
    )
    .await
    .expect("first tunnel did not open")
    .unwrap();
    let mut second_session = session.clone();
    let second = second_session.open_stream(&target, "Basic dTpw", false);
    tokio::pin!(second);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut second)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        first.write_all(b"first").await.unwrap();
        first.shutdown().await.unwrap();
        first.read_to_end(&mut response).await.unwrap();
    })
    .await
    .expect("first tunnel did not finish while the second was queued");
    assert_eq!(response, b"first");
    drop(first);
    let mut second = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    response.clear();
    tokio::time::timeout(Duration::from_secs(5), async {
        second.write_all(b"second").await.unwrap();
        second.shutdown().await.unwrap();
        second.read_to_end(&mut response).await.unwrap();
    })
    .await
    .expect("second tunnel did not finish after receiving a stream slot");
    assert_eq!(response, b"second");
    server.abort();
    let _ = server.await;
}
