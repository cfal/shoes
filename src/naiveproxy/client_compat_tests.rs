use std::{collections::BTreeMap, time::Duration};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::naive_client_session::NaiveClientSession;
use crate::address::NetLocation;

#[tokio::test(start_paused = true)]
async fn existing_settings_and_idle_policy_are_unchanged() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let session = NaiveClientSession::new(Box::new(client)).await.unwrap();
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();

    let mut settings = BTreeMap::new();
    let mut connection_window = 65_535;
    let mut acknowledged = false;
    while !acknowledged || connection_window == 65_535 {
        let mut header = [0; 9];
        peer.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        peer.read_exact(&mut payload).await.unwrap();
        match header[3] {
            4 if header[4] == 1 => acknowledged = true,
            4 => {
                for setting in payload.chunks_exact(6) {
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
