use std::{sync::Arc, time::Duration};
use shadowquic::{config::ShadowQuicClientCfg, dns::ResolverManager, shadowquic::outbound::ShadowQuicClient, squic::outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let args: Vec<String> = std::env::args().collect();
        let client = ShadowQuicClient::new(ShadowQuicClientCfg {
            addr: args[1].clone(), username: "alice".into(), password: "test-secret".into(),
            server_name: "localhost".into(), alpn: vec!["h3".into()], zero_rtt: true,
            ..Default::default()
        }, Arc::new(ResolverManager::new()));
        let conn = client.get_conn().await.unwrap();
        let mut tcp = outbound::connect_tcp(&conn, args[2].parse().unwrap()).await.unwrap();
        tcp.write_all(b"hello").await.unwrap();
        let mut reply = [0;5]; tcp.read_exact(&mut reply).await.unwrap(); assert_eq!(&reply,b"reply");
        let stats = outbound::get_peer_conn_stats(&conn).await.unwrap().unwrap(); assert!(stats.current_mtu >= 1200);
        for over_stream in [false, true] {
            let dst = args[3].parse().unwrap();
            let (sender, mut receiver) = outbound::associate_udp(&conn, "0.0.0.0:0".parse().unwrap(), over_stream).await.unwrap();
            sender.send((b"hello".to_vec().into(), dst)).await.unwrap();
            let (data, _) = receiver.recv().await.unwrap(); assert_eq!(&data[..], b"reply");
        }
        println!("reference ShadowQuic TCP, UDP datagram, UDP stream and stats passed");
    }).await.unwrap();
}
