use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig};

use crate::address::NetLocation;
use crate::resolver::{ResolveFuture, Resolver};

#[derive(Debug)]
struct LiteralResolver;

impl Resolver for LiteralResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let address = location.to_socket_addr_nonblocking();
        Box::pin(async move {
            address.map(|address| vec![address]).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bootstrap requires a literal endpoint",
                )
            })
        })
    }
}

pub(crate) fn controlled(endpoints: &[SocketAddr]) -> io::Result<Arc<dyn Resolver>> {
    if endpoints.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bootstrap DNS endpoints are empty",
        ));
    }
    let literal: Arc<dyn Resolver> = Arc::new(LiteralResolver);
    let chain = Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
        literal.clone(),
    ));
    let servers = endpoints
        .iter()
        .map(|endpoint| {
            let connections =
                [ConnectionConfig::udp(), ConnectionConfig::tcp()].map(|mut connection| {
                    connection.port = endpoint.port();
                    connection
                });
            NameServerConfig::new(endpoint.ip(), true, connections.to_vec())
        })
        .collect();
    Ok(Arc::new(
        super::hickory_resolver::HickoryResolver::build_with_ns_configs(
            servers,
            chain,
            literal,
            Default::default(),
            "managed bootstrap".to_owned(),
        )?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_bootstrap_cannot_recurse_into_native_resolution() {
        assert_eq!(
            LiteralResolver
                .resolve_location(&NetLocation::from_ip_addr("192.0.2.1".parse().unwrap(), 53,))
                .await
                .unwrap(),
            vec!["192.0.2.1:53".parse::<SocketAddr>().unwrap()]
        );
        assert!(
            LiteralResolver
                .resolve_location(&NetLocation::from_str("localhost:53", None).unwrap(),)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn controlled_bootstrap_pairs_tcp_fallback_and_tries_endpoints_concurrently() {
        use hickory_resolver::proto::{
            op::{Message, Query},
            rr::{Name, RecordType},
        };
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (tcp, udp) = crate::dns::bind_tcp_and_udp().await;
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver =
            controlled(&[silent.local_addr().unwrap(), udp.local_addr().unwrap()]).unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), tcp.accept())
                    .await
                    .is_err()
            );
            let mut response = Message::from_vec(&bytes[..length]).unwrap().into_response();
            response.metadata.truncation = true;
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            stream.read_exact(&mut bytes[..length]).await.unwrap();
            let response = Message::from_vec(&bytes[..length])
                .unwrap()
                .into_response()
                .to_vec()
                .unwrap();
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("bootstrap.test.").unwrap(),
            RecordType::TXT,
        ));
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            resolver.exchange(query.to_vec().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!Message::from_vec(&response).unwrap().truncation);
        server.await.unwrap();
    }
}
