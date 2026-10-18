use std::fmt;
use std::io;
use std::net::IpAddr;

use futures::StreamExt;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, OpCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsCode;
use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
use tokio::sync::{Mutex, Semaphore};

use super::proxy_runtime::ProxyRuntimeProvider;

struct Upstream {
    ip: IpAddr,
    config: ConnectionConfig,
    connection: Mutex<Option<DnsExchange<ProxyRuntimeProvider>>>,
}

/// Uses transport handles directly: the lookup pool can coalesce requests and
/// turn negative DNS messages into lookup errors, losing wire-level semantics.
pub(super) struct RawDnsExchange {
    upstreams: Vec<Upstream>,
    provider: ProxyRuntimeProvider,
    context: PoolContext,
    admission: Semaphore,
}

impl fmt::Debug for RawDnsExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawDnsExchange")
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

impl RawDnsExchange {
    pub fn new(
        servers: Vec<NameServerConfig>,
        provider: ProxyRuntimeProvider,
        options: ResolverOpts,
    ) -> Self {
        Self {
            upstreams: servers
                .into_iter()
                .flat_map(|server| {
                    server.connections.into_iter().map(move |config| Upstream {
                        ip: server.ip,
                        config,
                        connection: Mutex::new(None),
                    })
                })
                .collect(),
            provider,
            context: PoolContext::new(
                options,
                TlsConfig {
                    config: crate::rustls_config_util::create_dns_client_config(),
                },
            ),
            admission: Semaphore::new(64),
        }
    }

    pub async fn exchange(&self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        let deadline = self
            .context
            .options
            .timeout
            .saturating_mul(self.context.options.attempts.max(1).min(u32::MAX as usize) as u32);
        tokio::time::timeout(deadline, self.exchange_inner(bytes))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "DNS exchange deadline exceeded")
            })?
    }

    async fn exchange_inner(&self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        let mut request = super::message::decode(&bytes)?;
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
            || super::message::is_signed(&request)
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw DNS exchange requires one unsigned standard question",
            ));
        }
        let _permit = self.admission.acquire().await.map_err(io::Error::other)?;
        let id = request.metadata.id;
        request.metadata.id = rand::random();
        if let Some(edns) = &mut request.edns {
            edns.set_max_payload(edns.max_payload().min(super::message::UDP_PAYLOAD_LIMIT));
            edns.options_mut().remove(EdnsCode::Cookie);
        }
        let mut error = io::Error::new(io::ErrorKind::NotFound, "no real DNS upstreams configured");
        for _ in 0..self.context.options.attempts.max(1) {
            let upstreams: Vec<_> = self
                .upstreams
                .iter()
                .filter(|candidate| {
                    !matches!(candidate.config.protocol, ProtocolConfig::Tcp)
                        || !self.upstreams.iter().any(|udp| {
                            udp.ip == candidate.ip
                                && udp.config.port == candidate.config.port
                                && udp.config.bind_addr == candidate.config.bind_addr
                                && matches!(udp.config.protocol, ProtocolConfig::Udp)
                        })
                })
                .collect();
            let concurrency = self.context.options.num_concurrent_reqs.max(1);
            let waves = upstreams.len().div_ceil(concurrency).max(1);
            let slot_timeout = self.context.options.timeout / waves.min(u32::MAX as usize) as u32;
            let mut jobs: Vec<futures::future::BoxFuture<'_, io::Result<Message>>> = Vec::new();
            for upstream in upstreams {
                let message = request.clone();
                jobs.push(Box::pin(async move {
                    tokio::time::timeout(slot_timeout, self.send(upstream, message))
                        .await
                        .unwrap_or_else(|_| {
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "DNS upstream deadline exceeded",
                            ))
                        })
                }));
            }
            let mut answers = futures::stream::iter(jobs).buffer_unordered(concurrency);
            while let Some(result) = answers.next().await {
                match result {
                    Ok(mut answer) => {
                        if answer.metadata.message_type != MessageType::Response
                            || answer.metadata.op_code != request.metadata.op_code
                            || answer.queries != request.queries
                        {
                            error = io::Error::new(
                                io::ErrorKind::InvalidData,
                                "DNS reply question mismatch",
                            );
                            continue;
                        }
                        answer.metadata.id = id;
                        answer.queries.clone_from(&request.queries);
                        return answer.to_vec().map_err(io::Error::other);
                    }
                    Err(failure) => error = failure,
                }
            }
        }
        Err(error)
    }

    async fn send(&self, upstream: &Upstream, message: Message) -> io::Result<Message> {
        let answer = self.send_upstream(upstream, message.clone()).await?;
        if answer.metadata.truncation && matches!(upstream.config.protocol, ProtocolConfig::Udp) {
            // Only use explicitly configured TCP, including system-discovered UDP+TCP pairs.
            if let Some(tcp) = self.upstreams.iter().find(|candidate| {
                candidate.ip == upstream.ip
                    && candidate.config.port == upstream.config.port
                    && candidate.config.bind_addr == upstream.config.bind_addr
                    && matches!(candidate.config.protocol, ProtocolConfig::Tcp)
            }) {
                return self.send_upstream(tcp, message).await;
            }
        }
        Ok(answer)
    }

    async fn send_upstream(&self, upstream: &Upstream, message: Message) -> io::Result<Message> {
        for reconnect in 0..2 {
            let (connection, reused) = {
                let mut cached = upstream.connection.lock().await;
                let reused = cached.is_some();
                if cached.is_none() {
                    let future = self
                        .provider
                        .new_connection(upstream.ip, &upstream.config, &self.context)
                        .map_err(net_error)?;
                    *cached = Some(future.await.map_err(net_error)?);
                }
                (cached.as_ref().unwrap().clone(), reused)
            };
            let result = send_message(&connection, message.clone()).await;
            match result {
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    *upstream.connection.lock().await = None;
                    if reused && reconnect == 0 {
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        unreachable!()
    }
}

async fn send_message(
    connection: &DnsExchange<ProxyRuntimeProvider>,
    message: Message,
) -> io::Result<Message> {
    let request = DnsRequest::new(message, DnsRequestOptions::default());
    let answer = connection
        .send(request)
        .first_answer()
        .await
        .map_err(net_error)?;
    Ok(answer.into_message())
}

fn net_error(error: NetError) -> io::Error {
    let kind = match &error {
        NetError::Timeout => io::ErrorKind::TimedOut,
        NetError::Io(error) => error.kind(),
        NetError::Busy => io::ErrorKind::WouldBlock,
        NetError::NoConnections => io::ErrorKind::NotConnected,
        _ if error.is_connection_closed() => io::ErrorKind::ConnectionAborted,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType, rdata};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn exchange(addr: std::net::SocketAddr, tcp: bool) -> RawDnsExchange {
        let resolver = Arc::new(crate::resolver::NativeResolver::new());
        let provider = ProxyRuntimeProvider::with_bootstrap(
            Arc::new(crate::tcp::chain_builder::build_direct_chain_group(
                resolver.clone(),
            )),
            resolver,
            Duration::from_secs(1),
        );
        let mut config = if tcp {
            ConnectionConfig::tcp()
        } else {
            ConnectionConfig::udp()
        };
        config.port = addr.port();
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(1);
        options.attempts = 1;
        RawDnsExchange::new(
            vec![NameServerConfig::new(addr.ip(), true, vec![config])],
            provider,
            options,
        )
    }

    fn request() -> Message {
        let mut message = Message::query();
        message.metadata.id = 17;
        message.metadata.checking_disabled = true;
        message.metadata.recursion_desired = false;
        message.add_query(Query::query(
            Name::from_ascii("Case.Example.").unwrap(),
            RecordType::TXT,
        ));
        message
    }

    async fn read_tcp(stream: &mut tokio::net::TcpStream) -> Message {
        let len = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; len as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        Message::from_vec(&bytes).unwrap()
    }

    async fn write_tcp(stream: &mut tokio::net::TcpStream, message: Message) {
        let bytes = message.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_tcp_ids_and_negative_replies_stay_independent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw = exchange(listener.local_addr().unwrap(), true);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let first = read_tcp(&mut stream).await;
            let second = read_tcp(&mut stream).await;
            assert_ne!(first.metadata.id, second.metadata.id);
            for query in [second, first] {
                let mut answer = query.into_response();
                answer.metadata.response_code = if answer.queries[0].query_type == RecordType::TXT {
                    ResponseCode::Refused
                } else {
                    ResponseCode::ServFail
                };
                write_tcp(&mut stream, answer).await;
            }
        });
        let first = request();
        let mut second = request();
        second.queries[0].query_type = RecordType::HTTPS;
        let (a, b) = tokio::join!(
            raw.exchange(first.to_vec().unwrap()),
            raw.exchange(second.to_vec().unwrap())
        );
        let a = Message::from_vec(&a.unwrap()).unwrap();
        let b = Message::from_vec(&b.unwrap()).unwrap();
        assert_eq!(a.metadata.id, 17);
        assert_eq!(b.metadata.id, 17);
        assert_eq!(a.queries, first.queries);
        assert_eq!(b.queries, second.queries);
        assert_eq!(a.metadata.response_code, ResponseCode::Refused);
        assert_eq!(b.metadata.response_code, ResponseCode::ServFail);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_tcp_question_mismatch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw = exchange(listener.local_addr().unwrap(), true);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reply = read_tcp(&mut stream).await.into_response();
            reply.queries[0].query_type = RecordType::MX;
            write_tcp(&mut stream, reply).await;
        });
        assert_eq!(
            raw.exchange(request().to_vec().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dead_tcp_handle_reconnects_without_spinning() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raw = exchange(listener.local_addr().unwrap(), true);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let reply = read_tcp(&mut stream).await.into_response();
                write_tcp(&mut stream, reply).await;
                stream.shutdown().await.unwrap();
            }
        });
        for _ in 0..2 {
            tokio::time::timeout(
                Duration::from_secs(3),
                raw.exchange(request().to_vec().unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_only_configuration_returns_truncation_without_new_transport() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raw = exchange(socket.local_addr().unwrap(), false);
        let server = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut reply = Message::from_vec(&bytes[..len]).unwrap().into_response();
            reply.metadata.truncation = true;
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let reply = raw.exchange(request().to_vec().unwrap()).await.unwrap();
        assert!(Message::from_vec(&reply).unwrap().metadata.truncation);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn silent_first_server_does_not_starve_healthy_second_server() {
        for (system_pair, extra_silent) in [(false, false), (true, false), (true, true)] {
            let silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let second_silent = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let healthy = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let mut raw = exchange(silent.local_addr().unwrap(), false);
            raw.context.options.timeout = Duration::from_millis(200);
            if system_pair {
                let mut config = ConnectionConfig::tcp();
                config.port = silent.local_addr().unwrap().port();
                raw.upstreams.push(Upstream {
                    ip: "127.0.0.1".parse().unwrap(),
                    config,
                    connection: Mutex::new(None),
                });
            }
            raw.upstreams[0].ip = "127.0.0.1".parse().unwrap();
            if extra_silent {
                let mut config = ConnectionConfig::udp();
                config.port = second_silent.local_addr().unwrap().port();
                raw.upstreams.push(Upstream {
                    ip: "127.0.0.1".parse().unwrap(),
                    config,
                    connection: Mutex::new(None),
                });
            }
            let mut config = ConnectionConfig::udp();
            config.port = healthy.local_addr().unwrap().port();
            raw.upstreams.push(Upstream {
                ip: "127.0.0.1".parse().unwrap(),
                config,
                connection: Mutex::new(None),
            });
            let server = tokio::spawn(async move {
                let mut bytes = [0; 2048];
                let (len, peer) = healthy.recv_from(&mut bytes).await.unwrap();
                let reply = Message::from_vec(&bytes[..len]).unwrap().into_response();
                healthy
                    .send_to(&reply.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            });
            let answer = raw.exchange(request().to_vec().unwrap()).await.unwrap();
            assert_eq!(Message::from_vec(&answer).unwrap().metadata.id, 17);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stalled_tcp_exchange_has_a_complete_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut raw = exchange(listener.local_addr().unwrap(), true);
        raw.context.options.timeout = Duration::from_millis(50);
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            raw.exchange(request().to_vec().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn udp_preserves_negative_sections_and_flags() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raw = exchange(socket.local_addr().unwrap(), false);
        let server = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..len]).unwrap();
            assert!(query.metadata.checking_disabled);
            assert!(!query.metadata.recursion_desired);
            let mut response = query.into_response();
            response.metadata.response_code = ResponseCode::NXDomain;
            response.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                60,
                RData::TXT(rdata::TXT::new(vec!["negative metadata".into()])),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let response =
            Message::from_vec(&raw.exchange(request().to_vec().unwrap()).await.unwrap()).unwrap();
        assert_eq!(response.metadata.id, 17);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.queries[0].name.to_ascii(), "Case.Example.");
        assert_eq!(response.authorities.len(), 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_truncation_retries_the_same_configured_server_over_tcp() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
        let mut raw = exchange(addr, false);
        let mut config = ConnectionConfig::tcp();
        config.port = addr.port();
        raw.upstreams.push(Upstream {
            ip: addr.ip(),
            config,
            connection: Mutex::new(None),
        });
        let server = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let mut response = Message::from_vec(&bytes[..len]).unwrap().into_response();
            response.metadata.truncation = true;
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap() as usize;
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await.unwrap();
            let mut response = Message::from_vec(&bytes).unwrap().into_response();
            response.add_answer(Record::from_rdata(
                response.queries[0].name.clone(),
                42,
                RData::TXT(rdata::TXT::new(vec!["complete".into()])),
            ));
            let bytes = response.to_vec().unwrap();
            stream.write_u16(bytes.len() as u16).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let response =
            Message::from_vec(&raw.exchange(request().to_vec().unwrap()).await.unwrap()).unwrap();
        assert!(!response.metadata.truncation);
        assert_eq!(response.answers.len(), 1);
        server.await.unwrap();
    }
}
