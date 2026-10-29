use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use futures::future::{BoxFuture, Shared};
use futures::{FutureExt, StreamExt};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, OpCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsCode;
use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
use tokio::sync::{Mutex, Semaphore};

use super::proxy_runtime::ProxyRuntimeProvider;

type Connection =
    Shared<BoxFuture<'static, Result<DnsExchange<ProxyRuntimeProvider>, Arc<io::Error>>>>;
type SetupWaits = parking_lot::Mutex<Vec<Option<Connection>>>;
type PartialAnswer = parking_lot::Mutex<Option<Message>>;

struct Upstream {
    server_index: usize,
    ip: IpAddr,
    config: ConnectionConfig,
    connection: Mutex<Option<Connection>>,
}

impl Upstream {
    fn same_endpoint(&self, other: &Self) -> bool {
        self.ip == other.ip
            && self.config.port == other.config.port
            && self.config.bind_addr == other.config.bind_addr
    }
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
                .enumerate()
                .flat_map(|(server_index, server)| {
                    server.connections.into_iter().map(move |config| Upstream {
                        server_index,
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
        self.exchange_until(bytes, None).await
    }

    pub async fn exchange_with_deadline(
        &self,
        bytes: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> io::Result<Vec<u8>> {
        self.exchange_until(bytes, Some(deadline)).await
    }

    async fn exchange_until(
        &self,
        bytes: Vec<u8>,
        deadline: Option<tokio::time::Instant>,
    ) -> io::Result<Vec<u8>> {
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
        let id = request.metadata.id;
        request.metadata.id = rand::random();
        if let Some(edns) = &mut request.edns {
            edns.set_max_payload(edns.max_payload().min(super::message::UDP_PAYLOAD_LIMIT));
            edns.options_mut().remove(EdnsCode::Cookie);
        }
        let timeout = self
            .context
            .options
            .timeout
            .saturating_mul(self.context.options.attempts.max(1).min(u32::MAX as usize) as u32);
        let timeout = deadline.map_or(timeout, |deadline| {
            timeout.min(deadline.saturating_duration_since(tokio::time::Instant::now()))
        });
        let setups = parking_lot::Mutex::new(Vec::new());
        // A validated UDP partial must survive cancellation of its TCP retry.
        let partial = parking_lot::Mutex::new(None);
        let result =
            tokio::time::timeout(timeout, self.exchange_inner(&request, &setups, &partial))
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DNS exchange deadline exceeded",
                    ))
                })
                .or_else(|error| partial.into_inner().ok_or(error));
        if result.is_err()
            && setups
                .lock()
                .iter()
                .flatten()
                .any(|setup| !matches!(setup.peek(), Some(Err(_))))
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                crate::resolver::DnsSetupPending,
            ));
        }
        let mut answer = result?;
        answer.metadata.id = id;
        answer.queries.clone_from(&request.queries);
        answer.to_vec().map_err(io::Error::other)
    }

    async fn exchange_inner(
        &self,
        request: &Message,
        setups: &SetupWaits,
        partial: &PartialAnswer,
    ) -> io::Result<Message> {
        let _permit = self.admission.acquire().await.map_err(io::Error::other)?;
        let mut error = io::Error::new(io::ErrorKind::NotFound, "no real DNS upstreams configured");
        for _ in 0..self.context.options.attempts.max(1) {
            let upstreams: Vec<_> = self
                .upstreams
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    !matches!(candidate.config.protocol, ProtocolConfig::Tcp)
                        || !self.upstreams.iter().any(|udp| {
                            udp.server_index == candidate.server_index
                                && udp.same_endpoint(candidate)
                                && matches!(udp.config.protocol, ProtocolConfig::Udp)
                        })
                })
                .map(|(index, _)| index)
                .collect();
            let concurrency = self.context.options.num_concurrent_reqs.max(1);
            let waves = upstreams.len().div_ceil(concurrency).max(1);
            let slot_timeout = self.context.options.timeout / waves.min(u32::MAX as usize) as u32;
            let jobs = futures::stream::iter(upstreams).map(|index| {
                self.upstream_job(
                    &self.upstreams[index],
                    request,
                    slot_timeout,
                    setups,
                    partial,
                )
            });
            let mut answers = jobs.buffer_unordered(concurrency);
            while let Some(result) = answers.next().await {
                match result {
                    Ok(answer) => return Ok(answer),
                    Err(failure) => error = failure,
                }
            }
        }
        Err(error)
    }

    fn upstream_job<'a>(
        &'a self,
        upstream: &'a Upstream,
        request: &'a Message,
        timeout: std::time::Duration,
        setups: &'a SetupWaits,
        partial: &'a PartialAnswer,
    ) -> BoxFuture<'a, io::Result<Message>> {
        Box::pin(async move {
            tokio::time::timeout(
                timeout,
                self.send(upstream, request.clone(), setups, partial),
            )
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS upstream deadline exceeded",
                ))
            })
        })
    }

    async fn send(
        &self,
        upstream: &Upstream,
        message: Message,
        setups: &SetupWaits,
        partial: &PartialAnswer,
    ) -> io::Result<Message> {
        let answer = self
            .send_upstream(upstream, message.clone(), setups)
            .await?;
        check_answer(&answer, &message)?;
        if answer.metadata.truncation && matches!(upstream.config.protocol, ProtocolConfig::Udp) {
            // Only use explicitly configured TCP, including system-discovered UDP+TCP pairs.
            if let Some(tcp) = self.upstreams.iter().find(|candidate| {
                candidate.same_endpoint(upstream)
                    && matches!(candidate.config.protocol, ProtocolConfig::Tcp)
            }) {
                partial.lock().get_or_insert_with(|| answer.clone());
                let answer = self.send_upstream(tcp, message.clone(), setups).await?;
                check_answer(&answer, &message)?;
                return Ok(answer);
            }
        }
        Ok(answer)
    }

    async fn send_upstream(
        &self,
        upstream: &Upstream,
        message: Message,
        setups: &SetupWaits,
    ) -> io::Result<Message> {
        for reconnect in 0..2 {
            let (setup, reused) = {
                let mut cached = upstream.connection.lock().await;
                let reused = cached.is_some();
                if cached.is_none() {
                    let future = self
                        .provider
                        .new_connection(upstream.ip, &upstream.config, &self.context)
                        .map_err(net_error)?;
                    let deadline = tokio::time::Instant::now() + self.context.options.timeout;
                    *cached = Some(connection_setup(future, deadline));
                }
                (cached.as_ref().unwrap().clone(), reused)
            };
            // Only canceled waits remain, even if another query completes their setup.
            let wait_index = {
                let mut setups = setups.lock();
                let index = setups.len();
                setups.push(Some(setup.clone()));
                index
            };
            let connection = setup.clone().await;
            setups.lock()[wait_index] = None;
            let result = match connection {
                Ok(connection) => send_message(&connection, message.clone()).await,
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            };
            match result {
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    let mut cached = upstream.connection.lock().await;
                    if cached
                        .as_ref()
                        .is_some_and(|current| current.ptr_eq(&setup))
                    {
                        *cached = None;
                    }
                    drop(cached);
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

fn check_answer(answer: &Message, request: &Message) -> io::Result<()> {
    if answer.metadata.message_type != MessageType::Response
        || answer.metadata.op_code != request.metadata.op_code
        || answer.queries != request.queries
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS reply question mismatch",
        ));
    }
    Ok(())
}

fn connection_setup(
    future: BoxFuture<'static, Result<DnsExchange<ProxyRuntimeProvider>, NetError>>,
    deadline: tokio::time::Instant,
) -> Connection {
    // A losing query must not cancel a shared handshake. Dropping its cache owner still does.
    let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| {
                Arc::new(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS connection deadline exceeded",
                ))
            })?
            .map_err(|error| Arc::new(net_error(error)))
    }));
    async move {
        task.await
            .map_err(|error| Arc::new(io::Error::other(error)))?
    }
    .boxed()
    .shared()
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

pub(super) fn net_error(error: NetError) -> io::Error {
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
mod tests;
