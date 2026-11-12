use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::future::{BoxFuture, Shared};
use futures::{FutureExt, StreamExt};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::{DnsExchange, DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, OpCode};
use hickory_resolver::proto::rr::rdata::opt::EdnsCode;
use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use super::proxy_runtime::ProxyRuntimeProvider;

type Connection =
    Shared<BoxFuture<'static, Result<DnsExchange<ProxyRuntimeProvider>, Arc<io::Error>>>>;
type SetupWaits = Mutex<Vec<Option<Connection>>>;
type PartialAnswer = Mutex<Option<Message>>;

struct Upstream {
    server_index: usize,
    ip: IpAddr,
    config: ConnectionConfig,
    connection: Mutex<Option<Connection>>,
}

impl Upstream {
    fn evict(&self, setup: &Connection) {
        let mut cached = self.connection.lock();
        if cached.as_ref().is_some_and(|current| current.ptr_eq(setup)) {
            *cached = None;
        }
    }

    fn retire(&self, setup: &Connection) {
        self.evict(setup);
        if let Some(Ok(connection)) = setup.peek() {
            connection.shutdown();
        }
    }

    fn same_endpoint(&self, other: &Self) -> bool {
        self.ip == other.ip
            && self.config.port == other.config.port
            && self.config.bind_addr == other.config.bind_addr
    }
}

struct EstablishedExchange<'a> {
    upstream: &'a Upstream,
    setup: Connection,
    deadline: tokio::time::Instant,
    overall_deadline: tokio::time::Instant,
    completed: bool,
    outer: &'a ExchangeTimeout,
    slot: &'a ExchangeTimeout,
}

impl Drop for EstablishedExchange<'_> {
    fn drop(&mut self) {
        // Only an owned timer can retire a connection, never cancellation or admission delay.
        if !self.completed
            && (self.slot.expired.load(Ordering::Relaxed)
                || (self.outer.expired.load(Ordering::Relaxed)
                    && self.deadline <= self.overall_deadline))
        {
            self.upstream.retire(&self.setup);
            self.outer.retired.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct ExchangeTimeout {
    expired: AtomicBool,
    retired: AtomicBool,
}

impl ExchangeTimeout {
    async fn run<T>(
        &self,
        deadline: tokio::time::Instant,
        owned: bool,
        future: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let result = {
            tokio::pin!(future);
            let result = if owned {
                tokio::time::timeout_at(deadline, &mut future)
                    .await
                    .map_err(|_| ())
            } else {
                // An earlier caller deadline wins even when the executor polls it late.
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => Err(()),
                    result = &mut future => Ok(result),
                }
            };
            if result.is_err() {
                // Only retirement during this timeout's unwind can own its deadline.
                self.retired.store(false, Ordering::Relaxed);
            }
            self.expired.store(result.is_err(), Ordering::Relaxed);
            result
        };
        result.unwrap_or_else(|_| {
            Err(if owned || self.retired.load(Ordering::Relaxed) {
                io::Error::new(io::ErrorKind::TimedOut, "DNS transport deadline exceeded")
            } else {
                io::Error::new(io::ErrorKind::TimedOut, crate::resolver::DnsCallerDeadline)
            })
        })
    }
}

struct AttemptTiming<'a> {
    deadline: tokio::time::Instant,
    timeout: std::time::Duration,
    outer: &'a ExchangeTimeout,
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

    pub fn request_timeout(&self) -> std::time::Duration {
        let options = &self.context.options;
        options.timeout.saturating_mul(
            options
                .attempts
                .max(1)
                .saturating_add(1)
                .min(u32::MAX as usize) as u32,
        )
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
        let timeout = self.request_timeout();
        let transport_deadline = tokio::time::Instant::now().checked_add(timeout);
        let deadline = match (deadline, transport_deadline) {
            (Some(caller), Some(transport)) => caller.min(transport),
            (Some(deadline), None) | (None, Some(deadline)) => deadline,
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS request timeout is too large",
                ));
            }
        };
        let setups = Mutex::new(Vec::new());
        let expiration = ExchangeTimeout::default();
        let admitted = AtomicBool::new(false);
        // A validated UDP partial must survive cancellation of its TCP retry.
        let partial = Mutex::new(None);
        let result = expiration
            .run(
                deadline,
                false,
                self.exchange_inner(
                    &request,
                    &setups,
                    &partial,
                    AttemptTiming {
                        deadline,
                        timeout: self.context.options.timeout,
                        outer: &expiration,
                    },
                    &admitted,
                ),
            )
            .await
            .map_err(|error| {
                if !admitted.load(Ordering::Relaxed) && crate::resolver::dns_caller_deadline(&error)
                {
                    io::Error::new(io::ErrorKind::WouldBlock, "DNS admission deadline exceeded")
                } else {
                    error
                }
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

    pub fn retire(&self) {
        for upstream in &self.upstreams {
            let setup = upstream.connection.lock().take();
            if let Some(setup) = setup {
                upstream.retire(&setup);
            }
        }
    }

    async fn exchange_inner(
        &self,
        request: &Message,
        setups: &SetupWaits,
        partial: &PartialAnswer,
        timing: AttemptTiming<'_>,
        admitted: &AtomicBool,
    ) -> io::Result<Message> {
        let _permit = self.admission.acquire().await.map_err(io::Error::other)?;
        admitted.store(true, Ordering::Relaxed);
        let mut error = io::Error::new(io::ErrorKind::NotFound, "no real DNS upstreams configured");
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
        for _ in 0..self.context.options.attempts.max(1) {
            let jobs = futures::stream::iter(upstreams.iter().copied()).map(|index| {
                self.send(
                    &self.upstreams[index],
                    request,
                    setups,
                    partial,
                    AttemptTiming {
                        deadline: timing.deadline,
                        timeout: slot_timeout,
                        outer: timing.outer,
                    },
                )
            });
            let mut answers = jobs.buffer_unordered(concurrency);
            while let Some(result) = answers.next().await {
                match result {
                    Ok(answer) => return Ok(answer),
                    Err(failure) => error = failure,
                }
            }
            if !crate::resolver::RefreshingResolver::should_refresh_for_error(&error)
                && error.kind() != io::ErrorKind::WouldBlock
            {
                break;
            }
        }
        Err(error)
    }

    async fn send(
        &self,
        upstream: &Upstream,
        message: &Message,
        setups: &SetupWaits,
        partial: &PartialAnswer,
        timing: AttemptTiming<'_>,
    ) -> io::Result<Message> {
        let answer = self
            .send_upstream(upstream, message.clone(), setups, &timing)
            .await?;
        check_answer(&answer, message)?;
        if answer.metadata.truncation && matches!(upstream.config.protocol, ProtocolConfig::Udp) {
            // Only use explicitly configured TCP, including system-discovered UDP+TCP pairs.
            if let Some(tcp) = self.upstreams.iter().find(|candidate| {
                candidate.same_endpoint(upstream)
                    && matches!(candidate.config.protocol, ProtocolConfig::Tcp)
            }) {
                partial.lock().get_or_insert_with(|| answer.clone());
                let answer = self
                    .send_upstream(tcp, message.clone(), setups, &timing)
                    .await?;
                check_answer(&answer, message)?;
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
        timing: &AttemptTiming<'_>,
    ) -> io::Result<Message> {
        for reconnect in 0..2 {
            let (setup, reused) = {
                let mut cached = upstream.connection.lock();
                // Detached setup completion is only visible after polling its Shared handle.
                if cached
                    .as_ref()
                    .and_then(|setup| setup.clone().now_or_never())
                    .is_some_and(|result| result.is_err())
                {
                    *cached = None;
                }
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
            let connection = tokio::time::timeout(timing.timeout, setup.clone())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, crate::resolver::DnsSetupPending)
                })?;
            setups.lock()[wait_index] = None;
            let result = match connection {
                Ok(connection) => {
                    let slot = ExchangeTimeout::default();
                    let deadline = tokio::time::Instant::now() + timing.timeout;
                    slot.run(deadline, true, async {
                        let mut guard = EstablishedExchange {
                            upstream,
                            setup: setup.clone(),
                            deadline,
                            overall_deadline: timing.deadline,
                            completed: false,
                            outer: timing.outer,
                            slot: &slot,
                        };
                        let result = send_message(&connection, message.clone()).await;
                        guard.completed = true;
                        result
                    })
                    .await
                }
                Err(error) => Err(io::Error::new(error.kind(), SharedError(error))),
            };
            match result {
                Ok(answer) => return Ok(answer),
                Err(error) => {
                    let failed_setup = matches!(setup.peek(), Some(Err(_)));
                    let failed_transport =
                        crate::resolver::RefreshingResolver::should_refresh_for_error(&error);
                    if failed_setup || failed_transport {
                        // GOAWAY rejects new streams without invalidating accepted responses.
                        // Owned timers and explicit retirement still shut down the driver.
                        upstream.evict(&setup);
                    }
                    if failed_transport
                        && error.kind() != io::ErrorKind::TimedOut
                        && reused
                        && reconnect == 0
                        && tokio::time::Instant::now() < timing.deadline
                    {
                        continue;
                    }
                    return Err(error);
                }
            }
        }
        unreachable!()
    }
}

#[derive(Debug)]
struct SharedError(Arc<io::Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl Drop for RawDnsExchange {
    fn drop(&mut self) {
        self.retire();
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
    let task = tokio_util::task::AbortOnDropHandle::new(crate::network_tasks::spawn(async move {
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
    match error {
        NetError::Io(error) => io::Error::new(kind, SharedError(error)),
        error => io::Error::new(kind, error),
    }
}

#[cfg(test)]
mod tests;
