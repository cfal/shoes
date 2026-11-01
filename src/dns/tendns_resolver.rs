use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tendns::hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::Name,
};
use tokio::time::Instant;

use crate::address::{Address, NetLocation};
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

struct RawExchange(Arc<dyn Resolver>);

impl RawExchange {
    fn response(request: &Message, bytes: &[u8]) -> anyhow::Result<Message> {
        let response = super::message::decode(bytes)?;
        anyhow::ensure!(
            response.metadata.message_type == MessageType::Response
                && response.metadata.id == request.metadata.id
                && response.metadata.op_code == request.metadata.op_code
                && response.queries == request.queries,
            "unassociated tendns upstream response"
        );
        // Shoes can retain TC after exhausting its configured reliable transports.
        anyhow::ensure!(
            !response.metadata.truncation,
            "truncated tendns upstream response"
        );
        Ok(response)
    }
}

#[async_trait]
impl tendns::Exchange for RawExchange {
    async fn exchange(&self, request: Message) -> anyhow::Result<Message> {
        let bytes = self.0.exchange(request.to_vec()?).await?;
        Self::response(&request, &bytes)
    }

    async fn exchange_with_deadline(
        &self,
        request: Message,
        deadline: Instant,
    ) -> anyhow::Result<Message> {
        check_deadline(deadline)?;
        let bytes = self
            .0
            .exchange_with_deadline(request.to_vec()?, deadline)
            .await?;
        Self::response(&request, &bytes)
    }
}

/// Staged real-resolution adapter. Builders must keep fake-IP and synthetic-address
/// guards outside it, and must not cache its completed address results.
pub(super) struct TendnsResolver {
    private: Arc<tendns::Resolver>,
    raw: Arc<dyn Resolver>,
    strategy: tendns::IpStrategy,
    budget: Duration,
}

impl fmt::Debug for TendnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TendnsResolver")
            .field("strategy", &self.strategy)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl TendnsResolver {
    pub(super) fn new(
        policy: Arc<tendns::Policy>,
        raw: Arc<dyn Resolver>,
        strategy: tendns::IpStrategy,
        budget: Duration,
    ) -> io::Result<Self> {
        if budget.is_zero() || budget > Duration::from_secs(86_400) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tendns budget must be positive and at most 24 hours",
            ));
        }
        Ok(Self {
            private: Arc::new(tendns::Resolver::new(
                policy,
                Arc::new(RawExchange(raw.clone())),
            )),
            raw,
            strategy,
            budget,
        })
    }

    fn exchange_inner(&self, bytes: Vec<u8>, deadline: Option<Instant>) -> DnsExchangeFuture {
        let private = self.private.clone();
        let raw = self.raw.clone();
        let private_deadline = Instant::now() + self.budget;
        Box::pin(async move {
            let request = super::message::decode(&bytes)?;
            if !request
                .queries
                .iter()
                .any(|query| private.policy().claims(query.name()))
            {
                return match deadline {
                    Some(deadline) => raw.exchange_with_deadline(bytes, deadline).await,
                    None => raw.exchange(bytes).await,
                };
            }
            let deadline = deadline.map_or(private_deadline, |caller| caller.min(private_deadline));
            check_deadline(deadline)?;
            let invalid = if request.metadata.message_type != MessageType::Query {
                Some(ResponseCode::FormErr)
            } else if super::message::is_signed(&request) {
                Some(ResponseCode::Refused)
            } else {
                tendns::resolver::validate_request(&request)
            };
            let response = match invalid {
                Some(code) => tendns::resolver::local_response(&request, code),
                None => private
                    .answer_with_deadline(request, deadline)
                    .await
                    .map_err(map_error)?,
            };
            response.to_vec().map_err(io::Error::other)
        })
    }
}

impl Resolver for TendnsResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let Address::Hostname(host) = location.address() else {
            return self.raw.resolve_location(location);
        };
        // Inputs are hostnames, not DNS presentation strings with escape sequences.
        if host.is_empty() || host.contains('\\') {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid hostname",
                ))
            });
        }
        if host.starts_with('[')
            && location
                .to_string()
                .parse::<std::net::SocketAddrV6>()
                .is_ok()
        {
            return self.raw.resolve_location(location);
        }
        let name = match Name::from_str_relaxed(host) {
            Ok(name) => name,
            Err(error) => {
                // Rejects unparseable names rather than trusting native canonicalization
                // not to turn them into protected names.
                return Box::pin(
                    async move { Err(io::Error::new(io::ErrorKind::InvalidInput, error)) },
                );
            }
        };
        if !self.private.policy().claims(&name) {
            return self.raw.resolve_location(location);
        }
        let private = self.private.clone();
        let raw = self.raw.clone();
        let strategy = self.strategy;
        let port = location.port();
        let deadline = Instant::now() + self.budget;
        Box::pin(async move {
            let mut external = None;
            let native_addresses = &mut external;
            let addresses = private
                .lookup_ip(name, strategy, deadline, |target, deadline| async move {
                    check_deadline(deadline)?;
                    let location = NetLocation::new(Address::Hostname(target.to_ascii()), port);
                    let addresses =
                        tokio::time::timeout_at(deadline, raw.resolve_location(&location))
                            .await??;
                    let ips = addresses.iter().map(SocketAddr::ip).collect();
                    *native_addresses = Some(addresses);
                    Ok(ips)
                })
                .await
                .map_err(map_error)?;
            // Retains native IPv6 scope/flow information after private CNAME traversal.
            if let Some(mut native) = external {
                native.retain(|address| addresses.contains(&address.ip()));
                return Ok(native);
            }
            Ok(addresses
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        })
    }

    fn exchange(&self, bytes: Vec<u8>) -> DnsExchangeFuture {
        self.exchange_inner(bytes, None)
    }

    fn exchange_with_deadline(&self, bytes: Vec<u8>, deadline: Instant) -> DnsExchangeFuture {
        self.exchange_inner(bytes, Some(deadline))
    }
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            tendns::TimeoutError,
        ))
    } else {
        Ok(())
    }
}

fn map_error(error: anyhow::Error) -> io::Error {
    if error.is::<tendns::TimeoutError>() {
        return io::Error::new(io::ErrorKind::TimedOut, tendns::TimeoutError);
    }
    if let Some(error) = error.downcast_ref::<tendns::LookupError>() {
        return io::Error::new(io::ErrorKind::NotFound, *error);
    }
    match error.downcast::<io::Error>() {
        Ok(error) => error,
        Err(error) => io::Error::other(error.into_boxed_dyn_error()),
    }
}

#[cfg(test)]
mod tests;
