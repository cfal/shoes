use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::RecordType;

use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::resolver::Resolver;

use super::responder::{UDP_PAYLOAD_LIMIT, response};
use super::{DnsDecision, FakeDnsResponder, FakeIpOptions, FakeIpPool};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct FakeDnsContext {
    responder: Arc<FakeDnsResponder>,
    real: Arc<dyn Resolver>,
}

impl FakeDnsContext {
    #[cfg(test)]
    pub fn new(options: FakeIpOptions, real: Arc<dyn Resolver>) -> io::Result<Self> {
        options.validate()?;
        let pool = Arc::new(FakeIpPool::new(&options)?);
        Self::with_pool(options, real, pool)
    }

    pub(crate) fn with_pool(
        options: FakeIpOptions,
        real: Arc<dyn Resolver>,
        pool: Arc<FakeIpPool>,
    ) -> io::Result<Self> {
        Ok(Self {
            responder: Arc::new(FakeDnsResponder::new(options, pool)?),
            real,
        })
    }

    pub fn restore(&self, address: IpAddr) -> io::Result<Option<String>> {
        self.responder.pool.restore(address)
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.responder.pool.contains(address)
    }

    #[cfg(test)]
    pub fn allocate(&self, name: &str, ipv6: bool) -> io::Result<IpAddr> {
        self.responder.pool.allocate(name, ipv6)
    }

    pub fn tcp_stream(self: &Arc<Self>) -> Box<dyn AsyncStream> {
        Box::new(super::stream::TcpDnsStream::new(self.clone()))
    }

    pub fn udp_stream(self: &Arc<Self>) -> Box<dyn AsyncMessageStream> {
        Box::new(super::stream::UdpDnsStream::new(self.clone()))
    }

    pub async fn exchange(&self, bytes: Vec<u8>, tcp: bool) -> io::Result<Option<Vec<u8>>> {
        let request = match crate::dns::message::decode(&bytes) {
            Ok(request) => request,
            Err(_) => return Ok(None),
        };
        if request.metadata.message_type != MessageType::Query {
            return Ok(None);
        }
        let may_allocate = request.queries.len() == 1
            && matches!(
                request.queries[0].query_type,
                RecordType::A | RecordType::AAAA
            );
        let decision = if self.responder.pool.persistent() && may_allocate {
            let responder = self.responder.clone();
            let request = request.clone();
            let failure = response(&request, ResponseCode::ServFail);
            let decision = async move {
                let permit = responder
                    .pool
                    .persistence_admission
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(io::Error::other)?;
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    responder.decide(&request)
                })
                .await
                .map_err(io::Error::other)
            };
            match tokio::time::timeout(EXCHANGE_TIMEOUT, decision).await {
                Ok(Ok(decision)) => decision,
                _ => DnsDecision::Answer(failure),
            }
        } else {
            self.responder.decide(&request)
        };
        let answer = match decision {
            DnsDecision::Drop => return Ok(None),
            DnsDecision::Answer(answer) => answer,
            DnsDecision::Forward => {
                let deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
                let exchange = self.real.exchange_with_deadline(bytes, deadline).await;
                match exchange {
                    Ok(reply) => self
                        .check_response(&request, &reply)
                        .unwrap_or_else(|_| response(&request, ResponseCode::ServFail)),
                    Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                        response(&request, ResponseCode::Refused)
                    }
                    _ => response(&request, ResponseCode::ServFail),
                }
            }
        };
        let mut encoded = answer.to_vec().map_err(io::Error::other)?;
        let udp_payload_limit = request.max_payload().min(UDP_PAYLOAD_LIMIT);
        if !tcp && encoded.len() > usize::from(udp_payload_limit) {
            let mut truncated = answer.truncate();
            truncated.metadata.authentic_data = false;
            if let Some(edns) = &mut truncated.edns {
                *edns.options_mut() = Default::default();
                edns.set_max_payload(udp_payload_limit);
            }
            encoded = truncated.to_vec().map_err(io::Error::other)?;
            if encoded.len() > usize::from(udp_payload_limit) {
                truncated.queries.clear();
                encoded = truncated.to_vec().map_err(io::Error::other)?;
            }
            if encoded.len() > usize::from(udp_payload_limit) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS reply exceeds UDP limit",
                ));
            }
        }
        if encoded.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response exceeds TCP frame size",
            ));
        }
        Ok(Some(encoded))
    }

    fn check_response(&self, request: &Message, bytes: &[u8]) -> io::Result<Message> {
        let response = crate::dns::message::decode(bytes)?;
        if response.metadata.message_type != MessageType::Response
            || response.metadata.id != request.metadata.id
            || response.metadata.op_code != request.metadata.op_code
            || response.queries != request.queries
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unassociated DNS response",
            ));
        }
        if crate::dns::message::addresses(&response).any(|ip| self.contains(ip)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "real DNS returned a synthetic address",
            ));
        }
        Ok(response)
    }
}

#[derive(Debug)]
pub struct FakeDnsResolver {
    real: Arc<dyn Resolver>,
    context: Arc<FakeDnsContext>,
}

impl FakeDnsResolver {
    pub fn new(real: Arc<dyn Resolver>, context: Arc<FakeDnsContext>) -> Self {
        Self { real, context }
    }
}

impl Resolver for FakeDnsResolver {
    fn manual_selector_paths(&self) -> Vec<crate::control::selection::ManualSelectorPath> {
        self.real.manual_selector_paths()
    }

    fn resolve_location(
        &self,
        location: &crate::address::NetLocation,
    ) -> crate::resolver::ResolveFuture {
        let future = self.real.resolve_location(location);
        let context = self.context.clone();
        Box::pin(async move {
            let mut addresses = future.await?;
            addresses.retain(|address| !context.contains(address.ip()));
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "real DNS returned no usable addresses (possible Fake DNS loop)",
                ));
            }
            Ok(addresses)
        })
    }

    fn fake_dns_context(&self) -> Option<Arc<FakeDnsContext>> {
        Some(self.context.clone())
    }

    fn exchange(&self, request: Vec<u8>) -> crate::resolver::DnsExchangeFuture {
        self.real.exchange(request)
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> crate::resolver::DnsExchangeFuture {
        self.real.exchange_with_deadline(request, deadline)
    }
}
