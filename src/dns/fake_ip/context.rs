use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
use hickory_resolver::proto::rr::RData;

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
        let decision = if self.responder.pool.persistent() {
            let responder = self.responder.clone();
            let request = request.clone();
            tokio::task::spawn_blocking(move || responder.decide(&request))
                .await
                .map_err(io::Error::other)?
        } else {
            self.responder.decide(&request)
        };
        let answer = match decision {
            DnsDecision::Drop => return Ok(None),
            DnsDecision::Answer(answer) => answer,
            DnsDecision::Forward => {
                // Our upstream handles may rewrite IDs and wire encoding; TSIG cannot survive that.
                if crate::dns::message::is_signed(&request) {
                    response(&request, ResponseCode::Refused)
                } else {
                    let exchange =
                        tokio::time::timeout(EXCHANGE_TIMEOUT, self.real.exchange(bytes)).await;
                    match exchange {
                        Ok(Ok(reply)) => match self.check_response(&request, &reply) {
                            Ok(answer) => answer,
                            Err(_) => response(&request, ResponseCode::ServFail),
                        },
                        Ok(Err(err)) if err.kind() == io::ErrorKind::Unsupported => {
                            response(&request, ResponseCode::Refused)
                        }
                        _ => response(&request, ResponseCode::ServFail),
                    }
                }
            }
        };
        let mut encoded = answer.to_vec().map_err(io::Error::other)?;
        if !tcp && encoded.len() > request.max_payload().min(UDP_PAYLOAD_LIMIT) as usize {
            let mut truncated = answer.truncate();
            truncated.metadata.authentic_data = false;
            encoded = truncated.to_vec().map_err(io::Error::other)?;
            if encoded.len() > request.max_payload().min(UDP_PAYLOAD_LIMIT) as usize {
                truncated.queries.clear();
                encoded = truncated.to_vec().map_err(io::Error::other)?;
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
        for record in response.all_sections() {
            let ip = match record.data {
                RData::A(ip) => Some(IpAddr::V4(ip.0)),
                RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                _ => None,
            };
            if ip.is_some_and(|ip| self.contains(ip)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "real DNS returned a synthetic address",
                ));
            }
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
}
