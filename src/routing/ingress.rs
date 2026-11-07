use std::io;
use std::sync::Arc;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_chain::ClientChainGroup;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, IngressTarget};
use crate::control::connection_notes::{self, Phase};
use crate::resolver::{Resolver, resolve_location};

mod peek;
pub(crate) use peek::PeekMessageStream;

pub(crate) struct PreparedUdp {
    target: IngressTarget,
}

impl PreparedUdp {
    pub(crate) fn new(
        selector: &ClientProxySelector,
        destination: NetLocation,
    ) -> io::Result<Self> {
        Ok(Self {
            target: selector.prepare(destination.into())?,
        })
    }

    pub(crate) fn needs_sniff(&self, selector: &ClientProxySelector) -> bool {
        selector.has_protocol_rules() && matches!(self.target, IngressTarget::Forward(_))
    }

    pub(crate) async fn route<'a, S: AsyncMessageStream>(
        mut self,
        inbound: &mut PeekMessageStream<S>,
        selector: &'a ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<UdpRoute<'a>> {
        if self.needs_sniff(selector)
            && let IngressTarget::Forward(target) = &mut self.target
        {
            target.traffic.protocol = inbound.peek().await?;
        }
        route_prepared_udp(selector, self.target, resolver, false).await
    }
}

pub(crate) fn classify_target(
    selector: &ClientProxySelector,
    target: &mut IngressTarget,
    packet: &[u8],
) {
    if selector.has_protocol_rules()
        && let IngressTarget::Forward(target) = target
    {
        target.traffic.protocol = crate::sniff::udp::classify(packet);
    }
}

pub(crate) async fn connect_udp_packet(
    selector: &ClientProxySelector,
    destination: NetLocation,
    resolver: &Arc<dyn Resolver>,
    source: Option<std::net::SocketAddr>,
    packet: &[u8],
) -> io::Result<Box<dyn AsyncMessageStream>> {
    let mut target = selector.prepare(destination.into())?;
    classify_target(selector, &mut target, packet);
    Ok(
        connect_prepared_udp(selector, target, resolver, false, source)
            .await?
            .stream,
    )
}

pub(crate) struct UdpSetup {
    pub stream: Box<dyn AsyncMessageStream>,
    pub reply_identity: NetLocation,
}

#[derive(Debug)]
struct PolicyBlock;

impl std::fmt::Display for PolicyBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Destination blocked by routing rules")
    }
}

impl std::error::Error for PolicyBlock {}

pub(crate) fn is_policy_block(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<PolicyBlock>())
}

pub(crate) enum UdpRoute<'a> {
    Local(UdpSetup),
    Forward {
        chain: &'a ClientChainGroup,
        target: ResolvedLocation,
        reply_identity: NetLocation,
        info: crate::control::flows::FlowInfo,
    },
}

impl UdpRoute<'_> {
    pub(crate) fn with_source(mut self, source: Option<std::net::SocketAddr>) -> Self {
        if let Self::Forward { info, .. } = &mut self {
            info.source = source;
        }
        self
    }
    pub(crate) async fn connect(self, resolver: &Arc<dyn Resolver>) -> io::Result<UdpSetup> {
        match self {
            Self::Local(setup) => Ok(setup),
            Self::Forward {
                chain,
                target,
                reply_identity,
                info,
            } => Ok(UdpSetup {
                stream: chain.connect_udp_with_info(resolver, target, info).await?,
                reply_identity,
            }),
        }
    }
}

#[cfg(test)]
pub(crate) async fn route_udp<'a>(
    selector: &'a ClientProxySelector,
    destination: NetLocation,
    resolver: &Arc<dyn Resolver>,
) -> io::Result<UdpRoute<'a>> {
    route_prepared_udp(
        selector,
        selector.prepare(destination.into())?,
        resolver,
        false,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn connect_udp(
    selector: &ClientProxySelector,
    destination: NetLocation,
    resolver: &Arc<dyn Resolver>,
    source: Option<std::net::SocketAddr>,
) -> io::Result<Box<dyn AsyncMessageStream>> {
    connect_udp_packet(selector, destination, resolver, source, &[]).await
}

pub(crate) async fn connect_prepared_udp(
    selector: &ClientProxySelector,
    target: IngressTarget,
    resolver: &Arc<dyn Resolver>,
    require_ip_reply: bool,
    source: Option<std::net::SocketAddr>,
) -> io::Result<UdpSetup> {
    route_prepared_udp(selector, target, resolver, require_ip_reply)
        .await?
        .with_source(source)
        .connect(resolver)
        .await
}

async fn route_prepared_udp<'a>(
    selector: &'a ClientProxySelector,
    target: IngressTarget,
    resolver: &Arc<dyn Resolver>,
    require_ip_reply: bool,
) -> io::Result<UdpRoute<'a>> {
    let target = match target {
        IngressTarget::LocalDns {
            wire_destination,
            context,
        } => {
            let wire_destination = reply_destination(wire_destination, require_ip_reply);
            let reply_identity =
                if require_ip_reply && wire_destination.address().hostname().is_some() {
                    let address = resolve_location(&mut wire_destination.into(), resolver).await?;
                    NetLocation::from_ip_addr(address.ip(), address.port())
                } else {
                    wire_destination
                };
            return Ok(UdpRoute::Local(UdpSetup {
                stream: context.udp_stream(),
                reply_identity,
            }));
        }
        IngressTarget::Forward(mut target) => {
            target.traffic.network = crate::rules::Network::Udp;
            target
        }
    };
    let mut info = if selector.tracks_flows() {
        target.flow_info()
    } else {
        Default::default()
    };
    info.notes = selector.start_notes();
    let resolver = connection_notes::resolver(resolver, info.notes.as_ref(), Phase::Routing);
    let routed = selector
        .judge_prepared_with_notes(target, None, &resolver, info.notes.as_deref())
        .await?;
    match routed.decision {
        ConnectDecision::Allow {
            chain_group,
            mut remote_location,
        } => {
            let wire_destination = reply_destination(routed.wire_destination, require_ip_reply);
            let reply_identity =
                if require_ip_reply && wire_destination.address().hostname().is_some() {
                    let address = resolve_location(&mut remote_location, &resolver).await?;
                    NetLocation::from_ip_addr(address.ip(), address.port())
                } else {
                    wire_destination
                };
            Ok(UdpRoute::Forward {
                chain: chain_group,
                target: remote_location,
                reply_identity,
                info,
            })
        }
        ConnectDecision::Block => Err(io::Error::new(io::ErrorKind::PermissionDenied, PolicyBlock)),
    }
}

fn reply_destination(wire_destination: NetLocation, require_ip_reply: bool) -> NetLocation {
    if require_ip_reply
        && let Some(hostname) = wire_destination.address().hostname()
        && let Ok(ip) = hostname.parse()
    {
        return NetLocation::from_ip_addr(ip, wire_destination.port());
    }
    wire_destination
}

#[cfg(test)]
pub(crate) mod tests;
