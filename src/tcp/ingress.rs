use std::io;
use std::sync::Arc;

use tokio::io::AsyncRead;

use crate::address::NetLocation;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision, IngressTarget};
use crate::control::connection_notes::{self, ConnectionNotes, Phase};
use crate::resolver::Resolver;
use crate::sniff::{SNIFF_TIMEOUT, StreamProbe};

use super::tcp_handler::TcpClientSetupResult;

pub(crate) struct PreparedTcp {
    target: IngressTarget,
    prefix: Vec<u8>,
    probe: Option<StreamProbe>,
    source: Option<std::net::SocketAddr>,
    notes: Option<Arc<ConnectionNotes>>,
}

pub(crate) struct RoutedTcp {
    pub wire_destination: NetLocation,
    pub is_local_dns: bool,
    pub setup: Option<TcpClientSetupResult>,
    pub prefix: Vec<u8>,
}

pub(crate) struct TcpRoute<'a> {
    wire_destination: NetLocation,
    prefix: Vec<u8>,
    target: TcpRouteTarget<'a>,
    info: crate::control::flows::FlowInfo,
}

enum TcpRouteTarget<'a> {
    LocalDns(Arc<crate::dns::fake_ip::FakeDnsContext>),
    Forward(ConnectDecision<'a>),
}

impl TcpRoute<'_> {
    pub(crate) async fn connect(self, resolver: &Arc<dyn Resolver>) -> io::Result<RoutedTcp> {
        let is_local_dns = matches!(&self.target, TcpRouteTarget::LocalDns(_));
        let setup = match self.target {
            TcpRouteTarget::LocalDns(context) => Some(TcpClientSetupResult {
                client_stream: context.tcp_stream(),
                early_data: None,
            }),
            TcpRouteTarget::Forward(ConnectDecision::Allow {
                chain_group,
                remote_location,
            }) => Some(
                chain_group
                    .connect_tcp_with_info(remote_location, resolver, self.info)
                    .await?,
            ),
            TcpRouteTarget::Forward(ConnectDecision::Block) => None,
        };
        Ok(RoutedTcp {
            wire_destination: self.wire_destination,
            is_local_dns,
            setup,
            prefix: self.prefix,
        })
    }
}

impl PreparedTcp {
    pub(crate) fn new(
        selector: &ClientProxySelector,
        target: NetLocation,
        mut prefix: Vec<u8>,
    ) -> io::Result<Self> {
        let notes = selector.start_notes();
        if let Some(notes) = &notes {
            notes.event(Phase::Prepare, format_args!("destination {target}"));
        }
        let target = selector.prepare(target.into())?;
        let notes = notes.filter(|_| matches!(target, IngressTarget::Forward(_)));
        let probe = match &target {
            IngressTarget::Forward(target) if selector.should_sniff(target) => {
                Some(StreamProbe::from_prefix(std::mem::take(&mut prefix)))
            }
            _ => None,
        };
        Ok(Self {
            target,
            prefix,
            probe,
            source: None,
            notes,
        })
    }

    pub(crate) fn with_source(mut self, source: Option<std::net::SocketAddr>) -> Self {
        self.source = source;
        self
    }

    pub(crate) fn needs_sniff_read(&self) -> bool {
        self.probe.as_ref().is_some_and(StreamProbe::needs_more)
    }

    #[cfg(test)]
    pub(crate) async fn connect<R: AsyncRead + Unpin + ?Sized>(
        self,
        inbound: &mut R,
        selector: &ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<RoutedTcp> {
        self.route(inbound, selector, resolver)
            .await?
            .connect(resolver)
            .await
    }

    // Protocol adapters send any required optimistic reply before calling this method.
    pub(crate) async fn route<'a, R: AsyncRead + Unpin + ?Sized>(
        self,
        inbound: &mut R,
        selector: &'a ClientProxySelector,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<TcpRoute<'a>> {
        let (hostname, prefix) = if let Some(probe) = self.probe {
            let result = probe.finish(inbound, SNIFF_TIMEOUT).await?;
            (result.hostname, result.prefix)
        } else {
            (None, self.prefix)
        };
        let mut info = crate::control::flows::FlowInfo::default();
        if selector.tracks_flows()
            && let IngressTarget::Forward(target) = &self.target
        {
            info = target.flow_info();
            info.source = self.source;
            info.sniff_host = hostname.clone();
        }
        info.notes = self.notes;
        let (wire_destination, target) = match self.target {
            IngressTarget::LocalDns {
                wire_destination,
                context,
            } => (wire_destination, TcpRouteTarget::LocalDns(context)),
            IngressTarget::Forward(target) => {
                let resolver =
                    connection_notes::resolver(resolver, info.notes.as_ref(), Phase::Routing);
                let routed = selector
                    .judge_prepared_with_notes(
                        target,
                        hostname.as_deref(),
                        &resolver,
                        info.notes.as_deref(),
                    )
                    .await?;
                (
                    routed.wire_destination,
                    TcpRouteTarget::Forward(routed.decision),
                )
            }
        };
        Ok(TcpRoute {
            wire_destination,
            target,
            prefix,
            info,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
