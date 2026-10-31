//! Private routing drafts preserve expansion-before-settings-validation ordering.

use std::collections::HashMap;
use std::io;

use super::composition::{MAX_HOPS, MAX_NODES, invalid};
use super::plan_ops;
use super::resolved::{ChainPlan, HopPlan, ResolvedClientChain, ResolvedClientConfig};
use super::{ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection, GlobalLimits};
use crate::option_util::OneOrSome;

#[derive(Debug, Clone)]
pub(super) enum DraftClient {
    Pending {
        source: ClientConfig,
        carrier: Option<Box<ChainPlan<DraftClient>>>,
    },
    Ready(ResolvedClientConfig),
}

pub(super) type Groups = HashMap<String, HopPlan<DraftClient>>;

impl DraftClient {
    pub(super) fn resolved(&self) -> &ResolvedClientConfig {
        match self {
            Self::Ready(client) => client,
            Self::Pending { .. } => unreachable!("group settings have been validated"),
        }
    }

    pub(super) fn resolved_mut(&mut self) -> &mut ResolvedClientConfig {
        match self {
            Self::Ready(client) => client,
            Self::Pending { .. } => unreachable!("group settings have been validated"),
        }
    }

    pub(super) fn origin_mut(&mut self) -> &mut Option<crate::control::catalog::MemberOrigin> {
        match self {
            Self::Pending { source, .. } => &mut source.control,
            Self::Ready(client) => &mut client.control,
        }
    }
}

pub(super) fn draft_client(source: ClientConfig, groups: &Groups) -> io::Result<DraftClient> {
    let carrier = match &source.protocol {
        ClientProxyConfig::Wireguard(config) => config
            .peer_client_chain
            .as_ref()
            .map(|chain| expand(chain.hops.clone(), groups).map(Box::new))
            .transpose()?,
        _ => None,
    };
    Ok(DraftClient::Pending { source, carrier })
}

pub(super) fn expand(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
) -> io::Result<ChainPlan<DraftClient>> {
    expand_with(hops, groups, &mut Ok)
}

pub(super) fn compile_chain(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientChain> {
    let draft = expand_with(hops, groups, &mut |client| {
        lower_client(client, pems, limits).map(DraftClient::Ready)
    })?;
    lower_chain(draft, pems, limits)
}

fn expand_with(
    hops: OneOrSome<ClientChainHop>,
    groups: &Groups,
    inline: &mut impl FnMut(DraftClient) -> io::Result<DraftClient>,
) -> io::Result<ChainPlan<DraftClient>> {
    fn selection(
        value: ConfigSelection<ClientConfig>,
        groups: &Groups,
    ) -> io::Result<ConfigSelection<DraftClient>> {
        Ok(match value {
            ConfigSelection::Config(client) => {
                ConfigSelection::Config(draft_client(client, groups)?)
            }
            ConfigSelection::GroupName(name) => ConfigSelection::GroupName(name),
        })
    }
    let pending = plan_ops::map_one(hops, &mut |hop| {
        let (pool, values) = match hop {
            ClientChainHop::Single(value) => (false, OneOrSome::One(selection(value, groups)?)),
            ClientChainHop::Pool(values) => (
                true,
                plan_ops::map_one(values, &mut |value| selection(value, groups))?,
            ),
        };
        // Carrier expansion for the whole stage precedes inline settings validation.
        let values = plan_ops::map_one(values, &mut |value| {
            Ok::<_, io::Error>(match value {
                ConfigSelection::Config(client) => ConfigSelection::Config(inline(client)?),
                ConfigSelection::GroupName(name) => ConfigSelection::GroupName(name),
            })
        })?;
        Ok::<_, io::Error>((pool, values))
    })?;
    // Count complete referenced subtrees, including carriers, before cloning occurrences.
    let mut nodes = 0usize;
    let mut length = 0usize;
    for (pool, values) in pending.iter() {
        let mut longest = 0usize;
        nodes = nodes.saturating_add(usize::from(*pool));
        for value in values.iter() {
            let (count, hops) = match value {
                ConfigSelection::Config(client) => (client_nodes(client, usize::from(*pool))?, 1),
                ConfigSelection::GroupName(name) => measure(
                    groups
                        .get(name)
                        .ok_or_else(|| invalid(format!("Unknown client group: {name}")))?,
                    usize::from(*pool),
                )?,
            };
            nodes = nodes.saturating_add(count);
            longest = longest.max(hops);
            if nodes > MAX_NODES {
                return Err(invalid("client composition exceeds 16384 nodes"));
            }
        }
        length = length.saturating_add(longest);
        if length > MAX_HOPS {
            return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
        }
    }
    let hops = plan_ops::map_one(pending, &mut |(pool, values)| {
        let mut members = values
            .into_vec()
            .into_iter()
            .map(|value| {
                let hop = match value {
                    ConfigSelection::Config(client) => HopPlan::Single(client),
                    ConfigSelection::GroupName(name) => groups[&name].clone(),
                };
                ChainPlan {
                    hops: OneOrSome::One(hop),
                }
            })
            .collect::<Vec<_>>();
        Ok::<_, io::Error>(if pool {
            plan_ops::pool_choice(members)
        } else {
            members.remove(0).hops.into_vec().remove(0)
        })
    })?;
    plan_ops::validate(&hops, client_nodes, validate_health, validate_position)?;
    Ok(ChainPlan { hops })
}

pub(super) fn measure(hop: &HopPlan<DraftClient>, depth: usize) -> io::Result<(usize, usize)> {
    plan_ops::measure(hop, depth, client_nodes)
}

fn client_nodes(client: &DraftClient, depth: usize) -> io::Result<usize> {
    match client {
        DraftClient::Ready(client) => super::composition::client_nodes(client, depth),
        DraftClient::Pending { carrier, .. } => {
            let mut nodes = 1usize;
            if let Some(chain) = carrier {
                for hop in chain.hops.iter() {
                    nodes = nodes.saturating_add(measure(hop, depth + 1)?.0);
                }
            }
            if nodes > MAX_NODES {
                return Err(invalid("client composition exceeds 16384 nodes"));
            }
            Ok(nodes)
        }
    }
}

fn validate_health(client: &DraftClient, multiple: bool) -> io::Result<()> {
    match client {
        DraftClient::Ready(client) => super::health::validate_client(client, multiple),
        DraftClient::Pending { source, .. } => {
            super::health::validate_source_client(source, multiple)
        }
    }
}

fn validate_position(client: &DraftClient, offset: usize) -> io::Result<()> {
    match client {
        DraftClient::Ready(client) => super::composition::validate_position(client, offset),
        DraftClient::Pending { source, .. } => {
            source.validate_quic_key_exchange(offset == 0)?;
            super::composition::validate_position_flags(
                source.protocol.is_direct(),
                source.protocol.is_wireguard(),
                source.transport == super::Transport::Quic
                    && super::validate::source_contains_xhttp(&source.protocol),
                offset,
            )
        }
    }
}

pub(super) fn lower_chain(
    chain: ChainPlan<DraftClient>,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientChain> {
    plan_ops::map_chain(chain, &mut |client| lower_client(client, pems, limits))
}

pub(super) fn lower_client(
    client: DraftClient,
    pems: &HashMap<String, String>,
    limits: GlobalLimits,
) -> io::Result<ResolvedClientConfig> {
    match client {
        DraftClient::Ready(client) => Ok(client),
        DraftClient::Pending { source, carrier } => super::validate::resolve_client_config(
            source,
            carrier.map(|chain| *chain),
            pems,
            limits,
        ),
    }
}
