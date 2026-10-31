use std::io;

use super::resolved::{ChainPlan, ChoicePlan, HopPlan};
use crate::option_util::{NoneOrSome, OneOrSome};

pub(super) fn map_one<T, U, E>(
    items: OneOrSome<T>,
    f: &mut impl FnMut(T) -> Result<U, E>,
) -> Result<OneOrSome<U>, E> {
    Ok(match items {
        OneOrSome::One(item) => OneOrSome::One(f(item)?),
        OneOrSome::Some(items) => {
            OneOrSome::Some(items.into_iter().map(f).collect::<Result<_, _>>()?)
        }
    })
}

pub(super) fn map_some<T, U, E>(
    items: NoneOrSome<T>,
    f: &mut impl FnMut(T) -> Result<U, E>,
) -> Result<NoneOrSome<U>, E> {
    Ok(match items {
        NoneOrSome::Unspecified => NoneOrSome::Unspecified,
        NoneOrSome::None => NoneOrSome::None,
        NoneOrSome::One(item) => NoneOrSome::One(f(item)?),
        NoneOrSome::Some(items) => {
            NoneOrSome::Some(items.into_iter().map(f).collect::<Result<_, _>>()?)
        }
    })
}

pub(super) fn map_hop<C, D, E>(
    hop: HopPlan<C>,
    f: &mut impl FnMut(C) -> Result<D, E>,
) -> Result<HopPlan<D>, E> {
    Ok(match hop {
        HopPlan::Single(client) => HopPlan::Single(f(client)?),
        HopPlan::Choice(choice) => HopPlan::Choice(Box::new(ChoicePlan {
            name: choice.name,
            group_type: choice.group_type,
            labels: choice.labels,
            members: choice
                .members
                .into_iter()
                .map(|chain| map_chain(chain, f))
                .collect::<Result<_, _>>()?,
        })),
    })
}

pub(super) fn map_chain<C, D, E>(
    chain: ChainPlan<C>,
    f: &mut impl FnMut(C) -> Result<D, E>,
) -> Result<ChainPlan<D>, E> {
    Ok(ChainPlan {
        hops: map_one(chain.hops, &mut |hop| map_hop(hop, f))?,
    })
}

pub(super) fn clients<C: Sync>(hop: &HopPlan<C>) -> Box<dyn Iterator<Item = &C> + '_> {
    match hop {
        HopPlan::Single(client) => Box::new(std::iter::once(client)),
        HopPlan::Choice(choice) => Box::new(
            choice
                .members
                .iter()
                .flat_map(|chain| chain.hops.iter().flat_map(clients)),
        ),
    }
}

pub(super) fn visit_leaves<C: Send>(
    hop: &mut HopPlan<C>,
    f: &mut impl FnMut(&mut C) -> io::Result<()>,
) -> io::Result<()> {
    match hop {
        HopPlan::Single(client) => f(client),
        HopPlan::Choice(choice) => {
            for chain in &mut choice.members {
                for hop in chain.hops.iter_mut() {
                    visit_leaves(hop, f)?;
                }
            }
            Ok(())
        }
    }
}

pub(super) fn pool_choice<C>(members: Vec<ChainPlan<C>>) -> HopPlan<C> {
    HopPlan::Choice(Box::new(ChoicePlan {
        name: String::new(),
        group_type: super::GroupType::RoundRobin,
        labels: (0..members.len()).map(|index| index.to_string()).collect(),
        members,
    }))
}

pub(super) fn measure<C: Sync>(
    hop: &HopPlan<C>,
    depth: usize,
    leaf_nodes: fn(&C, usize) -> io::Result<usize>,
) -> io::Result<(usize, usize)> {
    use super::composition::{MAX_DEPTH, MAX_HOPS, MAX_NODES, invalid};
    if depth > MAX_DEPTH {
        return Err(invalid("client composition exceeds 64 levels"));
    }
    match hop {
        HopPlan::Single(client) => Ok((leaf_nodes(client, depth)?, 1)),
        HopPlan::Choice(choice) => {
            if choice.members.is_empty() || choice.members.len() != choice.labels.len() {
                return Err(invalid("choice requires nonempty, labeled members"));
            }
            let mut nodes = 1usize;
            let mut longest = 0usize;
            for member in &choice.members {
                if member.hops.iter().count() == 0 {
                    return Err(invalid("chain cannot be empty"));
                }
                let mut length = 0usize;
                for hop in member.hops.iter() {
                    let (count, hops) = measure(hop, depth + 1, leaf_nodes)?;
                    nodes = nodes.saturating_add(count);
                    length = length.saturating_add(hops);
                }
                longest = longest.max(length);
            }
            if nodes > MAX_NODES || longest > MAX_HOPS {
                return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
            }
            Ok((nodes, longest))
        }
    }
}

pub(super) fn validate<C: Sync>(
    hops: &OneOrSome<HopPlan<C>>,
    leaf_nodes: fn(&C, usize) -> io::Result<usize>,
    health: fn(&C, bool) -> io::Result<()>,
    position: fn(&C, usize) -> io::Result<()>,
) -> io::Result<()> {
    use super::composition::{MAX_HOPS, MAX_NODES, invalid};
    if hops.iter().count() == 0 {
        return Err(invalid("chain cannot be empty"));
    }
    let mut nodes = 0usize;
    let mut longest = 0usize;
    for hop in hops.iter() {
        let (count, length) = measure(hop, 0, leaf_nodes)?;
        nodes = nodes.saturating_add(count);
        longest = longest.saturating_add(length);
    }
    if nodes > MAX_NODES || longest > MAX_HOPS {
        return Err(invalid("client composition exceeds 16384 nodes or 64 hops"));
    }
    walk_health(hops, false, health)?;
    walk_positions(hops, 0, position).map(|_| ())
}

fn walk_health<C: Sync>(
    hops: &OneOrSome<HopPlan<C>>,
    mut multiple: bool,
    visit: fn(&C, bool) -> io::Result<()>,
) -> io::Result<bool> {
    for hop in hops.iter() {
        match hop {
            HopPlan::Single(client) => visit(client, multiple)?,
            HopPlan::Choice(choice) => {
                let mut paths = choice.members.len() > 1;
                for member in &choice.members {
                    paths |= walk_health(&member.hops, multiple, visit)?;
                }
                multiple = paths;
            }
        }
    }
    Ok(multiple)
}

fn walk_positions<C: Sync>(
    hops: &OneOrSome<HopPlan<C>>,
    mut offset: usize,
    visit: fn(&C, usize) -> io::Result<()>,
) -> io::Result<usize> {
    for hop in hops.iter() {
        match hop {
            HopPlan::Single(client) => {
                visit(client, offset)?;
                offset += 1;
            }
            HopPlan::Choice(choice) => {
                let mut end = offset;
                for member in &choice.members {
                    end = end.max(walk_positions(&member.hops, offset, visit)?);
                }
                offset = end;
            }
        }
    }
    Ok(offset)
}
