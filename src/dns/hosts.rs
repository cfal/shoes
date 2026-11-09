use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, RData, Record, RecordType, rdata};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::address::NetLocation;
use crate::option_util::OneOrSome;
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

use super::canonical_hostname;
use super::fake_ip::DnsDecision;
use super::fake_ip::responder::{precheck, response};

const HOSTS_TTL: u32 = 60;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct StaticHosts(BTreeMap<String, Vec<IpAddr>>);

impl<'de> Deserialize<'de> for StaticHosts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HostsVisitor;

        impl<'de> Visitor<'de> for HostsVisitor {
            type Value = StaticHosts;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a map of hostnames to IP addresses or nonempty IP lists")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                use serde::de::Error;

                let mut hosts = BTreeMap::new();
                while let Some((name, addresses)) = map.next_entry::<String, OneOrSome<IpAddr>>()? {
                    let key = canonical_hostname(&name).ok_or_else(|| {
                        M::Error::custom(format!("invalid hosts hostname: {name}"))
                    })?;
                    let mut ips = Vec::new();
                    for ip in addresses.into_vec() {
                        if ip.to_canonical().is_unspecified() {
                            return Err(M::Error::custom(format!(
                                "unspecified hosts address for {name}: {ip}"
                            )));
                        }
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                    if hosts.insert(key, ips).is_some() {
                        return Err(M::Error::custom(format!(
                            "duplicate hosts hostname: {name}"
                        )));
                    }
                }
                Ok(StaticHosts(hosts))
            }
        }

        deserializer.deserialize_any(HostsVisitor)
    }
}

impl StaticHosts {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn inherit(&mut self, other: &Self) {
        for (name, addresses) in &other.0 {
            self.0
                .entry(name.clone())
                .or_insert_with(|| addresses.clone());
        }
    }

    pub(crate) fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.0.values().flatten().copied()
    }

    pub(crate) fn lookup(&self, name: &str) -> Option<&[IpAddr]> {
        self.0.get(&canonical_hostname(name)?).map(Vec::as_slice)
    }

    pub(super) fn decide(&self, request: &Message) -> Option<DnsDecision> {
        if self.is_empty() {
            return None;
        }
        // Finds mapped questions before validation to keep malformed hits local
        // without changing unmapped raw request handling.
        let (query, addresses) = request.queries.iter().find_map(|query| {
            if query.query_class != DNSClass::IN
                || !matches!(query.query_type, RecordType::A | RecordType::AAAA)
            {
                return None;
            }
            self.lookup(&query.name.to_ascii())
                .map(|addresses| (query, addresses))
        })?;
        if let Some(decision) = precheck(request) {
            return Some(decision);
        }
        if !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || request.metadata.truncation
            || request.metadata.response_code != ResponseCode::NoError
        {
            return Some(DnsDecision::Answer(response(
                request,
                ResponseCode::FormErr,
            )));
        }
        let mut answer = response(request, ResponseCode::NoError);
        for ip in addresses {
            let data = match (ip, query.query_type) {
                (IpAddr::V4(ip), RecordType::A) => RData::A(rdata::A(*ip)),
                (IpAddr::V6(ip), RecordType::AAAA) => RData::AAAA(rdata::AAAA(*ip)),
                _ => continue,
            };
            answer.add_answer(Record::from_rdata(query.name.clone(), HOSTS_TTL, data));
        }
        Some(DnsDecision::Answer(answer))
    }
}

#[derive(Debug)]
pub(super) struct HostsResolver {
    hosts: Arc<StaticHosts>,
    inner: Arc<dyn Resolver>,
}

impl HostsResolver {
    pub(super) fn wrap(hosts: Arc<StaticHosts>, inner: Arc<dyn Resolver>) -> Arc<dyn Resolver> {
        if hosts.is_empty() {
            inner
        } else {
            Arc::new(Self { hosts, inner })
        }
    }

    fn answer(&self, bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let Ok(request) = super::message::decode(bytes) else {
            return Ok(None);
        };
        match self.hosts.decide(&request) {
            Some(DnsDecision::Answer(answer)) => {
                answer.to_vec().map(Some).map_err(io::Error::other)
            }
            Some(DnsDecision::Drop) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected DNS query",
            )),
            None | Some(DnsDecision::Forward) => Ok(None),
        }
    }
}

impl Resolver for HostsResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(addresses) = location
            .address()
            .hostname()
            .and_then(|name| self.hosts.lookup(name))
        {
            let addresses = addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, location.port()))
                .collect();
            return Box::pin(async move { Ok(addresses) });
        }
        self.inner.resolve_location(location)
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        match self.answer(&request) {
            Ok(Some(answer)) => Box::pin(async move { Ok(answer) }),
            Ok(None) => self.inner.exchange(request),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        match self.answer(&request) {
            Ok(Some(answer)) => Box::pin(async move { Ok(answer) }),
            Ok(None) => self.inner.exchange_with_deadline(request, deadline),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

#[cfg(test)]
mod tests;
