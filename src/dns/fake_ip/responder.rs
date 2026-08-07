//! Decides, for a single DNS query, whether to answer it locally with a fake
//! address or let it go upstream.
//!
//! Deliberately free of I/O: it takes the query bytes and returns either a
//! response to write back or a decision to forward. That keeps every rule in
//! this file unit-testable without a socket, a runtime, or a network.

use std::sync::Arc;

use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::{RData, Record, RecordType, rdata};

use super::bypass::BypassList;
use super::pool::FakeIpPool;

/// TTL handed out with a fake address, in seconds.
///
/// Deliberately tiny. The mapping behind an address can be recycled once the
/// pool is full, so a client holding a long-lived cache entry could otherwise
/// keep using an address that now stands for a different domain. A one-second
/// TTL brings the client back to us often enough that the lookup refreshes the
/// entry's recency and keeps it from being recycled while in use. Answering
/// costs a hash lookup and no network, so the extra queries are close to free.
const FAKE_IP_TTL_SECS: u32 = 1;

/// What to do with a DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDecision {
    /// Write these bytes back to the client. No upstream query happens.
    Answer(Vec<u8>),
    /// Not ours. Send it through the normal proxied path.
    Forward,
}

/// Answers A queries from a [`FakeIpPool`], and forwards everything else.
pub struct FakeIpResponder {
    pool: Arc<FakeIpPool>,
    bypass: BypassList,
}

impl FakeIpResponder {
    pub fn new(pool: Arc<FakeIpPool>, bypass: BypassList) -> Self {
        Self { pool, bypass }
    }

    pub fn pool(&self) -> &Arc<FakeIpPool> {
        &self.pool
    }

    /// Decide what to do with one DNS query datagram.
    ///
    /// Anything not clearly a single-question standard query is forwarded
    /// rather than guessed at — being wrong here means breaking name
    /// resolution, and forwarding is always a correct fallback.
    pub fn handle_query(&self, packet: &[u8]) -> DnsDecision {
        let Ok(request) = Message::from_vec(packet) else {
            return DnsDecision::Forward;
        };

        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return DnsDecision::Forward;
        }

        // Multi-question queries have no well-defined semantics and are
        // vanishingly rare in practice; upstream can have them.
        let [query] = request.queries.as_slice() else {
            return DnsDecision::Forward;
        };

        let record_type = query.query_type();
        if !matches!(record_type, RecordType::A | RecordType::AAAA) {
            // HTTPS/SVCB, SRV, TXT, MX, PTR and friends all carry real data
            // that a fake address cannot stand in for. Forwarding them keeps
            // ECH, ALPN hints and service discovery working; the query still
            // travels inside the tunnel, so nothing leaks.
            return DnsDecision::Forward;
        }

        let domain = normalize_name(&query.name().to_utf8());
        if domain.is_empty() || self.bypass.matches(&domain) {
            return DnsDecision::Forward;
        }

        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = ResponseCode::NoError;
        response.add_query(query.clone());

        if record_type == RecordType::A {
            let ip = self.pool.assign(&domain);
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                FAKE_IP_TTL_SECS,
                RData::A(rdata::A(ip)),
            ));
        }
        // AAAA falls through with no answer record: NOERROR with an empty
        // answer section is NODATA, which tells the client the name exists but
        // has no AAAA, so it retries with A and gets a fake address. Handing
        // out a fake IPv6 instead would be worse — the client would prefer it,
        // and the tunnel is not guaranteed to carry IPv6.

        match response.to_vec() {
            Ok(bytes) => DnsDecision::Answer(bytes),
            // Encoding our own small response should not fail; if it somehow
            // does, forwarding still resolves the name.
            Err(_) => DnsDecision::Forward,
        }
    }
}

impl std::fmt::Debug for FakeIpResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIpResponder")
            .field("pool", &self.pool)
            .finish()
    }
}

/// Lowercase and strip the root label, so lookups and bypass patterns agree.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::fake_ip::pool::FakeIpNetwork;
    use hickory_resolver::proto::rr::Name;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn responder(bypass: &[&str]) -> FakeIpResponder {
        let pool = Arc::new(
            FakeIpPool::new(FakeIpNetwork::parse("198.18.0.0/16").unwrap(), 8192).unwrap(),
        );
        FakeIpResponder::new(pool, BypassList::new(bypass.iter().copied()))
    }

    fn query_bytes(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(hickory_resolver::proto::op::Query::query(
            Name::from_str(name).unwrap(),
            record_type,
        ));
        message.to_vec().unwrap()
    }

    fn parse(decision: &DnsDecision) -> Message {
        match decision {
            DnsDecision::Answer(bytes) => Message::from_vec(bytes).unwrap(),
            DnsDecision::Forward => panic!("expected an answer, got Forward"),
        }
    }

    fn answer_ips(message: &Message) -> Vec<Ipv4Addr> {
        message
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_query_gets_a_fake_address_from_the_pool() {
        let responder = responder(&[]);
        let decision = responder.handle_query(&query_bytes("example.com.", RecordType::A));
        let response = parse(&decision);

        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.queries.len(), 1, "the question must be echoed");

        let ips = answer_ips(&response);
        assert_eq!(ips.len(), 1);
        assert!(responder.pool().is_fake_ip(ips[0]));
        assert_eq!(
            responder.pool().lookup(ips[0]).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn repeated_queries_return_the_same_address() {
        let responder = responder(&[]);
        let first = answer_ips(&parse(
            &responder.handle_query(&query_bytes("example.com.", RecordType::A)),
        ));
        let second = answer_ips(&parse(
            &responder.handle_query(&query_bytes("example.com.", RecordType::A)),
        ));
        assert_eq!(first, second);
    }

    #[test]
    fn the_answer_ttl_is_short_enough_to_keep_the_mapping_fresh() {
        let responder = responder(&[]);
        let response = parse(&responder.handle_query(&query_bytes("example.com.", RecordType::A)));
        assert_eq!(response.answers[0].ttl, FAKE_IP_TTL_SECS);
    }

    #[test]
    fn aaaa_query_gets_nodata_not_a_fake_address() {
        let responder = responder(&[]);
        let response =
            parse(&responder.handle_query(&query_bytes("example.com.", RecordType::AAAA)));

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(
            response.answers.is_empty(),
            "AAAA must be NODATA so the client falls back to A"
        );
        assert_eq!(response.queries.len(), 1);
    }

    /// The defect that made the original implementation unusable in a browser:
    /// every non-A type came back as an empty NOERROR.
    #[test]
    fn other_record_types_are_forwarded_not_blackholed() {
        let responder = responder(&[]);
        for record_type in [
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::SRV,
            RecordType::TXT,
            RecordType::MX,
            RecordType::PTR,
            RecordType::CNAME,
            RecordType::NS,
        ] {
            assert_eq!(
                responder.handle_query(&query_bytes("example.com.", record_type)),
                DnsDecision::Forward,
                "{:?} must be forwarded so it gets a real answer",
                record_type
            );
        }
    }

    #[test]
    fn bypassed_domains_are_forwarded_for_both_a_and_aaaa() {
        let responder = responder(&["*.local", "captive.apple.com"]);

        for record_type in [RecordType::A, RecordType::AAAA] {
            assert_eq!(
                responder.handle_query(&query_bytes("printer.local.", record_type)),
                DnsDecision::Forward
            );
            assert_eq!(
                responder.handle_query(&query_bytes("captive.apple.com.", record_type)),
                DnsDecision::Forward
            );
        }

        // A domain outside the bypass list is still answered locally.
        assert!(matches!(
            responder.handle_query(&query_bytes("example.com.", RecordType::A)),
            DnsDecision::Answer(_)
        ));
        assert!(
            responder
                .pool()
                .lookup("198.18.0.1".parse().unwrap())
                .is_some()
        );
    }

    #[test]
    fn a_bypassed_domain_never_consumes_a_pool_entry() {
        let responder = responder(&["*.local"]);
        responder.handle_query(&query_bytes("printer.local.", RecordType::A));
        assert_eq!(responder.pool().entry_count(), 0);
    }

    #[test]
    fn garbage_and_truncated_packets_are_forwarded() {
        let responder = responder(&[]);
        for packet in [
            &b""[..],
            &b"\x00"[..],
            &b"not a dns message at all"[..],
            &[0xffu8; 12][..],
        ] {
            assert_eq!(responder.handle_query(packet), DnsDecision::Forward);
        }
    }

    #[test]
    fn responses_and_non_query_opcodes_are_forwarded() {
        let responder = responder(&[]);

        let mut response_message = Message::new(1, MessageType::Response, OpCode::Query);
        response_message.add_query(hickory_resolver::proto::op::Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            responder.handle_query(&response_message.to_vec().unwrap()),
            DnsDecision::Forward
        );

        let mut update = Message::new(2, MessageType::Query, OpCode::Update);
        update.add_query(hickory_resolver::proto::op::Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(
            responder.handle_query(&update.to_vec().unwrap()),
            DnsDecision::Forward
        );
    }

    #[test]
    fn queries_without_exactly_one_question_are_forwarded() {
        let responder = responder(&[]);

        let empty = Message::new(3, MessageType::Query, OpCode::Query);
        assert_eq!(
            responder.handle_query(&empty.to_vec().unwrap()),
            DnsDecision::Forward
        );

        let mut two = Message::new(4, MessageType::Query, OpCode::Query);
        for name in ["a.example.com.", "b.example.com."] {
            two.add_query(hickory_resolver::proto::op::Query::query(
                Name::from_str(name).unwrap(),
                RecordType::A,
            ));
        }
        assert_eq!(
            responder.handle_query(&two.to_vec().unwrap()),
            DnsDecision::Forward
        );
    }

    #[test]
    fn names_are_matched_case_insensitively() {
        let responder = responder(&[]);
        let upper = parse(&responder.handle_query(&query_bytes("EXAMPLE.COM.", RecordType::A)));
        let lower = parse(&responder.handle_query(&query_bytes("example.com.", RecordType::A)));
        assert_eq!(answer_ips(&upper), answer_ips(&lower));
        assert_eq!(responder.pool().entry_count(), 1);
    }
}
