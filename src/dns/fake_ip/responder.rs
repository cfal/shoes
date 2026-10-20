use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, RData, Record, RecordType, rdata};

use super::pool::canonical_hostname;
use super::{FakeIpOptions, FakeIpPool, HttpsRecords, MissingFamily};
pub(super) use crate::dns::message::UDP_PAYLOAD_LIMIT;

pub const SYNTHETIC_TTL: u32 = 60;

#[derive(Debug)]
pub enum DnsDecision {
    Answer(Message),
    Forward,
    Drop,
}

#[derive(Debug)]
pub struct FakeDnsResponder {
    pub(super) pool: Arc<FakeIpPool>,
    options: FakeIpOptions,
}

impl FakeDnsResponder {
    pub fn new(options: FakeIpOptions, pool: Arc<FakeIpPool>) -> io::Result<Self> {
        options.validate()?;
        Ok(Self { pool, options })
    }

    pub fn decide(&self, request: &Message) -> DnsDecision {
        if request.metadata.message_type != MessageType::Query {
            return DnsDecision::Drop;
        }
        if request.metadata.op_code != OpCode::Query {
            return DnsDecision::Answer(response(request, ResponseCode::Refused));
        }
        // Upstream handles may rewrite IDs and wire encoding; signatures cannot survive that.
        if crate::dns::message::is_signed(request) {
            return DnsDecision::Answer(response(request, ResponseCode::Refused));
        }
        if request.queries.len() != 1 {
            return DnsDecision::Answer(response(request, ResponseCode::FormErr));
        }
        if request.version() != 0 {
            return DnsDecision::Answer(response(request, ResponseCode::BADVERS));
        }
        if request
            .queries
            .iter()
            .any(|q| matches!(q.query_type, RecordType::AXFR | RecordType::IXFR))
        {
            return DnsDecision::Answer(response(request, ResponseCode::Refused));
        }
        if !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || request.metadata.truncation
            || request.metadata.response_code != ResponseCode::NoError
        {
            return DnsDecision::Forward;
        }
        let query = &request.queries[0];
        if query.query_class != DNSClass::IN {
            return DnsDecision::Forward;
        }
        let Some(name) = canonical_hostname(&query.name.to_ascii()) else {
            return DnsDecision::Forward;
        };
        if self
            .options
            .bypass_domains
            .iter()
            .any(|mask| crate::client_proxy_selector::matches_domain(mask, &name))
        {
            return DnsDecision::Forward;
        }
        if matches!(query.query_type, RecordType::HTTPS | RecordType::SVCB)
            && self.options.https_records == HttpsRecords::Suppress
        {
            return DnsDecision::Answer(response(request, ResponseCode::NoError));
        }
        let ipv6 = match query.query_type {
            RecordType::A => false,
            RecordType::AAAA => true,
            _ => return DnsDecision::Forward,
        };
        if !self.pool.has_family(ipv6) {
            return match self.options.missing_family {
                MissingFamily::Forward => DnsDecision::Forward,
                MissingFamily::Nodata => {
                    DnsDecision::Answer(response(request, ResponseCode::NoError))
                }
            };
        }
        let address = match self.pool.allocate(&name, ipv6) {
            Ok(address) => address,
            Err(error) => {
                log::warn!("Fake DNS allocation failed: {error}");
                return DnsDecision::Answer(response(request, ResponseCode::ServFail));
            }
        };
        let mut answer = response(request, ResponseCode::NoError);
        let data = match address {
            IpAddr::V4(ip) => RData::A(rdata::A(ip)),
            IpAddr::V6(ip) => RData::AAAA(rdata::AAAA(ip)),
        };
        answer.add_answer(Record::from_rdata(query.name.clone(), SYNTHETIC_TTL, data));
        DnsDecision::Answer(answer)
    }
}

pub(super) fn response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.queries.clone_from(&request.queries);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    if let Some(edns) = &request.edns {
        let mut reply = Edns::new();
        reply
            .set_max_payload(UDP_PAYLOAD_LIMIT)
            .set_dnssec_ok(edns.flags().dnssec_ok);
        response.edns = Some(reply);
    }
    response
}

impl FakeIpOptions {
    pub fn validate(&self) -> io::Result<()> {
        FakeIpPool::validate(self)?;
        for pattern in &self.bypass_domains {
            if canonical_hostname(pattern).is_none() {
                return Err(super::options::invalid(format!(
                    "invalid fake DNS bypass domain: {pattern}"
                )));
            }
        }
        if self
            .state_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(super::options::invalid(
                "fake DNS state_file must not be empty",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::Query;
    use hickory_resolver::proto::rr::Name;

    fn request(name: &str, kind: RecordType) -> Message {
        let mut message = Message::query();
        message.metadata.id = 123;
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        message
    }

    fn responder(options: FakeIpOptions) -> FakeDnsResponder {
        let pool = Arc::new(FakeIpPool::new(&options).unwrap());
        FakeDnsResponder::new(options, pool).unwrap()
    }

    #[test]
    fn request_options_do_not_bypass_synthesis_or_get_echoed() {
        use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
        let responder = responder(FakeIpOptions::default());
        let mut query = request("cookie.example.", RecordType::A);
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0; 8]));
        edns.options_mut()
            .insert(EdnsOption::Unknown(65001, vec![1; 20]));
        query.edns = Some(edns);
        let DnsDecision::Answer(answer) = responder.decide(&query) else {
            panic!()
        };
        assert_eq!(answer.answers.len(), 1);
        assert!(answer.edns.unwrap().options().as_ref().is_empty());
    }

    #[test]
    fn answer_preserves_question_flags_and_identity() {
        let responder = responder(FakeIpOptions::default());
        let mut query = request("MiXeD.Example.", RecordType::A);
        query.edns = Some(Edns::new());
        query.edns.as_mut().unwrap().set_dnssec_ok(true);
        let DnsDecision::Answer(answer) = responder.decide(&query) else {
            panic!()
        };
        let answer = Message::from_vec(&answer.to_vec().unwrap()).unwrap();
        assert_eq!(answer.metadata.id, 123);
        assert_eq!(answer.queries[0].name.to_ascii(), "MiXeD.Example.");
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(answer.metadata.recursion_desired && answer.metadata.checking_disabled);
        assert!(!answer.metadata.authentic_data && !answer.metadata.authoritative);
        assert!(answer.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(answer.answers[0].ttl, SYNTHETIC_TTL);
        let RData::A(ip) = answer.answers[0].data else {
            panic!()
        };
        assert_eq!(
            responder.pool.restore(ip.0.into()).unwrap().as_deref(),
            Some("mixed.example")
        );
    }

    #[test]
    fn forwarding_is_not_empty_success() {
        let responder = responder(FakeIpOptions::default());
        for kind in [
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::MX,
            RecordType::SRV,
            RecordType::PTR,
            RecordType::CNAME,
            RecordType::ANY,
            RecordType::DNSKEY,
        ] {
            assert!(matches!(
                responder.decide(&request("example.test", kind)),
                DnsDecision::Forward
            ));
        }
        for name in ["127.0.0.1.", "bad_name.example"] {
            assert!(matches!(
                responder.decide(&request(name, RecordType::A)),
                DnsDecision::Forward
            ));
        }
        let mut multiple = request("example.test", RecordType::A);
        multiple.add_query(Query::query(
            Name::from_ascii("second.test").unwrap(),
            RecordType::A,
        ));
        let DnsDecision::Answer(answer) = responder.decide(&multiple) else {
            panic!()
        };
        assert_eq!(answer.metadata.response_code, ResponseCode::FormErr);
        multiple.metadata.message_type = MessageType::Response;
        assert!(matches!(responder.decide(&multiple), DnsDecision::Drop));
    }

    #[test]
    fn family_and_https_policies_respect_exclusions() {
        let responder = responder(FakeIpOptions {
            missing_family: MissingFamily::Nodata,
            https_records: HttpsRecords::Suppress,
            bypass_domains: vec!["Corp.Example.".into()],
            ..Default::default()
        });
        for kind in [RecordType::A, RecordType::AAAA, RecordType::HTTPS] {
            assert!(matches!(
                responder.decide(&request("host.corp.example", kind)),
                DnsDecision::Forward
            ));
        }
        for kind in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let DnsDecision::Answer(answer) = responder.decide(&request("example.test", kind))
            else {
                panic!()
            };
            assert!(answer.answers.is_empty());
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        }
        assert!(matches!(
            responder.decide(&request("notcorp.example", RecordType::A)),
            DnsDecision::Answer(_)
        ));
    }

    #[test]
    fn ipv6_question_is_independent_of_transport() {
        let responder = responder(FakeIpOptions {
            ipv6_range: Some("2001:2::/48".into()),
            ..Default::default()
        });
        let DnsDecision::Answer(answer) =
            responder.decide(&request("example.test", RecordType::AAAA))
        else {
            panic!()
        };
        assert!(matches!(answer.answers[0].data, RData::AAAA(_)));
    }

    #[test]
    fn badvers_and_refused_operations() {
        let responder = responder(FakeIpOptions::default());
        let mut query = request("example.test", RecordType::A);
        query.edns = Some(Edns::new());
        query.edns.as_mut().unwrap().set_version(1);
        let DnsDecision::Answer(answer) = responder.decide(&query) else {
            panic!()
        };
        assert_eq!(answer.metadata.response_code, ResponseCode::BADVERS);
        assert_eq!(answer.version(), 0);
        query.metadata.op_code = OpCode::Update;
        let DnsDecision::Answer(answer) = responder.decide(&query) else {
            panic!()
        };
        assert_eq!(answer.metadata.response_code, ResponseCode::Refused);
    }
}
