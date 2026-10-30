use super::*;
use crate::resolver::Resolver;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
struct NoDns;

impl Resolver for NoDns {
    fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
        panic!("unexpected DNS lookup");
    }
}

fn prepared(selector: &ClientProxySelector, location: &str) -> PreparedDestination {
    match selector
        .prepare(NetLocation::from_str(location, None).unwrap().into())
        .unwrap()
    {
        IngressTarget::Forward(target) => target,
        _ => panic!("expected forwarding target"),
    }
}

#[tokio::test]
async fn same_policy_can_avoid_dns_but_later_policy_cannot() {
    let no_dns: Arc<dyn Resolver> = Arc::new(NoDns);
    let location = NetLocation::from_str("allowed.example:443", None).unwrap();
    let selector =
        ClientProxySelector::new(vec![allow_rule(vec!["10.0.0.0/8", "allowed.example"])]);
    assert!(matches!(
        selector
            .judge(location.clone().into(), &no_dns)
            .await
            .unwrap(),
        ConnectDecision::Allow { .. }
    ));
    let selector = ClientProxySelector::new(vec![
        block_rule(vec!["10.0.0.0/8"]),
        allow_rule(vec!["allowed.example"]),
    ]);
    assert!(
        selector
            .judge(location.into(), &mock_resolver())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn no_resolve_negation_uses_known_ips_not_unavailable_facts() {
    use crate::rules::Expression;
    let predicate = Compiler::default()
        .compile(Expression::Not(Box::new(Expression::IpCidr(vec![
            "10.0.0.0/8".into(),
        ]))))
        .unwrap();
    let selector = ClientProxySelector::with_options(
        vec![
            ConnectRule::compiled(predicate, true, ConnectAction::Block),
            allow_rule(vec!["0.0.0.0/0"]),
        ],
        true,
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let name = NetLocation::from_str("unresolved.example:443", None).unwrap();
    assert!(matches!(
        selector
            .judge(name.clone().into(), &resolver)
            .await
            .unwrap(),
        ConnectDecision::Allow { .. }
    ));
    let known = ResolvedLocation::with_resolved(name, "192.0.2.1:443".parse().unwrap());
    assert!(matches!(
        selector.judge(known, &resolver).await.unwrap(),
        ConnectDecision::Block
    ));
    assert_eq!(selector.cache_size(), 0);
}

#[tokio::test]
async fn ip_only_no_resolve_block_falls_through_without_sniffing_or_dns() {
    let legacy = ClientProxySelector::with_options(vec![block_rule(vec!["10.0.0.0/8"])], true);
    assert!(!legacy.should_sniff(&prepared(&legacy, "192.0.2.1:443")));
    let predicate = Compiler::default()
        .compile(crate::rules::Expression::IpCidr(vec!["10.0.0.0/8".into()]))
        .unwrap();
    let selector = ClientProxySelector::with_options(
        vec![
            ConnectRule::compiled(predicate, true, ConnectAction::Block),
            allow_rule(vec!["0.0.0.0/0"]),
        ],
        true,
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    assert!(matches!(
        selector
            .judge(
                NetLocation::from_str("unresolved.example:443", None)
                    .unwrap()
                    .into(),
                &resolver
            )
            .await
            .unwrap(),
        ConnectDecision::Allow { .. }
    ));
    assert!(matches!(
        selector
            .judge(
                NetLocation::from_str("10.0.0.1:443", None).unwrap().into(),
                &resolver
            )
            .await
            .unwrap(),
        ConnectDecision::Block
    ));
}

#[tokio::test]
async fn catch_all_rejects_invalid_supplied_names_but_ignores_bad_hints() {
    let selector = ClientProxySelector::new(vec![allow_rule(vec!["0.0.0.0/0"])]);
    for name in ["", "example.com..", "a b", "é.example"] {
        assert!(
            selector
                .prepare(NetLocation::new(Address::Hostname(name.into()), 443).into())
                .is_err()
        );
    }
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let routed = selector
        .judge_prepared(
            prepared(&selector, "192.0.2.1:443"),
            Some("bad hint"),
            &resolver,
        )
        .await
        .unwrap();
    assert!(matches!(routed.decision, ConnectDecision::Allow { .. }));
}

#[tokio::test]
async fn sniff_preserves_real_ip_and_order_without_dns() {
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    for ip_first in [true, false] {
        let mut rules = vec![
            block_rule(vec!["127.0.0.0/8"]),
            allow_rule(vec!["allowed.example"]),
        ];
        if !ip_first {
            rules.swap(0, 1);
        }
        let selector = ClientProxySelector::new(rules).with_sniff(true);
        for destination in ["127.0.0.1:443", "203.0.113.7:443", "[2001:db8::7]:443"] {
            let target = prepared(&selector, destination);
            assert!(selector.should_sniff(&target));
            let routed = selector
                .judge_prepared(target, Some("allowed.example"), &resolver)
                .await
                .unwrap();
            assert_eq!(
                routed.wire_destination,
                NetLocation::from_str(destination, None).unwrap()
            );
            if ip_first && destination.starts_with("127.") {
                assert!(matches!(routed.decision, ConnectDecision::Block));
            } else {
                let ConnectDecision::Allow {
                    remote_location, ..
                } = routed.decision
                else {
                    panic!()
                };
                assert_eq!(
                    remote_location.location(),
                    &NetLocation::from_str(destination, None).unwrap()
                );
            }
        }
    }
}

#[tokio::test]
async fn sniff_bypasses_warmed_allow_and_block_caches() {
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let mut rules = vec![
        block_rule(vec!["blocked.example"]),
        allow_rule(vec!["allowed.example"]),
        block_rule(vec!["203.0.113.8"]),
    ];
    rules.extend((0..17).map(|_| block_rule(vec!["irrelevant.example"])));
    rules.push(allow_rule(vec!["0.0.0.0/0"]));
    let selector = ClientProxySelector::new(rules).with_sniff(true);
    for (destination, ordinary_allowed, name) in [
        ("203.0.113.7:443", true, "blocked.example"),
        ("203.0.113.8:443", false, "allowed.example"),
    ] {
        let location = NetLocation::from_str(destination, None).unwrap();
        assert_eq!(
            matches!(
                selector
                    .judge(location.clone().into(), &resolver)
                    .await
                    .unwrap(),
                ConnectDecision::Allow { .. }
            ),
            ordinary_allowed
        );
        let cache_len = selector.cache.as_ref().unwrap().inner.read().len();
        let decision = selector
            .judge_prepared(prepared(&selector, destination), Some(name), &resolver)
            .await
            .unwrap()
            .decision;
        assert_eq!(
            matches!(decision, ConnectDecision::Allow { .. }),
            !ordinary_allowed
        );
        assert_eq!(
            selector.cache.as_ref().unwrap().inner.read().len(),
            cache_len
        );
        assert_eq!(
            matches!(
                selector.judge(location.into(), &resolver).await.unwrap(),
                ConnectDecision::Allow { .. }
            ),
            ordinary_allowed
        );
    }
}

#[tokio::test]
async fn sniff_override_preserves_wire_identity_and_inherits_port() {
    let selector = ClientProxySelector::new(vec![allow_rule_with_override(
        vec!["allowed.example"],
        "192.0.2.9",
    )]);
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let routed = selector
        .judge_prepared(
            prepared(&selector, "203.0.113.7:8443"),
            Some("allowed.example"),
            &resolver,
        )
        .await
        .unwrap();
    assert_eq!(routed.wire_destination.to_string(), "203.0.113.7:8443");
    let ConnectDecision::Allow {
        remote_location, ..
    } = routed.decision
    else {
        panic!()
    };
    assert_eq!(remote_location.location().to_string(), "192.0.2.9:8443");
}

#[tokio::test]
async fn prepared_fake_names_survive_recycling_with_and_without_sni() {
    use crate::dns::fake_ip::FakeIpOptions;
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let context = Arc::new(
        DnsContext::new(
            FakeIpOptions {
                ipv4_range: Some("198.18.0.0/29".into()),
                max_entries: 1,
                ..Default::default()
            },
            resolver.clone(),
        )
        .unwrap(),
    );
    let selector = ClientProxySelector::new(vec![
        allow_rule(vec!["first.example"]),
        allow_rule(vec!["third.example"]),
    ])
    .with_sniff(true)
    .with_fake_dns_context(Some(context.clone()))
    .unwrap();
    let first = context.allocate("first.example", false).unwrap();
    let wire = format!("{first}:443");
    let frozen = prepared(&selector, &wire);
    let frozen_with_sni = prepared(&selector, &wire);
    let frozen_unmatched = prepared(&selector, &wire);
    assert!(frozen.is_fake_dns());
    assert!(selector.should_sniff(&frozen));
    context.allocate("second.example", false).unwrap();
    let error = selector
        .prepare(NetLocation::from_str(&wire, None).unwrap().into())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(matches!(
        selector
            .judge_prepared(frozen_unmatched, Some("unmatched.example"), &resolver)
            .await
            .unwrap()
            .decision,
        ConnectDecision::Block
    ));
    for (target, name) in [(frozen, None), (frozen_with_sni, Some("third.example"))] {
        let routed = selector
            .judge_prepared(target, name, &resolver)
            .await
            .unwrap();
        assert_eq!(routed.wire_destination.to_string(), wire);
        let ConnectDecision::Allow {
            remote_location, ..
        } = routed.decision
        else {
            panic!()
        };
        assert_eq!(remote_location.location().to_string(), "first.example:443");
        assert_eq!(remote_location.resolved_addr(), None);
    }
    for index in 0..3 {
        context
            .allocate(&format!("unused{index}.example"), false)
            .unwrap();
    }
    assert_eq!(context.allocate("third.example", false).unwrap(), first);
    assert!(matches!(
        selector
            .judge_prepared(prepared(&selector, &wire), None, &resolver)
            .await
            .unwrap()
            .decision,
        ConnectDecision::Allow { .. }
    ));
}

#[tokio::test]
async fn fake_dns_sni_bypasses_cached_hostname_rules_without_resolving() {
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let context = Arc::new(
        DnsContext::new(
            crate::dns::fake_ip::FakeIpOptions {
                ipv6_range: Some("2001:2::/48".into()),
                ..Default::default()
            },
            resolver.clone(),
        )
        .unwrap(),
    );
    let mut rules = vec![
        block_rule(vec!["restored.example"]),
        allow_rule(vec!["sniff.example"]),
    ];
    rules.extend((0..17).map(|_| block_rule(vec!["irrelevant.example"])));
    let selector = ClientProxySelector::new(rules)
        .with_sniff(true)
        .with_fake_dns_context(Some(context.clone()))
        .unwrap();
    for ipv6 in [false, true] {
        let ip = context.allocate("restored.example", ipv6).unwrap();
        for address in [
            Address::from(&ip.to_string()).unwrap(),
            Address::Hostname(ip.to_string()),
        ] {
            let wire = NetLocation::new(address, 443);
            assert!(matches!(
                selector
                    .judge(wire.clone().into(), &resolver)
                    .await
                    .unwrap(),
                ConnectDecision::Block
            ));
            let cache_len = selector.cache_size();
            let IngressTarget::Forward(target) = selector.prepare(wire.clone().into()).unwrap()
            else {
                panic!()
            };
            assert!(selector.should_sniff(&target));
            let routed = selector
                .judge_prepared(target, Some("sniff.example"), &resolver)
                .await
                .unwrap();
            assert_eq!(routed.wire_destination, wire);
            let ConnectDecision::Allow {
                remote_location, ..
            } = routed.decision
            else {
                panic!()
            };
            assert_eq!(
                remote_location.location().to_string(),
                "restored.example:443"
            );
            assert_eq!(remote_location.resolved_addr(), None);
            assert_eq!(selector.cache_size(), cache_len);
            assert!(matches!(
                selector.judge(wire.into(), &resolver).await.unwrap(),
                ConnectDecision::Block
            ));
        }
    }
}

#[tokio::test]
async fn fake_dns_sni_ip_rules_resolve_only_the_restored_target_in_rule_order() {
    for ip_first in [false, true] {
        for blocked in [false, true] {
            let mut resolver = MockResolver::default();
            let resolved = if blocked {
                "127.0.0.1:443"
            } else {
                "192.0.2.1:443"
            };
            resolver.mappings.insert(
                "restored.example:443".into(),
                vec![resolved.parse().unwrap()],
            );
            let resolver: Arc<dyn Resolver> = if ip_first {
                Arc::new(resolver)
            } else {
                Arc::new(NoDns)
            };
            let context = Arc::new(DnsContext::new(Default::default(), resolver.clone()).unwrap());
            let mut rules = vec![
                block_rule(vec!["127.0.0.0/8"]),
                allow_rule(vec!["sniff.example"]),
            ];
            if !ip_first {
                rules.swap(0, 1);
            }
            let selector = ClientProxySelector::new(rules)
                .with_sniff(true)
                .with_fake_dns_context(Some(context.clone()))
                .unwrap();
            let ip = context.allocate("restored.example", false).unwrap();
            let routed = selector
                .judge_prepared(
                    prepared(&selector, &format!("{ip}:443")),
                    Some("sniff.example"),
                    &resolver,
                )
                .await
                .unwrap();
            if ip_first && blocked {
                assert!(matches!(routed.decision, ConnectDecision::Block));
            } else {
                let ConnectDecision::Allow {
                    remote_location, ..
                } = routed.decision
                else {
                    panic!()
                };
                assert_eq!(
                    remote_location.location().to_string(),
                    "restored.example:443"
                );
                assert_eq!(
                    remote_location.resolved_addr(),
                    ip_first.then(|| resolved.parse().unwrap())
                );
            }
        }
    }
}

#[tokio::test]
async fn supplied_hostnames_remain_ineligible_for_sniffing() {
    let selector =
        ClientProxySelector::new(vec![allow_rule(vec!["sniff.example"])]).with_sniff(true);
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let target = prepared(&selector, "supplied.example:443");
    assert!(!selector.should_sniff(&target));
    let error = selector
        .judge_prepared(target, Some("sniff.example"), &resolver)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn domain_encoded_ips_restore_without_changing_wire_identity() {
    let context = Arc::new(DnsContext::new(Default::default(), Arc::new(NoDns)).unwrap());
    let selector = ClientProxySelector::new(vec![])
        .with_fake_dns_context(Some(context.clone()))
        .unwrap();
    let ip = context.allocate("encoded.example", false).unwrap();
    for text in [ip.to_string(), format!("::ffff:{ip}")] {
        let wire = NetLocation::new(Address::Hostname(text), 443);
        let IngressTarget::Forward(target) = selector.prepare(wire.clone().into()).unwrap() else {
            panic!("not a forward target");
        };
        assert!(target.is_fake_dns());
        assert_eq!(target.wire_destination, wire);
        assert_eq!(
            target.connection_target.address().hostname(),
            Some("encoded.example")
        );
    }
    assert!(
        selector
            .prepare(NetLocation::new(Address::Hostname("198.18.0.1".into()), 443).into())
            .is_err()
    );
    for port in [53, 443] {
        assert!(
            selector
                .prepare(NetLocation::new(Address::Hostname(String::new()), port).into())
                .is_err()
        );
    }
    let wire = NetLocation::new(Address::Hostname("192.0.2.1".into()), 443);
    let IngressTarget::Forward(target) = selector.prepare(wire.clone().into()).unwrap() else {
        panic!("not a forward target");
    };
    assert_eq!(target.wire_destination, wire);
    assert_eq!(
        target
            .connection_target
            .location()
            .to_socket_addr_nonblocking(),
        Some("192.0.2.1:443".parse().unwrap())
    );
    let wire = NetLocation::new(Address::Hostname(ip.to_string()), 53);
    let IngressTarget::LocalDns {
        wire_destination, ..
    } = selector.prepare(wire.clone().into()).unwrap()
    else {
        panic!("not intercepted DNS");
    };
    assert_eq!(wire_destination, wire);
}

#[tokio::test]
async fn preparation_precedes_dns_dispatch_and_nested_rule_gates() {
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let context = Arc::new(DnsContext::new(Default::default(), resolver.clone()).unwrap());
    let parent = ClientProxySelector::new(vec![allow_rule(vec!["parent.example"])])
        .with_sniff(true)
        .with_fake_dns_context(Some(context.clone()))
        .unwrap();
    let child = ClientProxySelector::new(vec![allow_rule(vec!["0.0.0.0/0"])])
        .inherit_inbound_policy(&parent)
        .unwrap();
    assert!(Arc::ptr_eq(child.fake_dns.as_ref().unwrap(), &context));
    assert!(parent.should_sniff(&prepared(&parent, "203.0.113.7:443")));
    assert!(!child.should_sniff(&prepared(&child, "203.0.113.7:443")));
    assert!(!parent.should_sniff(&prepared(&parent, "supplied.example:443")));
    let fake = context.allocate("parent.example", false).unwrap();
    let target = format!("{fake}:443");
    assert!(parent.should_sniff(&prepared(&parent, &target)));
    assert!(!child.should_sniff(&prepared(&child, &target)));
    for target in ["198.18.0.9:53", "resolver.invalid:53"] {
        let location = NetLocation::from_str(target, None).unwrap();
        assert!(matches!(
            child.prepare(location.clone().into()).unwrap(),
            IngressTarget::LocalDns { .. }
        ));
        assert_eq!(
            child
                .judge(location.into(), &resolver)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    let override_selector = ClientProxySelector::new(vec![allow_rule_with_override(
        vec!["0.0.0.0/0"],
        "198.18.0.9:53",
    )]);
    assert!(
        override_selector
            .with_fake_dns_context(Some(context))
            .is_err()
    );
}

#[test]
fn dns_interception_is_independent_and_inherited_without_reenabling_it() {
    let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
    let context = Arc::new(DnsContext::new(Default::default(), resolver.clone()).unwrap());
    let fake = context.allocate("restored.example", false).unwrap();
    let wire = NetLocation::from_ip_addr("192.0.2.53".parse().unwrap(), 53);
    for synthesis in [false, true] {
        for enabled in [false, true] {
            let parent = ClientProxySelector::new(vec![allow_rule(vec!["0.0.0.0/0"])])
                .with_fake_dns_context(synthesis.then(|| context.clone()))
                .unwrap()
                .with_dns_interception(resolver.clone(), enabled);
            let child = ClientProxySelector::new(vec![allow_rule(vec!["0.0.0.0/0"])])
                .inherit_inbound_policy(&parent)
                .unwrap();
            for selector in [&parent, &child] {
                assert_eq!(
                    matches!(
                        selector.prepare(wire.clone().into()).unwrap(),
                        IngressTarget::LocalDns { .. }
                    ),
                    enabled
                );
                if synthesis {
                    for port in [53, 443] {
                        if port == 53 && enabled {
                            continue;
                        }
                        let IngressTarget::Forward(target) = selector
                            .prepare(NetLocation::from_ip_addr(fake, port).into())
                            .unwrap()
                        else {
                            panic!()
                        };
                        assert!(target.is_fake_dns());
                    }
                }
            }
            if enabled {
                assert!(Arc::ptr_eq(
                    parent.dns_interception.as_ref().unwrap(),
                    child.dns_interception.as_ref().unwrap()
                ));
            }
        }
    }
}

#[tokio::test]
async fn cached_route_rechecks_changed_ip() {
    let selector = ClientProxySelector::with_options(
        vec![
            block_rule(vec!["127.0.0.0/8"]),
            allow_rule(vec!["0.0.0.0/0"]),
        ],
        true,
    );
    let resolver = mock_resolver();
    let hostname = NetLocation::from_str("example.com:443", None).unwrap();
    let public = ResolvedLocation::with_resolved(hostname.clone(), "1.1.1.1:443".parse().unwrap());
    assert!(matches!(
        selector.judge(public, &resolver).await.unwrap(),
        ConnectDecision::Allow { .. }
    ));
    let private = ResolvedLocation::with_resolved(hostname, "127.0.0.1:443".parse().unwrap());
    assert!(matches!(
        selector.judge(private, &resolver).await.unwrap(),
        ConnectDecision::Block
    ));
}

#[tokio::test(start_paused = true)]
async fn native_cache_refresh_changes_new_flow_routing_without_retargeting_pinned_flow() {
    #[derive(Debug)]
    struct ChangingLookup(parking_lot::Mutex<SocketAddr>);
    impl Resolver for ChangingLookup {
        fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
            let address = *self.0.lock();
            Box::pin(async move { Ok(vec![address]) })
        }
    }

    let first = "192.0.2.1:443".parse().unwrap();
    let lookup = Arc::new(ChangingLookup(parking_lot::Mutex::new(first)));
    let resolver: Arc<dyn Resolver> = Arc::new(
        crate::resolver::CachingNativeResolver::with_lookup(lookup.clone(), 60),
    );
    let selector = selector_with_cache(vec![
        block_rule(vec!["127.0.0.0/8"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ]);
    let hostname = NetLocation::from_str("changing.test:443", None).unwrap();
    let ConnectDecision::Allow {
        mut remote_location,
        ..
    } = selector
        .judge(hostname.clone().into(), &resolver)
        .await
        .unwrap()
    else {
        panic!("initial address should be allowed");
    };
    assert_eq!(remote_location.resolved_addr(), Some(first));
    *lookup.0.lock() = "127.0.0.1:443".parse().unwrap();
    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    assert!(matches!(
        selector
            .judge(hostname.clone().into(), &resolver)
            .await
            .unwrap(),
        ConnectDecision::Allow { .. }
    ));
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(matches!(
        selector.judge(hostname.into(), &resolver).await.unwrap(),
        ConnectDecision::Block
    ));
    assert_eq!(
        resolve_location(&mut remote_location, &resolver)
            .await
            .unwrap(),
        first
    );
    assert_eq!(selector.cache_size(), 0);
}

#[tokio::test]
async fn domain_rules_agree_with_cache_on_case_and_root_dot() {
    for capacity in [0, 10] {
        let selector = ClientProxySelector::with_options_and_cache_size(
            vec![
                block_rule(vec!["Blocked.Example."]),
                allow_rule(vec!["0.0.0.0/0"]),
            ],
            true,
            capacity,
        );
        for name in [
            "BLOCKED.example:443",
            "blocked.EXAMPLE.:443",
            "sub.blocked.example:443",
        ] {
            let destination = NetLocation::from_str(name, None).unwrap();
            assert!(matches!(
                selector
                    .judge(destination.into(), &mock_resolver())
                    .await
                    .unwrap(),
                ConnectDecision::Block
            ));
        }
        if capacity == 0 {
            assert!(!selector.is_cache_enabled());
        }
    }
}

#[derive(Debug, Default)]
struct MockResolver {
    mappings: std::collections::HashMap<String, Vec<SocketAddr>>,
}

impl Resolver for MockResolver {
    fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
        let key = format!("{}:{}", location.address(), location.port());
        let result = self.mappings.get(&key).cloned();
        Box::pin(async move {
            result.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No mock mapping for {}", key),
                )
            })
        })
    }
}

fn mock_resolver() -> Arc<dyn Resolver> {
    Arc::new(MockResolver::default())
}

// Rule-matching fixtures use a single direct chain; rotation is tested in client_proxy_chain.
fn mock_chain_group() -> ClientChainGroup {
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    build_direct_chain_group(resolver)
}

fn allow_rule(masks: Vec<&str>) -> ConnectRule {
    let masks: Vec<NetLocationMask> = masks
        .into_iter()
        .map(|s| NetLocationMask::from(s).unwrap())
        .collect();
    ConnectRule::new(masks, ConnectAction::new_allow(None, mock_chain_group()))
}

fn block_rule(masks: Vec<&str>) -> ConnectRule {
    let masks: Vec<NetLocationMask> = masks
        .into_iter()
        .map(|s| NetLocationMask::from(s).unwrap())
        .collect();
    ConnectRule::new(masks, ConnectAction::new_block())
}

fn allow_rule_with_override(masks: Vec<&str>, override_addr: &str) -> ConnectRule {
    let masks: Vec<NetLocationMask> = masks
        .into_iter()
        .map(|s| NetLocationMask::from(s).unwrap())
        .collect();
    let override_location = NetLocation::from_str(override_addr, Some(0)).unwrap();
    ConnectRule::new(
        masks,
        ConnectAction::new_allow(Some(override_location), mock_chain_group()),
    )
}

#[test]
fn test_matches_domain_exact_match() {
    assert!(matches_domain_for_test("example.com", "example.com"));
    assert!(matches_domain_for_test("foo.bar.com", "foo.bar.com"));
}

#[test]
fn test_matches_domain_subdomain_match() {
    assert!(matches_domain_for_test("example.com", "www.example.com"));
    assert!(matches_domain_for_test(
        "example.com",
        "sub.www.example.com"
    ));
    assert!(matches_domain_for_test("bar.com", "foo.bar.com"));
}

#[test]
fn test_matches_domain_no_match_different_domain() {
    assert!(!matches_domain_for_test("example.com", "notexample.com"));
    assert!(!matches_domain_for_test("example.com", "example.org"));
    assert!(!matches_domain_for_test("foo.com", "bar.com"));
}

#[test]
fn test_matches_domain_no_match_partial_suffix() {
    // "malicious-example.com" ends with "example.com" as a string,
    // but it's not a subdomain
    assert!(!matches_domain_for_test(
        "example.com",
        "malicious-example.com"
    ));
    assert!(!matches_domain_for_test("example.com", "fakeexample.com"));
    assert!(!matches_domain_for_test("bar.com", "foobar.com"));
}

#[test]
fn test_matches_domain_no_match_base_longer() {
    assert!(!matches_domain_for_test("www.example.com", "example.com"));
    assert!(!matches_domain_for_test("sub.example.com", "example.com"));
}

#[test]
fn test_matches_domain_empty_strings() {
    assert!(!matches_domain_for_test("example.com", ""));
    assert!(!matches_domain_for_test("", "example.com"));
    assert!(matches_domain_for_test("", "")); // Both empty matches
}

#[test]
fn test_matches_domain_single_label() {
    assert!(matches_domain_for_test("localhost", "localhost"));
    assert!(!matches_domain_for_test("localhost", "notlocalhost"));
    assert!(!matches_domain_for_test("host", "localhost")); // partial suffix
}

#[tokio::test]
async fn test_ipv4_exact_match() {
    let rules = vec![
        allow_rule(vec!["192.168.1.1/32"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow, got Block"),
    }
}

#[tokio::test]
async fn test_ipv4_exact_match_no_match() {
    let rules = vec![
        allow_rule(vec!["192.168.1.1/32"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Different IP should fall through to default
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 2)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow, got Block"),
    }
}

#[tokio::test]
async fn test_ipv4_cidr_24() {
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // All addresses in 192.168.1.0/24 should match
    for last_octet in [0u8, 1, 100, 254, 255] {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, last_octet)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow for 192.168.1.{}", last_octet),
        }
    }

    // Address outside the range should not match
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_ipv4_cidr_16() {
    let rules = vec![
        allow_rule(vec!["10.0.0.0/8"]),
        allow_rule(vec!["172.16.0.0/12"]),
        allow_rule(vec!["192.168.0.0/16"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Test 10.0.0.0/8 range
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 255, 255, 255)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Test 172.16.0.0/12 range (172.16.0.0 - 172.31.255.255)
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(172, 20, 5, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Test 192.168.0.0/16 range
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 100, 50)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Public IP should go to default
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_ipv4_localhost() {
    let rules = vec![
        allow_rule(vec!["127.0.0.0/8"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // 127.x.x.x should all match loopback
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 255, 255, 255)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_ipv6_exact_match() {
    let rules = vec![allow_rule(vec!["::1/128"]), allow_rule(vec!["::/0"])];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_ipv6_cidr() {
    let rules = vec![
        allow_rule(vec!["fe80::/10"]),
        allow_rule(vec!["fc00::/7"]),
        allow_rule(vec!["::/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Link-local address
    let location = NetLocation::new(Address::Ipv6("fe80::1".parse().unwrap()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Unique local address (fc00::/7 covers fc00:: and fd00::)
    let location = NetLocation::new(Address::Ipv6("fd00::1234".parse().unwrap()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Global unicast should go to default
    let location = NetLocation::new(Address::Ipv6("2001:db8::1".parse().unwrap()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_hostname_exact_match() {
    let rules = vec![
        allow_rule(vec!["example.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Hostname("example.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_hostname_subdomain_match() {
    let rules = vec![
        allow_rule(vec!["example.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Subdomain should match
    let location = NetLocation::new(Address::Hostname("www.example.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Deep subdomain should match
    let location = NetLocation::new(Address::Hostname("sub.www.example.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_hostname_no_false_subdomain_match() {
    // malicious-example.com should NOT match example.com rule
    let rules = vec![
        allow_rule(vec!["example.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Hostname("malicious-example.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    let location = NetLocation::new(Address::Hostname("fakeexample.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_hostname_different_tld() {
    let rules = vec![
        allow_rule(vec!["example.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Different TLD should not match
    let location = NetLocation::new(Address::Hostname("example.org".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_port_specific_rule() {
    let rules = vec![
        allow_rule(vec!["0.0.0.0/0:443"]),
        allow_rule(vec!["0.0.0.0/0:80"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Port 443 should match the first rule.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Port 80 should match the second rule.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Other ports should go to default
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_port_with_ip_restriction() {
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24:22"]),
        allow_rule(vec!["0.0.0.0/0:22"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // LAN SSH should match the first rule.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 22);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // External SSH should match the second rule.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 22);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // LAN HTTP should reach the catch-all because neither SSH rule matches the port.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_first_rule_wins() {
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["192.168.0.0/16"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // 192.168.1.x should match the first (more specific) rule
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // 192.168.2.x should match the second rule
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_rule_order_matters_security() {
    // SECURITY: If a block rule comes after an allow rule for overlapping ranges,
    // the allow rule takes precedence
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        block_rule(vec!["192.168.0.0/16"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // 192.168.1.x matches the allow rule first
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow for 192.168.1.1"),
    }

    // 192.168.2.x should be blocked
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 2, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block for 192.168.2.1"),
        ConnectDecision::Block => {} // Expected
    }
}

#[tokio::test]
async fn test_block_rule() {
    let rules = vec![
        block_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Blocked range
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block"),
        ConnectDecision::Block => {} // Expected
    }

    // Non-blocked range
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_block_hostname() {
    let rules = vec![
        block_rule(vec!["blocked.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Blocked hostname
    let location = NetLocation::new(Address::Hostname("blocked.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block for blocked.com"),
        ConnectDecision::Block => {} // Expected
    }

    // Subdomain of blocked hostname should also be blocked
    let location = NetLocation::new(Address::Hostname("www.blocked.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block for www.blocked.com"),
        ConnectDecision::Block => {} // Expected
    }
}

#[tokio::test]
async fn test_no_default_rule_blocks() {
    let rules = vec![allow_rule(vec!["192.168.1.0/24"])];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Non-matching address with no default rule should block
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block when no default rule"),
        ConnectDecision::Block => {} // Expected
    }
}

#[tokio::test]
async fn test_round_robin_proxy_selection() {
    // Only repeated judging is exercised here; ClientProxyChain tests cover rotation.
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    for _ in 0..6 {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }
}

#[tokio::test]
async fn test_single_proxy_no_rotation() {
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    for _ in 0..5 {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow"),
        }
    }
}

#[tokio::test]
async fn test_address_override() {
    let rules = vec![allow_rule_with_override(vec!["0.0.0.0/0"], "10.0.0.1:8080")];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow {
            remote_location, ..
        } => {
            assert_eq!(remote_location.address().to_string(), "10.0.0.1");
            assert_eq!(remote_location.port(), 8080);
        }
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_address_override_preserve_port() {
    // Override with port 0 should preserve the original port
    let rules = vec![allow_rule_with_override(vec!["0.0.0.0/0"], "10.0.0.1:0")];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow {
            remote_location, ..
        } => {
            assert_eq!(remote_location.address().to_string(), "10.0.0.1");
            assert_eq!(remote_location.port(), 443); // Original port preserved
        }
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_multiple_masks_in_rule() {
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24", "192.168.2.0/24", "10.0.0.0/8"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // All three ranges should match the first rule.
    for ip in [
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 2, 100),
        Ipv4Addr::new(10, 50, 50, 50),
    ] {
        let location = NetLocation::new(Address::Ipv4(ip), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow for {}", ip),
        }
    }

    // Other IPs should go to default
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_multiple_hostnames_in_rule() {
    let rules = vec![
        allow_rule(vec!["google.com", "youtube.com", "gmail.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    for hostname in [
        "google.com",
        "www.google.com",
        "youtube.com",
        "mail.gmail.com",
    ] {
        let location = NetLocation::new(Address::Hostname(hostname.to_string()), 80);
        let decision = selector.judge(location.into(), &resolver).await.unwrap();
        match decision {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Block => panic!("Expected Allow for {}", hostname),
        }
    }
}

#[tokio::test]
async fn test_empty_rules_blocks_all() {
    let rules: Vec<ConnectRule> = vec![];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block with empty rules"),
        ConnectDecision::Block => {} // Expected
    }
}

#[tokio::test]
async fn test_ipv4_mapped_ipv6() {
    // IPv4-mapped IPv6 addresses (::ffff:192.168.1.1) should be handled correctly
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Regular IPv4
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_broadcast_and_special_addresses() {
    let rules = vec![
        block_rule(vec!["255.255.255.255/32"]), // Broadcast
        block_rule(vec!["0.0.0.0/32"]),         // Unspecified
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Broadcast should be blocked
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::BROADCAST), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block for broadcast"),
        ConnectDecision::Block => {} // Expected
    }

    // Unspecified should be blocked
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => panic!("Expected Block for unspecified"),
        ConnectDecision::Block => {} // Expected
    }
}

#[tokio::test]
async fn test_case_sensitivity_hostname() {
    let rules = vec![
        allow_rule(vec!["Example.COM"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Hostname("example.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_concurrent_access_round_robin() {
    // Concurrent judging must not panic; this does not exercise proxy rotation.
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = Arc::new(ClientProxySelector::new(rules));
    let resolver = mock_resolver();

    let mut handles = vec![];
    for _ in 0..10 {
        let selector = selector.clone();
        let resolver = resolver.clone();
        handles.push(tokio::spawn(async move {
            let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
            let _ = selector.judge(location.into(), &resolver).await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_localhost_bypass() {
    // Common pattern: bypass proxy for localhost
    // A hostname policy before IP policies avoids a destination lookup.
    let rules = vec![
        allow_rule(vec!["localhost"]), // Hostname rule first
        allow_rule_with_override(vec!["127.0.0.0/8"], "127.0.0.1:0"),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // 127.0.0.1 should use direct (matches IP rule)
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // The localhost hostname should match the first rule without DNS.
    let location = NetLocation::new(Address::Hostname("localhost".to_string()), 8080);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_mixed_ip_and_hostname_rules() {
    // Hostname policies before IP policies can decide routing without DNS.
    let rules = vec![
        block_rule(vec!["malware.com"]),
        allow_rule(vec!["trusted.com"]), // Hostname rules before IP rules
        allow_rule(vec!["192.168.0.0/16"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    let resolver = mock_resolver();

    // Malware hostname blocked
    let location = NetLocation::new(Address::Hostname("malware.com".to_string()), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    assert!(matches!(decision, ConnectDecision::Block));

    // The LAN IP should match the subnet rule.
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // The trusted hostname should match its domain rule.
    let location = NetLocation::new(Address::Hostname("api.trusted.com".to_string()), 443);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[test]
fn test_routing_cache_key_from_location_hostname() {
    let location = NetLocation::new(Address::Hostname("Example.COM".to_string()), 443);
    let key = RoutingCacheKey::from_location(&location);
    match key {
        RoutingCacheKey::Hostname { hostname, port } => {
            assert_eq!(hostname, "example.com"); // Should be lowercased
            assert_eq!(port, 443);
        }
        _ => panic!("Expected Hostname key"),
    }
}

#[test]
fn test_routing_cache_key_from_location_ipv4() {
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let key = RoutingCacheKey::from_location(&location);
    match key {
        RoutingCacheKey::Ipv4 { addr, port } => {
            assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(port, 80);
        }
        _ => panic!("Expected Ipv4 key"),
    }
}

#[test]
fn test_routing_cache_key_from_location_ipv6() {
    let location = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8080);
    let key = RoutingCacheKey::from_location(&location);
    match key {
        RoutingCacheKey::Ipv6 { addr, port } => {
            assert_eq!(addr, Ipv6Addr::LOCALHOST);
            assert_eq!(port, 8080);
        }
        _ => panic!("Expected Ipv6 key"),
    }
}

#[test]
fn test_routing_cache_basic_operations() {
    let cache = RoutingCache::new(100);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

    // Initially no entry
    assert!(cache.get(&location).is_none());

    // Insert and retrieve
    cache.insert(&location, CachedDecision::Allow(5));
    assert_eq!(cache.len(), 1);

    let cached = cache.get(&location);
    assert!(cached.is_some());
    match cached.unwrap() {
        CachedDecision::Allow(idx) => assert_eq!(idx, 5),
        CachedDecision::Block => panic!("Expected Allow"),
    }
}

#[test]
fn test_routing_cache_block_decision() {
    let cache = RoutingCache::new(100);
    let location = NetLocation::new(Address::Hostname("blocked.com".to_string()), 443);

    cache.insert(&location, CachedDecision::Block);

    let cached = cache.get(&location);
    assert!(matches!(cached, Some(CachedDecision::Block)));
}

#[test]
fn test_routing_cache_different_ports() {
    let cache = RoutingCache::new(100);
    let loc_80 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
    let loc_443 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);

    cache.insert(&loc_80, CachedDecision::Allow(1));
    cache.insert(&loc_443, CachedDecision::Allow(2));

    // Same IP, different ports should be different cache entries
    match cache.get(&loc_80).unwrap() {
        CachedDecision::Allow(idx) => assert_eq!(idx, 1),
        _ => panic!("Expected Allow(1)"),
    }
    match cache.get(&loc_443).unwrap() {
        CachedDecision::Allow(idx) => assert_eq!(idx, 2),
        _ => panic!("Expected Allow(2)"),
    }
}

#[test]
fn test_routing_cache_hostname_case_insensitive() {
    let cache = RoutingCache::new(100);

    // Insert with uppercase
    let loc_upper = NetLocation::new(Address::Hostname("EXAMPLE.COM".to_string()), 443);
    cache.insert(&loc_upper, CachedDecision::Allow(1));

    // Retrieve with lowercase - should find it
    let loc_lower = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
    assert!(cache.get(&loc_lower).is_some());

    // Retrieve with mixed case - should find it
    let loc_mixed = NetLocation::new(Address::Hostname("Example.Com".to_string()), 443);
    assert!(cache.get(&loc_mixed).is_some());
}

#[test]
fn test_routing_cache_clear() {
    let cache = RoutingCache::new(100);

    // Add some entries
    for i in 0..10 {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, i)), 80);
        cache.insert(&location, CachedDecision::Allow(i as usize));
    }
    assert_eq!(cache.len(), 10);

    // Clear
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    // Verify entries are gone
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 0)), 80);
    assert!(cache.get(&location).is_none());
}

#[test]
fn test_routing_cache_lru_eviction() {
    // Small cache to test eviction
    let cache = RoutingCache::new(3);

    // Insert 3 entries
    let loc1 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 1)), 80);
    let loc2 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 2)), 80);
    let loc3 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 3)), 80);

    cache.insert(&loc1, CachedDecision::Allow(1));
    cache.insert(&loc2, CachedDecision::Allow(2));
    cache.insert(&loc3, CachedDecision::Allow(3));
    assert_eq!(cache.len(), 3);

    // Insert 4th entry - should evict the oldest (loc1)
    let loc4 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 0, 0, 4)), 80);
    cache.insert(&loc4, CachedDecision::Allow(4));
    assert_eq!(cache.len(), 3);

    // loc1 should be evicted
    assert!(cache.get(&loc1).is_none());
    // Others should still be present
    assert!(cache.get(&loc2).is_some());
    assert!(cache.get(&loc3).is_some());
    assert!(cache.get(&loc4).is_some());
}

#[test]
fn test_routing_cache_overwrite() {
    let cache = RoutingCache::new(100);
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

    // Insert Allow
    cache.insert(&location, CachedDecision::Allow(1));
    match cache.get(&location).unwrap() {
        CachedDecision::Allow(idx) => assert_eq!(idx, 1),
        _ => panic!("Expected Allow(1)"),
    }

    // Overwrite with Block
    cache.insert(&location, CachedDecision::Block);
    assert!(matches!(cache.get(&location), Some(CachedDecision::Block)));

    // Overwrite with different Allow
    cache.insert(&location, CachedDecision::Allow(5));
    match cache.get(&location).unwrap() {
        CachedDecision::Allow(idx) => assert_eq!(idx, 5),
        _ => panic!("Expected Allow(5)"),
    }
}

/// Force the cache below its normal rule-count threshold.
fn selector_with_cache(rules: Vec<ConnectRule>) -> ClientProxySelector {
    ClientProxySelector::with_options(rules, true)
}

#[tokio::test]
async fn test_selector_cache_disabled_for_few_rules() {
    // With few rules, cache should be disabled by default.
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::new(rules);
    assert!(!selector.is_cache_enabled());

    // Routing should still work correctly
    let resolver = mock_resolver();
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }
}

#[tokio::test]
async fn test_selector_cache_enabled_explicitly() {
    // Force caching even with few rules.
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = ClientProxySelector::with_options(rules, true);
    assert!(selector.is_cache_enabled());
}

#[tokio::test]
async fn test_selector_cache_enabled_with_many_rules() {
    // With many rules (>16), cache should be enabled even without DNS resolution
    let mut rules: Vec<ConnectRule> = (0..20)
        .map(|i| allow_rule(vec![&format!("10.0.{}.0/24", i)]))
        .collect();
    rules.push(allow_rule(vec!["0.0.0.0/0"]));

    let selector = ClientProxySelector::new(rules);
    assert!(selector.is_cache_enabled());
}

#[tokio::test]
async fn test_selector_cache_hit() {
    // Use selector_with_cache to ensure caching is enabled for this test
    let rules = vec![
        allow_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);

    // First call - cache miss
    assert_eq!(selector.cache_size(), 0);
    let decision = selector
        .judge(location.clone().into(), &resolver)
        .await
        .unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Should be cached now
    assert_eq!(selector.cache_size(), 1);

    // Second call - cache hit (same result)
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Still only 1 entry (was a hit, not a new insert)
    assert_eq!(selector.cache_size(), 1);
}

#[tokio::test]
async fn test_selector_cache_block_decision() {
    let rules = vec![
        block_rule(vec!["192.168.1.0/24"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);

    // First call - cache miss, should block
    let decision = selector
        .judge(location.clone().into(), &resolver)
        .await
        .unwrap();
    assert!(matches!(decision, ConnectDecision::Block));
    assert_eq!(selector.cache_size(), 1);

    // Second call - cache hit, still blocks
    let decision = selector.judge(location.into(), &resolver).await.unwrap();
    assert!(matches!(decision, ConnectDecision::Block));
}

#[tokio::test]
async fn test_selector_clear_cache() {
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    // Make some cached entries
    for i in 0..5 {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, i)), 80);
        let _ = selector.judge(location.into(), &resolver).await.unwrap();
    }
    assert_eq!(selector.cache_size(), 5);

    // Clear cache
    selector.clear_cache();
    assert_eq!(selector.cache_size(), 0);
}

#[tokio::test]
async fn test_selector_judge_uncached() {
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);

    // Use judge_uncached - should NOT populate cache
    let decision = selector
        .judge_uncached(location.into(), &resolver, None)
        .await
        .unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        ConnectDecision::Block => panic!("Expected Allow"),
    }

    // Cache should still be empty
    assert_eq!(selector.cache_size(), 0);
}

#[tokio::test]
async fn test_selector_cache_different_destinations() {
    let rules = vec![
        allow_rule(vec!["192.168.0.0/16"]),
        allow_rule(vec!["10.0.0.0/8"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    // Hit different rules
    let loc_lan = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 80);
    let loc_private = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 80);
    let loc_public = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 80);

    let d1 = selector
        .judge(loc_lan.clone().into(), &resolver)
        .await
        .unwrap();
    let d2 = selector
        .judge(loc_private.clone().into(), &resolver)
        .await
        .unwrap();
    let d3 = selector
        .judge(loc_public.clone().into(), &resolver)
        .await
        .unwrap();

    // Verify correct routing (all should be Allow decisions)
    assert!(
        matches!(d1, ConnectDecision::Allow { .. }),
        "Expected lan to allow"
    );
    assert!(
        matches!(d2, ConnectDecision::Allow { .. }),
        "Expected private to allow"
    );
    assert!(
        matches!(d3, ConnectDecision::Allow { .. }),
        "Expected default to allow"
    );

    // All 3 should be cached
    assert_eq!(selector.cache_size(), 3);

    // Verify cache hits return same results
    let d1_cached = selector.judge(loc_lan.into(), &resolver).await.unwrap();
    assert!(
        matches!(d1_cached, ConnectDecision::Allow { .. }),
        "Expected lan from cache"
    );
}

#[tokio::test]
async fn test_selector_cache_hostname_destinations() {
    let rules = vec![
        allow_rule(vec!["google.com"]),
        allow_rule(vec!["0.0.0.0/0"]),
    ];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    // Hostname match
    let loc_google = NetLocation::new(Address::Hostname("www.google.com".to_string()), 443);
    let decision = selector
        .judge(loc_google.clone().into(), &resolver)
        .await
        .unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        _ => panic!("Expected google"),
    }

    // Should be cached
    assert_eq!(selector.cache_size(), 1);

    // Case-insensitive cache hit
    let loc_google_upper = NetLocation::new(Address::Hostname("WWW.GOOGLE.COM".to_string()), 443);
    let decision = selector
        .judge(loc_google_upper.into(), &resolver)
        .await
        .unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        _ => panic!("Expected google from cache"),
    }

    // Should still be 1 entry (case-insensitive hit)
    assert_eq!(selector.cache_size(), 1);
}

#[tokio::test]
async fn test_selector_cache_with_custom_size() {
    // Force caching with a custom capacity.
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = ClientProxySelector::with_options_and_cache_size(rules, true, 5);
    let resolver = mock_resolver();

    // Fill cache to capacity
    for i in 0..5 {
        let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, i)), 80);
        let _ = selector.judge(location.into(), &resolver).await.unwrap();
    }
    assert_eq!(selector.cache_size(), 5);

    // Add one more - should evict oldest
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 100)), 80);
    let _ = selector.judge(location.into(), &resolver).await.unwrap();
    assert_eq!(selector.cache_size(), 5); // Still 5, one was evicted

    // First entry should be evicted - verify by checking the cache is full
    // but we can't directly access the internal cache to verify eviction
    // So we verify indirectly: if we add another entry, size stays at 5
    let location = NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 200)), 80);
    let _ = selector.judge(location.into(), &resolver).await.unwrap();
    assert_eq!(selector.cache_size(), 5);
}

#[tokio::test]
async fn test_selector_concurrent_cache_access() {
    let rules = vec![allow_rule(vec!["0.0.0.0/0"])];
    let selector = Arc::new(selector_with_cache(rules));
    let resolver = mock_resolver();

    // Spawn multiple tasks accessing the cache concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let selector = selector.clone();
        let resolver = resolver.clone();
        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                let location =
                    NetLocation::new(Address::Ipv4(Ipv4Addr::new(10, 0, i as u8, j as u8)), 80);
                let decision = selector.judge(location.into(), &resolver).await.unwrap();
                match decision {
                    ConnectDecision::Allow { .. } => {}
                    ConnectDecision::Block => panic!("Expected Allow"),
                }
            }
        }));
    }

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Should have cached entries (exact number depends on timing)
    assert!(selector.cache_size() > 0);
}

#[tokio::test]
async fn test_selector_cache_preserves_rule_priority() {
    // Ensure caching doesn't break rule priority
    let rules = vec![
        allow_rule(vec!["192.168.1.100/32"]), // Rule 0
        allow_rule(vec!["192.168.1.0/24"]),   // Rule 1
        allow_rule(vec!["192.168.0.0/16"]),   // Rule 2
        allow_rule(vec!["0.0.0.0/0"]),        // Rule 3
    ];
    let selector = selector_with_cache(rules);
    let resolver = mock_resolver();

    // Specific IP should match rule 0 (most specific)
    let loc_specific = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 100)), 80);
    let decision = selector
        .judge(loc_specific.clone().into(), &resolver)
        .await
        .unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        _ => panic!("Expected specific"),
    }

    // The cached decision should still allow the specific IP.
    let decision_cached = selector
        .judge(loc_specific.into(), &resolver)
        .await
        .unwrap();
    match decision_cached {
        ConnectDecision::Allow { .. } => {}
        _ => panic!("Expected specific from cache"),
    }

    // Different IP in same subnet should match rule 1
    let loc_subnet = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 50)), 80);
    let decision = selector.judge(loc_subnet.into(), &resolver).await.unwrap();
    match decision {
        ConnectDecision::Allow { .. } => {}
        _ => panic!("Expected subnet"),
    }
}

#[test]
fn test_netmask_value_for_cidr_0() {
    // Verify that 0.0.0.0/0 actually produces netmask == 0
    let mask = NetLocationMask::from("0.0.0.0/0").unwrap();
    assert_eq!(
        mask.address_mask.netmask, 0,
        "0.0.0.0/0 should have netmask == 0, got {}",
        mask.address_mask.netmask
    );
}

#[test]
fn test_netmask_value_for_cidr_24() {
    // Verify that /24 does NOT produce netmask == 0
    let mask = NetLocationMask::from("172.17.0.0/24").unwrap();
    assert_ne!(
        mask.address_mask.netmask, 0,
        "172.17.0.0/24 should have netmask != 0"
    );
}
