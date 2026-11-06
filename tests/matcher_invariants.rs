use shoes::rules::{Compiler, Expression, Outcome};

#[test]
fn traffic_sets_and_composites_match_membership_with_and_without_traffic() {
    use shoes::rules::{Network, Protocol, Traffic};
    for networks in [
        vec![],
        vec![Network::Tcp],
        vec![Network::Udp],
        vec![Network::Tcp, Network::Udp, Network::Tcp],
    ] {
        for protocols in [
            vec![],
            vec![Protocol::Stun],
            vec![Protocol::Dtls],
            vec![Protocol::Stun, Protocol::Dtls, Protocol::Stun],
        ] {
            let network = Expression::Network(networks.clone());
            let protocol = Expression::Protocol(protocols.clone());
            for (expression, union, inverted) in [
                (
                    Expression::All(vec![network.clone(), protocol.clone()]),
                    false,
                    false,
                ),
                (
                    Expression::Any(vec![network.clone(), protocol.clone()]),
                    true,
                    false,
                ),
                (
                    Expression::Not(Box::new(Expression::Any(vec![network, protocol]))),
                    true,
                    true,
                ),
            ] {
                let mut compiler = Compiler::default();
                let group = compiler.compile(expression).unwrap();
                compiler.groups.insert("traffic".into(), group);
                let predicate = compiler
                    .compile(Expression::RuleSourceGroup("traffic".into()))
                    .unwrap();
                if !networks.is_empty() && !protocols.is_empty() {
                    assert!(predicate.dependencies.network);
                    assert!(predicate.dependencies.protocol);
                }
                for traffic in [
                    None,
                    Some(Traffic::TCP),
                    Some(Traffic::UDP),
                    Some(Traffic {
                        network: Network::Udp,
                        protocol: Some(Protocol::Stun),
                    }),
                    Some(Traffic {
                        network: Network::Udp,
                        protocol: Some(Protocol::Dtls),
                    }),
                ] {
                    let network_matches = traffic.is_some_and(|t| networks.contains(&t.network));
                    let protocol_matches = traffic
                        .and_then(|t| t.protocol)
                        .is_some_and(|p| protocols.contains(&p));
                    let matches = if union {
                        network_matches || protocol_matches
                    } else {
                        network_matches && protocol_matches
                    };
                    let expected = if matches != inverted {
                        Outcome::Match
                    } else {
                        Outcome::Miss
                    };
                    assert_eq!(
                        predicate.evaluate_with_traffic(None, None, 443, traffic),
                        expected,
                        "networks={networks:?}, protocols={protocols:?}, union={union}, inverted={inverted}, traffic={traffic:?}"
                    );
                    if traffic.is_none() {
                        assert_eq!(predicate.evaluate(None, None, 443), expected);
                    }
                }
            }
        }
    }
}

// Fixed generator and seed make failures independent of rand crate versions.
fn next_port(state: &mut u64) -> u16 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*state >> 32) as u16
}

#[test]
fn port_range_union_matches_linear_oracle_and_boolean_composition() {
    let mut seed = 0x0051_10e5_2026_u64;
    for case in 0..128 {
        let mut ranges = Vec::new();
        for _ in 0..32 {
            let start = next_port(&mut seed);
            let end = start.saturating_add(next_port(&mut seed) % 256);
            ranges.push((start, end));
        }
        ranges.extend([(0, 0), (u16::MAX, u16::MAX), ranges[0]]);
        let expression = Expression::PortRanges(ranges.clone());
        let predicate = Compiler::default().compile(expression.clone()).unwrap();
        let inverted = Compiler::default()
            .compile(Expression::Not(Box::new(expression.clone())))
            .unwrap();
        let combined = Compiler::default()
            .compile(Expression::All(vec![
                expression.clone(),
                Expression::Any(vec![expression, Expression::Never]),
            ]))
            .unwrap();
        let queries = ranges
            .iter()
            .flat_map(|&(start, end)| [start.saturating_sub(1), start, end, end.saturating_add(1)])
            .chain((0..256).map(|_| next_port(&mut seed)));
        for port in queries {
            let matches = ranges
                .iter()
                .any(|&(start, end)| start <= port && port <= end);
            let (expected, inverted_expected) = if matches {
                (Outcome::Match, Outcome::Miss)
            } else {
                (Outcome::Miss, Outcome::Match)
            };
            assert_eq!(
                predicate.evaluate(None, None, port),
                expected,
                "case={case} port={port}"
            );
            assert_eq!(
                combined.evaluate(None, None, port),
                expected,
                "case={case} port={port}"
            );
            assert_eq!(
                inverted.evaluate(None, None, port),
                inverted_expected,
                "case={case} port={port}"
            );
        }
    }
}
