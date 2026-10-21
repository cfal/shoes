use super::*;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

#[derive(Debug)]
struct CountedResolver(AtomicU64);

impl Resolver for CountedResolver {
    fn resolve_location(&self, _: &NetLocation) -> crate::resolver::ResolveFuture {
        self.0.fetch_add(1, Relaxed);
        Box::pin(async { Ok(vec!["203.0.113.7:443".parse().unwrap()]) })
    }
}

fn variable(name: &str, default: usize) -> usize {
    std::env::var(name)
        .map(|v| v.parse().unwrap())
        .unwrap_or(default)
}

fn random(state: &mut u64) -> usize {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as usize
}

#[test]
#[ignore = "manual release-mode selector comparison"]
fn selector_measurement() {
    let count = variable("BENCH_COUNT", 100_000);
    let policies = variable("BENCH_POLICIES", 1);
    let mode = std::env::var("BENCH_MODE").unwrap_or("ordinary".into());
    let workload = std::env::var("BENCH_WORKLOAD").unwrap_or("mixed".into());
    let guards = std::env::var("BENCH_PORTS").unwrap_or("none".into());
    assert!(count > 0 && policies > 0 && policies <= count);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let counted = Arc::new(CountedResolver(AtomicU64::new(0)));
    let resolver: Arc<dyn Resolver> = counted.clone();
    let name = |i| format!("h{i}.group{}.example", i % 16);
    let entry_port = |i| {
        if guards == "mixed" && i % 2 == 0 {
            80
        } else {
            443
        }
    };
    let started = Instant::now();
    let mut rules = Vec::new();
    if mode == "dns" {
        rules.push(ConnectRule::new(
            vec![NetLocationMask::from("198.18.0.0/15").unwrap()],
            ConnectAction::Block,
        ));
    }
    for policy in 0..policies {
        let masks = (count * policy / policies..count * (policy + 1) / policies)
            .map(|i| {
                let mask = if guards == "none" {
                    name(i)
                } else {
                    format!("{}:{}", name(i), entry_port(i))
                };
                NetLocationMask::from(&mask).unwrap()
            })
            .collect();
        rules.push(ConnectRule::new(masks, ConnectAction::Block));
    }
    rules.push(ConnectRule::new(
        vec![NetLocationMask::ANY],
        ConnectAction::new_allow(
            None,
            crate::tcp::chain_builder::build_direct_chain_group(resolver.clone()),
        ),
    ));
    let cache_enabled = mode == "warm" || mode == "cold";
    let cache_size = if cache_enabled { 10_000 } else { 0 };
    let selector =
        ClientProxySelector::with_options_and_cache_size(rules, cache_enabled, cache_size);
    assert_eq!(selector.is_cache_enabled(), cache_enabled);
    let build_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut rng = 0x83ab_d317_26e3_a175;
    let query_count = if mode == "cold" { 32768 } else { 4096 };
    let queries: Vec<_> = (0..query_count)
        .map(|query| {
            let id = match workload.as_str() {
                "early" => random(&mut rng) % count.min(16),
                "late" => count - 1 - random(&mut rng) % count.min(16),
                _ => random(&mut rng) % count,
            };
            let hit = workload != "miss" && (workload != "mixed" || random(&mut rng) & 1 == 0);
            let mut host = if hit {
                format!("a.{}", name(id))
            } else {
                format!("miss{}.invalid", random(&mut rng))
            };
            if mode == "cold" {
                host = format!("q{query}.{host}");
            }
            if random(&mut rng) & 3 == 0 {
                host.make_ascii_uppercase();
                host.push('.');
            }
            let port = if guards == "none" || random(&mut rng) & 1 == 0 {
                443
            } else {
                80
            };
            let expected = hit && (guards == "none" || port == entry_port(id));
            let location = NetLocation::new(Address::Hostname(host.clone()), port);
            (host, location, expected)
        })
        .collect();
    if mode == "cold" {
        let keys: std::collections::HashSet<_> = queries
            .iter()
            .map(|(_, location, _)| RoutingCacheKey::from_location(location))
            .collect();
        assert_eq!(keys.len(), query_count);
        assert!(query_count > cache_size);
    }
    let lookup = |i: usize| {
        let (host, location, _) = &queries[i & (query_count - 1)];
        runtime.block_on(async {
            if mode == "floor" {
                return black_box(location.clone()).port() == 443;
            }
            if mode == "sniff" {
                let literal =
                    NetLocation::from_ip_addr("203.0.113.7".parse().unwrap(), location.port());
                let IngressTarget::Forward(target) = selector.prepare(literal.into()).unwrap()
                else {
                    panic!()
                };
                matches!(
                    selector
                        .judge_prepared(target, Some(host), &resolver)
                        .await
                        .unwrap()
                        .decision,
                    ConnectDecision::Block
                )
            } else {
                matches!(
                    selector
                        .judge(location.clone().into(), &resolver)
                        .await
                        .unwrap(),
                    ConnectDecision::Block
                )
            }
        })
    };
    if mode != "floor" {
        for (i, (_, _, expected)) in queries.iter().enumerate() {
            assert_eq!(lookup(i), *expected, "query {i}");
        }
    }
    let mut cursor = 0usize;
    let mut run = |n: usize| {
        let start = Instant::now();
        for _ in 0..n {
            black_box(lookup(black_box(cursor)));
            cursor = cursor.wrapping_add(1);
        }
        start.elapsed().as_secs_f64() * 1e9 / n as f64
    };
    let calibration = run(32).max(1.0);
    let iterations = (5_000_000.0 / calibration).clamp(4.0, 262_144.0) as usize;
    run(iterations);
    counted.0.store(0, Relaxed);
    let mut samples: Vec<_> = (0..15).map(|_| run(iterations)).collect();
    samples.sort_by(f64::total_cmp);
    let resolver_calls = counted.0.load(Relaxed);
    assert_eq!(
        resolver_calls,
        if mode == "dns" {
            (15 * iterations) as u64
        } else {
            0
        }
    );
    println!(
        "SELECTOR_BENCH {}",
        serde_json::json!({
            "count": count, "policies": policies, "mode": mode, "workload": workload, "ports": guards,
            "build_ms": build_ms, "median_ns": samples[7], "batch_p95_ns": samples[14],
            "iterations": iterations, "samples": samples, "resolver_calls": resolver_calls,
        })
    );
}
