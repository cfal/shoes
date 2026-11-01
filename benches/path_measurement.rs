use super::*;
use crate::config::{ResolvedConfig as RuntimeConfig, ResolvedRuleActionConfig as RuntimeAction};
use serde_json::{Value, json};
use std::hint::black_box;
use std::time::{Duration, Instant};

fn client(name: &str) -> Value {
    json!({"name":name,"address":"192.0.2.1:1080","protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}})
}

fn fixture(case: &str) -> String {
    let mut config = Vec::new();
    let mut rules = 1;
    let chain = match case {
        "fixed-1" | "fixed-4" => {
            let hops = if case == "fixed-1" { 1 } else { 4 };
            Value::Array((0..hops).map(|n| client(&format!("fixed-{n}"))).collect())
        }
        "rr-16" | "wide-16000" => {
            let count = if case == "rr-16" { 16 } else { 16_000 };
            config.push(json!({"client_group":"out", "type":if count == 16 { "round-robin" } else { "selector" },
                "client_chains":(0..count).map(|n| json!({"chain":[client(&format!("leaf-{n}"))]})).collect::<Vec<_>>()}));
            json!("out")
        }
        "nested-64" | "nested-1024" | "shared-64x64" => {
            let width = if case == "nested-1024" { 32 } else { 8 };
            if case == "shared-64x64" {
                rules = 64;
            }
            for n in 0..width {
                config.push(json!({"client_group":format!("manual-{n}"),"type":"selector",
                    "client_chains":(0..width).map(|m| json!({"chain":[client(&format!("leaf-{n}-{m}"))]})).collect::<Vec<_>>()}));
            }
            config.push(json!({"client_group":"out","type":"url-test","url":"http://probe.invalid/",
                "client_chains":(0..width).map(|n| json!({"chain":[format!("manual-{n}")]})).collect::<Vec<_>>()}));
            config.push(json!({"client_group":"exit","client_chain":client("exit-leaf")}));
            json!(["out", "exit"])
        }
        "deep-48" => {
            config.push(json!({"client_group":"depth-0","client_chain":client("bottom")}));
            for n in 1..=48 {
                config.push(json!({"client_group":format!("depth-{n}"),"type":"selector",
                    "client_chains":[{"chain":[format!("depth-{}",n-1)]},{"chain":[client(&format!("leaf-{n}"))]}]}));
            }
            json!("depth-48")
        }
        _ => panic!("unknown PATH_CASE: {case}"),
    };
    config.push(json!({"address":"0.0.0.0:0","protocol":{"type":"socks"},
        "rules":(0..rules).map(|_| json!({"mask":"0.0.0.0/0","action":"allow","client_chain":chain})).collect::<Vec<_>>()}));
    serde_json::to_string(&config).unwrap()
}

fn prepare(source: &str) -> (crate::config::ValidatedConfigs, Vec<ClientProxyChain>) {
    let validated =
        crate::config::create_server_configs(serde_json::from_str(source).unwrap()).unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let mut chains = Vec::new();
    for config in &validated.configs {
        let RuntimeConfig::Server(server) = config else {
            continue;
        };
        for rule in server.rules.iter() {
            let RuntimeAction::Allow { client_chains, .. } = &rule.action else {
                continue;
            };
            for chain in client_chains.iter() {
                chains.push(
                    crate::tcp::chain_builder::try_build_client_proxy_chain(
                        chain.hops.clone(),
                        resolver.clone(),
                    )
                    .unwrap(),
                );
            }
        }
    }
    (validated, chains)
}

fn select(chain: &ClientProxyChain, udp: bool) {
    drop(black_box(black_box(chain).select(black_box(udp)).unwrap()));
}

#[test]
#[ignore = "manual path preparation/selection measurement; release for timing, debug for allocations"]
fn path_measurement() {
    let case = std::env::var("PATH_CASE").unwrap_or_else(|_| "nested-64".into());
    println!(
        "\nPATH_META,{case},debug_assertions={}",
        cfg!(debug_assertions)
    );
    let source = fixture(&case);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    drop(prepare(&source));
    for sample in 0..7 {
        let start = Instant::now();
        let prepared = prepare(black_box(&source));
        let elapsed = start.elapsed();
        assert!(!prepared.1.is_empty());
        println!(
            "PATH,prepare,{case},{sample},{},{}",
            prepared.1.len(),
            elapsed.as_nanos()
        );
        drop(prepared);
    }
    let (validated, chains) = prepare(&source);
    assert_eq!(chains.len(), if case == "shared-64x64" { 64 } else { 1 });
    let expected_hops = match case.as_str() {
        "fixed-4" => 4,
        "nested-64" | "nested-1024" | "shared-64x64" => 2,
        _ => 1,
    };
    assert_eq!(chains[0].num_hops(), expected_hops);
    assert!(chains[0].supports_udp());
    if let Some(catalog) = &validated.catalog {
        for group in catalog.selection.automatic.0.values() {
            for (index, member) in group.members.iter().enumerate() {
                catalog.selection.automatic.record(
                    member,
                    &group.config.url,
                    Some(10 + index as u16),
                );
            }
        }
    }
    for udp in [false, true] {
        for _ in 0..512 {
            select(&chains[0], udp);
        }
        for sample in 0..7 {
            let start = Instant::now();
            let mut iterations = 0;
            while start.elapsed() < Duration::from_millis(75) {
                for _ in 0..256 {
                    select(&chains[0], udp);
                }
                iterations += 256;
            }
            println!(
                "PATH,select-{udp},{case},{sample},{iterations},{}",
                start.elapsed().as_nanos()
            );
        }
        #[cfg(debug_assertions)]
        {
            let (_, counts) = crate::control::connection_notes_allocation_tests::measure(|| {
                for _ in 0..128 {
                    select(&chains[0], udp);
                }
            });
            assert_eq!(counts.live_bytes, 0, "selection retains allocations");
            println!(
                "PATH_ALLOC,select-{udp},{case},128,{},{},{}",
                counts.allocations, counts.live_bytes, counts.peak_bytes
            );
        }
    }
    #[cfg(debug_assertions)]
    {
        let (prepared, counts) =
            crate::control::connection_notes_allocation_tests::measure(|| prepare(&source));
        let (_, dropped) =
            crate::control::connection_notes_allocation_tests::measure(|| drop(prepared));
        assert_eq!(
            counts.live_bytes + dropped.live_bytes,
            0,
            "preparation retains allocations after drop"
        );
        println!(
            "PATH_ALLOC,prepare,{case},1,{},{},{}",
            counts.allocations, counts.live_bytes, counts.peak_bytes
        );
    }
}
