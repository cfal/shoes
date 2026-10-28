use ipnetwork::IpNetwork;
use serde_json::{Value, json};

use super::spec::Spec;

fn meta(key: &str) -> Value {
    json!({"meta": {"key": key}})
}

fn ct(key: &str) -> Value {
    json!({"ct": {"key": key}})
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload": {"protocol": protocol, "field": field}})
}

fn masked(value: Value, mask: u32) -> Value {
    json!({"&": [value, mask]})
}

fn matches(left: Value, op: &str, right: Value) -> Value {
    json!({"match": {"left": left, "op": op, "right": right}})
}

fn mark(key: Value, mask: u32, value: u32) -> Value {
    json!({"mangle": {"key": key.clone(), "value": {"|": [masked(key, !(mask & !value)), value]}}})
}

fn prefixes(networks: &[IpNetwork], ipv6: bool) -> Vec<Value> {
    let mut networks: Vec<_> = networks
        .iter()
        .copied()
        .filter(|n| n.is_ipv6() == ipv6)
        .collect();
    networks.sort_by_key(|n| (n.prefix(), n.network()));
    let mut unique: Vec<IpNetwork> = Vec::new();
    for network in networks {
        if !unique
            .iter()
            .any(|existing| existing.contains(network.network()))
        {
            unique.push(network);
        }
    }
    unique
        .into_iter()
        .map(|network| {
            json!({"prefix": {
                "addr": network.network().to_string(),
                "len": network.prefix()
            }})
        })
        .collect()
}

pub(super) fn install(
    spec: &Spec,
    table: &str,
    owner: &str,
    on_link: &[IpNetwork],
    redirect: [Option<u16>; 2],
) -> Value {
    let mut commands = vec![json!({"create": {"table": {"family": "inet", "name": table}}})];
    for (name, hook) in [
        ("output", Some(("route", "output", -150))),
        ("select", None),
        ("capture", None),
        ("redirect", Some(("nat", "output", -100))),
        ("guard", Some(("filter", "input", -10))),
        ("prerouting", Some(("filter", "prerouting", -175))),
    ] {
        let mut chain = json!({"family": "inet", "table": table, "name": name});
        if let Some((kind, hook, priority)) = hook {
            chain["type"] = json!(kind);
            chain["hook"] = json!(hook);
            chain["prio"] = json!(priority);
            chain["policy"] = json!("accept");
        }
        commands.push(json!({"add": {"chain": chain}}));
    }
    for (name, networks) in [
        ("include", spec.routes.as_slice()),
        ("exclude", spec.excludes.as_slice()),
        ("onlink", on_link),
    ] {
        for (ipv6, suffix, kind) in [(false, "4", "ipv4_addr"), (true, "6", "ipv6_addr")] {
            let mut set = json!({
                "family": "inet", "table": table, "name": format!("{name}{suffix}"),
                "type": kind, "flags": ["interval"]
            });
            let elements = prefixes(networks, ipv6);
            if !elements.is_empty() {
                set["elem"] = json!(elements);
            }
            commands.push(json!({"add": {"set": set}}));
        }
    }
    let mut rule = |chain: &str, label: &str, expressions: Vec<Value>| {
        commands.push(json!({"add": {"rule": {
            "family": "inet", "table": table, "chain": chain,
            "expr": expressions, "comment": format!("{owner}:{label}")
        }}}));
    };
    let mask = spec.linux.mark_mask;
    let capture = spec.linux.capture_mark;
    let bypass = spec.linux.bypass_mark;
    // Mark-aware reverse-path filters must find the private route for replies injected by the TUN.
    rule(
        "prerouting",
        "captured-reply",
        vec![
            matches(meta("iifname"), "==", json!(spec.name)),
            matches(masked(ct("mark"), mask), "==", json!(capture)),
            mark(meta("mark"), mask, capture),
        ],
    );
    if spec.dns_hijack {
        for address in spec.dns_addresses().unwrap_or_default() {
            for protocol in ["tcp", "udp"] {
                rule(
                    "output",
                    "dns-readiness",
                    vec![
                        matches(masked(meta("mark"), mask), "==", json!(bypass)),
                        matches(meta("oifname"), "==", json!(spec.name)),
                        matches(
                            payload(if address.is_ipv4() { "ip" } else { "ip6" }, "daddr"),
                            "==",
                            json!(address),
                        ),
                        matches(payload(protocol, "dport"), "==", json!(53)),
                        json!({"return": null}),
                    ],
                );
            }
        }
    }
    rule(
        "output",
        "recursive-egress",
        vec![
            matches(masked(meta("mark"), mask), "==", json!(bypass)),
            matches(meta("oifname"), "==", json!(spec.name)),
            json!({"counter": null}),
            json!({"drop": null}),
        ],
    );
    rule(
        "output",
        "bypass",
        vec![
            matches(masked(meta("mark"), mask), "==", json!(bypass)),
            json!({"return": null}),
        ],
    );
    rule(
        "output",
        "foreign-mark",
        vec![
            matches(masked(meta("mark"), !mask), "!=", json!(0)),
            json!({"return": null}),
        ],
    );
    rule(
        "output",
        "reply",
        vec![
            matches(ct("direction"), "==", json!("reply")),
            json!({"return": null}),
        ],
    );
    rule(
        "output",
        "untracked",
        vec![
            matches(ct("state"), "==", json!("untracked")),
            json!({"return": null}),
        ],
    );
    rule(
        "output",
        "local",
        vec![
            matches(
                json!({"fib": {"result": "type", "flags": ["daddr"]}}),
                "==",
                json!("local"),
            ),
            json!({"return": null}),
        ],
    );
    for (family, reserved) in [
        (
            "ip",
            vec!["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"],
        ),
        ("ip6", vec!["::/127", "fe80::/10", "ff00::/8"]),
    ] {
        let networks: Vec<IpNetwork> = reserved.iter().map(|s| s.parse().unwrap()).collect();
        rule(
            "output",
            "reserved",
            vec![
                matches(
                    payload(family, "daddr"),
                    "==",
                    json!({"set": prefixes(&networks, family == "ip6")}),
                ),
                json!({"return": null}),
            ],
        );
    }
    for (family, set) in [("ip", "@include4"), ("ip6", "@include6")] {
        rule(
            "output",
            "selected-address",
            vec![
                matches(payload(family, "daddr"), "==", json!(set)),
                json!({"goto": {"target": "select"}}),
            ],
        );
    }
    rule(
        "select",
        "retained-flow",
        vec![
            matches(masked(ct("mark"), mask), "==", json!(capture)),
            mark(meta("mark"), mask, capture),
            json!({"counter": null}),
            json!({"return": null}),
        ],
    );
    rule(
        "select",
        "confirmed-native-flow",
        vec![
            matches(ct("status"), "in", json!("confirmed")),
            json!({"return": null}),
        ],
    );
    rule(
        "select",
        "existing-native-flow",
        vec![
            matches(
                ct("state"),
                "==",
                json!({"set": ["established", "related"]}),
            ),
            json!({"return": null}),
        ],
    );
    rule(
        "select",
        "not-tcp-establishment",
        vec![
            matches(
                json!({"&": [payload("tcp", "flags"), ["syn", "ack"]]}),
                "!=",
                json!("syn"),
            ),
            json!({"return": null}),
        ],
    );
    for (family, set) in [("ip", "@exclude4"), ("ip6", "@exclude6")] {
        rule(
            "select",
            "excluded-address",
            vec![
                matches(payload(family, "daddr"), "==", json!(set)),
                json!({"return": null}),
            ],
        );
    }
    if spec.dns_hijack {
        for protocol in ["tcp", "udp"] {
            rule(
                "select",
                "dns",
                vec![
                    matches(payload(protocol, "dport"), "==", json!(53)),
                    json!({"goto": {"target": "capture"}}),
                ],
            );
        }
    }
    for (family, set) in [("ip", "@onlink4"), ("ip6", "@onlink6")] {
        rule(
            "select",
            "onlink",
            vec![
                matches(payload(family, "daddr"), "==", json!(set)),
                json!({"return": null}),
            ],
        );
    }
    rule(
        "capture",
        "untrackable",
        vec![
            matches(ct("state"), "==", json!("invalid")),
            json!({"drop": null}),
        ],
    );
    let mut protocols = vec!["tcp", "udp"];
    if spec.icmp {
        protocols.extend(["icmp", "ipv6-icmp"]);
    }
    rule(
        "select",
        "capture-protocols",
        vec![
            matches(meta("l4proto"), "==", json!({"set": protocols})),
            json!({"goto": {"target": "capture"}}),
        ],
    );
    rule(
        "capture",
        "mark",
        vec![
            mark(ct("mark"), mask, capture),
            mark(meta("mark"), mask, capture),
            json!({"counter": null}),
        ],
    );
    for (protocol, port) in ["ip", "ip6"].into_iter().zip(redirect) {
        let Some(port) = port else {
            continue;
        };
        let gateway = spec
            .redirect_gateway(protocol == "ip6")
            .expect("validated redirect gateway");
        // Route nexthop, unlike OUTPUT interface metadata, reflects bound-device rerouting.
        rule(
            "redirect",
            "tcp",
            vec![
                matches(meta("l4proto"), "==", json!("tcp")),
                matches(masked(meta("mark"), mask), "==", json!(capture)),
                matches(payload(protocol, "daddr"), "!=", json!(gateway)),
                matches(
                    json!({"rt": {"key": "nexthop", "family": protocol}}),
                    "==",
                    json!(gateway),
                ),
                json!({"counter": null}),
                json!({"redirect": {"port": port}}),
            ],
        );
        let destination = matches(payload("tcp", "dport"), "==", json!(port));
        for (label, condition) in [
            (
                "not-dnat",
                matches(masked(ct("status"), 32), "==", json!(0)),
            ),
            (
                "not-captured",
                matches(masked(ct("mark"), mask), "!=", json!(capture)),
            ),
        ] {
            rule(
                "guard",
                label,
                vec![
                    matches(
                        payload(protocol, "daddr"),
                        "==",
                        json!(if protocol == "ip" { "127.0.0.1" } else { "::1" }),
                    ),
                    destination.clone(),
                    condition,
                    json!({"drop": null}),
                ],
            );
        }
    }
    json!({"nftables": commands})
}

pub(super) fn update_onlink(table: &str, networks: &[IpNetwork]) -> Value {
    let mut commands = Vec::new();
    for (ipv6, name) in [(false, "onlink4"), (true, "onlink6")] {
        commands.push(json!({"flush": {"set": {"family": "inet", "table": table, "name": name, "type": if ipv6 { "ipv6_addr" } else { "ipv4_addr" }}}}));
        let elements = prefixes(networks, ipv6);
        if !elements.is_empty() {
            commands.push(json!({"add": {"element": {"family": "inet", "table": table, "name": name, "elem": elements}}}));
        }
    }
    json!({"nftables": commands})
}

pub(super) fn remove(table: &str) -> Value {
    json!({"nftables": [{"delete": {"table": {"family": "inet", "name": table}}}]})
}

pub(super) fn with_onlink(listing: &Value, networks: &[IpNetwork]) -> Value {
    let mut listing = listing.clone();
    if let Some(entries) = listing["nftables"].as_array_mut() {
        for entry in entries {
            let Some(set) = entry.get_mut("set") else {
                continue;
            };
            let ipv6 = match set["name"].as_str() {
                Some("onlink4") => false,
                Some("onlink6") => true,
                _ => continue,
            };
            set["elem"] = json!(prefixes(networks, ipv6));
        }
    }
    listing
}

fn canonical_policy(document: &Value) -> Option<std::collections::BTreeMap<String, Vec<Value>>> {
    fn normalize(value: &mut Value) {
        // Newer nft versions render the TCP flag mask as an explicit bitwise OR.
        if *value == json!({"|": ["syn", "ack"]}) {
            *value = json!(["syn", "ack"]);
            return;
        }
        match value {
            Value::Object(object) => {
                if let Some(flags @ Value::String(_)) = object.get_mut("flags") {
                    *flags = json!([flags.as_str().unwrap()]);
                }
                if object.get("match").is_some_and(|value| {
                    value["left"] == ct("status") && value["op"] == "!" && value["right"] == "dnat"
                }) {
                    *value = matches(masked(ct("status"), 32), "==", json!(0));
                    return;
                }
                for value in object.values_mut() {
                    normalize(value);
                }
                if let Some(Value::Array(elements)) = object.get_mut("set") {
                    elements.sort_by_key(Value::to_string);
                }
                if let Some(prefix) = object.get("prefix")
                    && let (Some(address), Some(len)) =
                        (prefix["addr"].as_str(), prefix["len"].as_u64())
                    && let Ok(address) = address.parse()
                    && let Ok(len) = u8::try_from(len)
                    && let Ok(network) = IpNetwork::new(address, len)
                {
                    // Older nft versions render intervals ending at the maximum address as ranges.
                    *value = if network.network() == network.broadcast() {
                        json!(network.network())
                    } else {
                        json!({"range": [network.network(), network.broadcast()]})
                    };
                }
            }
            Value::Array(values) => values.iter_mut().for_each(normalize),
            _ => {}
        }
    }
    let entries = document.get("nftables")?.as_array()?;
    let mut objects = std::collections::BTreeMap::<String, Vec<Value>>::new();
    for entry in entries {
        let entry = entry
            .get("add")
            .or_else(|| entry.get("create"))
            .unwrap_or(entry);
        if entry.get("metainfo").is_some() {
            continue;
        }
        let entry = entry.as_object()?;
        if entry.len() != 1 {
            return None;
        }
        let (kind, value) = entry.iter().next()?;
        if !["table", "chain", "set", "rule"].contains(&kind.as_str()) {
            return None;
        }
        let mut value = value.clone();
        normalize(&mut value);
        let object = value.as_object_mut()?;
        object.remove("handle");
        if kind == "set" {
            let elements = object.entry("elem").or_insert(json!([])).as_array_mut()?;
            elements.sort_by_key(Value::to_string);
        }
        if kind == "rule" {
            for expression in object.get_mut("expr")?.as_array_mut()? {
                if expression.get("counter").is_some() {
                    *expression = json!({"counter": null});
                }
            }
        }
        let identity = if kind == "rule" {
            object.get("chain")?.as_str()?
        } else {
            object.get("name")?.as_str()?
        };
        objects
            .entry(format!("{kind}:{identity}"))
            .or_default()
            .push(value);
    }
    Some(objects)
}

pub(super) fn same_policy(listing: &Value, expected: &Value) -> bool {
    match (canonical_policy(listing), canonical_policy(expected)) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => false,
    }
}
