use super::*;
use crate::config::{ResolvedConfig, RuleConfig, create_server_configs};
use crate::rules::Outcome;
use serde_json::{Value, json};

fn server(rules: Value) -> Value {
    json!({"address": "127.0.0.1:1080", "protocol": {"type": "socks"}, "rules": rules})
}

fn write_domains(path: &Path, name: &str) {
    std::fs::write(
        path,
        json!({"version": 1, "rules": [{"domain": [name]}]}).to_string(),
    )
    .unwrap();
}

fn compile(value: Value, config_file: &Path) -> io::Result<crate::config::ValidatedConfigs> {
    let mut configs = serde_json::from_value::<Vec<Config>>(value).unwrap();
    anchor(&mut configs, config_file)?;
    create_server_configs(configs)
}

#[test]
fn source_unions_inline_references_and_policy_order() {
    let dir = tempfile::tempdir().unwrap();
    write_domains(&dir.path().join("a.json"), "a.example");
    write_domains(&dir.path().join("b.json"), "b.example");
    let validated = compile(
        json!([
            {"rule_source_group": "files", "rules": ["a.json", {"path": "b.json"}]},
            {"rule_group": "policies", "rules": [
                {"masks": {"rule_source_group": "files"}, "action": "block"},
                {"masks": "0.0.0.0/0"}
            ]},
            server([json!("policies"), json!({"masks": {"all": [
                {"path": "a.json"}, {"destination_port": [443]}
            ]}})].into()),
        ]),
        &dir.path().join("config.yaml"),
    )
    .unwrap();
    assert_eq!(
        validated.reload_files,
        [dir.path().join("a.json"), dir.path().join("b.json")]
    );
    let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected server")
    };
    let rules: Vec<_> = server.rules.iter().collect();
    assert_eq!(rules.len(), 3);
    assert!(matches!(
        rules[0].action,
        crate::config::ResolvedRuleActionConfig::Block
    ));
    assert!(matches!(
        rules[1].action,
        crate::config::ResolvedRuleActionConfig::Allow { .. }
    ));
    let union = rules[0].criteria.compiled.as_ref().unwrap();
    for name in ["a.example", "b.example"] {
        assert_eq!(union.evaluate(Some(name), None, 80), Outcome::Match);
    }
    assert_eq!(
        union.evaluate(Some("other.example"), None, 80),
        Outcome::Miss
    );
    let inline = rules[2].criteria.compiled.as_ref().unwrap();
    assert_eq!(
        inline.evaluate(Some("a.example"), None, 443),
        Outcome::Match
    );
    assert_eq!(inline.evaluate(Some("a.example"), None, 80), Outcome::Miss);
}

#[test]
fn native_source_groups_compose_and_forward_reference_without_actions() {
    let dir = tempfile::tempdir().unwrap();
    let validated = compile(
        json!([
            {"rule_source_group": "outer", "rules": [
                {"rule_source_group": "inner"}, {"domain": ["other.example"]}
            ]},
            {"rule_source_group": "inner", "rules": [{"all": [
                {"domain_suffix": ["example.com"]},
                {"destination_port": [443]},
                {"not": {"domain": ["except.example.com"]}}
            ]}]},
            server(json!([{"masks": {"rule_source_group": "outer"}, "action": "block"}]))
        ]),
        &dir.path().join("config.yaml"),
    )
    .unwrap();
    let ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let rule = server.rules.iter().next().unwrap();
    let predicate = rule.criteria.compiled.as_ref().unwrap();
    for (name, port, expected) in [
        ("example.com", 443, Outcome::Match),
        ("sub.example.com", 80, Outcome::Miss),
        ("except.example.com", 443, Outcome::Miss),
        ("other.example", 80, Outcome::Match),
    ] {
        assert_eq!(predicate.evaluate(Some(name), None, port), expected);
    }
    for rules in [
        json!([{"rule_source_group": "cycle"}]),
        json!([{"not": {"rule_source_group": "cycle"}}]),
    ] {
        assert!(
            compile(
                json!([{"rule_source_group": "cycle", "rules": rules}]),
                &dir.path().join("config.yaml")
            )
            .err()
            .unwrap()
            .to_string()
            .contains("cyclic")
        );
    }
}

#[test]
fn flat_sources_are_policy_shorthand_not_source_groups() {
    let dir = tempfile::tempdir().unwrap();
    write_domains(&dir.path().join("list.json"), "example.com");
    compile(
        json!([
            {"rule_group": "policy", "rules": [{"path": "list.json", "action": "block"}]},
            server(json!("policy"))
        ]),
        &dir.path().join("config.yaml"),
    )
    .unwrap();
    for value in [
        json!({"path": "list.json", "masks": {"domain": ["example.com"]}}),
        json!({"path": "list.json", "mask": "example.com"}),
        json!({"path": "list.json", "typo": true}),
    ] {
        assert!(serde_json::from_value::<RuleConfig>(value).is_err());
    }
    assert!(
        serde_json::from_value::<Vec<Config>>(json!([
            {"rule_group": "old", "rules": ["list.json"]}
        ]))
        .is_err()
    );
}

#[test]
fn source_group_depth_is_order_independent_and_includes_callers() {
    for reversed in [false, true] {
        let mut groups: Vec<_> = (0..101)
            .map(|i| {
                json!({"rule_source_group": format!("g{i}"), "rules": [
                    if i == 100 { json!({"domain": ["example.com"]}) }
                    else { json!({"rule_source_group": format!("g{}", i+1)}) }
                ]})
            })
            .collect();
        if reversed {
            groups.reverse();
        }
        assert!(
            create_server_configs(serde_json::from_value(json!(groups)).unwrap())
                .err()
                .unwrap()
                .to_string()
                .contains("100 levels")
        );
    }
    let nested = (0..100).fold(
        json!({"rule_source_group": "group"}),
        |child, _| json!({"not": child}),
    );
    let configs = serde_json::from_value(json!([
        {"rule_source_group": "group", "rules": [{"domain": ["example.com"]}]},
        server(json!([{"masks": nested}]))
    ]))
    .unwrap();
    assert!(
        create_server_configs(configs)
            .err()
            .unwrap()
            .to_string()
            .contains("100 levels")
    );
}

#[test]
fn source_group_work_budget_counts_repeated_references_and_caller_compositions() {
    let groups = |levels: usize| {
        let mut configs =
            vec![json!({"rule_source_group": "g0", "rules": [{"ip_cidr": ["192.0.2.0/24"]}]})];
        for level in 1..=levels {
            let child = json!({"rule_source_group": format!("g{}", level - 1)});
            configs.push(
                json!({"rule_source_group": format!("g{level}"), "rules": [child.clone(), child]}),
            );
        }
        configs
    };
    for reversed in [false, true] {
        let mut configs = groups(40);
        if reversed {
            configs.reverse();
        }
        configs.push(server(
            json!([{"masks": {"rule_source_group": "g40"}, "action": "block"}]),
        ));
        let error = create_server_configs(serde_json::from_value(json!(configs)).unwrap())
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("expanded rule evaluation budget"),
            "{error}"
        );
    }
    for copies in [1, 32] {
        let mut configs = groups(16);
        configs.push(server(json!([{"masks": {"any": vec![json!({"rule_source_group": "g16"}); copies]}, "action": "block"}])));
        let result = create_server_configs(serde_json::from_value(json!(configs)).unwrap());
        if copies == 1 {
            let validated = result.unwrap();
            let ResolvedConfig::Server(server) = &validated.configs[0] else {
                panic!()
            };
            let rule = server.rules.iter().next().unwrap();
            let predicate = rule.criteria.compiled.as_ref().unwrap();
            assert!(!predicate.has_no_resolve_ip());
            assert_eq!(
                predicate.evaluate(None, Some("198.51.100.1".parse().unwrap()), 80),
                Outcome::Miss
            );
        } else {
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("expanded rule evaluation budget")
            );
        }
    }
    for copies in [1, 32] {
        let references = json!(vec!["p"; copies]);
        let mut websocket = server(json!([]));
        websocket["protocol"] = json!({"type": "websocket", "targets": [{
            "protocol": {"type": "socks"}, "override_rules": references
        }]});
        for destination in [
            server(references.clone()),
            json!({"device_name": "tun-test", "address": "10.0.0.1", "netmask": "255.255.255.0", "rules": references}),
            websocket,
        ] {
            let mut configs = groups(16);
            configs.push(json!({"rule_group": "p", "rules": [{
                "masks": {"rule_source_group": "g16"}, "action": "block"
            }]}));
            configs.push(destination);
            let result = create_server_configs(serde_json::from_value(json!(configs)).unwrap());
            if copies == 1 {
                assert!(result.is_ok(), "{}", result.err().unwrap());
            } else {
                let error = result.err().unwrap();
                assert!(
                    error
                        .to_string()
                        .contains("expanded rule evaluation budget"),
                    "{error}"
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn managed_cache_namespace_rejects_dangling_local_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cache");
    std::fs::create_dir(&cache_dir).unwrap();
    let path = cache_dir.join("cache.json");
    let alias = dir.path().join("alias.json");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    let mut configs: Vec<Config> = serde_json::from_value(json!([
        {"global_settings": {"rule_cache_dir": cache_dir}},
        {"rule_source_group": "local", "rules": [{"path": alias}]}
    ]))
    .unwrap();
    let error = validate_remote_paths(&mut configs, &[]).unwrap_err();
    assert!(error.to_string().contains("local aliases"), "{error}");
}

#[test]
fn inline_and_named_sources_share_the_same_predicate() {
    let dir = tempfile::tempdir().unwrap();
    write_domains(&dir.path().join("a.json"), "a.example");
    let mut configs: Vec<Config> = serde_json::from_value(json!([
        {"rule_source_group": "files", "rules": ["a.json"]},
        server(json!([
            {"masks": {"rule_source_group": "files"}},
            {"masks": {"path": "a.json", "format": "singbox_json"}},
        ])),
    ]))
    .unwrap();
    anchor(&mut configs, &dir.path().join("config.yaml")).unwrap();
    let mut compiler = Compiler::default();
    load(&mut configs, &mut compiler).unwrap();
    rule_visit::compile(&mut configs, &mut compiler).unwrap();
    let Config::Server(server) = &configs[1] else {
        panic!("expected server")
    };
    for selection in server.rules.iter() {
        let crate::config::ConfigSelection::Config(rule) = selection else {
            panic!("expected inline rule")
        };
        assert!(Arc::ptr_eq(
            rule.criteria.compiled.as_ref().unwrap(),
            &compiler.groups["files"]
        ));
    }
    assert_eq!(compiler.sources.len(), 1);
}

#[test]
fn group_names_are_unique_and_cross_kind_references_fail() {
    let dir = tempfile::tempdir().unwrap();
    write_domains(&dir.path().join("a.json"), "a.example");
    for (value, message) in [
        (
            json!([
                {"rule_source_group": "files", "rules": ["a.json"]}, server(json!("files"))
            ]),
            "is a rule source group",
        ),
        (
            json!([
                {"rule_group": "policies", "rules": [{"masks": "example.com"}]},
                server(json!([{"masks": {"not": {"rule_source_group": "policies"}}}]))
            ]),
            "contains policies with actions",
        ),
        (
            json!([server(
                json!([{"masks": {"rule_source_group": "block-all"}}])
            )]),
            "contains policies with actions",
        ),
        (
            json!([server(json!([{"masks": {"rule_source_group": "a.json"}}]))]),
            "unknown rule source group",
        ),
        (json!([server(json!("missing"))]), "unknown rule group"),
        (
            json!([
                {"rule_source_group": "same", "rules": ["a.json"]},
                {"rule_group": "same", "rules": [{"masks": "example.com"}]}
            ]),
            "duplicate or empty rule group name",
        ),
        (
            json!([{"rule_source_group": "block-all", "rules": ["a.json"]}]),
            "duplicate or empty rule group name",
        ),
        (
            json!([{"rule_source_group": "", "rules": ["a.json"]}]),
            "duplicate or empty rule group name",
        ),
    ] {
        let error = compile(value, &dir.path().join("config.yaml"))
            .err()
            .unwrap();
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[test]
fn every_rule_location_anchors_discovers_and_compiles_inline_sources() {
    let dir = tempfile::tempdir().unwrap();
    let rule = |name: &str| {
        json!({"masks": {"all": [
            {"path": format!("{name}.json")}, {"not": {"domain": ["excluded.example"]}}
        ]}})
    };
    let websocket = json!({"type": "websocket", "targets": [{
        "protocol": {"type": "socks"}, "override_rules": [rule("websocket")]
    }]});
    let tls = |name: &str| {
        json!({
            "cert": "unused", "key": "unused", "protocol": websocket,
            "override_rules": [rule(name)]
        })
    };
    let mut configs: Vec<Config> = serde_json::from_value(json!([
        {"rule_source_group": "files", "rules": ["group.json"]},
        {"rule_group": "policies", "rules": [rule("policy")]},
        {"device_name": "tun-test", "address": "10.0.0.1", "netmask": "255.255.255.0", "rules": [rule("tun")]},
        {"address": "127.0.0.1:1080", "rules": [rule("server")], "protocol": {
            "type": "tls", "tls_targets": {"front.test": tls("tls")},
            "default_tls_target": tls("default"),
            "shadowtls_targets": {"front.test": {
                "password": "unused", "handshake": {"address": "example.com:443"},
                "protocol": websocket, "override_rules": [rule("shadow")]
            }},
            "reality_targets": {"front.test": {
                "private_key": "unused", "dest": "example.com:443", "override_rules": [rule("reality")],
                "protocol": {"type": "xhttp", "http_version": "h1", "protocol": websocket}
            }}
        }}
    ])).unwrap();
    let names = [
        "default",
        "group",
        "policy",
        "reality",
        "server",
        "shadow",
        "tls",
        "tun",
        "websocket",
    ];
    anchor(&mut configs, &dir.path().join("config.yaml")).unwrap();
    let expected: Vec<_> = names
        .iter()
        .map(|name| dir.path().join(format!("{name}.json")))
        .collect();
    assert_eq!(dependencies(&mut configs).unwrap(), expected);
    for path in &expected {
        write_domains(path, "example.com");
    }
    let mut compiler = Compiler::default();
    load(&mut configs, &mut compiler).unwrap();
    rule_visit::compile(&mut configs, &mut compiler).unwrap();
    assert_eq!(compiler.sources.len(), expected.len());
    let mut count = 0;
    rule_visit::visit(
        &mut configs,
        &mut |rule: &mut RuleConfig| {
            assert_eq!(
                rule.criteria
                    .compiled
                    .as_ref()
                    .unwrap()
                    .evaluate(Some("example.com"), None, 443),
                Outcome::Match
            );
            count += 1;
            Ok(())
        },
        &mut |_| Ok(()),
    )
    .unwrap();
    assert_eq!(count, 11);
}

#[test]
fn inline_sources_in_string_configs_require_absolute_paths() {
    let configs =
        serde_json::from_value(json!([server(json!([{"masks": {"path": "a.json"}}]))])).unwrap();
    let error = create_server_configs(configs).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("must be absolute for string configs")
    );
}

#[tokio::test]
async fn each_config_file_anchors_its_own_inline_and_group_sources() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let mut files = Vec::new();
    for (index, dir, name) in [(0, &first, "first.example"), (1, &second, "second.example")] {
        write_domains(&dir.path().join("list.json"), name);
        let config = if index == 0 {
            json!([
                {"rule_source_group": "files", "rules": ["list.json"]},
                server(json!([{"masks": {"rule_source_group": "files"}}]))
            ])
        } else {
            let mut config = server(json!([{"masks": {"path": "list.json"}}]));
            config["address"] = json!("127.0.0.1:1081");
            json!([config])
        };
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, config.to_string()).unwrap();
        files.push(path.to_str().unwrap().to_owned());
    }
    let configs = crate::config::load_configs(&files).await.unwrap();
    let validated = create_server_configs(configs).unwrap();
    for (index, name) in ["first.example", "second.example"].into_iter().enumerate() {
        let crate::config::ResolvedConfig::Server(server) = &validated.configs[index] else {
            panic!("expected server")
        };
        let rule = server.rules.iter().next().unwrap();
        assert_eq!(
            rule.criteria
                .compiled
                .as_ref()
                .unwrap()
                .evaluate(Some(name), None, 443),
            Outcome::Match
        );
    }
    assert_eq!(validated.reload_files.len(), 2);
}

#[test]
fn decoding_options_and_distinct_source_limits_apply_to_inline_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("list.txt");
    std::fs::write(&path, "DOMAIN,example.com\n").unwrap();
    let mut source = RuleSource::from_path(path);
    source.behavior = Some(Behavior::Classical);
    let mut compiler = Compiler::default();
    load_source(&source, &mut compiler).unwrap();
    source.behavior = Some(Behavior::Domain);
    assert!(load_source(&source, &mut compiler).is_err());
    let path = dir.path().join("list.json");
    write_domains(&path, "example.com");
    let source = RuleSource::from_path(path.clone());
    let predicate = load_source(&source, &mut Compiler::default()).unwrap();
    let mut compiler = Compiler::default();
    for index in 0..1024 {
        compiler.sources.insert(
            SourceKey {
                path: dir.path().join(format!("unused-{index}.json")),
                format: Format::SingboxJson,
                behavior: None,
                code: None,
                attributes: vec![],
            },
            predicate.clone(),
        );
    }
    assert!(
        load_source(&source, &mut compiler)
            .unwrap_err()
            .to_string()
            .contains("1024 distinct")
    );
    compiler.sources.remove(&SourceKey {
        path: dir.path().join("unused-0.json"),
        format: Format::SingboxJson,
        behavior: None,
        code: None,
        attributes: vec![],
    });
    let first = load_source(&source, &mut compiler).unwrap();
    let second = load_source(&source, &mut compiler).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
}
