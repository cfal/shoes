use super::*;
use crate::config::{ConfigSelection, RuleActionConfig, RuleConfig, create_server_configs};
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
            {"rule_group": "files", "rules": ["a.json", {"path": "b.json"}]},
            {"rule_group": "policies", "rules": [
                {"masks": {"rule_group": "files"}, "action": "block"},
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
    let Config::Server(server) = &validated.configs[0] else {
        panic!("expected server")
    };
    let rules: Vec<_> = server
        .rules
        .iter()
        .map(|selection| {
            let ConfigSelection::Config(rule) = selection else {
                panic!("unexpanded policy")
            };
            rule
        })
        .collect();
    assert_eq!(rules.len(), 3);
    assert!(matches!(rules[0].action, RuleActionConfig::Block));
    assert!(matches!(rules[1].action, RuleActionConfig::Allow { .. }));
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
fn inline_and_named_sources_share_the_same_predicate() {
    let dir = tempfile::tempdir().unwrap();
    write_domains(&dir.path().join("a.json"), "a.example");
    let mut configs: Vec<Config> = serde_json::from_value(json!([
        {"rule_group": "files", "rules": ["a.json"]},
        server(json!([
            {"masks": {"rule_group": "files"}},
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
        let ConfigSelection::Config(rule) = selection else {
            panic!("expected rule")
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
                {"rule_group": "files", "rules": ["a.json"]}, server(json!("files"))
            ]),
            "contains file sources",
        ),
        (
            json!([
                {"rule_group": "policies", "rules": [{"masks": "example.com"}]},
                server(json!([{"masks": {"not": {"rule_group": "policies"}}}]))
            ]),
            "contains policies with actions",
        ),
        (
            json!([server(json!([{"masks": {"rule_group": "block-all"}}]))]),
            "contains policies with actions",
        ),
        (
            json!([server(json!([{"masks": {"rule_group": "a.json"}}]))]),
            "unknown rule group",
        ),
        (json!([server(json!("missing"))]), "unknown rule group"),
        (
            json!([
                {"rule_group": "same", "rules": ["a.json"]},
                {"rule_group": "same", "rules": [{"masks": "example.com"}]}
            ]),
            "duplicate or empty rule group name",
        ),
        (
            json!([{"rule_group": "block-all", "rules": ["a.json"]}]),
            "duplicate or empty rule group name",
        ),
        (
            json!([{"rule_group": "", "rules": ["a.json"]}]),
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
        {"rule_group": "files", "rules": ["group.json"]},
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
                {"rule_group": "files", "rules": ["list.json"]},
                server(json!([{"masks": {"rule_group": "files"}}]))
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
        let Config::Server(server) = &validated.configs[index] else {
            panic!("expected server")
        };
        let ConfigSelection::Config(rule) = server.rules.iter().next().unwrap() else {
            panic!("expected rule")
        };
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
