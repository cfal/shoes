use super::*;
use crate::rule_set::{Format, RuleSource, load_source};
use crate::rules::Outcome;
use std::sync::Arc;

#[test]
fn wire_validation_preserves_defaults_and_duplicate_rejection() {
    let name = [0x12, 1, b'a'];
    assert!(matches!(
        domain(&name, &[], &mut Compiler::default()).unwrap(),
        Some(Expression::DomainKeyword(names)) if names == ["a"]
    ));
    for fields in [vec![0x08, 0, 0x08, 0], name.to_vec()] {
        let bytes = [name.as_slice(), &fields].concat();
        assert_eq!(
            domain(&bytes, &[], &mut Compiler::default())
                .unwrap_err()
                .to_string(),
            "unsupported DAT domain field or enum"
        );
    }

    for bytes in [
        &[][..],
        &[0x0a, 1, b'a'],
        &[0x10, 0],
        &[0x18, 7],
        &[0x10, 1, 0x0a, 1, b'a'],
    ] {
        validate_attribute(bytes).unwrap();
    }
    for bytes in [
        &[0x0a, 0, 0x0a, 0][..],
        &[0x10, 0, 0x10, 1],
        &[0x10, 1, 0x18, 7],
        &[0x18, 7, 0x10, 1],
        &[0x10, 2],
    ] {
        assert_eq!(
            validate_attribute(bytes).unwrap_err().to_string(),
            "unsupported or duplicate DAT attribute field"
        );
    }

    let ip = [0x0a, 4, 192, 0, 2, 1];
    let mut ranges = IpRanges::default();
    cidr(&ip, &mut ranges).unwrap();
    assert_eq!(ranges.v4, [(0, u32::MAX)]);
    for fields in [ip.to_vec(), vec![0x10, 24, 0x10, 24]] {
        let bytes = [ip.as_slice(), &fields].concat();
        assert_eq!(
            cidr(&bytes, &mut IpRanges::default())
                .unwrap_err()
                .to_string(),
            "unsupported DAT CIDR field"
        );
    }
}

#[test]
fn attributes_are_charged_before_prost_materialization() {
    let mut bytes = vec![0x12, 1, b'a'];
    bytes.extend_from_slice(&[0x1a, 0].repeat(10_000));
    let mut budget = Compiler::default();
    budget.charge(511 * 1024 * 1024, 0).unwrap();
    assert!(
        domain(&bytes, &[], &mut budget)
            .unwrap_err()
            .to_string()
            .contains("budget")
    );
}

#[test]
fn literal_category_exclamation_is_not_selector_syntax() {
    let bytes = Sites {
        entries: vec![Site {
            code: "GEOLOCATION-!CN".into(),
            domains: vec![Domain {
                kind: 3,
                value: "example.com".into(),
                attributes: vec![],
            }],
        }],
    }
    .encode_to_vec();
    let expression = decode(
        &bytes,
        false,
        "geolocation-!cn",
        &[],
        &mut Compiler::default(),
    )
    .unwrap();
    let predicate = Compiler::default().compile(expression).unwrap();
    assert_eq!(
        predicate.evaluate(Some("example.com"), None, 80),
        Outcome::Match
    );
    for code in ["!cn", "test@ads", "geosite:test"] {
        assert!(selector(code, true).is_err());
    }
}

#[derive(Clone, PartialEq, Message)]
struct Site {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domains: Vec<Domain>,
}
#[derive(Clone, PartialEq, Message)]
struct Sites {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<Site>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidrs: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    reverse: bool,
}
#[derive(Clone, PartialEq, Message)]
struct GeoIps {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoIp>,
}

#[test]
fn equivalent_geosite_options_share_cached_predicates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geosite.dat");
    let bytes = Sites {
        entries: vec![Site {
            code: "TEST".into(),
            domains: [
                ("both.example", vec!["ads", "mobile"]),
                ("ads.example", vec!["ads"]),
            ]
            .into_iter()
            .map(|(value, attributes)| Domain {
                kind: 3,
                value: value.into(),
                attributes: attributes
                    .into_iter()
                    .map(|key| Attribute {
                        key: key.into(),
                        value: Some(attribute::Value::Bool(true)),
                    })
                    .collect(),
            })
            .collect(),
        }],
    }
    .encode_to_vec();
    std::fs::write(&path, bytes).unwrap();
    let mut source = RuleSource {
        path,
        format: Some(Format::GeositeDat),
        behavior: None,
        code: Some("test".into()),
        attributes: vec!["ads".into(), "mobile".into()],
    };
    let mut compiler = Compiler::default();
    let first = load_source(&source, &mut compiler).unwrap();
    assert_eq!(
        first.evaluate(Some("both.example"), None, 80),
        Outcome::Match
    );
    assert_eq!(first.evaluate(Some("ads.example"), None, 80), Outcome::Miss);
    source.code = Some("TEST".into());
    source.attributes = vec!["MOBILE".into(), "ADS".into(), "ads".into()];
    let equivalent = load_source(&source, &mut compiler).unwrap();
    assert!(Arc::ptr_eq(&first, &equivalent));
    assert_eq!(compiler.sources.len(), 1);

    source.attributes = vec!["ads".into()];
    let different = load_source(&source, &mut compiler).unwrap();
    assert!(!Arc::ptr_eq(&first, &different));
    assert_eq!(
        different.evaluate(Some("ads.example"), None, 80),
        Outcome::Match
    );
    assert_eq!(compiler.sources.len(), 2);

    source.code = Some("ABSENT".into());
    let error = load_source(&source, &mut compiler).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("DAT category \"ABSENT\" not found")
    );
    assert_eq!(compiler.sources.len(), 2);
}

#[test]
fn geoip_cache_preserves_distinct_categories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("geoip.dat");
    let bytes = GeoIps {
        entries: ["TEST", "OTHER"]
            .into_iter()
            .map(|code| GeoIp {
                code: code.into(),
                reverse: code == "OTHER",
                cidrs: vec![Cidr {
                    ip: vec![192, 0, 2, 0],
                    prefix: 24,
                }],
            })
            .collect(),
    }
    .encode_to_vec();
    std::fs::write(&path, bytes).unwrap();
    let mut source = RuleSource {
        path,
        format: Some(Format::GeoipDat),
        behavior: None,
        code: Some("test".into()),
        attributes: vec![],
    };
    let mut compiler = Compiler::default();
    let first = load_source(&source, &mut compiler).unwrap();
    source.code = Some("TEST".into());
    assert!(Arc::ptr_eq(
        &first,
        &load_source(&source, &mut compiler).unwrap()
    ));
    assert_eq!(compiler.sources.len(), 1);

    source.code = Some("other".into());
    let different = load_source(&source, &mut compiler).unwrap();
    assert!(!Arc::ptr_eq(&first, &different));
    let ip = Some("192.0.2.1".parse().unwrap());
    assert_eq!(first.evaluate(None, ip, 80), Outcome::Match);
    assert_eq!(different.evaluate(None, ip, 80), Outcome::Miss);
    assert_eq!(compiler.sources.len(), 2);

    source.attributes = vec!["ADS".into()];
    let error = load_source(&source, &mut compiler).unwrap_err();
    assert!(error.to_string().contains("GeoIP has no attribute filters"));
    assert_eq!(compiler.sources.len(), 2);
}

#[test]
fn selected_category_duplicates_and_unselected_framing_reject() {
    let category = Site {
        code: "TEST".into(),
        domains: vec![],
    };
    let bytes = Sites {
        entries: vec![category.clone(), category],
    }
    .encode_to_vec();
    assert_eq!(
        decode(&bytes, false, "test", &[], &mut Compiler::default())
            .unwrap_err()
            .to_string(),
        "duplicate selected DAT category"
    );
    assert_eq!(
        decode(&bytes, false, "absent", &[], &mut Compiler::default())
            .unwrap_err()
            .to_string(),
        "DAT category \"absent\" not found"
    );
    for code in ["a", "absent"] {
        for (category, error) in [
            (vec![0x12, 0], "DAT category has no code"),
            (
                vec![0x0a, 1, b'a', 0x0a, 1, b'a'],
                "unsupported or duplicate DAT category field",
            ),
            (
                vec![0x0a, 1, b'a', 0x18, 2],
                "unsupported or duplicate DAT category field",
            ),
        ] {
            let mut bytes = vec![0x0a, category.len() as u8];
            bytes.extend(category);
            assert_eq!(
                decode(&bytes, true, code, &[], &mut Compiler::default())
                    .unwrap_err()
                    .to_string(),
                error
            );
        }
    }
    // Duplicate reverse flags are checked only in the selected category.
    let bytes = [0x0a, 7, 0x0a, 1, b'a', 0x18, 0, 0x18, 1];
    assert_eq!(
        decode(&bytes, true, "a", &[], &mut Compiler::default())
            .unwrap_err()
            .to_string(),
        "duplicate or unsupported DAT category field"
    );
    assert_eq!(
        decode(&bytes, true, "absent", &[], &mut Compiler::default())
            .unwrap_err()
            .to_string(),
        "DAT category \"absent\" not found"
    );
}

#[test]
fn categories_domain_kinds_and_boolean_attributes() {
    let mut sites = Sites {
        entries: vec![Site {
            code: "TEST".into(),
            domains: [
                (0, "keyword"),
                (1, "^regex[0-9]+$"),
                (2, "suffix.example"),
                (3, "exact.example"),
            ]
            .into_iter()
            .map(|(kind, value)| Domain {
                kind,
                value: value.into(),
                attributes: vec![Attribute {
                    key: "ads".into(),
                    value: Some(attribute::Value::Bool(true)),
                }],
            })
            .collect(),
        }],
    };
    sites.entries[0].domains.push(Domain {
        kind: 3,
        value: "false.example".into(),
        attributes: vec![Attribute {
            key: "ads".into(),
            value: Some(attribute::Value::Bool(false)),
        }],
    });
    let bytes = sites.encode_to_vec();
    let expression = decode(
        &bytes,
        false,
        "test",
        &["ads".into()],
        &mut Compiler::default(),
    )
    .unwrap();
    let p = Compiler::default().compile(expression).unwrap();
    for name in [
        "a.keyword.example",
        "regex27",
        "suffix.example",
        "a.suffix.example",
        "exact.example",
    ] {
        assert_eq!(p.evaluate(Some(name), None, 80), Outcome::Match);
    }
    assert_eq!(p.evaluate(Some("a.exact.example"), None, 80), Outcome::Miss);
    assert_eq!(p.evaluate(Some("false.example"), None, 80), Outcome::Miss);
    assert!(decode(&bytes, false, "absent", &[], &mut Compiler::default()).is_err());
    assert!(decode(&bytes, false, "test@ads", &[], &mut Compiler::default()).is_err());
    sites.entries[0].domains[0].kind = 99;
    assert!(
        decode(
            &sites.encode_to_vec(),
            false,
            "test",
            &[],
            &mut Compiler::default()
        )
        .is_err()
    );
}

#[test]
fn cidr_reverse_family_and_strict_wire_validation() {
    let bytes = GeoIps {
        entries: vec![GeoIp {
            code: "TEST".into(),
            reverse: true,
            cidrs: vec![
                Cidr {
                    ip: vec![192, 0, 2, 0],
                    prefix: 24,
                },
                Cidr {
                    ip: "2001:db8::"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    prefix: 32,
                },
            ],
        }],
    }
    .encode_to_vec();
    let p = Compiler::default()
        .compile(decode(&bytes, true, "test", &[], &mut Compiler::default()).unwrap())
        .unwrap();
    assert_eq!(
        p.evaluate(None, Some("192.0.2.1".parse().unwrap()), 80),
        Outcome::Miss
    );
    assert_eq!(
        p.evaluate(None, Some("2001:db8::1".parse().unwrap()), 80),
        Outcome::Miss
    );
    assert_eq!(
        p.evaluate(None, Some("198.51.100.1".parse().unwrap()), 80),
        Outcome::Match
    );
    assert_eq!(
        p.evaluate(Some("x"), None, 80),
        Outcome::Unknown { may_resolve: true }
    );
    for n in 1..bytes.len() {
        assert!(decode(&bytes[..n], true, "test", &[], &mut Compiler::default()).is_err());
    }
    let mut unknown = bytes.clone();
    prost::encoding::encode_key(2, WireType::Varint, &mut unknown);
    prost::encoding::encode_varint(0, &mut unknown);
    assert!(decode(&unknown, true, "test", &[], &mut Compiler::default()).is_err());
    assert!(
        decode(
            &bytes,
            true,
            "test",
            &["ads".into()],
            &mut Compiler::default()
        )
        .is_err()
    );
    let malformed = Cidr {
        ip: vec![1, 2, 3, 4],
        prefix: 33,
    }
    .encode_to_vec();
    assert!(cidr(&malformed, &mut IpRanges::default()).is_err());
}
