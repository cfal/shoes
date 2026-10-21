use std::io;

use prost::Message;
use prost::encoding::{WireType, decode_key, decode_varint};

use crate::rules::{Compiler, Expression, IpRanges, MAX_ENTRIES, MAX_STRING_BYTES, invalid};

// Minimal bindings for Xray common/geodata/geodat.proto. Unknown enums remain
// numeric until validation; absent enum values keep the proto3 substring default.
#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attributes: Vec<Attribute>,
}

#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(oneof = "attribute::Value", tags = "2, 3")]
    value: Option<attribute::Value>,
}

mod attribute {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        #[prost(bool, tag = "2")]
        Bool(bool),
        #[prost(int64, tag = "3")]
        Integer(i64),
    }
}

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

enum Field<'a> {
    Bytes(&'a [u8]),
    Number(u64),
}

// Scan framing with Prost's wire primitives, borrowing unselected categories.
// Strict field checks happen before Message::decode can discard unknown fields.
fn fields<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u32, Field<'a>) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let (tag, wire) = decode_key(&mut bytes).map_err(|e| invalid(e.to_string()))?;
        let value = match wire {
            WireType::Varint => {
                Field::Number(decode_varint(&mut bytes).map_err(|e| invalid(e.to_string()))?)
            }
            WireType::LengthDelimited => {
                let len = decode_varint(&mut bytes).map_err(|e| invalid(e.to_string()))?;
                let len = usize::try_from(len).map_err(|_| invalid("DAT length overflow"))?;
                if len > bytes.len() {
                    return Err(invalid("truncated DAT field"));
                }
                let (value, remaining) = bytes.split_at(len);
                bytes = remaining;
                Field::Bytes(value)
            }
            _ => return Err(invalid("unsupported DAT wire type")),
        };
        visit(tag, value)?;
    }
    Ok(())
}

fn selector(value: &str, category: bool) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_') || (category && b == b'!')
        })
        || value.starts_with('!')
    {
        return Err(invalid(
            "invalid DAT selector; use a literal category code and separate boolean attributes",
        ));
    }
    Ok(())
}

pub(super) fn decode(
    bytes: &[u8],
    geoip: bool,
    code: &str,
    attributes: &[String],
    budget: &mut Compiler,
) -> io::Result<Expression> {
    selector(code, true)?;
    for attr in attributes {
        selector(attr, false)?;
    }
    if geoip && !attributes.is_empty() {
        return Err(invalid("GeoIP has no attribute filters"));
    }
    let mut selected = None;
    fields(bytes, |tag, field| {
        let (1, Field::Bytes(category)) = (tag, field) else {
            return Err(invalid("unsupported DAT list field"));
        };
        if !category_code(category, geoip)?.eq_ignore_ascii_case(code) {
            return Ok(());
        }
        if selected.is_some() {
            return Err(invalid("duplicate selected DAT category"));
        }
        selected = Some(category_entries(category, geoip, attributes, budget)?);
        Ok(())
    })?;
    selected.ok_or_else(|| invalid(format!("DAT category {code:?} not found")))
}

fn category_code(category: &[u8], geoip: bool) -> io::Result<&str> {
    let mut code = None;
    fields(category, |tag, field| {
        match (tag, field) {
            (1, Field::Bytes(value)) if code.is_none() => {
                code = Some(
                    std::str::from_utf8(value).map_err(|_| invalid("invalid DAT category code"))?,
                );
            }
            (2, Field::Bytes(_)) => {}
            (3, Field::Number(0 | 1)) if geoip => {}
            _ => return Err(invalid("unsupported or duplicate DAT category field")),
        }
        Ok(())
    })?;
    code.ok_or_else(|| invalid("DAT category has no code"))
}

fn category_entries(
    category: &[u8],
    geoip: bool,
    attributes: &[String],
    budget: &mut Compiler,
) -> io::Result<Expression> {
    let mut count = 0;
    let mut rules = Vec::new();
    let mut ips = IpRanges::default();
    let mut invert = None;
    fields(category, |tag, field| {
        match (tag, field) {
            (1, _) => {}
            (3, Field::Number(value)) if invert.is_none() => invert = Some(value != 0),
            (2, Field::Bytes(item)) => {
                count += 1;
                if count > MAX_ENTRIES {
                    return Err(invalid("DAT entry limit exceeded"));
                }
                budget.charge(item.len().saturating_mul(8).saturating_add(256), 1)?;
                if geoip {
                    cidr(item, &mut ips)?;
                } else if let Some(rule) = domain(item, attributes, budget)? {
                    rules.push(rule);
                }
            }
            _ => return Err(invalid("duplicate or unsupported DAT category field")),
        }
        Ok(())
    })?;
    Ok(if geoip {
        Expression::Ranges(ips, false).inverted(invert.unwrap_or(false))
    } else {
        Expression::or(rules)
    })
}

fn domain(
    bytes: &[u8],
    attributes: &[String],
    budget: &mut Compiler,
) -> io::Result<Option<Expression>> {
    let mut kind_seen = false;
    let mut value_seen = false;
    fields(bytes, |tag, field| {
        match (tag, field) {
            (1, Field::Number(0..=3)) if !kind_seen => kind_seen = true,
            (2, Field::Bytes(value)) if !value_seen => {
                value_seen = true;
                if value.is_empty() || value.len() > MAX_STRING_BYTES {
                    return Err(invalid("invalid DAT domain value length"));
                }
            }
            (3, Field::Bytes(attr)) => {
                // Prost grows the repeated field geometrically; include old and
                // new vector storage before decoding even an empty attribute.
                budget.charge(4 * std::mem::size_of::<Attribute>(), 1)?;
                validate_attribute(attr)?;
            }
            _ => return Err(invalid("unsupported DAT domain field or enum")),
        }
        Ok(())
    })?;
    let domain = Domain::decode(bytes).map_err(|e| invalid(e.to_string()))?;
    if domain.value.is_empty() || !domain.value.is_ascii() {
        return Err(invalid(
            "DAT domains require nonempty ASCII A-label spelling",
        ));
    }
    if !attributes.iter().all(|key| {
        domain.attributes.iter().any(|a| {
            a.key.eq_ignore_ascii_case(key) && a.value == Some(attribute::Value::Bool(true))
        })
    }) {
        return Ok(None);
    }
    let v = vec![domain.value];
    Ok(Some(match domain.kind {
        0 => Expression::DomainKeyword(v),
        1 => Expression::DomainRegex(v),
        2 => Expression::DomainSuffix(v),
        3 => Expression::Domain(v),
        _ => return Err(invalid("unsupported DAT domain enum")),
    }))
}

fn validate_attribute(bytes: &[u8]) -> io::Result<()> {
    let mut key_seen = false;
    let mut value_seen = false;
    fields(bytes, |tag, field| {
        match (tag, field) {
            (1, Field::Bytes(key)) if key.len() <= 128 && !key_seen => key_seen = true,
            (2, Field::Number(0 | 1)) | (3, Field::Number(_)) if !value_seen => {
                value_seen = true;
            }
            _ => return Err(invalid("unsupported or duplicate DAT attribute field")),
        }
        Ok(())
    })
}

fn cidr(bytes: &[u8], ranges: &mut IpRanges) -> io::Result<()> {
    let mut ip_seen = false;
    let mut prefix_seen = false;
    fields(bytes, |tag, field| {
        match (tag, field) {
            (1, Field::Bytes(ip)) if matches!(ip.len(), 4 | 16) && !ip_seen => ip_seen = true,
            (2, Field::Number(0..=128)) if !prefix_seen => prefix_seen = true,
            _ => return Err(invalid("unsupported DAT CIDR field")),
        }
        Ok(())
    })?;
    let cidr = Cidr::decode(bytes).map_err(|e| invalid(e.to_string()))?;
    match cidr.ip.len() {
        4 if cidr.prefix <= 32 => {
            let ip = u32::from_be_bytes(cidr.ip.as_slice().try_into().unwrap());
            let mask = u32::MAX.checked_shl(32 - cidr.prefix).unwrap_or(0);
            ranges.add_v4(ip & mask, ip | !mask)
        }
        16 if cidr.prefix <= 128 => {
            let ip = u128::from_be_bytes(cidr.ip.as_slice().try_into().unwrap());
            let mask = u128::MAX.checked_shl(128 - cidr.prefix).unwrap_or(0);
            ranges.add_v6(ip & mask, ip | !mask)
        }
        _ => Err(invalid("invalid DAT CIDR family or prefix")),
    }
}

#[cfg(test)]
mod tests {
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
}
