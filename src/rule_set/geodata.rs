use std::io;

use prost::Message;
use prost::encoding::{WireType, decode_key, decode_varint};

use crate::rules::{Compiler, Expression, IpRanges, invalid};

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

fn selector(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(invalid(
            "DAT selectors require nonempty ASCII letters, digits, '-' or '_'; use attributes for boolean filters",
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
    selector(code)?;
    for attr in attributes {
        selector(attr)?;
    }
    if geoip && !attributes.is_empty() {
        return Err(invalid("GeoIP has no attribute filters"));
    }
    let mut found = false;
    let mut result = Expression::Never;
    fields(bytes, |tag, field| {
        let (1, Field::Bytes(category)) = (tag, field) else {
            return Err(invalid("unsupported DAT list field"));
        };
        let mut category_code = None;
        fields(category, |tag, field| {
            match (tag, field) {
                (1, Field::Bytes(value)) if category_code.is_none() => {
                    category_code = Some(
                        std::str::from_utf8(value)
                            .map_err(|_| invalid("invalid DAT category code"))?,
                    );
                }
                (2, Field::Bytes(_)) => {}
                (3, Field::Number(0 | 1)) if geoip => {}
                _ => return Err(invalid("unsupported or duplicate DAT category field")),
            }
            Ok(())
        })?;
        let category_code = category_code.ok_or_else(|| invalid("DAT category has no code"))?;
        if !category_code.eq_ignore_ascii_case(code) {
            return Ok(());
        }
        if found {
            return Err(invalid("duplicate selected DAT category"));
        }
        found = true;
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
                    if count > super::binary::MAX_ENTRIES {
                        return Err(invalid("DAT entry limit exceeded"));
                    }
                    budget.charge(item.len().saturating_mul(8).saturating_add(256), 1)?;
                    if geoip {
                        cidr(item, &mut ips)?;
                    } else if let Some(rule) = domain(item, attributes)? {
                        rules.push(rule);
                    }
                }
                _ => return Err(invalid("duplicate or unsupported DAT category field")),
            }
            Ok(())
        })?;
        result = if geoip {
            Expression::Ranges(ips, false).inverted(invert.unwrap_or(false))
        } else {
            Expression::or(rules)
        };
        Ok(())
    })?;
    if !found {
        return Err(invalid(format!("DAT category {code:?} not found")));
    }
    Ok(result)
}

fn domain(bytes: &[u8], attributes: &[String]) -> io::Result<Option<Expression>> {
    let mut seen = [false; 3];
    fields(bytes, |tag, field| {
        match (tag, field) {
            (1, Field::Number(0..=3)) if !std::mem::replace(&mut seen[1], true) => {}
            (2, Field::Bytes(value)) if !std::mem::replace(&mut seen[2], true) => {
                if value.is_empty() || value.len() > 64 * 1024 {
                    return Err(invalid("invalid DAT domain value length"));
                }
            }
            (3, Field::Bytes(attr)) => {
                let mut key = false;
                let mut value = false;
                fields(attr, |tag, field| {
                    match (tag, field) {
                        (1, Field::Bytes(s))
                            if s.len() <= 128 && !std::mem::replace(&mut key, true) => {}
                        (2, Field::Number(0 | 1)) | (3, Field::Number(_))
                            if !std::mem::replace(&mut value, true) => {}
                        _ => return Err(invalid("unsupported or duplicate DAT attribute field")),
                    }
                    Ok(())
                })?;
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

fn cidr(bytes: &[u8], ranges: &mut IpRanges) -> io::Result<()> {
    let mut seen = [false; 3];
    fields(bytes, |tag, field| {
        match (tag, field) {
            (1, Field::Bytes(ip))
                if matches!(ip.len(), 4 | 16) && !std::mem::replace(&mut seen[1], true) => {}
            (2, Field::Number(0..=128)) if !std::mem::replace(&mut seen[2], true) => {}
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
    use crate::rules::Outcome;

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
