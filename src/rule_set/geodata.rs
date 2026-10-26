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
mod tests;
