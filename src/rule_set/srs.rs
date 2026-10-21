use std::io;

use super::binary::{Reader, inflate};
use super::singbox::{LiteralKind, Parts, literals, port_ranges};
use crate::rules::{Compiler, Expression, IpRanges, MAX_DEPTH, MAX_ENTRIES, invalid};

pub fn decode(bytes: &[u8], budget: &mut Compiler) -> io::Result<Expression> {
    if bytes.len() < 4 || &bytes[..3] != b"SRS" || !(1..=5).contains(&bytes[3]) {
        return Err(invalid("expected SRS version 1-5"));
    }
    let payload = inflate(&bytes[4..], budget)?;
    let mut reader = Reader::new(&payload, budget);
    let count = reader.count(false, MAX_ENTRIES, 1)?;
    reader.charge(count * 128)?;
    let mut remaining = MAX_ENTRIES;
    let mut rules = Vec::with_capacity(count);
    for i in 0..count {
        rules.push(
            rule(&mut reader, bytes[3], 0, &mut remaining)
                .map_err(|e| invalid(format!("SRS rule {i}: {e}")))?,
        );
    }
    reader.end()?;
    Ok(Expression::or(rules))
}

fn rule(
    reader: &mut Reader<'_>,
    version: u8,
    depth: usize,
    remaining: &mut usize,
) -> io::Result<Expression> {
    if depth > MAX_DEPTH || *remaining == 0 {
        return Err(invalid("SRS rule count/nesting limit exceeded"));
    }
    *remaining -= 1;
    match reader.byte()? {
        0 => default_rule(reader, version),
        1 => logical_rule(reader, version, depth, remaining),
        tag => Err(invalid(format!("unsupported SRS rule type {tag}"))),
    }
}

fn default_rule(reader: &mut Reader<'_>, version: u8) -> io::Result<Expression> {
    let mut parts = Parts::default();
    let mut seen = [false; 256];
    loop {
        let tag = reader.byte()?;
        if tag == 255 {
            return parts.finish(reader.boolean()?);
        }
        if std::mem::replace(&mut seen[tag as usize], true) {
            return Err(invalid(format!("duplicate SRS tag {tag}")));
        }
        match tag {
            2 => {
                let mut exact = Vec::new();
                let mut suffix = Vec::new();
                let keys = reader.domain_keys(false)?;
                if keys.is_empty() {
                    return Err(invalid("empty SRS domain set"));
                }
                for key in keys {
                    match key.as_bytes().first() {
                        Some(b'\n') if version >= 2 => suffix.push(key[1..].to_owned()),
                        Some(b'\r') if key.starts_with("\r.") => suffix.push(key[1..].to_owned()),
                        Some(b'\n' | b'\r') => {
                            return Err(invalid("invalid SRS domain marker/version"));
                        }
                        _ => exact.push(key),
                    }
                }
                if !exact.is_empty() {
                    parts.address.push(literals(exact, LiteralKind::Exact)?);
                }
                if !suffix.is_empty() {
                    parts.address.push(literals(suffix, LiteralKind::Suffix)?);
                }
            }
            3 => {
                let strings = reader.strings()?;
                if !strings.is_empty() {
                    parts.address.push(literals(strings, LiteralKind::Keyword)?);
                }
            }
            4 => {
                let strings = reader.strings()?;
                if !strings.is_empty() {
                    parts.address.push(Expression::DomainRegex(strings));
                }
            }
            6 => {
                if reader.byte()? != 1 {
                    return Err(invalid("unsupported SRS IP-set version"));
                }
                let count = reader.count(true, MAX_ENTRIES, 2)?;
                if count == 0 {
                    return Err(invalid("empty SRS IP set"));
                }
                reader.charge(count * 64)?;
                let mut ranges = IpRanges::default();
                for _ in 0..count {
                    let a = reader.count(false, 16, 1)?;
                    let from = reader.take(a)?;
                    let b = reader.count(false, 16, 1)?;
                    let to = reader.take(b)?;
                    ranges.add_encoded(from, to, false)?;
                }
                parts.address.push(Expression::Ranges(ranges, false));
            }
            9 => {
                let count = reader.count(false, MAX_ENTRIES, 2)?;
                reader.charge(count * 8)?;
                let mut ports = Vec::with_capacity(count);
                for _ in 0..count {
                    let port = reader.u16()?;
                    ports.push((port, port));
                }
                if count != 0 {
                    parts.ports.push(Expression::PortRanges(ports));
                }
            }
            10 => {
                let strings = reader.strings()?;
                if !strings.is_empty() {
                    parts.ports.push(port_ranges(strings)?);
                }
            }
            _ => return Err(invalid(format!("unsupported SRS predicate tag {tag}"))),
        }
    }
}

fn logical_rule(
    reader: &mut Reader<'_>,
    version: u8,
    depth: usize,
    remaining: &mut usize,
) -> io::Result<Expression> {
    let mode = reader.byte()?;
    if mode > 1 {
        return Err(invalid("invalid SRS logical mode"));
    }
    let count = reader.count(false, MAX_ENTRIES, 1)?;
    reader.charge(count * 128)?;
    if count == 0 {
        return Err(invalid("empty SRS logical rule"));
    }
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        children.push(rule(reader, version, depth + 1, remaining)?);
    }
    Ok(if mode == 0 {
        Expression::All(children)
    } else {
        Expression::Any(children)
    }
    .inverted(reader.boolean()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Compiler, Outcome};
    use std::io::Write;

    fn decode(bytes: &[u8]) -> io::Result<Expression> {
        super::decode(bytes, &mut Compiler::default())
    }

    fn wrap(version: u8, payload: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let mut bytes = vec![b'S', b'R', b'S', version];
        bytes.extend(encoder.finish().unwrap());
        bytes
    }

    #[test]
    fn upstream_fixture_matches_source_and_rejects_truncation() {
        let bytes = include_bytes!("../../tests/fixtures/rule_sets/singbox-v2.srs");
        let json = include_bytes!("../../tests/fixtures/rule_sets/singbox.json");
        let expected = Compiler::default()
            .compile(super::super::singbox::decode(json, &mut Compiler::default()).unwrap())
            .unwrap();
        for version in 2..=5 {
            let mut bytes = bytes.to_vec();
            bytes[3] = version;
            let actual = Compiler::default()
                .compile(decode(&bytes).unwrap())
                .unwrap();
            for name in [
                None,
                Some("exact.example"),
                Some("a.exact.example"),
                Some("suffix.example"),
                Some("a.suffix.example"),
                Some("strict.example"),
                Some("a.strict.example"),
                Some("upper.example"),
                Some("keyword.example"),
                Some("regex27.example"),
                Some("case.example"),
                Some("not.example"),
            ] {
                for ip in [
                    None,
                    Some("192.0.2.1".parse().unwrap()),
                    Some("2001:db8::1".parse().unwrap()),
                    Some("203.0.113.7".parse().unwrap()),
                ] {
                    for port in [80, 443, 8000, 8002, 8443] {
                        assert_eq!(
                            actual.evaluate(name, ip, port),
                            expected.evaluate(name, ip, port)
                        );
                    }
                }
            }
        }
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "accepted truncation at {n}");
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut corrupt = bytes.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode(&corrupt).is_err());
    }

    #[test]
    fn versions_empty_sets_and_unsupported_items() {
        for v in 1..=5 {
            let predicate = Compiler::default()
                .compile(decode(&wrap(v, &[0])).unwrap())
                .unwrap();
            assert_eq!(predicate.evaluate(None, None, 1), Outcome::Miss);
            assert!(decode(&wrap(v, &[1, 0, 255, 0])).is_err());
            assert!(
                decode(&wrap(v, &[1, 0, 5]))
                    .unwrap_err()
                    .to_string()
                    .contains("tag 5")
            );
            assert!(decode(&wrap(v, &[1, 1, 0, 0, 0])).is_err());
        }
        assert!(decode(&wrap(6, &[0])).is_err());
    }

    fn chain(key: &[u8]) -> Vec<u8> {
        assert!(key.len() < 32);
        let mut out = vec![0, 1];
        out.extend((1u64 << key.len()).to_be_bytes());
        out.push(1);
        let bitmap = (0..key.len()).fold(1u64 << (2 * key.len()), |b, i| b | (1 << (2 * i + 1)));
        out.extend(bitmap.to_be_bytes());
        out.push(key.len() as u8);
        out.extend(key.iter().rev());
        out
    }

    #[test]
    fn original_v1_exact_and_strict_suffix_union() {
        let mut payload = vec![2];
        for key in [b"a".as_slice(), b"\r.a"] {
            payload.extend([0, 2]);
            payload.extend(chain(key));
            payload.extend([255, 0]);
        }
        let p = Compiler::default()
            .compile(decode(&wrap(1, &payload)).unwrap())
            .unwrap();
        for name in ["a", "b.a", "c.b.a"] {
            assert_eq!(p.evaluate(Some(name), None, 1), Outcome::Match);
        }
        assert_eq!(p.evaluate(Some("ba"), None, 1), Outcome::Miss);
    }

    #[test]
    fn empty_lists_are_absent_but_empty_index_objects_reject() {
        for tag in [3, 4, 9, 10] {
            for invert in [0, 1] {
                assert!(decode(&wrap(2, &[1, 0, tag, 0, 255, invert])).is_err());
            }
            let mut payload = vec![1, 0, 2];
            payload.extend(chain(b"a"));
            payload.extend([tag, 0, 255, 0]);
            let p = Compiler::default()
                .compile(decode(&wrap(2, &payload)).unwrap())
                .unwrap();
            assert_eq!(p.evaluate(Some("a"), None, 443), Outcome::Match);
        }
        let mut empty_ips = vec![1, 0, 6, 1];
        empty_ips.extend(0u64.to_be_bytes());
        empty_ips.extend([9, 1, 1, 187, 255, 1]);
        assert!(decode(&wrap(2, &empty_ips)).is_err());
        // A valid empty root-only domain set: no terminals, one node terminator.
        let mut empty_names = vec![1, 0, 2, 0, 0, 1];
        empty_names.extend(1u64.to_be_bytes());
        empty_names.extend([0, 9, 1, 1, 187, 255, 1]);
        assert!(decode(&wrap(2, &empty_names)).is_err());
    }

    #[test]
    fn repeated_predicate_tag_rejects_before_empty_rule_validation() {
        assert_eq!(
            decode(&wrap(2, &[1, 0, 3, 0, 3, 0, 255, 0]))
                .unwrap_err()
                .to_string(),
            "SRS rule 0: duplicate SRS tag 3"
        );
    }

    #[test]
    fn mapped_ipv6_and_inconsistent_tries_reject() {
        let mut payload = vec![1, 0, 6, 1];
        payload.extend(1u64.to_be_bytes());
        for _ in 0..2 {
            payload.push(16);
            payload.extend(
                "::ffff:192.0.2.1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
        }
        payload.extend([255, 0]);
        assert!(
            decode(&wrap(1, &payload))
                .unwrap_err()
                .to_string()
                .contains("mapped")
        );
        for (index, byte) in [(9, 0x80), (18, 0x80), (18, 1)] {
            let mut trie = chain(b"a");
            trie[index] = byte;
            assert!(
                Reader::new(&trie, &mut Compiler::default())
                    .domain_keys(false)
                    .is_err()
            );
        }
    }
}
