use std::io::{self, Read};

use super::binary::{Reader, append_inflated};
use super::mihomo::{Behavior, domain_entry};
use crate::rules::{Compiler, Expression, IpRanges, MAX_ENTRIES, invalid};

const MAX_WINDOW: usize = 8 * 1024 * 1024;

fn inflate(bytes: &[u8], budget: &mut Compiler) -> io::Result<Vec<u8>> {
    budget.charge(MAX_WINDOW * 3, 0)?;
    let mut decoder =
        ruzstd::decoding::StreamingDecoder::new_with_max_window_size(bytes, MAX_WINDOW as u64)
            .map_err(|e| invalid(format!("MRS zstd header: {e}")))?;
    let mut output = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let len = decoder.read(&mut chunk)?;
        if len == 0 {
            break;
        }
        append_inflated(&mut output, &chunk[..len], budget)?;
    }
    let (remaining, decoder) = decoder.into_parts();
    if !remaining.is_empty() || !decoder.is_finished() {
        return Err(invalid("MRS requires exactly one complete zstd frame"));
    }
    if let Some(expected) = decoder.get_checksum_from_data()
        && decoder.get_calculated_checksum() != Some(expected)
    {
        return Err(invalid("MRS zstd checksum mismatch"));
    }
    if decoder.content_size() != 0 && decoder.content_size() != output.len() as u64 {
        return Err(invalid("MRS zstd content size mismatch"));
    }
    Ok(output)
}

pub(super) fn decode(
    bytes: &[u8],
    behavior: Option<Behavior>,
    budget: &mut Compiler,
) -> io::Result<Expression> {
    let payload = inflate(bytes, budget)?;
    let mut r = Reader::new(&payload, budget);
    if r.take(4)? != b"MRS\x01" {
        return Err(invalid("expected MRS version 1"));
    }
    let actual = match r.byte()? {
        0 => Behavior::Domain,
        1 => Behavior::Ipcidr,
        _ => {
            return Err(invalid(
                "unsupported MRS behavior (classical is not supported)",
            ));
        }
    };
    if behavior.is_some_and(|b| b != actual) {
        return Err(invalid("MRS behavior disagrees with config"));
    }
    if r.u64()? > MAX_ENTRIES as u64 {
        return Err(invalid("negative or oversized MRS source count"));
    }
    let extra = r.count(true, 64 * 1024, 1)?;
    r.take(extra)?;
    let expression = match actual {
        Behavior::Domain => {
            let keys = r.domain_keys(true)?;
            let mut rules = Vec::with_capacity(keys.len());
            for key in keys {
                if key.starts_with('.')
                    || key.ends_with('.')
                    || key.bytes().any(|b| b.is_ascii_uppercase())
                {
                    return Err(invalid("noncanonical MRS domain key"));
                }
                // MRS's internal + marker denotes a strict suffix. Inclusive
                // source entries also produce a separate exact terminal.
                rules.push(domain_entry(if key.starts_with("+.") {
                    &key[1..]
                } else {
                    &key
                })?);
            }
            Expression::or(rules)
        }
        Behavior::Ipcidr => {
            if r.byte()? != 1 {
                return Err(invalid("unsupported MRS IP-set version"));
            }
            let count = r.count(true, MAX_ENTRIES, 32)?;
            r.charge(count * 64)?;
            let mut ranges = IpRanges::default();
            for _ in 0..count {
                ranges.add_encoded(r.take(16)?, r.take(16)?, true)?;
            }
            Expression::Ranges(ranges, false)
        }
        Behavior::Classical => unreachable!(),
    };
    r.end()?;
    Ok(expression)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Outcome;

    fn raw_frame(payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 256);
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, payload.len() as u8];
        frame.extend_from_slice(&((payload.len() as u32 * 8) + 1).to_le_bytes()[..3]);
        frame.extend_from_slice(payload);
        frame
    }

    fn ip_frame(ranges: &[(&str, &str)]) -> Vec<u8> {
        let mut body = b"MRS\x01\x01".to_vec();
        body.extend(9i64.to_be_bytes()); // Input count is not the merged range count.
        body.extend(3i64.to_be_bytes());
        body.extend(b"ext");
        body.push(1);
        body.extend((ranges.len() as i64).to_be_bytes());
        for &(a, b) in ranges {
            for value in [a, b] {
                body.extend(value.parse::<std::net::Ipv6Addr>().unwrap().octets());
            }
        }
        raw_frame(&body)
    }

    #[test]
    fn noncanonical_domain_keys_reject_instead_of_changing_membership() {
        for key in ["A", ".a", "a.", "+.a", "a"] {
            let mut body = b"MRS\x01\x00".to_vec();
            body.extend(1i64.to_be_bytes());
            body.extend(0i64.to_be_bytes());
            body.push(1);
            body.extend(1i64.to_be_bytes());
            body.extend((1u64 << key.len()).to_be_bytes());
            body.extend(1i64.to_be_bytes());
            let bitmap =
                (0..key.len()).fold(1u64 << (key.len() * 2), |bits, i| bits | (1 << (2 * i + 1)));
            body.extend(bitmap.to_be_bytes());
            body.extend((key.len() as i64).to_be_bytes());
            body.extend(key.bytes().rev());
            let result = decode(&raw_frame(&body), None, &mut Compiler::default());
            assert_eq!(result.is_ok(), matches!(key, "+.a" | "a"), "{key}");
        }
    }

    #[test]
    fn frames_families_and_bounds() {
        let bytes = ip_frame(&[
            ("::ffff:192.0.2.0", "::ffff:192.0.2.255"),
            ("::", "::1:0:0:0"),
        ]);
        let p = Compiler::default()
            .compile(decode(&bytes, None, &mut Compiler::default()).unwrap())
            .unwrap();
        for ip in ["192.0.2.0", "192.0.2.255", "::ffff:192.0.2.1", "::1"] {
            assert_eq!(
                p.evaluate(None, Some(ip.parse().unwrap()), 80),
                Outcome::Match
            );
        }
        assert_eq!(
            p.evaluate(None, Some("198.51.100.1".parse().unwrap()), 80),
            Outcome::Miss
        );
        assert!(decode(&bytes, Some(Behavior::Domain), &mut Compiler::default()).is_err());
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n], None, &mut Compiler::default()).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing, None, &mut Compiler::default()).is_err());
        let mixed = ip_frame(&[("::ffff:192.0.2.0", "2001:db8::1")]);
        assert!(decode(&mixed, None, &mut Compiler::default()).is_err());
        assert!(inflate(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0xff], &mut Compiler::default()).is_err());
        let mut body = b"MRS\x01\x00".to_vec();
        body.extend((-1i64).to_be_bytes());
        body.extend(0i64.to_be_bytes());
        assert!(decode(&raw_frame(&body), None, &mut Compiler::default()).is_err());
    }

    #[test]
    fn upstream_provider_fixtures() {
        for (binary, text, behavior) in [
            (
                include_bytes!("../../tests/fixtures/rule_sets/mihomo-domain.mrs").as_slice(),
                include_bytes!("../../tests/fixtures/rule_sets/mihomo-domain.txt").as_slice(),
                Behavior::Domain,
            ),
            (
                include_bytes!("../../tests/fixtures/rule_sets/mihomo-ip.mrs").as_slice(),
                include_bytes!("../../tests/fixtures/rule_sets/mihomo-ip.txt").as_slice(),
                Behavior::Ipcidr,
            ),
        ] {
            let actual = Compiler::default()
                .compile(decode(binary, Some(behavior), &mut Compiler::default()).unwrap())
                .unwrap();
            let expected = Compiler::default()
                .compile(
                    super::super::mihomo::decode(text, false, behavior, &mut Compiler::default())
                        .unwrap(),
                )
                .unwrap();
            for name in [
                None,
                Some("exact.example"),
                Some("suffix.example"),
                Some("a.suffix.example"),
                Some("strict.example"),
                Some("a.b.strict.example"),
                Some("a.wildcard.example"),
                Some("a.b.wildcard.example"),
                Some("a.b.middle.example"),
            ] {
                for ip in [
                    None,
                    Some("192.0.2.1".parse().unwrap()),
                    Some("2001:db8::1".parse().unwrap()),
                    Some("198.51.100.1".parse().unwrap()),
                ] {
                    assert_eq!(
                        actual.evaluate(name, ip, 443),
                        expected.evaluate(name, ip, 443),
                        "{name:?} {ip:?}"
                    );
                }
            }
            for n in 0..binary.len() {
                assert!(decode(&binary[..n], None, &mut Compiler::default()).is_err());
            }
            let mut corrupt = binary.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(decode(&corrupt, None, &mut Compiler::default()).is_err());
        }
    }
}
