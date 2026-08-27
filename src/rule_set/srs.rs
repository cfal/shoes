//! `.srs` container decoding.
//!
//! ```text
//! file    := "SRS" | version:u8 | zlib(payload)
//! payload := uvarint(rule_count) | rule*
//! rule    := rule_type:u8 | body            ; 0 = default, 1 = logical
//! default := item* | 0xFF | invert:u8
//! ```
//!
//! This module knows the wire format and nothing about matching.

use std::io::{Error, Result};
use std::net::Ipv4Addr;

use super::ip_set::IpSet;
use super::succinct::DomainMatcher;

pub const MAGIC: &[u8; 3] = b"SRS";
pub const MAX_VERSION: u8 = 5;

// Only the tags this module branches on are named as constants; `item_name`
// covers the rest. An unused `pub const` would fail clippy under -D warnings.
pub const ITEM_DOMAIN: u8 = 2;
pub const ITEM_DOMAIN_KEYWORD: u8 = 3;
pub const ITEM_DOMAIN_REGEX: u8 = 4;
pub const ITEM_SOURCE_IP_CIDR: u8 = 5;
pub const ITEM_IP_CIDR: u8 = 6;
pub const ITEM_FINAL: u8 = 0xFF;

/// Names for every tag sing-box can emit, so an unsupported one can say what it
/// was rather than just its number.
fn item_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0 => "query_type",
        1 => "network",
        2 => "domain",
        3 => "domain_keyword",
        4 => "domain_regex",
        5 => "source_ip_cidr",
        6 => "ip_cidr",
        7 => "source_port",
        8 => "source_port_range",
        9 => "port",
        10 => "port_range",
        11 => "process_name",
        12 => "process_path",
        13 => "package_name",
        14 => "wifi_ssid",
        15 => "wifi_bssid",
        16 => "adguard_domain",
        17 => "process_path_regex",
        18 => "network_type",
        19 => "network_is_expensive",
        20 => "network_is_constrained",
        21 => "network_interface_address",
        22 => "default_interface_address",
        23 => "package_name_regex",
        _ => return None,
    })
}

/// A decoded rule, before regexes are compiled.
#[derive(Debug, Default)]
pub struct RawRule {
    pub domain: Option<DomainMatcher>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub ip_cidr: Option<IpSet>,
    pub has_source_ip_cidr: bool,
    pub invert: bool,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::other("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or_else(|| Error::other("truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u64_be(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn uvarint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if shift >= 64 {
                return Err(Error::other("uvarint overflow"));
            }
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn len_prefixed(&mut self) -> Result<&'a [u8]> {
        let n = self.uvarint()? as usize;
        self.take(n)
    }

    fn u64_slice(&mut self) -> Result<Vec<u64>> {
        let n = self.uvarint()? as usize;
        if n == 0 {
            return Ok(Vec::new());
        }
        let byte_len = n
            .checked_mul(8)
            .ok_or_else(|| Error::other("length overflow"))?;
        let bytes = self.take(byte_len)?;
        let (words, _) = bytes.as_chunks::<8>();
        Ok(words.iter().map(|c| u64::from_be_bytes(*c)).collect())
    }

    fn str_list(&mut self) -> Result<Vec<String>> {
        let n = self.uvarint()? as usize;
        // Cap the pre-allocation: `n` is attacker-controlled until it is read.
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let bytes = self.len_prefixed()?;
            out.push(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| Error::other("string is not valid UTF-8"))?,
            );
        }
        Ok(out)
    }
}

pub fn decode(bytes: &[u8]) -> Result<Vec<RawRule>> {
    if bytes.len() < 4 || &bytes[..3] != MAGIC {
        return Err(Error::other("bad magic, expected \"SRS\""));
    }
    let version = bytes[3];
    if version > MAX_VERSION {
        return Err(Error::other(format!(
            "unsupported format version {version}, expected 1 through {MAX_VERSION}"
        )));
    }

    let compressed = &bytes[4..];
    let payload = inflate(compressed)?;

    let mut reader = Reader::new(&payload);
    let count = reader.uvarint()?;
    let mut rules = Vec::with_capacity((count as usize).min(1024));
    for index in 0..count {
        let rule =
            read_rule(&mut reader).map_err(|e| Error::other(format!("rule[{index}]: {e}")))?;
        rules.push(rule);
    }
    if !reader.at_end() {
        return Err(Error::other("trailing bytes after the last rule"));
    }
    Ok(rules)
}

/// Guards against a corrupt file inflating to something that will not fit in a
/// packet tunnel's memory budget. The largest published rule-set inflates to
/// under a megabyte.
const MAX_INFLATED_LEN: usize = 64 * 1024 * 1024;

/// Inflate the zlib stream, refusing anything that does not end cleanly.
///
/// `ZlibDecoder::read_to_end` is not usable here: on a truncated stream it
/// reports success and returns a short payload, at every level of truncation,
/// even when only the four-byte Adler trailer is missing. A short payload would
/// leave a domain trie with a clipped label array -- a matcher that is quietly
/// wrong rather than one that fails. Driving `Decompress` to `StreamEnd`
/// instead makes the trailer, and with it the checksum, mandatory.
fn inflate(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decompress = flate2::Decompress::new(true);
    let mut out: Vec<u8> = Vec::with_capacity(compressed.len().saturating_mul(4).max(1024));

    loop {
        let consumed = decompress.total_in() as usize;
        let before_in = decompress.total_in();
        let before_out = decompress.total_out();

        let status = decompress
            .decompress_vec(
                &compressed[consumed..],
                &mut out,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|e| Error::other(format!("could not inflate payload: {e}")))?;

        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if out.len() == out.capacity() {
                    if out.capacity() >= MAX_INFLATED_LEN {
                        return Err(Error::other(format!(
                            "inflated payload exceeds {MAX_INFLATED_LEN} bytes"
                        )));
                    }
                    out.reserve(out.capacity());
                    continue;
                }
                if decompress.total_in() == before_in && decompress.total_out() == before_out {
                    return Err(Error::other(
                        "compressed stream is truncated: it ends before its trailer",
                    ));
                }
            }
        }
    }

    if decompress.total_in() != compressed.len() as u64 {
        return Err(Error::other(format!(
            "trailing bytes after the compressed stream: consumed {} of {}",
            decompress.total_in(),
            compressed.len()
        )));
    }

    Ok(out)
}

fn read_rule(reader: &mut Reader<'_>) -> Result<RawRule> {
    match reader.u8()? {
        0 => read_default_rule(reader),
        1 => Err(Error::other("logical rules are not supported")),
        other => Err(Error::other(format!("unknown rule type {other}"))),
    }
}

fn read_default_rule(reader: &mut Reader<'_>) -> Result<RawRule> {
    let mut rule = RawRule::default();
    loop {
        let tag = reader.u8()?;
        match tag {
            ITEM_DOMAIN => {
                let encoding = reader.u8()?;
                if encoding != 0 {
                    return Err(Error::other(format!(
                        "domain matcher: unsupported encoding version {encoding}"
                    )));
                }
                let leaves = reader.u64_slice()?;
                let label_bitmap = reader.u64_slice()?;
                let labels = reader.len_prefixed()?.to_vec();
                rule.domain = Some(DomainMatcher::from_parts(leaves, label_bitmap, labels));
            }
            ITEM_DOMAIN_KEYWORD => rule.domain_keyword = reader.str_list()?,
            ITEM_DOMAIN_REGEX => rule.domain_regex = reader.str_list()?,
            ITEM_SOURCE_IP_CIDR => {
                // Decoded rather than skipped: item payloads are not
                // self-delimiting, so skipping would desynchronise the stream.
                // Rejection happens in rule.rs, which knows it cannot evaluate it.
                read_ip_set(reader)?;
                rule.has_source_ip_cidr = true;
            }
            ITEM_IP_CIDR => rule.ip_cidr = Some(read_ip_set(reader)?),
            ITEM_FINAL => {
                rule.invert = reader.u8()? != 0;
                return Ok(rule);
            }
            other => {
                return Err(Error::other(match item_name(other) {
                    Some(name) => format!("item type {other} ({name}) is not supported"),
                    None => format!("unknown item type {other}"),
                }));
            }
        }
    }
}

fn read_ip_set(reader: &mut Reader<'_>) -> Result<IpSet> {
    let encoding = reader.u8()?;
    if encoding != 1 {
        return Err(Error::other(format!(
            "ip set: unsupported encoding version {encoding}"
        )));
    }
    // Fixed-width big-endian, not a uvarint. This is what sing-box writes.
    let count = reader.u64_be()? as usize;
    let mut ranges = Vec::with_capacity(count.min(65536));
    for _ in 0..count {
        let from = read_addr(reader)?;
        let to = read_addr(reader)?;
        ranges.push((from, to));
    }
    IpSet::new(ranges)
}

fn read_addr(reader: &mut Reader<'_>) -> Result<u128> {
    let bytes = reader.len_prefixed()?;
    match bytes.len() {
        4 => {
            let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            Ok(u128::from(addr.to_ipv6_mapped()))
        }
        16 => Ok(u128::from_be_bytes(bytes.try_into().unwrap())),
        n => Err(Error::other(format!(
            "ip set: address of {n} bytes, expected 4 or 16"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Wrap a payload in the container: magic, version, zlib.
    fn container(version: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::from(*MAGIC);
        out.push(version);
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        out.extend(encoder.finish().unwrap());
        out
    }

    /// One default rule holding one IPv4 range, then the final marker.
    fn one_ip_rule() -> Vec<u8> {
        let mut p = vec![
            0x01, // one rule
            0x00, // rule type: default
            ITEM_IP_CIDR,
            0x01, // ip set encoding version
        ];
        p.extend(1u64.to_be_bytes()); // range count, fixed-width big-endian
        p.push(4);
        p.extend([10, 0, 0, 0]);
        p.push(4);
        p.extend([10, 0, 0, 255]);
        p.push(ITEM_FINAL);
        p.push(0x00); // invert = false
        p
    }

    #[test]
    fn decodes_a_single_ip_rule() {
        let rules = decode(&container(1, &one_ip_rule())).unwrap();
        assert_eq!(rules.len(), 1);
        let set = rules[0].ip_cidr.as_ref().unwrap();
        assert_eq!(set.len(), 1);
        assert!(!rules[0].invert);
        assert!(rules[0].domain.is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = container(1, &one_ip_rule());
        bytes[0] = b'X';
        let err = decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");
    }

    #[test]
    fn rejects_a_future_version() {
        let err = decode(&container(99, &one_ip_rule())).unwrap_err();
        assert!(err.to_string().contains("version 99"), "{err}");
    }

    #[test]
    fn rejects_a_truncated_stream() {
        // flate2 inflates what it can and reports Ok, so every one of these
        // would otherwise pass through as a short, silently wrong payload.
        let bytes = container(1, &one_ip_rule());
        for cut in [1usize, 4, 5, 10] {
            match decode(&bytes[..bytes.len() - cut]) {
                Ok(_) => panic!("a cut of {cut} bytes was accepted"),
                Err(e) => assert!(e.to_string().contains("truncated"), "cut {cut}: {e}"),
            }
        }
    }

    #[test]
    fn rejects_bytes_appended_after_the_compressed_stream() {
        let mut bytes = container(1, &one_ip_rule());
        bytes.extend([0xDE, 0xAD]);
        let err = decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"), "{err}");
    }

    #[test]
    fn rejects_logical_rules() {
        let payload = vec![0x01, 0x01];
        let err = decode(&container(1, &payload)).unwrap_err();
        assert!(err.to_string().contains("logical"), "{err}");
    }

    #[test]
    fn names_a_known_but_unsupported_item() {
        let payload = vec![0x01, 0x00, 13];
        let err = decode(&container(1, &payload)).unwrap_err();
        assert!(err.to_string().contains("package_name"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_item_tag() {
        let payload = vec![0x01, 0x00, 0x7e];
        let err = decode(&container(1, &payload)).unwrap_err();
        assert!(err.to_string().contains("unknown item type 126"), "{err}");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut payload = one_ip_rule();
        payload.push(0xAA);
        let err = decode(&container(1, &payload)).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn decodes_domain_keyword_and_regex_lists() {
        let mut p = vec![0x01, 0x00, ITEM_DOMAIN_KEYWORD, 0x01, 0x03];
        p.extend(b"ads");
        p.push(ITEM_DOMAIN_REGEX);
        p.push(0x01);
        p.push(0x05);
        p.extend(b"^a.*$");
        p.push(ITEM_FINAL);
        p.push(0x01); // invert = true
        let rules = decode(&container(2, &p)).unwrap();
        assert_eq!(rules[0].domain_keyword, vec!["ads".to_string()]);
        assert_eq!(rules[0].domain_regex, vec!["^a.*$".to_string()]);
        assert!(rules[0].invert);
    }

    #[test]
    fn source_ip_cidr_is_decoded_and_flagged() {
        let mut p = vec![0x01, 0x00, ITEM_SOURCE_IP_CIDR, 0x01];
        p.extend(1u64.to_be_bytes());
        p.push(4);
        p.extend([192, 168, 0, 0]);
        p.push(4);
        p.extend([192, 168, 0, 255]);
        p.push(ITEM_FINAL);
        p.push(0x00);
        let rules = decode(&container(1, &p)).unwrap();
        assert!(rules[0].has_source_ip_cidr);
        assert!(rules[0].ip_cidr.is_none());
    }
}
