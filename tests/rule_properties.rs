use std::io::Write;
use std::path::Path;

use shoes::rule_set::{Behavior, Format, RuleSource, load_source};
use shoes::rules::{Compiler, Outcome};

const MAX_INPUT: usize = 4096;
const BUDGET: usize = 72 * 1024 * 1024;
const SEED: u64 = 0x726c_7365_745f_3234;

fn rule_source(path: &Path, format: Format) -> RuleSource {
    RuleSource {
        path: path.to_owned(),
        format: Some(format),
        behavior: (format == Format::MihomoText).then_some(Behavior::Domain),
        code: None,
        attributes: vec![],
    }
}

fn load_outcomes(
    path: &Path,
    bytes: &[u8],
    format: Format,
    budget: usize,
) -> std::io::Result<Vec<Outcome>> {
    assert!(bytes.len() <= MAX_INPUT);
    std::fs::write(path, bytes).unwrap();
    let mut compiler = Compiler::default();
    // Use the public accounting API to cap decoding, inflation and compilation.
    compiler.charge(512 * 1024 * 1024 - budget, 0).unwrap();
    let predicate = load_source(&rule_source(path, format), &mut compiler)?;
    let address = "192.0.2.1".parse().unwrap();
    Ok(["exact.example", "a.suffix.example", "miss.invalid"]
        .into_iter()
        .flat_map(|name| {
            [80, 443, 8443].map(|port| predicate.evaluate(Some(name), Some(address), port))
        })
        .collect())
}

fn random(state: &mut u64) -> usize {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as usize
}

#[test]
fn bounded_rule_mutations_are_deterministic_and_do_not_panic() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let seeds = [
        (
            Format::SingboxJson,
            include_bytes!("fixtures/rule_sets/singbox.json").as_slice(),
        ),
        (
            Format::Srs,
            include_bytes!("fixtures/rule_sets/singbox-v2.srs").as_slice(),
        ),
        (
            Format::MihomoText,
            include_bytes!("fixtures/rule_sets/mihomo-domain.txt").as_slice(),
        ),
    ];
    let comparable = |result: std::io::Result<Vec<Outcome>>| {
        result.map_err(|error| (error.kind(), error.to_string()))
    };
    let mut state = SEED;
    let mut cases = 0;
    for (format, seed) in seeds {
        // Ensure the reserved budget still reaches successful parsing, not just rejection.
        assert!(
            load_outcomes(&path, seed, format, BUDGET).is_ok(),
            "seed {format:?}"
        );
        for case in 0..96 {
            let mut bytes = seed.to_vec();
            let index = random(&mut state) % bytes.len();
            match case % 4 {
                0 => bytes.truncate(index),
                1 => bytes[index] ^= (random(&mut state) as u8) | 1,
                2 => bytes.insert(index, random(&mut state) as u8),
                _ => bytes.extend_from_slice(&[0xff, 0, b'{', b']']),
            }
            assert_eq!(
                comparable(load_outcomes(&path, &bytes, format, BUDGET)),
                comparable(load_outcomes(&path, &bytes, format, BUDGET)),
                "seed={SEED:#x}, format={format:?}, case={case}, bytes={bytes:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 288);
    println!("seed={SEED:#x}; cases={cases}; max_input={MAX_INPUT}; budget={BUDGET}");
}

#[test]
fn bounded_compressed_expansion_rejects_before_full_inflation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    let mut encoder =
        flate2::write::ZlibEncoder::new(b"SRS\x02".to_vec(), flate2::Compression::best());
    for _ in 0..512 {
        encoder.write_all(&[0; 4096]).unwrap();
    }
    let bytes = encoder.finish().unwrap();
    let error = load_outcomes(&path, &bytes, Format::Srs, 4 * 1024 * 1024).unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
}

#[test]
fn generated_domain_rules_agree_for_shared_normalized_subset() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source");
    for count in [1, 2, 16, 32] {
        let names: Vec<_> = (0..count).map(|i| format!("h{i}.example")).collect();
        let variants: Vec<_> = names
            .iter()
            .map(|s| format!("{}.", s.to_uppercase()))
            .collect();
        let json = serde_json::json!({"version": 2, "rules": [{"domain": names}]});
        let parse = |bytes: &[u8], format| {
            std::fs::write(&path, bytes).unwrap();
            load_source(&rule_source(&path, format), &mut Compiler::default()).unwrap()
        };
        let json_rules = parse(json.to_string().as_bytes(), Format::SingboxJson);
        // Sing-box literals preserve upstream case semantics; only Mihomo folds
        // pattern case. Compare the intentionally shared normalized subset.
        let text_rules = parse(variants.join("\n").as_bytes(), Format::MihomoText);
        for i in 0..=count {
            let expected = if i < count {
                Outcome::Match
            } else {
                Outcome::Miss
            };
            for query in [format!("h{i}.example"), format!("H{i}.EXAMPLE.")] {
                let name = shoes::rules::domain::normalize(&query).unwrap();
                assert_eq!(json_rules.evaluate(Some(&name), None, 443), expected);
                assert_eq!(text_rules.evaluate(Some(&name), None, 443), expected);
            }
        }
    }
}
