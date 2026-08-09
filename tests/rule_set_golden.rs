//! Decoding assertions against rule-sets published by sing-box.
//!
//! These files are the format's specification in practice. A decoder for a
//! reverse-engineered binary format without real inputs is not meaningfully
//! tested, so about 255 KB of fixtures is a deliberate trade.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use shoes::rule_set::{MatchTarget, RuleSet, normalize_domain};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rule_sets")
        .join(name)
}

fn load(name: &str) -> std::sync::Arc<RuleSet> {
    RuleSet::load(name, &fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn domain_target(domain: &str) -> MatchTarget<'_> {
    MatchTarget {
        domain: Some(domain),
        ip: None,
    }
}

fn ip_target(a: u8, b: u8, c: u8, d: u8) -> MatchTarget<'static> {
    MatchTarget {
        domain: None,
        ip: Some(u128::from(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())),
    }
}

#[test]
fn every_published_fixture_decodes() {
    for name in [
        "geosite-google.srs",
        "geosite-telegram.srs",
        "geosite-cloudflare.srs",
        "geosite-category-ads-all.srs",
        "geoip-ru.srs",
        "geoip-us.srs",
    ] {
        load(name);
    }
}

#[test]
fn geosite_google_matches_google_domains() {
    // This set carries a domain trie and two domain_regex patterns. If the two
    // were ANDed instead of ORed, almost none of this would match.
    let set = load("geosite-google.srs");
    assert!(set.matches(&domain_target("google.com")));
    assert!(set.matches(&domain_target("www.google.com")));
    assert!(!set.matches(&domain_target("example.invalid")));
}

#[test]
fn geosite_telegram_matches_telegram_domains() {
    let set = load("geosite-telegram.srs");
    assert!(set.matches(&domain_target("telegram.org")));
    assert!(set.matches(&domain_target("api.telegram.org")));
    assert!(!set.matches(&domain_target("telegram.org.example.invalid")));
}

#[test]
fn matching_is_case_insensitive_after_normalisation() {
    let set = load("geosite-cloudflare.srs");
    let normalised = normalize_domain("CLOUDFLARE.COM.");
    assert!(set.matches(&domain_target(normalised.as_ref())));
}

#[test]
fn geoip_ru_matches_a_russian_address_and_not_a_us_one() {
    let set = load("geoip-ru.srs");
    // Yandex, allocated in RU.
    assert!(set.matches(&ip_target(77, 88, 8, 8)));
    // Google Public DNS, allocated in US.
    assert!(!set.matches(&ip_target(8, 8, 8, 8)));
}

#[test]
fn geoip_us_matches_a_us_address() {
    let set = load("geoip-us.srs");
    assert!(set.matches(&ip_target(8, 8, 8, 8)));
    assert!(!set.matches(&ip_target(77, 88, 8, 8)));
}

#[test]
fn a_domain_set_does_not_match_on_ip_alone() {
    let set = load("geosite-google.srs");
    assert!(!set.matches(&ip_target(8, 8, 8, 8)));
}

#[test]
fn an_ip_set_does_not_match_on_domain_alone() {
    let set = load("geoip-ru.srs");
    assert!(!set.matches(&domain_target("yandex.ru")));
}
