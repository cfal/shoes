use super::*;

const KEY_HEX: &str = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a";
const PHOBOS_KEY: &str = "phobos-shared-secret-text";

const V20: &str = r#"
jc: 3
jmin: 40
jmax: 70
s1: 15
s2: 18
s3: 20
s4: 23
h1: "100000-100100"
h2: "200000-200100"
h3: "300000-300100"
h4: "400000-400100"
i1: "<b 0xc0ffee><r 16><t>"
"#;

fn parse(yaml: &str) -> Result<AmneziaSettings, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

fn v30() -> String {
    format!(
        "{V20}header_protection_key: \"{KEY_HEX}\"\ncontent_padding_addition: \"0-32\"\nrekey_after_time: \"110-130\"\n"
    )
}

fn v31() -> String {
    format!("{}random_trailers: true\ndisable_cookies: true\n", v30())
}

#[cfg(unix)]
#[test]
fn amnezia_versions_parse_and_convert() {
    for yaml in [V20.to_owned(), v30(), v31()] {
        parse(&yaml).unwrap().to_gotatun().unwrap();
    }
    let config = parse(&v31()).unwrap().to_gotatun().unwrap();
    assert!(config.random_trailers && config.disable_cookies);
    let plain = parse(&v30()).unwrap().to_gotatun().unwrap();
    assert!(!plain.random_trailers && !plain.disable_cookies);
    assert!(plain.header_protection_key.is_some());
    assert_eq!(parse(V20).unwrap().transport_overhead(), 23);
}

#[cfg(unix)]
#[test]
fn conf_style_values_match_uapi_parse() {
    let blob = "ab".repeat(1000);
    let i1 = format!("<b 0x{blob}><r 24><t>");
    let yaml = format!("h1: 1234567\nh2: 7654321\nh3: 9999999\nh4: 11111111\ni1: \"{i1}\"\n");
    let converted = parse(&yaml).unwrap().to_gotatun().unwrap();

    let mut expected = gotatun::amnezia::AmneziaConfig::default();
    for (key, value) in [
        ("h1", "1234567"),
        ("h2", "7654321"),
        ("h3", "9999999"),
        ("h4", "11111111"),
        ("i1", i1.as_str()),
    ] {
        assert!(expected.apply_uapi_line(key, value).unwrap());
    }
    expected.validate().unwrap();
    assert_eq!(converted, expected);
}

#[test]
fn header_protection_key_hex_and_base64_agree() {
    let hex = parse(&format!("header_protection_key: \"{KEY_HEX}\"")).unwrap();
    let b64 = STANDARD.encode([0x1au8; 32]);
    let base64 = parse(&format!("header_protection_key: \"{b64}\"")).unwrap();
    assert_eq!(hex, base64);
    let serialized = serde_yaml::to_string(&hex).unwrap();
    assert!(serialized.contains(KEY_HEX), "{serialized}");
    assert!(parse("header_protection_key: \"abcd\"").is_err());
}

#[cfg(unix)]
#[test]
fn rejects_what_amneziawg_go_rejects() {
    let cases = [
        "h1: \"100-200\"\nh2: \"150-250\"\n",
        "jc: 2\njmin: 80\njmax: 40\n",
        &format!("s1: 11\ns2: 12\ns3: 12\ns4: 12\nheader_protection_key: \"{KEY_HEX}\"\n"),
    ];
    for yaml in cases {
        assert!(parse(yaml).unwrap().to_gotatun().is_err(), "{yaml}");
    }
    for yaml in ["j1: x\n", "itime: 5\n"] {
        let error = parse(yaml).and_then(|s| {
            s.to_gotatun()
                .map_err(<serde_yaml::Error as serde::de::Error>::custom)
        });
        assert!(error.is_err(), "{yaml}");
    }
}

#[test]
fn secrets_absent_from_debug_and_errors() {
    let settings = parse(&v30()).unwrap();
    assert!(!format!("{settings:?}").contains(KEY_HEX));
    assert!(!format!("{settings:?}").contains("26, 26"));
    let phobos: PhobosSettings = serde_yaml::from_str(&format!("key: {PHOBOS_KEY}")).unwrap();
    assert!(!format!("{phobos:?}").contains(PHOBOS_KEY));

    let bad_key = "9b".repeat(31) + "zz";
    let error = parse(&format!("header_protection_key: \"{bad_key}\""))
        .unwrap_err()
        .to_string();
    assert!(!error.contains(&bad_key), "{error}");
    let error = serde_yaml::from_str::<PhobosSettings>("key: [1, 2]")
        .unwrap_err()
        .to_string();
    assert!(!error.contains('1'), "{error}");

    #[cfg(unix)]
    {
        // A key that is valid text but fails validation elsewhere.
        let low = format!("s1: 1\nheader_protection_key: \"{KEY_HEX}\"\n");
        let error = parse(&low).unwrap().to_gotatun().unwrap_err().to_string();
        assert!(!error.contains(KEY_HEX), "{error}");
        let long = "k".repeat(300);
        let settings: PhobosSettings = serde_yaml::from_str(&format!("key: {long}")).unwrap();
        let error = settings.to_gotatun().unwrap_err().to_string();
        assert!(!error.contains(&long), "{error}");
    }
}

#[cfg(unix)]
#[test]
fn phobos_parses_and_converts() {
    for masking in ["none", "stun", "media", "auto", "tls"] {
        let settings: PhobosSettings = serde_yaml::from_str(&format!(
            "key: {PHOBOS_KEY}\nmasking: {masking}\nmax_dummy: 100\nobfuscate_bytes: 7\nmedia_pt: 96\nmedia_ssrc: 4000000000\nmedia_clock: 30\n"
        ))
        .unwrap();
        let config = settings.to_gotatun().unwrap();
        assert_eq!(config.key(), PHOBOS_KEY.as_bytes());
        assert_eq!(config.max_dummy, 100);
        assert_eq!(config.obfuscate_bytes, 7);
    }
    let too_many: PhobosSettings =
        serde_yaml::from_str(&format!("key: {PHOBOS_KEY}\nmax_dummy: 2000")).unwrap();
    assert!(too_many.to_gotatun().is_err());
    let empty: PhobosSettings = serde_yaml::from_str("key: \"\"").unwrap();
    assert!(empty.to_gotatun().is_err());
    assert!(serde_yaml::from_str::<PhobosSettings>("masking: stun").is_err());
}

#[cfg(unix)]
#[test]
fn masking_overhead_matches_fork() {
    use gotatun::phobos::Masking;
    let pairs = [
        (PhobosMasking::None, Masking::None),
        (PhobosMasking::Stun, Masking::Stun),
        (PhobosMasking::Media, Masking::Media),
        (PhobosMasking::Auto, Masking::None),
        (PhobosMasking::Tls, Masking::None),
    ];
    for (ours, theirs) in pairs {
        assert_eq!(usize::from(ours.overhead()), theirs.overhead());
    }
}
