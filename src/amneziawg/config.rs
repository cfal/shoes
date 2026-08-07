//! Convert shoes AmneziaWG config types into boringtun types.

use std::net::IpAddr;

use base64::Engine;
use boringtun::amnezia::{
    Amnezia3Config, CpsChain, HeaderConfig, HeaderRange, InitPacketConfig, JunkConfig,
    PaddingConfig, U32Range,
};
use boringtun::x25519;

use crate::config::{AmneziaWgClientConfig, AmneziaWgParams};

/// Parsed runtime configuration for the AmneziaWG tunnel.
pub struct AwgRuntimeConfig {
    pub private_key: x25519::StaticSecret,
    pub peer_public_key: x25519::PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub local_addresses: Vec<(IpAddr, u8)>,
    pub mtu: u16,
    pub amnezia: Amnezia3Config,
}

impl AwgRuntimeConfig {
    pub fn from_client_config(config: &AmneziaWgClientConfig) -> std::io::Result<Self> {
        let b64 = base64::engine::general_purpose::STANDARD;

        // Decode private key
        let private_key_bytes: [u8; 32] = b64
            .decode(config.private_key.expose())
            .map_err(|e| ioerr(&format!("invalid private_key base64: {}", e)))?
            .try_into()
            .map_err(|_| ioerr("private_key must be 32 bytes"))?;
        let private_key = x25519::StaticSecret::from(private_key_bytes);

        // Decode peer public key
        let peer_pub_bytes: [u8; 32] = b64
            .decode(&config.peer_public_key)
            .map_err(|e| ioerr(&format!("invalid peer_public_key base64: {}", e)))?
            .try_into()
            .map_err(|_| ioerr("peer_public_key must be 32 bytes"))?;
        let peer_public_key = x25519::PublicKey::from(peer_pub_bytes);

        // Decode optional preshared key
        let preshared_key = config
            .preshared_key
            .as_ref()
            .map(|psk| {
                let bytes: [u8; 32] = b64
                    .decode(psk.expose())
                    .map_err(|e| ioerr(&format!("invalid preshared_key base64: {}", e)))?
                    .try_into()
                    .map_err(|_| ioerr("preshared_key must be 32 bytes"))?;
                Ok::<_, std::io::Error>(bytes)
            })
            .transpose()?;

        // Parse local addresses
        let local_addresses: Vec<(IpAddr, u8)> = config
            .local_addresses
            .iter()
            .map(|s| parse_ip_prefix(s))
            .collect::<Result<_, _>>()?;

        // Convert AWG 2.0/3.0 params. Content padding is clamped against the
        // tunnel MTU, so the two have to agree.
        let amnezia = convert_amnezia_config(&config.awg, config.mtu)?;

        Ok(Self {
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive: config.persistent_keepalive,
            local_addresses,
            mtu: config.mtu,
            amnezia,
        })
    }
}

pub fn convert_amnezia_config(awg: &AmneziaWgParams, mtu: u16) -> std::io::Result<Amnezia3Config> {
    let default_headers = HeaderConfig::wireguard_compatible();
    let headers = HeaderConfig::new(
        parse_header_range(&awg.h1, default_headers.init)?,
        parse_header_range(&awg.h2, default_headers.response)?,
        parse_header_range(&awg.h3, default_headers.cookie)?,
        parse_header_range(&awg.h4, default_headers.transport)?,
    )
    .map_err(|e| ioerr(&format!("invalid header config: {}", e)))?;

    let paddings = PaddingConfig {
        s1: awg.s1,
        s2: awg.s2,
        s3: awg.s3,
        s4: awg.s4,
    };

    let junk = if awg.jc > 0 {
        JunkConfig::new(awg.jc, awg.jmin, awg.jmax)
            .map_err(|e| ioerr(&format!("invalid junk config: {}", e)))?
    } else {
        JunkConfig::disabled()
    };

    let init_packets = InitPacketConfig {
        i1: parse_optional_cps(&awg.i1)?,
        i2: parse_optional_cps(&awg.i2)?,
        i3: parse_optional_cps(&awg.i3)?,
        i4: parse_optional_cps(&awg.i4)?,
        i5: parse_optional_cps(&awg.i5)?,
    };

    // Amnezia3Config is #[non_exhaustive]: start from the WireGuard-compatible
    // default and overwrite what the config names.
    let mut config = Amnezia3Config::default();
    config.junk = junk;
    config.paddings = paddings;
    config.headers = headers;
    config.init_packets = init_packets;
    config.mtu = u32::from(mtu);

    config.header_protection_key = awg
        .header_protection_key
        .as_ref()
        .map(|key| parse_header_protection_key(key.expose()))
        .transpose()?
        // An all-zero key means "off", the same as omitting it.
        .filter(|key| key.iter().any(|byte| *byte != 0));

    config.content_padding_addition =
        parse_optional_u32_range(&awg.content_padding_addition, "content_padding_addition")?
            .filter(|range| !range.is_zero());

    let timings = &mut config.timing_ranges;
    if let Some(range) = parse_optional_u32_range(&awg.rekey_after_time, "rekey_after_time")? {
        timings.rekey_after_time = range;
    }
    if let Some(range) = parse_optional_u32_range(&awg.rekey_timeout, "rekey_timeout")? {
        timings.rekey_timeout = range;
    }
    if let Some(range) = parse_optional_u32_range(&awg.reject_after_time, "reject_after_time")? {
        timings.reject_after_time = range;
    }
    if let Some(range) = parse_optional_u32_range(&awg.keepalive_timeout, "keepalive_timeout")? {
        timings.keepalive_timeout = range;
    }
    if let Some(range) =
        parse_optional_u32_range(&awg.max_handshake_attempts, "max_handshake_attempts")?
    {
        timings.max_handshake_attempts = range;
    }
    if let Some(range) = parse_optional_u32_range(
        &awg.persistent_keepalive_interval,
        "persistent_keepalive_interval",
    )? {
        timings.persistent_keepalive = range;
    }

    config
        .validate()
        .map_err(|e| ioerr(&format!("invalid AmneziaWG config: {}", e)))?;

    Ok(config)
}

fn parse_header_range(s: &Option<String>, default: HeaderRange) -> std::io::Result<HeaderRange> {
    match s {
        Some(s) => HeaderRange::parse(s)
            .map_err(|e| ioerr(&format!("invalid header range '{}': {}", s, e))),
        None => Ok(default),
    }
}

fn parse_optional_u32_range(s: &Option<String>, field: &str) -> std::io::Result<Option<U32Range>> {
    match s {
        Some(s) => {
            let range = U32Range::parse(s)
                .map_err(|e| ioerr(&format!("invalid {} range '{}': {}", field, s, e)))?;
            Ok(Some(range))
        }
        None => Ok(None),
    }
}

/// Accept the key in either spelling AmneziaWG uses: base64 as a `.conf`
/// writes it, or 64 hex characters as the UAPI socket does.
fn parse_header_protection_key(s: &str) -> std::io::Result<[u8; 32]> {
    let trimmed = s.trim();

    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| ioerr(&format!("invalid header_protection_key hex: {}", e)))?;
        }
        return Ok(key);
    }

    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| ioerr(&format!("invalid header_protection_key base64: {}", e)))?
        .try_into()
        .map_err(|_| ioerr("header_protection_key must be 32 bytes"))
}

fn parse_optional_cps(s: &Option<String>) -> std::io::Result<Option<CpsChain>> {
    match s {
        Some(s) => {
            let chain = CpsChain::parse(s)
                .map_err(|e| ioerr(&format!("invalid CPS chain '{}': {}", s, e)))?;
            Ok(Some(chain))
        }
        None => Ok(None),
    }
}

fn parse_ip_prefix(s: &str) -> std::io::Result<(IpAddr, u8)> {
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str
            .parse()
            .map_err(|e| ioerr(&format!("invalid IP '{}': {}", addr_str, e)))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| ioerr(&format!("invalid prefix '{}': {}", prefix_str, e)))?;
        Ok((addr, prefix))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|e| ioerr(&format!("invalid IP '{}': {}", s, e)))?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Ok((addr, prefix))
    }
}

fn ioerr(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_prefix_v4_with_prefix() {
        let (addr, prefix) = parse_ip_prefix("10.0.0.1/24").unwrap();
        assert_eq!(addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_ip_prefix_v4_without_prefix() {
        let (addr, prefix) = parse_ip_prefix("192.168.1.1").unwrap();
        assert_eq!(addr, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_parse_ip_prefix_v6_with_prefix() {
        let (addr, prefix) = parse_ip_prefix("fd00::1/64").unwrap();
        assert_eq!(addr, "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 64);
    }

    #[test]
    fn test_parse_ip_prefix_v6_without_prefix() {
        let (addr, prefix) = parse_ip_prefix("::1").unwrap();
        assert_eq!(addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(prefix, 128);
    }

    #[test]
    fn test_parse_ip_prefix_invalid_addr() {
        assert!(parse_ip_prefix("not-an-ip/24").is_err());
    }

    #[test]
    fn test_parse_ip_prefix_invalid_prefix() {
        assert!(parse_ip_prefix("10.0.0.1/abc").is_err());
    }

    /// Every field unset — the 2.0 fields and the 3.0 ones alike.
    fn empty_params() -> AmneziaWgParams {
        AmneziaWgParams {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            h1: None,
            h2: None,
            h3: None,
            h4: None,
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            header_protection_key: None,
            content_padding_addition: None,
            rekey_after_time: None,
            rekey_timeout: None,
            reject_after_time: None,
            keepalive_timeout: None,
            max_handshake_attempts: None,
            persistent_keepalive_interval: None,
        }
    }

    #[test]
    fn empty_params_are_wireguard_compatible() {
        let config = convert_amnezia_config(&empty_params(), 1280).unwrap();

        // Identical to plain WireGuard apart from the MTU, which shoes always
        // supplies from its own tunnel config rather than boringtun's default.
        let mut expected = Amnezia3Config::from_amnezia2(Default::default());
        expected.mtu = 1280;
        assert_eq!(config, expected);
    }

    #[test]
    fn omitted_headers_keep_the_wireguard_message_types() {
        let mut params = empty_params();
        params.h1 = Some("100".to_string());

        let config = convert_amnezia_config(&params, 1280).unwrap();
        let default = HeaderConfig::wireguard_compatible();
        assert_ne!(config.headers.init, default.init);
        assert_eq!(config.headers.response, default.response);
        assert_eq!(config.headers.cookie, default.cookie);
        assert_eq!(config.headers.transport, default.transport);
    }

    #[test]
    fn header_protection_key_accepts_base64_and_hex() {
        let key = [0x11u8; 32];
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);

        // Header protection requires at least 12 bytes of padding on each of S1-S4.
        let padded = |source: String| {
            let mut params = empty_params();
            params.s1 = 12;
            params.s2 = 12;
            params.s3 = 12;
            params.s4 = 12;
            params.header_protection_key = Some(source.into());
            params
        };

        for source in [hex, b64] {
            let config = convert_amnezia_config(&padded(source), 1280).unwrap();
            assert_eq!(config.header_protection_key, Some(key));
        }
    }

    #[test]
    fn all_zero_header_protection_key_disables_it() {
        let mut params = empty_params();
        params.header_protection_key = Some(
            base64::engine::general_purpose::STANDARD
                .encode([0u8; 32])
                .into(),
        );

        let config = convert_amnezia_config(&params, 1280).unwrap();
        assert_eq!(config.header_protection_key, None);
    }

    #[test]
    fn header_protection_rejects_padding_below_the_nonce_size() {
        let mut params = empty_params();
        params.s1 = 11;
        params.header_protection_key = Some(
            base64::engine::general_purpose::STANDARD
                .encode([0x22u8; 32])
                .into(),
        );

        assert!(convert_amnezia_config(&params, 1280).is_err());
    }

    #[test]
    fn timing_ranges_accept_single_values_and_ranges() {
        let mut params = empty_params();
        params.rekey_after_time = Some("90".to_string());
        params.keepalive_timeout = Some("5-15".to_string());

        let config = convert_amnezia_config(&params, 1280).unwrap();
        assert_eq!(config.timing_ranges.rekey_after_time, U32Range::single(90));
        assert_eq!(config.timing_ranges.keepalive_timeout.lo, 5);
        assert_eq!(config.timing_ranges.keepalive_timeout.hi, 15);
        // Unset ranges stay at the WireGuard constants.
        assert!(config.timing_ranges.rekey_timeout.is_zero());
    }

    #[test]
    fn content_padding_and_mtu_are_carried_through() {
        let mut params = empty_params();
        params.content_padding_addition = Some("0-64".to_string());

        let config = convert_amnezia_config(&params, 1420).unwrap();
        assert_eq!(
            config.content_padding_addition,
            Some(U32Range::new(0, 64).unwrap())
        );
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    fn inverted_range_is_rejected() {
        let mut params = empty_params();
        params.rekey_timeout = Some("30-5".to_string());

        assert!(convert_amnezia_config(&params, 1280).is_err());
    }

    #[test]
    fn uses_awg3_only_reports_the_three_zero_fields() {
        let mut params = empty_params();
        assert!(!params.uses_awg3());

        params.jc = 4;
        params.s1 = 20;
        params.h1 = Some("100".to_string());
        assert!(!params.uses_awg3());

        params.content_padding_addition = Some("0-64".to_string());
        assert!(params.uses_awg3());
    }
}
