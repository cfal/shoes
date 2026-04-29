//! Convert shoes AmneziaWG config types into boringtun types.

use std::net::IpAddr;

use base64::Engine;
use boringtun::amnezia::{
    Amnezia2Config, CpsChain, HeaderConfig, HeaderRange, InitPacketConfig, JunkConfig,
    PaddingConfig,
};
use boringtun::x25519;

use crate::config::{AmneziaWg2Config, AmneziaWgClientConfig};

/// Parsed runtime configuration for the AmneziaWG tunnel.
pub struct AwgRuntimeConfig {
    pub private_key: x25519::StaticSecret,
    pub peer_public_key: x25519::PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub local_addresses: Vec<(IpAddr, u8)>,
    pub mtu: u16,
    pub amnezia: Amnezia2Config,
}

impl AwgRuntimeConfig {
    pub fn from_client_config(config: &AmneziaWgClientConfig) -> std::io::Result<Self> {
        let b64 = base64::engine::general_purpose::STANDARD;

        // Decode private key
        let private_key_bytes: [u8; 32] = b64
            .decode(&config.private_key)
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
                    .decode(psk)
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

        // Convert AWG 2.0 params
        let amnezia = convert_amnezia_config(&config.awg)?;

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

fn convert_amnezia_config(awg: &AmneziaWg2Config) -> std::io::Result<Amnezia2Config> {
    let headers = HeaderConfig::new(
        parse_header_range(&awg.h1)?,
        parse_header_range(&awg.h2)?,
        parse_header_range(&awg.h3)?,
        parse_header_range(&awg.h4)?,
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

    Ok(Amnezia2Config {
        junk,
        paddings,
        headers,
        init_packets,
    })
}

fn parse_header_range(s: &str) -> std::io::Result<HeaderRange> {
    HeaderRange::parse(s).map_err(|e| ioerr(&format!("invalid header range '{}': {}", s, e)))
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
