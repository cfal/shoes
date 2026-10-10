use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum TlsKeyExchangeGroup {
    X25519MLKEM768,
    SecP256r1MLKEM768,
    X25519,
    SecP256r1,
    SecP384r1,
}

impl TlsKeyExchangeGroup {
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::X25519MLKEM768 | Self::SecP256r1MLKEM768)
    }

    pub fn rustls_group(self) -> &'static dyn rustls::crypto::SupportedKxGroup {
        use rustls::crypto::aws_lc_rs::kx_group;
        match self {
            Self::X25519MLKEM768 => kx_group::X25519MLKEM768,
            Self::SecP256r1MLKEM768 => kx_group::SECP256R1MLKEM768,
            Self::X25519 => kx_group::X25519,
            Self::SecP256r1 => kx_group::SECP256R1,
            Self::SecP384r1 => kx_group::SECP384R1,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TlsKeyExchangeGroups(Option<Vec<TlsKeyExchangeGroup>>);

impl<'de> Deserialize<'de> for TlsKeyExchangeGroups {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let groups = Vec::<TlsKeyExchangeGroup>::deserialize(deserializer)?;
        if groups.is_empty() {
            return Err(serde::de::Error::custom(
                "key_exchange_groups must not be empty",
            ));
        }
        for (index, group) in groups.iter().enumerate() {
            if groups[..index].contains(group) {
                return Err(serde::de::Error::custom(
                    "duplicate key_exchange_groups entry",
                ));
            }
        }
        Ok(Self(Some(groups)))
    }
}

impl TlsKeyExchangeGroups {
    pub fn is_default(&self) -> bool {
        self.0.is_none()
    }

    pub fn groups(&self) -> Option<&[TlsKeyExchangeGroup]> {
        self.0.as_deref()
    }

    pub fn requires_hybrid(&self) -> bool {
        self.groups()
            .is_some_and(|groups| groups.iter().all(|g| g.is_hybrid()))
    }

    pub fn validate_vision(&self, vision: bool) -> std::io::Result<()> {
        if vision && self.requires_hybrid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hybrid-only key_exchange_groups cannot be combined with Vision: direct copy bypasses TLS encryption",
            ));
        }
        Ok(())
    }

    pub fn validate_zero_rtt(&self, zero_rtt_handshake: bool) -> std::io::Result<()> {
        if zero_rtt_handshake && self.requires_hybrid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "hybrid-only key_exchange_groups cannot be combined with zero_rtt_handshake",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientProxyConfig, ClientQuicConfig, ServerQuicConfig, TlsServerConfig};

    #[test]
    fn allowlists_are_nonempty_unique_and_native_only() {
        for yaml in [
            "[]",
            "null",
            "[X25519, X25519]",
            "[SecP384r1MLKEM1024]",
            "[MLKEM768]",
            "[typo]",
        ] {
            assert!(
                serde_yaml::from_str::<TlsKeyExchangeGroups>(yaml).is_err(),
                "{yaml}"
            );
        }
        for (yaml, strict) in [
            ("[X25519MLKEM768]", true),
            ("[SecP256r1MLKEM768, X25519MLKEM768]", true),
            ("[X25519MLKEM768, X25519]", false),
            ("[SecP256r1, SecP384r1]", false),
        ] {
            let groups: TlsKeyExchangeGroups = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(groups.requires_hybrid(), strict);
            assert_eq!(
                groups,
                serde_yaml::from_str(&serde_yaml::to_string(&groups).unwrap()).unwrap()
            );
            assert_eq!(groups.validate_vision(true).is_err(), strict);
            assert_eq!(groups.validate_zero_rtt(true).is_err(), strict);
            assert!(groups.validate_vision(false).is_ok());
        }
    }

    #[test]
    fn ordinary_tls_and_quic_share_the_allowlist() {
        for field in ["", "key_exchange_groups: [SecP256r1MLKEM768]\n"] {
            let strict = !field.is_empty();
            let client: ClientProxyConfig =
                serde_yaml::from_str(&format!("type: tls\n{field}protocol: {{type: socks}}\n"))
                    .unwrap();
            let ClientProxyConfig::Tls(tls) = &client else {
                panic!()
            };
            assert_eq!(tls.key_exchange_groups.requires_hybrid(), strict);
            let serialized = serde_yaml::to_string(&client).unwrap();
            assert_eq!(serialized.contains("key_exchange_groups"), strict);
            assert!(serde_yaml::from_str::<ClientProxyConfig>(&serialized).is_ok());
            let server: TlsServerConfig = serde_yaml::from_str(&format!(
                "{field}cert: cert\nkey: key\nprotocol: {{type: socks}}\n"
            ))
            .unwrap();
            assert_eq!(server.key_exchange_groups.requires_hybrid(), strict);
            let client: ClientQuicConfig =
                serde_yaml::from_str(&format!("verify: true\n{field}")).unwrap();
            assert_eq!(client.key_exchange_groups.requires_hybrid(), strict);
            let server: ServerQuicConfig =
                serde_yaml::from_str(&format!("cert: cert\nkey: key\n{field}")).unwrap();
            assert_eq!(server.key_exchange_groups.requires_hybrid(), strict);
        }
    }

    #[test]
    fn shadowtls_cannot_silently_ignore_allowlists() {
        for yaml in [
            "type: shadowtls\npassword: password\nkey_exchange_groups: [X25519MLKEM768]\nprotocol: {type: socks}",
            "type: tls\nshadowtls_password: password\nkey_exchange_groups: [X25519MLKEM768]\nprotocol: {type: socks}",
        ] {
            assert!(serde_yaml::from_str::<ClientProxyConfig>(yaml).is_err());
        }
        let yaml = "password: password\nkey_exchange_groups: [X25519MLKEM768]\nhandshake: {cert: cert, key: key}\nprotocol: {type: socks}";
        assert!(serde_yaml::from_str::<crate::config::ShadowTlsServerConfig>(yaml).is_err());
    }
}
