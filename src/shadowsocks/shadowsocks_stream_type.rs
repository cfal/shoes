pub enum ShadowsocksStreamType {
    AEAD,
    AEAD2022Server,
    AEAD2022Client,
}

impl ShadowsocksStreamType {
    pub fn max_payload_len(&self) -> usize {
        match self {
            ShadowsocksStreamType::AEAD => {
                // for AEAD ciphers:
                // from https://shadowsocks.org/guide/aead.html#tcp
                //
                // "Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF.
                // The higher two bits are reserved and must be set to zero. Payload is therefore
                // limited to 16*1024 - 1 bytes."
                0x3fff
            }
            ShadowsocksStreamType::AEAD2022Server | ShadowsocksStreamType::AEAD2022Client => {
                // for AEAD 2022 ciphers:
                // from https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
                // "A payload chunk can have up to 0xFFFF (65535) bytes of unencrypted payload. The 0x3FFF (16383)
                // length cap in Shadowsocks AEAD does not apply to this edition."
                0xffff
            }
        }
    }
}
