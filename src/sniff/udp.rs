use crate::rules::Protocol;

pub(crate) fn classify(packet: &[u8]) -> Option<Protocol> {
    if stun(packet) {
        Some(Protocol::Stun)
    } else if dtls(packet) {
        Some(Protocol::Dtls)
    } else {
        None
    }
}

fn stun(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] & 0xc0 != 0 || packet[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if !len.is_multiple_of(4) || len + 20 != packet.len() {
        return false;
    }
    // RFC 8489 attribute lengths exclude padding, whose contents are unconstrained.
    let mut attributes = &packet[20..];
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return false;
        }
        let len = u16::from_be_bytes([attributes[2], attributes[3]]) as usize;
        let padded = (len + 3) & !3;
        let Some(rest) = attributes.get(4 + padded..) else {
            return false;
        };
        attributes = rest;
    }
    true
}

fn dtls(mut packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    // Classic records may be concatenated. CID and unified headers require session state.
    while !packet.is_empty() {
        if packet.len() < 13
            || !matches!(packet[0], 20..=24 | 26)
            || packet[1] != 0xfe
            || !matches!(packet[2], 0xff | 0xfd)
        {
            return false;
        }
        let len = u16::from_be_bytes([packet[11], packet[12]]) as usize;
        let Some(rest) = packet.get(13 + len..) else {
            return false;
        };
        packet = rest;
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Fixtures from sing-box common/sniff/{stun,dtls}_test.go at 0af5fae7.
    pub(crate) fn stun_packet() -> Vec<u8> {
        hex("000100002112a44224b1a025d0c180c484341306")
    }

    pub(crate) fn dtls_packet() -> Vec<u8> {
        hex(
            "16fefd0000000000000000007e010000720000000000000072fefd668a43523798e064bd806d0c87660de9c611a59bbdfc3892c4e072d94f2cafc40000000cc02bc02fc00ac014c02cc0300100003c000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b00020100000e000900060008000700010000170000",
        )
    }

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn reference_packets_and_truncations() {
        for (packet, protocol) in [
            (stun_packet(), Protocol::Stun),
            (dtls_packet(), Protocol::Dtls),
            (
                hex(
                    "17fefd000100000000000100440001000000000001a4f682b77ecadd10f3f3a2f78d90566212366ff8209fd77314f5a49352f9bb9bd12f4daba0b4736ae29e46b9714d3b424b3e6d0234736619b5aa0d3f",
                ),
                Protocol::Dtls,
            ),
        ] {
            assert_eq!(classify(&packet), Some(protocol));
            for len in 0..packet.len() {
                assert_eq!(classify(&packet[..len]), None, "{protocol:?}: {len}");
            }
            let mut trailing = packet;
            trailing.push(0);
            assert_eq!(classify(&trailing), None);
        }
    }

    #[test]
    fn stun_attributes_and_transaction_ids() {
        let mut packet = stun_packet();
        for txid in [0, 255] {
            packet[8..20].fill(txid);
            assert_eq!(classify(&packet), Some(Protocol::Stun));
        }
        packet[1] = 3; // TURN Allocate is STUN-formatted too.
        packet[3] = 8;
        packet.extend_from_slice(&[0x80, 0xff, 0, 1, 42, 255, 255, 255]);
        assert_eq!(classify(&packet), Some(Protocol::Stun));
        for (index, value) in [(0, 0x40), (0, 0x80), (4, 0), (3, 7), (23, 5)] {
            let mut invalid = packet.clone();
            invalid[index] = value;
            assert_eq!(classify(&invalid), None);
        }
    }

    #[test]
    fn dtls_records_versions_and_unsupported_headers() {
        let hello = dtls_packet();
        let mut packet = hello.clone();
        packet.extend_from_slice(&hello);
        assert_eq!(classify(&packet), Some(Protocol::Dtls));
        packet.pop();
        assert_eq!(classify(&packet), None);
        for version in [0xfd, 0xff] {
            for content_type in [20, 21, 22, 23, 24, 26] {
                let mut packet = hello.clone();
                packet[0] = content_type;
                packet[2] = version;
                packet[3..11].fill(255);
                assert_eq!(classify(&packet), Some(Protocol::Dtls));
            }
        }
        for (index, value) in [(0, 25), (0, 32), (0, 128), (1, 3), (2, 0xfc)] {
            let mut packet = hello.clone();
            packet[index] = value;
            assert_eq!(classify(&packet), None);
        }
    }
}
