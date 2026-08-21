//! The 32-byte segment metadata. `docs/protocol.md`, "Metadata Format".

use crate::mieru::METADATA_LEN;

/// Protocol type values. `docs/protocol.md`.
pub const OPEN_SESSION_REQUEST: u8 = 2;
pub const OPEN_SESSION_RESPONSE: u8 = 3;
pub const CLOSE_SESSION_REQUEST: u8 = 4;
pub const CLOSE_SESSION_RESPONSE: u8 = 5;
pub const DATA_CLIENT_TO_SERVER: u8 = 6;
pub const DATA_SERVER_TO_CLIENT: u8 = 7;
pub const ACK_CLIENT_TO_SERVER: u8 = 8;
pub const ACK_SERVER_TO_CLIENT: u8 = 9;
/// The low-entropy extension. Recognised so it can be refused; never produced.
pub const DATA_CLIENT_TO_SERVER_LOW_ENTROPY: u8 = 10;
pub const DATA_SERVER_TO_CLIENT_LOW_ENTROPY: u8 = 11;

/// Session metadata: protocol types 2 through 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    pub protocol: u8,
    pub timestamp_minutes: u32,
    pub session_id: u32,
    pub seq: u32,
    pub status: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

/// Data metadata: protocol types 6 through 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMetadata {
    pub protocol: u8,
    pub timestamp_minutes: u32,
    pub session_id: u32,
    pub seq: u32,
    pub unack_seq: u32,
    pub window_size: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Metadata {
    Session(SessionMetadata),
    Data(DataMetadata),
}

pub fn encode_session(meta: &SessionMetadata) -> [u8; METADATA_LEN] {
    let mut out = [0u8; METADATA_LEN];
    out[0] = meta.protocol;
    // out[1] is unused.
    out[2..6].copy_from_slice(&meta.timestamp_minutes.to_be_bytes());
    out[6..10].copy_from_slice(&meta.session_id.to_be_bytes());
    out[10..14].copy_from_slice(&meta.seq.to_be_bytes());
    out[14] = meta.status;
    out[15..17].copy_from_slice(&meta.payload_len.to_be_bytes());
    out[17] = meta.suffix_len;
    // out[18..32] is unused.
    out
}

pub fn encode_data(meta: &DataMetadata) -> [u8; METADATA_LEN] {
    let mut out = [0u8; METADATA_LEN];
    out[0] = meta.protocol;
    // out[1] is unused.
    out[2..6].copy_from_slice(&meta.timestamp_minutes.to_be_bytes());
    out[6..10].copy_from_slice(&meta.session_id.to_be_bytes());
    out[10..14].copy_from_slice(&meta.seq.to_be_bytes());
    out[14..18].copy_from_slice(&meta.unack_seq.to_be_bytes());
    out[18..20].copy_from_slice(&meta.window_size.to_be_bytes());
    out[20] = meta.fragment;
    out[21] = meta.prefix_len;
    out[22..24].copy_from_slice(&meta.payload_len.to_be_bytes());
    out[24] = meta.suffix_len;
    // out[25..32] is unused.
    out
}

pub fn parse(input: &[u8]) -> std::io::Result<Metadata> {
    if input.len() < METADATA_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "mieru metadata is {} bytes, want {METADATA_LEN}",
                input.len()
            ),
        ));
    }
    let be32 =
        |at: usize| u32::from_be_bytes([input[at], input[at + 1], input[at + 2], input[at + 3]]);
    let be16 = |at: usize| u16::from_be_bytes([input[at], input[at + 1]]);

    match input[0] {
        protocol @ (OPEN_SESSION_REQUEST
        | OPEN_SESSION_RESPONSE
        | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE) => Ok(Metadata::Session(SessionMetadata {
            protocol,
            timestamp_minutes: be32(2),
            session_id: be32(6),
            seq: be32(10),
            status: input[14],
            payload_len: be16(15),
            suffix_len: input[17],
        })),
        protocol @ (DATA_CLIENT_TO_SERVER
        | DATA_SERVER_TO_CLIENT
        | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT) => Ok(Metadata::Data(DataMetadata {
            protocol,
            timestamp_minutes: be32(2),
            session_id: be32(6),
            seq: be32(10),
            unack_seq: be32(14),
            window_size: be16(18),
            fragment: input[20],
            prefix_len: input[21],
            payload_len: be16(22),
            suffix_len: input[24],
        })),
        DATA_CLIENT_TO_SERVER_LOW_ENTROPY | DATA_SERVER_TO_CLIENT_LOW_ENTROPY => {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the peer used mieru's low entropy extension, which this client does not implement",
            ))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown mieru protocol type {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_metadata_round_trips() {
        let original = SessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            timestamp_minutes: 0x0a0b0c0d,
            session_id: 0x11223344,
            seq: 0x55667788,
            status: 0,
            payload_len: 1024,
            suffix_len: 7,
        };
        let encoded = encode_session(&original);
        assert_eq!(encoded.len(), METADATA_LEN);
        match parse(&encoded).unwrap() {
            Metadata::Session(parsed) => assert_eq!(parsed, original),
            other => panic!("expected session metadata, got {other:?}"),
        }
    }

    #[test]
    fn test_data_metadata_round_trips() {
        let original = DataMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            timestamp_minutes: 42,
            session_id: 7,
            seq: 9,
            unack_seq: 3,
            window_size: 512,
            fragment: 2,
            prefix_len: 11,
            payload_len: 4096,
            suffix_len: 13,
        };
        let encoded = encode_data(&original);
        assert_eq!(encoded.len(), METADATA_LEN);
        match parse(&encoded).unwrap() {
            Metadata::Data(parsed) => assert_eq!(parsed, original),
            other => panic!("expected data metadata, got {other:?}"),
        }
    }

    /// Field offsets are the thing a reimplementation gets wrong, so pin the
    /// bytes of a known encoding rather than only round-tripping.
    #[test]
    fn test_session_field_offsets() {
        let encoded = encode_session(&SessionMetadata {
            protocol: OPEN_SESSION_REQUEST,
            timestamp_minutes: 0x01020304,
            session_id: 0x05060708,
            seq: 0x090a0b0c,
            status: 0x0d,
            payload_len: 0x0e0f,
            suffix_len: 0x10,
        });
        assert_eq!(encoded[0], 2, "protocol type is byte 0");
        assert_eq!(
            &encoded[2..6],
            &[1, 2, 3, 4],
            "timestamp is big-endian at 2"
        );
        assert_eq!(&encoded[6..10], &[5, 6, 7, 8], "session id at 6");
        assert_eq!(&encoded[10..14], &[9, 10, 11, 12], "sequence at 10");
        assert_eq!(encoded[14], 0x0d, "status at 14");
        assert_eq!(&encoded[15..17], &[0x0e, 0x0f], "payload length at 15");
        assert_eq!(encoded[17], 0x10, "suffix length at 17");
    }

    #[test]
    fn test_data_field_offsets() {
        let encoded = encode_data(&DataMetadata {
            protocol: DATA_CLIENT_TO_SERVER,
            timestamp_minutes: 0x01020304,
            session_id: 0x05060708,
            seq: 0x090a0b0c,
            unack_seq: 0x0d0e0f10,
            window_size: 0x1112,
            fragment: 0x13,
            prefix_len: 0x14,
            payload_len: 0x1516,
            suffix_len: 0x17,
        });
        assert_eq!(encoded[0], 6);
        assert_eq!(&encoded[2..6], &[1, 2, 3, 4]);
        assert_eq!(&encoded[6..10], &[5, 6, 7, 8]);
        assert_eq!(&encoded[10..14], &[9, 10, 11, 12]);
        assert_eq!(&encoded[14..18], &[0x0d, 0x0e, 0x0f, 0x10], "unack at 14");
        assert_eq!(&encoded[18..20], &[0x11, 0x12], "window at 18");
        assert_eq!(encoded[20], 0x13, "fragment at 20");
        assert_eq!(encoded[21], 0x14, "prefix length at 21");
        assert_eq!(&encoded[22..24], &[0x15, 0x16], "payload length at 22");
        assert_eq!(encoded[24], 0x17, "suffix length at 24");
    }

    #[test]
    fn test_low_entropy_types_are_refused() {
        let mut encoded = [0u8; METADATA_LEN];
        encoded[0] = DATA_CLIENT_TO_SERVER_LOW_ENTROPY;
        let err = parse(&encoded).unwrap_err();
        assert!(err.to_string().contains("low entropy"), "{err}");

        encoded[0] = DATA_SERVER_TO_CLIENT_LOW_ENTROPY;
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn test_unknown_protocol_type_is_refused() {
        let mut encoded = [0u8; METADATA_LEN];
        encoded[0] = 99;
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn test_short_input_is_refused() {
        assert!(parse(&[0u8; METADATA_LEN - 1]).is_err());
    }
}
