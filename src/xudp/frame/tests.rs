use super::*;

// ==========================================================================
// Basic encode/decode tests
// ==========================================================================

#[test]
fn test_encode_decode_new_frame_udp() {
    let metadata = FrameMetadata {
        session_id: 42,
        status: SessionStatus::New,
        option: FrameOption::new().with_data(),
        target: Some(NetLocation::new(
            Address::Ipv4("1.1.1.1".parse().unwrap()),
            53,
        )),
        network: Some(TargetNetwork::Udp),
    };

    let mut buf = BytesMut::new();
    metadata.encode(&mut buf).unwrap();

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 42);
    assert_eq!(decoded.status, SessionStatus::New);
    assert!(decoded.option.has_data());
    assert_eq!(decoded.network, Some(TargetNetwork::Udp));
    assert!(decoded.target.is_some());
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 53);
}

#[test]
fn test_encode_decode_keep_frame_udp() {
    let metadata = FrameMetadata {
        session_id: 100,
        status: SessionStatus::Keep,
        option: FrameOption::new().with_data(),
        target: Some(NetLocation::new(
            Address::Ipv4("8.8.8.8".parse().unwrap()),
            53,
        )),
        network: Some(TargetNetwork::Udp),
    };

    let mut buf = BytesMut::new();
    metadata.encode(&mut buf).unwrap();

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 100);
    assert_eq!(decoded.status, SessionStatus::Keep);
    assert!(decoded.option.has_data());
    assert_eq!(decoded.network, Some(TargetNetwork::Udp));
}

#[test]
fn test_encode_decode_end_frame() {
    let metadata = FrameMetadata {
        session_id: 50,
        status: SessionStatus::End,
        option: FrameOption::new(),
        target: None,
        network: None,
    };

    let mut buf = BytesMut::new();
    metadata.encode(&mut buf).unwrap();

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 50);
    assert_eq!(decoded.status, SessionStatus::End);
    assert!(!decoded.option.has_data());
}

#[test]
fn test_encode_decode_hostname() {
    let metadata = FrameMetadata {
        session_id: 1,
        status: SessionStatus::New,
        option: FrameOption::new(),
        target: Some(NetLocation::new(
            Address::Hostname("example.com".to_string()),
            443,
        )),
        network: Some(TargetNetwork::Tcp),
    };

    let mut buf = BytesMut::new();
    metadata.encode(&mut buf).unwrap();

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 1);
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 443);
    match target.address() {
        Address::Hostname(h) => assert_eq!(h, "example.com"),
        _ => panic!("expected hostname"),
    }
}

/// Test decoding a frame with extra metadata bytes (GlobalID simulation)
/// Xray-core appends 8-byte GlobalID for UDP session continuity.
/// We skip these bytes like sing-box
#[test]
fn test_decode_frame_with_globalid_extra_bytes() {
    let mut buf = BytesMut::new();

    // Manually construct a frame with GlobalID (8 extra bytes)
    // Format: length(2) + session_id(2) + status(1) + option(1) + network(1) + port(2) + addr_type(1) + ipv4(4) + GlobalID(8)
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 4 + 8; // 20 bytes
    buf.put_u16(metadata_len);
    buf.put_u16(123); // session_id
    buf.put_u8(0x01); // SessionStatus::New
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x02); // TargetNetwork::Udp
    buf.put_u16(53); // port
    buf.put_u8(0x01); // address type: IPv4
    buf.put_slice(&[8, 8, 8, 8]); // 8.8.8.8
    buf.put_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // GlobalID (8 bytes)

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 123);
    assert_eq!(decoded.status, SessionStatus::New);
    assert!(decoded.option.has_data());
    assert_eq!(decoded.network, Some(TargetNetwork::Udp));
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 53);
    assert_eq!(target.address(), &Address::Ipv4("8.8.8.8".parse().unwrap()));

    // Buffer should be fully consumed
    assert_eq!(buf.len(), 0, "Buffer should be fully consumed after decode");
}

/// Test Keep frame without destination (TCP keep)
/// This is a minimal Keep frame with just session_id + status + option
#[test]
fn test_decode_keep_frame_tcp_no_destination() {
    let mut buf = BytesMut::new();

    // Minimal Keep frame: length(2) + session_id(2) + status(1) + option(1) = 4 bytes metadata
    buf.put_u16(4); // metadata length
    buf.put_u16(42); // session_id
    buf.put_u8(0x02); // SessionStatus::Keep
    buf.put_u8(0x01); // FrameOption::DATA

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 42);
    assert_eq!(decoded.status, SessionStatus::Keep);
    assert!(decoded.option.has_data());
    assert!(decoded.network.is_none(), "TCP Keep should have no network");
    assert!(
        decoded.target.is_none(),
        "TCP Keep should have no destination"
    );
    assert_eq!(buf.len(), 0);
}

/// Test Keep frame with UDP destination change
/// Per Xray-core: Keep frames CAN have destination if network byte is 0x02 (UDP)
#[test]
fn test_decode_keep_frame_udp_with_destination() {
    let mut buf = BytesMut::new();

    // Keep+UDP frame with destination
    // Format: length(2) + session_id(2) + status(1) + option(1) + network(1) + port(2) + addr_type(1) + ipv4(4)
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 4; // 12 bytes
    buf.put_u16(metadata_len);
    buf.put_u16(99); // session_id
    buf.put_u8(0x02); // SessionStatus::Keep
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x02); // TargetNetwork::Udp - this triggers destination parsing
    buf.put_u16(1234); // port
    buf.put_u8(0x01); // address type: IPv4
    buf.put_slice(&[192, 168, 1, 1]); // 192.168.1.1

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 99);
    assert_eq!(decoded.status, SessionStatus::Keep);
    assert_eq!(decoded.network, Some(TargetNetwork::Udp));
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 1234);
    assert_eq!(buf.len(), 0);
}

/// Test Keep frame where first byte after header is NOT 0x02 (not UDP)
/// Should NOT parse destination even if there's extra data
#[test]
fn test_decode_keep_frame_non_udp_extra_bytes() {
    let mut buf = BytesMut::new();

    // Keep frame where network byte is 0x01 (TCP) - should NOT parse destination
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 4; // 12 bytes total
    buf.put_u16(metadata_len);
    buf.put_u16(50); // session_id
    buf.put_u8(0x02); // SessionStatus::Keep
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x01); // TargetNetwork::Tcp (NOT UDP!)
    buf.put_u16(443); // port (should be skipped)
    buf.put_u8(0x01); // address type
    buf.put_slice(&[1, 2, 3, 4]); // address (should be skipped)

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 50);
    assert_eq!(decoded.status, SessionStatus::Keep);
    // Network and target should be None because first byte wasn't 0x02
    assert!(
        decoded.network.is_none(),
        "Keep+TCP should not parse network"
    );
    assert!(
        decoded.target.is_none(),
        "Keep+TCP should not parse destination"
    );
    // Extra bytes should be consumed/skipped
    assert_eq!(buf.len(), 0, "Extra bytes should be consumed");
}

/// Test KeepAlive frame (status 0x04)
#[test]
fn test_decode_keepalive_frame() {
    let mut buf = BytesMut::new();

    buf.put_u16(4); // metadata length
    buf.put_u16(1); // session_id
    buf.put_u8(0x04); // SessionStatus::KeepAlive
    buf.put_u8(0x00); // no options

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 1);
    assert_eq!(decoded.status, SessionStatus::KeepAlive);
    assert!(!decoded.option.has_data());
    assert!(!decoded.option.has_error());
    assert_eq!(buf.len(), 0);
}

/// Test End frame with ERROR option
#[test]
fn test_decode_end_frame_with_error() {
    let mut buf = BytesMut::new();

    buf.put_u16(4); // metadata length
    buf.put_u16(77); // session_id
    buf.put_u8(0x03); // SessionStatus::End
    buf.put_u8(0x02); // FrameOption::ERROR

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 77);
    assert_eq!(decoded.status, SessionStatus::End);
    assert!(!decoded.option.has_data());
    assert!(decoded.option.has_error());
    assert_eq!(buf.len(), 0);
}

/// Test IPv6 destination
#[test]
fn test_decode_new_frame_ipv6() {
    let mut buf = BytesMut::new();

    // New frame with IPv6 destination
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 16; // 24 bytes
    buf.put_u16(metadata_len);
    buf.put_u16(200); // session_id
    buf.put_u8(0x01); // SessionStatus::New
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x02); // TargetNetwork::Udp
    buf.put_u16(53); // port
    buf.put_u8(0x03); // address type: IPv6
    buf.put_slice(&[
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ]); // 2001:4860:4860::8888

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 200);
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 53);
    match target.address() {
        Address::Ipv6(v6) => {
            assert_eq!(v6.to_string(), "2001:4860:4860::8888");
        }
        _ => panic!("expected IPv6"),
    }
    assert_eq!(buf.len(), 0);
}

// ==========================================================================
// Error handling tests
// ==========================================================================

/// Test incomplete buffer (not enough for length field)
#[test]
fn test_decode_incomplete_length() {
    let mut buf = BytesMut::new();
    buf.put_u8(0x00); // Only 1 byte, need 2 for length

    let result = FrameMetadata::decode(&mut buf).unwrap();
    assert!(result.is_none(), "Should return None for incomplete length");
    assert_eq!(buf.len(), 1, "Buffer should not be consumed");
}

/// Test incomplete metadata (length says more than available)
#[test]
fn test_decode_incomplete_metadata() {
    let mut buf = BytesMut::new();
    buf.put_u16(10); // metadata length = 10
    buf.put_u16(1); // session_id
    // Only 2 bytes of metadata, but length says 10

    let result = FrameMetadata::decode(&mut buf).unwrap();
    assert!(
        result.is_none(),
        "Should return None for incomplete metadata"
    );
}

/// Test metadata too short (less than 4 bytes)
#[test]
fn test_decode_metadata_too_short() {
    let mut buf = BytesMut::new();
    buf.put_u16(2); // metadata length = 2 (too short, need at least 4)
    buf.put_u16(1); // only 2 bytes of metadata

    let result = FrameMetadata::decode(&mut buf);
    assert!(result.is_err(), "Should error on metadata too short");
}

/// Test invalid session status
#[test]
fn test_decode_invalid_session_status() {
    let mut buf = BytesMut::new();
    buf.put_u16(4); // metadata length
    buf.put_u16(1); // session_id
    buf.put_u8(0x99); // Invalid status!
    buf.put_u8(0x00); // option

    let result = FrameMetadata::decode(&mut buf);
    assert!(result.is_err(), "Should error on invalid session status");
}

/// Test invalid network type in New frame
#[test]
fn test_decode_invalid_network_type() {
    let mut buf = BytesMut::new();
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 4;
    buf.put_u16(metadata_len);
    buf.put_u16(1); // session_id
    buf.put_u8(0x01); // SessionStatus::New
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x99); // Invalid network type!
    buf.put_u16(53); // port
    buf.put_u8(0x01); // address type
    buf.put_slice(&[1, 2, 3, 4]);

    let result = FrameMetadata::decode(&mut buf);
    assert!(result.is_err(), "Should error on invalid network type");
}

/// Test invalid address type
#[test]
fn test_decode_invalid_address_type() {
    let mut buf = BytesMut::new();
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 4;
    buf.put_u16(metadata_len);
    buf.put_u16(1); // session_id
    buf.put_u8(0x01); // SessionStatus::New
    buf.put_u8(0x01); // FrameOption::DATA
    buf.put_u8(0x02); // TargetNetwork::Udp
    buf.put_u16(53); // port
    buf.put_u8(0x99); // Invalid address type!
    buf.put_slice(&[1, 2, 3, 4]);

    let result = FrameMetadata::decode(&mut buf);
    assert!(result.is_err(), "Should error on invalid address type");
}

#[test]
fn test_frame_format_compatibility() {
    let mut buf = BytesMut::new();

    // Xray-core format for New+UDP:
    // 2 bytes - length (of metadata after this field)
    // 2 bytes - session id
    // 1 byte - status
    // 1 byte - option
    // 1 byte - network
    // 2 bytes - port
    // n bytes - address (1 byte type + address bytes)

    let metadata_len: u16 = 2 + 1 + 1 + 1 + 2 + 1 + 4; // = 12
    buf.put_u16(metadata_len);
    buf.put_u16(0x0001); // session_id = 1
    buf.put_u8(0x01); // SessionStatusNew
    buf.put_u8(0x01); // OptionData
    buf.put_u8(0x02); // TargetNetworkUDP
    buf.put_u16(443); // port (big-endian)
    buf.put_u8(0x01); // AddressTypeIPv4
    buf.put_slice(&[93, 184, 216, 34]); // 93.184.216.34 (example.com)

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();

    assert_eq!(decoded.session_id, 1);
    assert_eq!(decoded.status, SessionStatus::New);
    assert!(decoded.option.has_data());
    assert!(!decoded.option.has_error());
    assert_eq!(decoded.network, Some(TargetNetwork::Udp));

    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 443);
    assert_eq!(
        target.address(),
        &Address::Ipv4("93.184.216.34".parse().unwrap())
    );
}

/// Test domain name encoding
#[test]
fn test_domain_format() {
    let mut buf = BytesMut::new();

    let domain = "dns.google";
    let metadata_len: u16 = 4 + 1 + 2 + 1 + 1 + domain.len() as u16; // 19
    buf.put_u16(metadata_len);
    buf.put_u16(5); // session_id
    buf.put_u8(0x01); // SessionStatusNew
    buf.put_u8(0x01); // OptionData
    buf.put_u8(0x02); // TargetNetworkUDP
    buf.put_u16(853); // DNS over TLS port
    buf.put_u8(0x02); // AddressTypeDomain
    buf.put_u8(domain.len() as u8);
    buf.put_slice(domain.as_bytes());

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    let target = decoded.target.unwrap();
    assert_eq!(target.port(), 853);
    match target.address() {
        Address::Hostname(h) => assert_eq!(h, "dns.google"),
        _ => panic!("expected hostname"),
    }
}

/// Test that our encoder produces Xray-compatible output
#[test]
fn test_encode_xray_compatible() {
    let metadata = FrameMetadata {
        session_id: 100,
        status: SessionStatus::New,
        option: FrameOption::new().with_data(),
        target: Some(NetLocation::new(
            Address::Ipv4("1.1.1.1".parse().unwrap()),
            53,
        )),
        network: Some(TargetNetwork::Udp),
    };

    let mut buf = BytesMut::new();
    metadata.encode(&mut buf).unwrap();

    // Verify the wire format
    assert_eq!(buf[0..2], [0x00, 0x0c]); // length = 12 (big-endian)
    assert_eq!(buf[2..4], [0x00, 0x64]); // session_id = 100 (big-endian)
    assert_eq!(buf[4], 0x01); // SessionStatusNew
    assert_eq!(buf[5], 0x01); // OptionData
    assert_eq!(buf[6], 0x02); // TargetNetworkUDP
    assert_eq!(buf[7..9], [0x00, 0x35]); // port = 53 (big-endian)
    assert_eq!(buf[9], 0x01); // AddressTypeIPv4
    assert_eq!(buf[10..14], [1, 1, 1, 1]); // 1.1.1.1
}

/// Test maximum session ID (u16::MAX)
#[test]
fn test_max_session_id() {
    let mut buf = BytesMut::new();
    buf.put_u16(4);
    buf.put_u16(0xFFFF); // max session_id
    buf.put_u8(0x02); // Keep
    buf.put_u8(0x00);

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.session_id, 65535);
}

/// Test both DATA and ERROR options set
#[test]
fn test_data_and_error_options() {
    let mut buf = BytesMut::new();
    buf.put_u16(4);
    buf.put_u16(1);
    buf.put_u8(0x03); // End
    buf.put_u8(0x03); // DATA | ERROR

    let decoded = FrameMetadata::decode(&mut buf).unwrap().unwrap();
    assert!(decoded.option.has_data());
    assert!(decoded.option.has_error());
}
