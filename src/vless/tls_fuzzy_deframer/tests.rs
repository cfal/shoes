use super::*;

/// Helper to create a TLS record with given content type and payload
/// For Handshake records (0x16), prepends handshake type to payload
fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(content_type);
    record.push(0x03); // Version major
    record.push(0x03); // Version minor

    // For Handshake records, prepend handshake type (0x01 = ClientHello)
    if content_type == 0x16 {
        let total_len = 1 + payload.len(); // handshake type byte + payload
        record.extend_from_slice(&(total_len as u16).to_be_bytes());
        record.push(0x01); // ClientHello handshake type
        record.extend_from_slice(payload);
    } else {
        let len = payload.len() as u16;
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(payload);
    }

    record
}

#[test]
fn test_no_prefix_complete_record() {
    let mut deframer = FuzzyTlsDeframer::new();

    // TLS record with no prefix
    let record = make_tls_record(0x16, b"Hello");
    deframer.feed(&record);

    // Should immediately transition to Deframing and return the record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => assert_eq!(r, &record[..]),
        other => panic!("Expected TlsRecord, got {:?}", other),
    }
}

#[test]
fn test_prefix_then_complete_record() {
    let mut deframer = FuzzyTlsDeframer::new();

    // VLESS-like prefix (26 bytes of zeros) + TLS record
    let mut data = vec![0x00; 26];
    let record = make_tls_record(0x16, b"Hello");
    data.extend_from_slice(&record);

    deframer.feed(&data);

    // First call should return the prefix
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 26),
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // Second call should return the TLS record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => assert_eq!(r, &record[..]),
        other => panic!("Expected TlsRecord, got {:?}", other),
    }

    // Third call should return incomplete
    match deframer.next_record().unwrap() {
        DeframeResult::NeedData => {}
        other => panic!("Expected IncompleteRecord, got {:?}", other),
    }
}

#[test]
fn test_small_non_tls_prefix_returned_immediately() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Small prefix (3 bytes) that cannot be TLS (doesn't start with 0x16)
    deframer.feed(&[0x00, 0x01, 0x02]);

    // Should return as UnknownPrefix since it can never be TLS
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.as_ref(), &[0x00, 0x01, 0x02]);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_large_prefix_returned_proactively() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Large prefix (10 bytes) with no partial pattern at end
    deframer.feed(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);

    // Should return prefix, keeping nothing (suffix_len = 0)
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 10),
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_prefix_with_partial_pattern_suffix() {
    let mut deframer = FuzzyTlsDeframer::new();

    // 10 bytes of junk + partial TLS pattern [0x16, 0x03]
    deframer.feed(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x16, 0x03,
    ]);

    // Should return 10 bytes as prefix, keep [0x16, 0x03] as potential pattern
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 10),
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 2);

    // Now feed the rest of the pattern
    deframer.feed(&[0x01, 0x00, 0x05, 0x01, b'H', b'e', b'l', b'l', b'o']);

    // Should get the complete TLS record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => {
            assert_eq!(r[0], 0x16); // Handshake
            assert_eq!(r.len(), 5 + 5); // header + payload
        }
        other => panic!("Expected TlsRecord, got {:?}", other),
    }
}

#[test]
fn test_partial_pattern_alone_not_discarded() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Just a partial pattern [0x16, 0x03]
    deframer.feed(&[0x16, 0x03]);

    // Should wait for more data, not discard
    match deframer.next_record().unwrap() {
        DeframeResult::NeedData => {}
        other => panic!("Expected IncompleteRecord, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 2);
}

#[test]
fn test_multiple_records_after_prefix() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Prefix + two TLS records
    let mut data = vec![0x00; 26];
    let record1 = make_tls_record(0x16, b"First");
    let record2 = make_tls_record(0x17, b"Second");
    data.extend_from_slice(&record1);
    data.extend_from_slice(&record2);

    deframer.feed(&data);

    // Get prefix
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 26),
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // Get first record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => assert_eq!(r, &record1[..]),
        other => panic!("Expected TlsRecord, got {:?}", other),
    }

    // Get second record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => assert_eq!(r, &record2[..]),
        other => panic!("Expected TlsRecord, got {:?}", other),
    }

    // No more data
    match deframer.next_record().unwrap() {
        DeframeResult::NeedData => {}
        other => panic!("Expected IncompleteRecord, got {:?}", other),
    }
}

#[test]
fn test_split_feed_across_pattern() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Feed prefix + partial pattern in first call
    // [0x00, 0x01, 0x02] is non-TLS, [0x16, 0x03] is valid TLS prefix
    deframer.feed(&[0x00, 0x01, 0x02, 0x16, 0x03]);

    // Should return the non-TLS prefix immediately, keeping [0x16, 0x03]
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.as_ref(), &[0x00, 0x01, 0x02]);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // Should have [0x16, 0x03] buffered
    assert_eq!(deframer.pending_bytes(), 2);

    // Now need more data to complete the pattern
    match deframer.next_record().unwrap() {
        DeframeResult::NeedData => {}
        other => panic!("Expected NeedData, got {:?}", other),
    }

    // Feed rest of pattern + record
    deframer.feed(&[0x01, 0x00, 0x05, 0x01, b'H', b'e', b'l', b'l', b'o']);

    // Should get the complete TLS record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(_) => {}
        other => panic!("Expected TlsRecord, got {:?}", other),
    }
}

#[test]
fn test_pending_bytes_accounting() {
    let mut deframer = FuzzyTlsDeframer::new();

    assert_eq!(deframer.pending_bytes(), 0);

    // Feed some data
    deframer.feed(&[0x00, 0x01, 0x02]);
    assert_eq!(deframer.pending_bytes(), 3);

    // Feed more to exceed threshold
    deframer.feed(&[0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(deframer.pending_bytes(), 9);

    // Extract prefix
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 9),
        _ => panic!("Expected UnknownPrefix"),
    }

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_pending_bytes_during_state_transition() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Feed prefix + complete TLS record
    let mut data = vec![0x00; 26]; // VLESS prefix
    let record = make_tls_record(0x16, b"Test");
    data.extend_from_slice(&record);

    deframer.feed(&data);

    // Before extracting anything, pending_bytes should be full buffer
    assert_eq!(deframer.pending_bytes(), 26 + record.len());

    // Extract prefix (state transitions to Deframing, TLS data fed to inner)
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.len(), 26);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // After extracting prefix, pending_bytes should show TLS record length
    // (TLS data is now in inner deframer)
    assert_eq!(deframer.pending_bytes(), record.len());

    // Extract the TLS record
    match deframer.next_record().unwrap() {
        DeframeResult::TlsRecord(r) => assert_eq!(r.len(), record.len()),
        other => panic!("Expected TlsRecord, got {:?}", other),
    }

    // After extracting record, buffer should be empty
    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_clear() {
    let mut deframer = FuzzyTlsDeframer::new();

    deframer.feed(&[0x00, 0x01, 0x02]);
    assert_eq!(deframer.pending_bytes(), 3);

    deframer.clear();
    assert_eq!(deframer.pending_bytes(), 0);
    assert_eq!(deframer.state, FuzzyState::Searching);
}

#[test]
fn discard_buffered_preserves_tls_framing_at_a_record_boundary() {
    let hello = make_tls_record(0x16, b"hello");
    let application = make_tls_record(0x17, b"application");
    for tail_len in 0..=application.len() {
        let mut deframer = FuzzyTlsDeframer::new();
        deframer.feed(&hello);
        assert!(matches!(
            deframer.next_record().unwrap(),
            DeframeResult::TlsRecord(_)
        ));
        deframer.feed(&application[..tail_len]);
        if tail_len < application.len() {
            assert!(matches!(
                deframer.next_record().unwrap(),
                DeframeResult::NeedData
            ));
        }
        deframer.discard_buffered();
        assert_eq!(deframer.pending_bytes(), 0);
        deframer.feed(&application);
        match deframer.next_record().unwrap() {
            DeframeResult::TlsRecord(bytes) => assert_eq!(bytes.as_ref(), application),
            result => panic!("lost TLS framing: {result:?}"),
        }
        assert_eq!(deframer.pending_bytes(), 0);
        assert!(matches!(
            deframer.next_record().unwrap(),
            DeframeResult::NeedData
        ));
    }
}

#[test]
fn discard_buffered_does_not_promote_searching_to_tls() {
    let mut deframer = FuzzyTlsDeframer::new();
    deframer.feed(&[0x16, 3]);
    assert!(matches!(
        deframer.next_record().unwrap(),
        DeframeResult::NeedData
    ));
    deframer.discard_buffered();
    assert_eq!(deframer.pending_bytes(), 0);
    let application = make_tls_record(0x17, b"application");
    deframer.feed(&application);
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(bytes) => assert_eq!(bytes.as_ref(), application),
        result => panic!("unexpected TLS recognition: {result:?}"),
    }
}

#[test]
fn test_false_tls_pattern_continues_search() {
    let mut deframer = FuzzyTlsDeframer::new();

    // Data with [0x16, 0x03] but not a valid TLS pattern (wrong minor version)
    // Pattern needs: [0x16, 0x03, 0x01-0x03, ?, ?, 0x01|0x02]
    let data = vec![0x00, 0x01, 0x16, 0x03, 0x04, 0x00, 0x00, 0x01]; // 0x04 is invalid minor version

    deframer.feed(&data);

    // Should return as prefix since pattern search fails
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => assert_eq!(prefix.len(), 8),
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.state, FuzzyState::Searching);
}

#[test]
fn test_small_non_tls_data_returns_unknown_prefix() {
    // 5 bytes of clearly non-TLS data should return UnknownPrefix, not NeedData
    let mut deframer = FuzzyTlsDeframer::new();

    // HTTP chunked terminator: "0\r\n\r\n" - clearly not TLS (starts with 0x30, not 0x16)
    let chunked_terminator: &[u8] = &[0x30, 0x0d, 0x0a, 0x0d, 0x0a];
    deframer.feed(chunked_terminator);

    // Should return UnknownPrefix for all 5 bytes (no valid TLS suffix)
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.len(), 5);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // Buffer should be empty now
    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_small_data_with_tls_suffix_keeps_suffix() {
    // Data ending with 0x16 should keep that byte as potential TLS start
    let mut deframer = FuzzyTlsDeframer::new();

    // [0x0a, 0x0b, 0x16] - last byte could be TLS start
    deframer.feed(&[0x0a, 0x0b, 0x16]);

    // Should return UnknownPrefix for first 2 bytes, keep 0x16
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.as_ref(), &[0x0a, 0x0b]);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    // Should have 1 byte (0x16) still buffered
    assert_eq!(deframer.pending_bytes(), 1);
    assert_eq!(deframer.remaining_data(), &[0x16]);
}

#[test]
fn test_small_valid_tls_prefix_returns_need_data() {
    // A valid TLS prefix should return NeedData
    let mut deframer = FuzzyTlsDeframer::new();

    // [0x16, 0x03] - valid TLS prefix, need more data
    deframer.feed(&[0x16, 0x03]);

    match deframer.next_record().unwrap() {
        DeframeResult::NeedData => {}
        other => panic!("Expected NeedData, got {:?}", other),
    }

    // All data should still be buffered
    assert_eq!(deframer.pending_bytes(), 2);
}

#[test]
fn test_small_invalid_tls_prefix_returns_unknown() {
    // [0x16, 0x04] - starts with 0x16 but 0x04 is invalid major version
    let mut deframer = FuzzyTlsDeframer::new();

    deframer.feed(&[0x16, 0x04]);

    // 0x16 alone could be TLS, but [0x16, 0x04] cannot
    // Should return 0x16 as unknown and... wait, no.
    // Actually [0x16] alone IS a valid prefix. The issue is [0x16, 0x04].
    // After seeing 0x04, we know [0x16, 0x04] is not TLS.
    // But we should check if any suffix could be TLS.
    // [0x04] alone is not a valid TLS prefix (doesn't start with 0x16).
    // So return both bytes as UnknownPrefix.
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.as_ref(), &[0x16, 0x04]);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_data_ending_with_valid_tls_prefix() {
    // [0x00, 0x01, 0x16, 0x03, 0x03] - ends with valid TLS prefix
    let mut deframer = FuzzyTlsDeframer::new();

    deframer.feed(&[0x00, 0x01, 0x16, 0x03, 0x03]);

    // Should return first 2 bytes as unknown, keep last 3 as potential TLS
    match deframer.next_record().unwrap() {
        DeframeResult::UnknownPrefix(prefix) => {
            assert_eq!(prefix.as_ref(), &[0x00, 0x01]);
        }
        other => panic!("Expected UnknownPrefix, got {:?}", other),
    }

    assert_eq!(deframer.pending_bytes(), 3);
    assert_eq!(deframer.remaining_data(), &[0x16, 0x03, 0x03]);
}
