use super::*;
use futures::task::noop_waker_ref;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn poll_read_record_retains_partial_data_across_pending() {
    let record = make_tls_record(0x17, b"payload");
    for split in [2, 8] {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        let mut deframer = TlsDeframer::new();
        let mut scratch = [0; 32];
        let mut cx = Context::from_waker(noop_waker_ref());
        writer.write_all(&record[..split]).await.unwrap();
        assert!(
            deframer
                .poll_read_record(&mut reader, &mut cx, &mut scratch, true)
                .is_pending()
        );
        writer.write_all(&record[split..]).await.unwrap();
        let Poll::Ready(Ok(Some(received))) =
            deframer.poll_read_record(&mut reader, &mut cx, &mut scratch, true)
        else {
            panic!("complete record remained pending");
        };
        assert_eq!(received, record);
    }
}

#[test]
fn bounded_record_read_leaves_the_next_record_on_the_transport() {
    let record = make_tls_record(0x17, b"payload");
    for split in [0, 2, 8] {
        let mut deframer = TlsDeframer::new();
        deframer.feed(&record[..split]);
        let data = [&record[split..], b"opaque tail"].concat();
        let mut reader = data.as_slice();
        let mut scratch = [0; 64];
        let mut cx = Context::from_waker(noop_waker_ref());
        let Poll::Ready(Ok(Some(received))) =
            deframer.poll_read_record(&mut reader, &mut cx, &mut scratch, false)
        else {
            panic!("complete record remained pending");
        };
        assert_eq!(received, record);
        assert_eq!(reader, b"opaque tail");
        assert_eq!(deframer.pending_bytes(), 0);
    }
}

#[test]
fn poll_read_record_distinguishes_clean_and_truncated_eof() {
    let record = make_tls_record(0x17, b"payload");
    for length in 0..record.len() {
        let mut reader = &record[..length];
        let mut deframer = TlsDeframer::new();
        let mut scratch = [0; 32];
        let mut cx = Context::from_waker(noop_waker_ref());
        let result = deframer.poll_read_record(&mut reader, &mut cx, &mut scratch, true);
        if length == 0 {
            assert!(matches!(result, Poll::Ready(Ok(None))));
        } else {
            assert!(
                matches!(result, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
            );
        }
    }
}

/// Helper to create a TLS record with given content type and payload
fn make_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(content_type);
    record.push(0x03); // Version major
    record.push(0x03); // Version minor
    let len = payload.len() as u16;
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(payload);
    record
}

#[test]
fn test_single_complete_packet() {
    let mut deframer = TlsDeframer::new();

    let payload = b"Hello, TLS!";
    let record = make_tls_record(0x17, payload); // Application Data

    deframer.feed(&record);

    let read_record = deframer.next_record().unwrap();
    assert!(read_record.is_some());
    let read_record = read_record.unwrap();
    assert_eq!(read_record, &record[..]);

    // Verify no more packets
    assert!(deframer.next_record().unwrap().is_none());
}

#[test]
fn test_partial_packet_split_header() {
    let mut deframer = TlsDeframer::new();

    let payload = b"Partial header test";
    let record = make_tls_record(0x16, payload); // Handshake

    // Feed first 3 bytes (partial header)
    deframer.feed(&record[..3]);
    assert!(deframer.next_record().unwrap().is_none());

    // Feed rest of header
    deframer.feed(&record[3..5]);
    assert!(deframer.next_record().unwrap().is_none());

    // Feed payload
    deframer.feed(&record[5..]);
    let extracted_record = deframer.next_record().unwrap();
    assert!(extracted_record.is_some());
    assert_eq!(extracted_record.unwrap(), &record[..]);
}

#[test]
fn test_partial_packet_split_payload() {
    let mut deframer = TlsDeframer::new();

    let payload = vec![0x42; 100]; // 100 bytes of 0x42
    let record = make_tls_record(0x17, &payload);

    // Feed header + half payload
    let split_point = 5 + 50;
    deframer.feed(&record[..split_point]);
    assert!(deframer.next_record().unwrap().is_none());

    // Feed rest of payload
    deframer.feed(&record[split_point..]);
    let extracted_record = deframer.next_record().unwrap();
    assert!(extracted_record.is_some());
    assert_eq!(extracted_record.unwrap(), &record[..]);
}

#[test]
fn test_multiple_packets_at_once() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"First");
    let record2 = make_tls_record(0x17, b"Second");
    let record3 = make_tls_record(0x16, b"Third");

    // Feed all three at once
    let mut combined = Vec::new();
    combined.extend_from_slice(&record1);
    combined.extend_from_slice(&record2);
    combined.extend_from_slice(&record3);

    deframer.feed(&combined);

    // Extract all three (automatically consumed)
    let rec1 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec1, &record1[..]);

    let rec2 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec2, &record2[..]);

    let rec3 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec3, &record3[..]);

    assert!(deframer.next_record().unwrap().is_none());
}

#[test]
fn test_multiple_packets_partial_boundary() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"Record One");
    let record2 = make_tls_record(0x17, b"Record Two");

    let mut combined = Vec::new();
    combined.extend_from_slice(&record1);
    combined.extend_from_slice(&record2);

    // Feed up to middle of second record
    let split = record1.len() + 8;
    deframer.feed(&combined[..split]);

    // Should get first record (automatically consumed)
    let rec1 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec1, &record1[..]);

    // Second record not complete yet
    assert!(deframer.next_record().unwrap().is_none());

    // Feed rest
    deframer.feed(&combined[split..]);
    let rec2 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec2, &record2[..]);
}

#[test]
fn test_tls10_accepted() {
    let mut deframer = TlsDeframer::new();

    let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x05]; // TLS 1.0
    record.extend_from_slice(b"Hello");

    deframer.feed(&record);

    let result = deframer.next_record();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().unwrap(), &record[..]);
}

#[test]
fn test_invalid_protocol_version() {
    let mut deframer = TlsDeframer::new();

    let mut record = vec![0x16, 0x02, 0x00, 0x00, 0x05]; // SSL 2.0 (invalid)
    record.extend_from_slice(b"Hello");

    deframer.feed(&record);

    let result = deframer.next_record();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid TLS protocol version")
    );
}

#[test]
fn test_invalid_content_type() {
    let mut deframer = TlsDeframer::new();

    let mut record = vec![0xFF, 0x03, 0x03, 0x00, 0x05]; // Invalid content type
    record.extend_from_slice(b"Hello");

    deframer.feed(&record);

    let result = deframer.next_record();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid TLS content type")
    );
}

#[test]
fn test_excessive_payload_length() {
    let mut deframer = TlsDeframer::new();

    // Payload length > 18432 (TLS 1.2 max ciphertext)
    let record = vec![0x17, 0x03, 0x03, 0xFF, 0xFF]; // 65535 bytes

    deframer.feed(&record);

    let result = deframer.next_record();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
}

#[test]
fn test_byte_by_byte_feed() {
    let mut deframer = TlsDeframer::new();

    let record = make_tls_record(0x16, b"Byte by byte");

    // Feed one byte at a time
    for byte in &record[..record.len() - 1] {
        deframer.feed(&[*byte]);
        assert!(deframer.next_record().unwrap().is_none());
    }

    // Feed last byte
    deframer.feed(&[record[record.len() - 1]]);
    let extracted_record = deframer.next_record().unwrap().unwrap();
    assert_eq!(extracted_record, &record[..]);
}

#[test]
fn test_clear() {
    let mut deframer = TlsDeframer::new();

    let record = make_tls_record(0x16, b"Test");
    deframer.feed(&record[..3]); // Partial

    assert_eq!(deframer.pending_bytes(), 3);

    deframer.clear();

    assert_eq!(deframer.pending_bytes(), 0);
    assert!(deframer.next_record().unwrap().is_none());
}

#[test]
fn test_empty_payload() {
    let mut deframer = TlsDeframer::new();

    let record = make_tls_record(0x16, b""); // Empty payload

    deframer.feed(&record);

    let extracted_record = deframer.next_record().unwrap().unwrap();
    assert_eq!(extracted_record.len(), 5); // Just the header
    assert_eq!(extracted_record, &record[..]);
}

#[test]
fn test_max_size_payload() {
    let mut deframer = TlsDeframer::new();

    // Test with maximum TLS 1.2 ciphertext size (18,432 bytes)
    let payload = vec![0xAA; 18432];
    let record = make_tls_record(0x17, &payload);

    deframer.feed(&record);

    let extracted_record = deframer.next_record().unwrap().unwrap();
    assert_eq!(extracted_record, &record[..]);
}

#[test]
fn test_reuse_after_consume() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"First");
    let record2 = make_tls_record(0x17, b"Second");

    // First packet (automatically consumed)
    deframer.feed(&record1);
    let rec1 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec1, &record1[..]);

    // Second packet (automatically consumed)
    deframer.feed(&record2);
    let rec2 = deframer.next_record().unwrap().unwrap();
    assert_eq!(rec2, &record2[..]);

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_next_records_empty() {
    let mut deframer = TlsDeframer::new();

    let records = deframer.next_records().unwrap();
    assert!(records.is_empty());
}

#[test]
fn test_next_records_single() {
    let mut deframer = TlsDeframer::new();

    let record = make_tls_record(0x16, b"Single");
    deframer.feed(&record);

    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0], &record[..]);
}

#[test]
fn test_next_records_multiple() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"First");
    let record2 = make_tls_record(0x17, b"Second");
    let record3 = make_tls_record(0x16, b"Third");

    let mut combined = Vec::new();
    combined.extend_from_slice(&record1);
    combined.extend_from_slice(&record2);
    combined.extend_from_slice(&record3);

    deframer.feed(&combined);

    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0], &record1[..]);
    assert_eq!(records[1], &record2[..]);
    assert_eq!(records[2], &record3[..]);

    assert_eq!(deframer.pending_bytes(), 0);
}

#[test]
fn test_next_records_partial_remaining() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"Complete");
    let record2 = make_tls_record(0x17, b"Incomplete");

    let mut combined = Vec::new();
    combined.extend_from_slice(&record1);
    combined.extend_from_slice(&record2[..10]); // Only partial second record

    deframer.feed(&combined);

    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0], &record1[..]);

    // Should still have partial data
    assert_eq!(deframer.pending_bytes(), 10);
}

#[test]
fn test_next_records_error_propagation() {
    let mut deframer = TlsDeframer::new();

    // Invalid record with bad content type
    let mut bad_record = vec![0xFF, 0x03, 0x03, 0x00, 0x05];
    bad_record.extend_from_slice(b"Hello");

    deframer.feed(&bad_record);

    let result = deframer.next_records();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid TLS content type")
    );
}

#[test]
fn test_next_records_mixed_complete_and_partial() {
    let mut deframer = TlsDeframer::new();

    let record1 = make_tls_record(0x16, b"First");
    let record2 = make_tls_record(0x17, b"Second");

    // Feed first complete record and partial second
    deframer.feed(&record1);
    deframer.feed(&record2[..8]);

    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0], &record1[..]);

    // Complete the second record
    deframer.feed(&record2[8..]);

    let records = deframer.next_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0], &record2[..]);
}
