use std::io;

use bytes::Bytes;
use rustls::reality::FlightPlan;

pub(super) fn verify_staged_flight(wire: &[u8], target: &[Bytes], hello: &[u8]) -> io::Result<()> {
    let mut deframer = crate::crypto::tls_deframer::TlsDeframer::new();
    deframer.feed(wire);
    let actual = deframer.next_records().map_err(io::Error::other)?;
    if actual.len() != target.len()
        || deframer.pending_bytes() != 0
        || actual
            .iter()
            .zip(target)
            .any(|(a, b)| a.len() != b.len() || a[..5] != b[..5])
        || actual.first().is_none_or(|record| &record[5..] != hello)
        || actual
            .get(1)
            .is_none_or(|record| record.as_ref() != [20, 3, 3, 0, 1, 1])
    {
        return Err(io::Error::other(
            "REALITY staged flight differs from admitted target",
        ));
    }
    Ok(())
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Unsupported REALITY target record layout or insufficient capacity",
    )
}

pub(super) fn flight_plan(records: &[Bytes]) -> io::Result<FlightPlan> {
    if !matches!(records.len(), 3 | 6 | 7) {
        return Err(unsupported());
    }
    for (index, record) in records.iter().enumerate() {
        let header = record.get(..5).ok_or_else(unsupported)?;
        let expected_type = match index {
            0 => 22,
            1 => 20,
            _ => 23,
        };
        if header[0] != expected_type
            || header[1..3] != [3, 3]
            || record.len() != 5 + usize::from(u16::from_be_bytes([header[3], header[4]]))
        {
            return Err(unsupported());
        }
    }
    if records[1].as_ref() != [20, 3, 3, 0, 1, 1] {
        return Err(unsupported());
    }
    if (records.len() == 3) != (records[2].len() > 512) {
        return Err(unsupported());
    }
    let handshake_end = if records.len() == 3 { 3 } else { 6 };
    let lengths: Vec<_> = records[2..handshake_end].iter().map(Bytes::len).collect();
    FlightPlan::new(&lengths, records.get(6).map(Bytes::len)).map_err(|_| unsupported())
}
