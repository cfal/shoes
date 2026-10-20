use std::io;

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::svcb::SvcParamValue;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinDecoder};

pub(super) const UDP_PAYLOAD_LIMIT: u16 = 1232;

pub(super) fn addresses(message: &Message) -> impl Iterator<Item = std::net::IpAddr> + '_ {
    message.all_sections().flat_map(|record| {
        let address = match record.data {
            RData::A(ip) => Some(ip.0.into()),
            RData::AAAA(ip) => Some(ip.0.into()),
            _ => None,
        };
        let binding = match &record.data {
            RData::HTTPS(https) => Some(&https.0),
            RData::SVCB(svcb) => Some(svcb),
            _ => None,
        };
        address.into_iter().chain(
            binding
                .into_iter()
                .flat_map(|binding| &binding.svc_params)
                .flat_map(|(_, value)| {
                    let v4 = match value {
                        SvcParamValue::Ipv4Hint(hint) => hint.0.as_slice(),
                        _ => &[],
                    };
                    let v6 = match value {
                        SvcParamValue::Ipv6Hint(hint) => hint.0.as_slice(),
                        _ => &[],
                    };
                    v4.iter()
                        .map(|ip| ip.0.into())
                        .chain(v6.iter().map(|ip| ip.0.into()))
                }),
        )
    })
}

pub(super) fn decode(bytes: &[u8]) -> io::Result<Message> {
    if bytes.len() < 12 || bytes.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS message length",
        ));
    }
    // Hickory reserves QDCOUNT entries before reading the questions.
    let count = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    if count > (bytes.len() - 12) / 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS question count",
        ));
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if decoder.index() != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing DNS data",
        ));
    }
    Ok(message)
}

pub(super) fn is_signed(message: &Message) -> bool {
    message.signature().is_some()
        || message
            .additionals
            .iter()
            .any(|record| matches!(record.record_type(), RecordType::SIG | RecordType::TSIG))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbounded_counts_and_trailing_bytes() {
        let mut bytes = Message::query().to_vec().unwrap();
        assert!(decode(&bytes).is_ok());
        bytes.push(0);
        assert!(decode(&bytes).is_err());
        bytes[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode(&bytes).is_err());
    }
}
