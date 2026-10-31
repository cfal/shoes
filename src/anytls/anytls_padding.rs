//! AnyTLS padding scheme implementation
//!
//! Provides configurable packet padding to obfuscate TLS-in-TLS fingerprints.
//! Based on the AnyTLS protocol specification.

use crate::anytls::anytls_types::StringMap;
use md5::{Digest, Md5};
use rand::RngExt;
use std::sync::Arc;

pub(super) type SharedPadding = Arc<parking_lot::RwLock<Arc<PaddingFactory>>>;

#[cfg(test)]
pub(super) struct PaddingWriteCase {
    pub sizes: &'static str,
    pub payload: bytes::BytesMut,
    pub writes: Vec<Vec<u8>>,
}

#[cfg(test)]
pub(super) fn padding_write_cases() -> impl Iterator<Item = PaddingWriteCase> {
    use super::anytls_types::{Command, Frame};
    use bytes::{Bytes, BytesMut};

    [
        ("", 0, vec![], vec![]),
        ("", 5, vec![], vec![5]),
        ("c,20-20", 0, vec![], vec![]),
        ("c,20-20", 5, vec![8], vec![20]),
        ("5-5,c,20-20", 5, vec![], vec![5]),
        ("10-10", 5, vec![], vec![5]),
        ("12-12", 5, vec![], vec![5]),
        ("13-13", 5, vec![1], vec![13]),
        ("2-2,20-20", 5, vec![10], vec![2, 20]),
        ("2-2", 5, vec![], vec![2, 3]),
        ("20-20,2-2", 5, vec![8, 2], vec![20, 9]),
        ("65555-65555", 5, vec![65535, 1], vec![65555]),
        ("65536-65536", 0, vec![65535, 1], vec![65550]),
    ]
    .into_iter()
    .map(|(sizes, payload_len, padding_lengths, write_lengths)| {
        let payload = BytesMut::from(vec![42; payload_len].as_slice());
        let mut wire = payload.clone();
        for length in padding_lengths {
            Frame::with_data(Command::Waste, 0, Bytes::from(vec![0; length]))
                .encode_into(&mut wire)
                .unwrap();
        }
        let writes = write_lengths
            .into_iter()
            .map(|length| wire.split_to(length).to_vec())
            .collect();
        assert!(wire.is_empty());
        PaddingWriteCase {
            sizes,
            payload,
            writes,
        }
    })
}

pub(super) fn append_padding(
    buf: &mut bytes::BytesMut,
    mut remaining: usize,
    includes_headers: bool,
) {
    use super::anytls_types::{Command, FRAME_HEADER_SIZE};
    use bytes::BufMut;
    loop {
        if includes_headers {
            if remaining <= FRAME_HEADER_SIZE {
                break;
            }
            remaining -= FRAME_HEADER_SIZE;
        } else if remaining == 0 {
            break;
        }
        let length = remaining.min(u16::MAX as usize);
        buf.reserve(FRAME_HEADER_SIZE + length);
        buf.put_u8(Command::Waste as u8);
        buf.put_u32(0);
        buf.put_u16(length as u16);
        buf.put_bytes(0, length);
        remaining -= length;
    }
}

/// Check mark constant - indicates "stop if no more data" in padding scheme
pub const CHECK_MARK: i32 = -1;

/// Default padding scheme from the AnyTLS specification
pub const DEFAULT_PADDING_SCHEME: &str = r#"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000"#;

/// PaddingFactory generates padding sizes according to the configured scheme
#[derive(Debug, Clone)]
pub struct PaddingFactory {
    /// Parsed scheme as key-value map
    scheme: StringMap,
    /// Raw scheme bytes (for transmission to clients)
    raw_scheme: Vec<u8>,
    /// Stop padding after this many packets
    stop: u32,
    /// MD5 hash of the scheme (for comparison)
    md5: String,
}

impl PaddingFactory {
    /// Create a new PaddingFactory from raw scheme bytes
    pub fn new(raw_scheme: &[u8]) -> Result<Self, String> {
        let scheme = StringMap::from_bytes(raw_scheme);

        let stop = scheme
            .get("stop")
            .ok_or_else(|| "missing 'stop' in padding scheme".to_string())?
            .parse::<i64>()
            .map_err(|_| "invalid 'stop' value in padding scheme".to_string())?;

        let mut hasher = Md5::new();
        hasher.update(raw_scheme);
        let md5_result: [u8; 16] = hasher.finalize().into();
        let md5 = md5_result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        Ok(Self {
            scheme,
            raw_scheme: raw_scheme.to_vec(),
            // The reference wraps signed stop values to u32; -1 means never stop.
            stop: stop as u32,
            md5,
        })
    }

    /// Create the default padding factory
    pub fn default_factory() -> Arc<Self> {
        Arc::new(
            Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
                .expect("default padding scheme should be valid"),
        )
    }

    /// Get the stop value (number of packets to pad)
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// Get the MD5 hash of the scheme
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// Get the raw scheme bytes
    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    /// Generate record payload sizes for a given packet number
    ///
    /// Returns a vector of sizes, where CHECK_MARK (-1) indicates
    /// "stop processing if no more payload data"
    ///
    /// # Arguments
    /// * `pkt` - The packet number (0-indexed)
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let key = pkt.to_string();
        let Some(spec) = self.scheme.get(&key) else {
            return Vec::new();
        };

        let mut sizes = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();

            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }

            let Some((min, max)) = part.split_once('-') else {
                continue;
            };
            let min: i64 = match min.trim().parse() {
                Ok(value) if value > 0 && value <= 1 << 20 => value,
                _ => continue,
            };
            let max: i64 = match max.trim().parse() {
                Ok(value) if value > 0 && value <= 1 << 20 => value,
                _ => continue,
            };
            let (min, max) = (min.min(max), min.max(max));
            let size = if min == max {
                min
            } else {
                rand::rng().random_range(min..max)
            };
            sizes.push(size as i32);
        }

        sizes
    }
}

impl Default for PaddingFactory {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME.as_bytes())
            .expect("default padding scheme should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::super::anytls_types::{Command, FRAME_HEADER_SIZE};
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn reference_ranges_and_large_padding_frames() {
        let factory = PaddingFactory::new(b"stop=-1\n1=31-30,65535-65535,65536-65536,1048576-1048576,1048577-1048577,0-5\n01=99-99").unwrap();
        assert_eq!(factory.stop(), u32::MAX);
        assert_eq!(
            factory.generate_record_payload_sizes(1),
            vec![30, 65535, 65536, 1048576]
        );
        for mixed in [true, false] {
            for length in [65535, 65536, 200000, 1048576] {
                let mut wire = BytesMut::new();
                append_padding(&mut wire, length, mixed);
                let encoded_len = wire.len();
                let mut bodies = 0;
                let mut frames = 0;
                while let Some(frame) =
                    super::super::anytls_types::FrameCodec::decode(&mut wire).unwrap()
                {
                    assert_eq!(frame.cmd, Command::Waste);
                    assert!(frame.data.len() <= 65535);
                    bodies += frame.data.len();
                    frames += 1;
                }
                assert!(wire.is_empty());
                if mixed {
                    assert!(encoded_len <= length && length - encoded_len <= FRAME_HEADER_SIZE);
                } else {
                    assert_eq!(bodies, length);
                    assert_eq!(encoded_len, length + frames * FRAME_HEADER_SIZE);
                }
            }
        }
    }

    #[test]
    fn test_default_factory() {
        let factory = PaddingFactory::default();
        assert_eq!(factory.stop(), 8);
        assert!(!factory.md5().is_empty());
    }

    #[test]
    fn test_generate_fixed_size() {
        let factory = PaddingFactory::default();

        // Packet 0 should be 30-30 (fixed)
        let sizes = factory.generate_record_payload_sizes(0);
        assert_eq!(sizes, vec![30]);
    }

    #[test]
    fn test_generate_random_range() {
        let factory = PaddingFactory::default();

        // Packet 1 should be 100-400 (random in range)
        for _ in 0..100 {
            let sizes = factory.generate_record_payload_sizes(1);
            assert_eq!(sizes.len(), 1);
            assert!((100..400).contains(&sizes[0]));
        }
    }

    #[test]
    fn test_check_mark() {
        let scheme = "stop=3\n2=400-500,c,500-1000";
        let factory = PaddingFactory::new(scheme.as_bytes()).unwrap();
        let sizes = factory.generate_record_payload_sizes(2);

        assert_eq!(sizes.len(), 3);
        assert!((400..500).contains(&sizes[0]));
        assert_eq!(sizes[1], CHECK_MARK);
        assert!((500..1000).contains(&sizes[2]));
    }

    #[test]
    fn ranges_are_exclusive_positive_and_bounded() {
        for (range, expected) in [
            ("1-2", vec![1]),
            ("2-1", vec![1]),
            ("1048576-1048576", vec![1 << 20]),
            ("1048577-1048577", vec![]),
            ("1-1048577", vec![]),
            ("0-1", vec![]),
            ("0-0", vec![]),
            ("-1-1", vec![]),
            ("invalid,1,1-x,1-2-3", vec![]),
            ("invalid,2-2,0-1,3-3", vec![2, 3]),
        ] {
            let factory = PaddingFactory::new(format!("stop=2\n1={range}").as_bytes()).unwrap();
            for _ in 0..64 {
                assert_eq!(
                    factory.generate_record_payload_sizes(1),
                    expected,
                    "{range}"
                );
            }
        }
    }

    #[test]
    fn test_beyond_stop() {
        let factory = PaddingFactory::default();

        // Packet 10 is beyond stop=8, should return empty
        let sizes = factory.generate_record_payload_sizes(10);
        assert!(sizes.is_empty());
    }

    #[test]
    fn test_md5_consistency() {
        let factory1 = PaddingFactory::default();
        let factory2 = PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap();

        assert_eq!(factory1.md5(), factory2.md5());
    }

    #[test]
    fn test_custom_scheme() {
        let scheme = "stop=2\n0=100-100\n1=200-200";
        let factory = PaddingFactory::new(scheme.as_bytes()).unwrap();

        assert_eq!(factory.stop(), 2);
        assert_eq!(factory.generate_record_payload_sizes(0), vec![100]);
        assert_eq!(factory.generate_record_payload_sizes(1), vec![200]);
    }

    #[test]
    fn test_invalid_scheme_missing_stop() {
        let scheme = "0=100-100";
        let result = PaddingFactory::new(scheme.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn signed_stop_values_wrap_like_the_reference() {
        for (stop, expected) in [
            ("-1", u32::MAX),
            ("-2", u32::MAX - 1),
            ("4294967295", u32::MAX),
            ("4294967296", 0),
            ("4294967297", 1),
        ] {
            let scheme = format!("stop={stop}\n0=31-31");
            assert_eq!(
                PaddingFactory::new(scheme.as_bytes()).unwrap().stop(),
                expected
            );
        }
        for stop in [
            "",
            "-",
            "1.5",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(PaddingFactory::new(format!("stop={stop}").as_bytes()).is_err());
        }
    }
}
