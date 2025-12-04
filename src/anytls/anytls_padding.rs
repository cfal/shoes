//! AnyTLS padding scheme implementation
//!
//! Provides configurable packet padding to obfuscate TLS-in-TLS fingerprints.
//! Based on the AnyTLS protocol specification.

use crate::anytls::anytls_types::StringMap;
use md5::{Digest, Md5};
use rand::Rng;
use std::sync::Arc;

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
            .parse::<u32>()
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
            stop,
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
        let parts: Vec<&str> = spec.split(',').collect();

        for part in parts {
            let part = part.trim();

            // Check mark - indicates "stop if no more data"
            if part == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }

            // Parse range: "min-max"
            if let Some((min_str, max_str)) = part.split_once('-') {
                let min_val: i64 = match min_str.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => continue,
                };
                let max_val: i64 = match max_str.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => continue,
                };

                // Ensure min <= max
                let (min_val, max_val) = (min_val.min(max_val), min_val.max(max_val));

                if min_val == max_val {
                    // Fixed size
                    sizes.push(min_val as i32);
                } else {
                    // Random size in range [min, max]
                    let mut rng = rand::rng();
                    let size = rng.random_range(min_val..=max_val);
                    sizes.push(size as i32);
                }
            }
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
    use super::*;

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
            assert!(sizes[0] >= 100 && sizes[0] <= 400);
        }
    }

    #[test]
    fn test_check_mark() {
        let scheme = "stop=3\n2=400-500,c,500-1000";
        let factory = PaddingFactory::new(scheme.as_bytes()).unwrap();
        let sizes = factory.generate_record_payload_sizes(2);

        assert_eq!(sizes.len(), 3);
        assert!(sizes[0] >= 400 && sizes[0] <= 500);
        assert_eq!(sizes[1], CHECK_MARK);
        assert!(sizes[2] >= 500 && sizes[2] <= 1000);
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
}
