use subtle::ConstantTimeEq;

#[derive(Debug, Clone)]
pub struct ShadowTlsHmac {
    context: aws_lc_rs::hmac::Context,
}

impl ShadowTlsHmac {
    pub fn new(key: &aws_lc_rs::hmac::Key) -> Self {
        Self {
            context: aws_lc_rs::hmac::Context::with_key(key),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    pub fn authenticates_record(&self, record: &[u8]) -> bool {
        let Some((tag, payload)) = record.split_at_checked(4) else {
            return false;
        };
        let mut candidate = self.clone();
        candidate.update(payload);
        bool::from(candidate.finalized_digest().ct_eq(tag))
    }

    pub fn digest(&self) -> [u8; 4] {
        let tag = self.context.clone().sign();
        let mut out = [0u8; 4];
        out.copy_from_slice(&tag.as_ref()[0..4]);
        out
    }

    pub fn finalized_digest(self) -> [u8; 4] {
        let tag = self.context.sign();
        let mut out = [0u8; 4];
        out.copy_from_slice(&tag.as_ref()[0..4]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_verification_is_bounded_and_does_not_advance_the_mac() {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, b"test");
        let mac = ShadowTlsHmac::new(&key);
        for size in 0..4 {
            assert!(!mac.authenticates_record(&[0; 4][..size]));
        }
        let mut signed = mac.clone();
        signed.update(b"payload");
        let mut record = signed.finalized_digest().to_vec();
        record.extend_from_slice(b"payload");
        assert!(mac.authenticates_record(&record));
        assert!(mac.authenticates_record(&record));
        for index in 0..record.len() {
            record[index] ^= 1;
            assert!(!mac.authenticates_record(&record));
            record[index] ^= 1;
        }
    }
}
