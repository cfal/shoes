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

/// Constant-time comparison of two Shadow-TLS HMAC tags.
///
/// The tags authenticate the peer, so a data-dependent (short-circuiting)
/// comparison would leak, through timing, how many leading bytes matched -
/// enough to forge a tag byte by byte and defeat the anti-probing check.
#[inline]
pub fn tags_equal(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
