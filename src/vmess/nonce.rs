use aws_lc_rs::aead::{Nonce, NonceSequence};
use aws_lc_rs::error::Unspecified;

pub struct VmessNonceSequence {
    count: u16,
    nonce: [u8; 12],
}

impl VmessNonceSequence {
    pub fn new(data: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&data[2..12]);
        Self { count: 0, nonce }
    }
}

impl NonceSequence for VmessNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        // the nonce is correct for the first packet since the first two
        // bytes are already zero.
        let ret = Nonce::assume_unique_for_key(self.nonce);
        self.count = self.count.wrapping_add(1);
        self.nonce[0] = (self.count >> 8) as u8;
        self.nonce[1] = (self.count & 0xff) as u8;
        Ok(ret)
    }
}

pub struct SingleUseNonce {
    nonce: [u8; 12],
    used: bool,
}

impl SingleUseNonce {
    pub fn new(data: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(data);
        Self { nonce, used: false }
    }
}

impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        if self.used {
            panic!("SingleUseNonce used twice");
        }
        self.used = true;
        Nonce::try_assume_unique_for_key(&self.nonce)
    }
}
