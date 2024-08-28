use sha2::{Digest, Sha256};

trait VmessHash: std::fmt::Debug {
    fn setup_new(&self) -> Box<dyn VmessHash>;
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

#[derive(Debug)]
struct Sha256Hash(Sha256);

impl Sha256Hash {
    fn create() -> Self {
        Self(Sha256::new())
    }
}

impl VmessHash for Sha256Hash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        Box::new(Sha256Hash(self.0.clone()))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }
}

#[derive(Debug)]
struct RecursiveHash {
    inner: Box<dyn VmessHash>,
    outer: Box<dyn VmessHash>,
    default_inner: [u8; 64],
    default_outer: [u8; 64],
}

impl RecursiveHash {
    fn create(key: &[u8], hash: Box<dyn VmessHash>) -> Self {
        let mut default_outer = [0u8; 64];
        let mut default_inner = [0u8; 64];

        // for hmac, we would normally have to get a derived key
        // by hashing the key when it's longer than 64 bytes, but
        // that doesn't happen for vmess's usecase.
        assert!(key.len() <= 64);

        default_outer[0..key.len()].copy_from_slice(key);
        default_inner[0..key.len()].copy_from_slice(key);

        for b in default_outer.iter_mut() {
            *b ^= 0x5c;
        }
        for b in default_inner.iter_mut() {
            *b ^= 0x36;
        }

        let mut inner = hash.setup_new();
        let outer = hash;
        inner.update(&default_inner);
        Self {
            inner,
            outer,
            default_inner,
            default_outer,
        }
    }
}

impl VmessHash for RecursiveHash {
    fn setup_new(&self) -> Box<dyn VmessHash> {
        let new_inner = self.inner.setup_new();
        let new_outer = self.outer.setup_new();

        let mut new_default_inner = [0u8; 64];
        let mut new_default_outer = [0u8; 64];
        new_default_inner.copy_from_slice(&self.default_inner);
        new_default_outer.copy_from_slice(&self.default_outer);

        Box::new(RecursiveHash {
            inner: new_inner,
            outer: new_outer,
            default_inner: new_default_inner,
            default_outer: new_default_outer,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&mut self) -> [u8; 32] {
        let inner_result: [u8; 32] = self.inner.finalize();
        self.outer.update(&self.default_outer);
        self.outer.update(&inner_result);
        self.outer.finalize()
    }
}

pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current = Box::new(RecursiveHash::create(
        b"VMess AEAD KDF",
        Box::new(Sha256Hash::create()),
    ));
    for path_item in path.iter() {
        current = Box::new(RecursiveHash::create(path_item, current))
    }
    current.update(key);
    current.finalize()
}

pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finalize().into()
}
