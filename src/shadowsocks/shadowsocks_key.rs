use std::fmt::Debug;

pub trait ShadowsocksKey: Send + Sync + Debug {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]>;

    fn create_identity_headers(&self, _salt: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
