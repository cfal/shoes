use std::fmt::Debug;

pub trait ShadowsocksKey: Send + Sync + Debug {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]>;
}
