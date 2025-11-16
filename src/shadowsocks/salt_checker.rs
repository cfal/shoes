use std::fmt::Debug;

pub trait SaltChecker: Send + Sync + Debug {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool;
}
