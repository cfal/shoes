//! Scoped synthetic DNS identities. Real outbound resolution remains separate.

mod options;
mod pool;
pub(super) mod responder;

#[cfg(test)]
mod tests;

pub use options::{FakeIpConfig, FakeIpOptions, HttpsRecords, MissingFamily};
pub use pool::FakeIpPool;
pub use responder::{DnsDecision, FakeDnsResponder};
