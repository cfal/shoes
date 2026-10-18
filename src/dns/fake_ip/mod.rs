//! Scoped synthetic DNS identities. Real outbound resolution remains separate.

mod options;
mod pool;
mod responder;

pub use options::{FakeIpConfig, FakeIpOptions, HttpsRecords, MissingFamily};
pub use pool::FakeIpPool;
pub use responder::{DnsDecision, FakeDnsResponder};
