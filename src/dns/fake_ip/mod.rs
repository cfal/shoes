//! Scoped synthetic DNS identities. Real outbound resolution remains separate.

mod context;
mod options;
mod pool;
mod responder;
mod stream;

#[cfg(test)]
mod tests;

pub use context::{FakeDnsContext, FakeDnsResolver};
pub use options::{FakeIpConfig, FakeIpOptions, HttpsRecords, MissingFamily};
pub use pool::FakeIpPool;
pub use responder::{DnsDecision, FakeDnsResponder};
