//! This module contains the error handling logic and types for the h3 crate.

mod codes;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
pub mod connection_error_creators;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
pub(crate) mod connection_error_creators;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
pub mod internal_error;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
pub(crate) mod internal_error;

mod error;

pub use codes::Code;
pub use error::{ConnectionError, LocalError, StreamError};
