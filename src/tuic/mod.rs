//! TUIC v5: server, client and the frame codec they share.

// The client half of the codec has no caller in the binary until the connector
// lands in the next commit, and the binary declares this module privately.
// Scoped to the codec so the server next door stays under the lint.
#[allow(dead_code)]
pub mod frame;
pub mod server;

pub use server::start_tuic_server;
