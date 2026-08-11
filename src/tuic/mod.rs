//! TUIC v5: server, client and the frame codec they share.

pub mod client;
// The Packet, Dissociate and Heartbeat encoders have no caller in the binary
// until UDP relaying lands. Scoped to the codec so the server and the TCP
// client next door stay under the lint; remove it then.
#[allow(dead_code)]
pub mod frame;
pub mod server;

pub use client::TuicConnector;
pub use server::start_tuic_server;
