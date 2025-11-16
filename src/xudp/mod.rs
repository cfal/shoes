// XUDP (Extended UDP) protocol implementation
// Protocol-agnostic UDP multiplexing over TCP connections
// Used by both VLESS and VMess protocols

pub mod frame;
pub mod message_stream;

pub use message_stream::XudpMessageStream;
