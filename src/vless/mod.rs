// VLESS protocol implementation with VISION support

// Public API
pub mod vless_client_handler;
pub mod vless_server_handler;

// Internal implementation details
pub mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_unpad;
mod vless_message_stream;
mod vless_response_stream;
mod vless_util;

// Re-export VlessMessageStream for use by other protocols (e.g., Shadowsocks UoT V2)
pub use vless_message_stream::VlessMessageStream;
