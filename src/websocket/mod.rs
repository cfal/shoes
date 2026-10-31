mod early_data;
mod early_stream;
mod websocket_handler;
mod websocket_stream;

pub(crate) use early_data::{EarlyData, validate_early_data};

pub(crate) fn is_zero(value: &usize) -> bool {
    *value == 0
}

pub use websocket_handler::{
    WebsocketServerTarget, WebsocketTcpClientHandler, WebsocketTcpServerHandler,
};
