//! This module contains the internal error type, which is used to represent errors, which have not yet affected the connection state

use std::error::Error;

use crate::{frame::FrameProtocolError, quic::ConnectionErrorIncoming};

use super::codes::Code;
use std::fmt::Display;

/// This error type represents an internal error type, which is used
/// to represent errors, which have not yet affected the connection state
///
/// This error type is generated from the error types of h3s submodules or by the modules itself.
///
/// This error type is used in functions which handle a http3 connection state
#[derive(Debug, Clone, Hash)]
pub struct InternalConnectionError {
    /// The error code
    pub(crate) code: Code,
    /// The error message
    pub(crate) message: String,
}

impl InternalConnectionError {
    /// Create a new internal connection error
    pub fn new(code: Code, message: String) -> Self {
        Self { code, message }
    }
    /// Creates a new internal connection error from a frame error
    pub fn got_frame_error(value: FrameProtocolError) -> Self {
        match value {
            FrameProtocolError::InvalidStreamId(id) => InternalConnectionError {
                code: Code::H3_ID_ERROR,
                message: format!("invalid stream id: {}", id),
            },
            FrameProtocolError::InvalidPushId(id) => InternalConnectionError {
                code: Code::H3_ID_ERROR,
                message: format!("invalid push id: {}", id),
            },
            FrameProtocolError::Settings(error) => InternalConnectionError {
                // TODO: Check spec which error code to return when a bad settings frame arrives on a stream which is not allowed to have settings
                //       At the moment, because the Frame is parsed before the stream type is checked, the H3_SETTINGS_ERROR is returned.
                //       Same for the InvalidStreamId and InvalidPushId
                    code: Code::H3_SETTINGS_ERROR,
                    message: error.to_string(),
            },
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
            //# These frame
            //# types MUST NOT be sent, and their receipt MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.
            FrameProtocolError::ForbiddenFrame(number) => InternalConnectionError {
                    code: Code::H3_FRAME_UNEXPECTED,
                    message: format!("received a forbidden frame with number {}", number),
            },
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
            //# A frame payload that contains additional bytes
            //# after the identified fields or a frame payload that terminates before
            //# the end of the identified fields MUST be treated as a connection
            //# error of type H3_FRAME_ERROR.
            FrameProtocolError::InvalidFrameValue | FrameProtocolError::Malformed => InternalConnectionError {
                code: Code::H3_FRAME_ERROR,
                message: "frame payload that contains additional bytes after the identified fields or a frame payload that terminates before the end of the identified fields".to_string(),
            },
            }
    }
}

/// Error type which combines different internal errors
#[derive(Debug, Clone)]
pub enum ErrorOrigin {
    /// Internal Error
    Internal(InternalConnectionError),
    /// Quick layer error
    Quic(ConnectionErrorIncoming),
}

impl Display for ErrorOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorOrigin::Internal(error) => write!(f, "Internal Error: {}", error.message),
            ErrorOrigin::Quic(error) => write!(f, "Quic Error: {:?}", error),
        }
    }
}

impl Error for ErrorOrigin {}

impl From<InternalConnectionError> for ErrorOrigin {
    fn from(error: InternalConnectionError) -> Self {
        ErrorOrigin::Internal(error)
    }
}

impl From<ConnectionErrorIncoming> for ErrorOrigin {
    fn from(error: ConnectionErrorIncoming) -> Self {
        ErrorOrigin::Quic(error)
    }
}
