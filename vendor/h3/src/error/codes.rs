//! HTTP/3 error codes.

use std::fmt::{self};

/// An HTTP/3 "application error code".
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Code {
    code: u64,
}

impl Code {
    /// Numerical error code
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9114.html#errors>
    /// and <https://www.rfc-editor.org/rfc/rfc9000.html#error-codes>
    pub const fn value(&self) -> u64 {
        self.code
    }
}

impl PartialEq<u64> for Code {
    fn eq(&self, other: &u64) -> bool {
        *other == self.code
    }
}

// ===== impl Code =====

macro_rules! codes {
    (
        $(
            $(#[$docs:meta])*
            ($num:expr, $name:ident);
        )+
    ) => {
        impl Code {
        $(
            $(#[$docs])*
            pub const $name: Code = Code{code: $num};
        )+
        }

        impl fmt::Debug for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.code {
                $(
                    $num => f.write_str(stringify!($name)),
                )+
                    other => write!(f, "{:#x}", other),
                }
            }
        }

        impl fmt::Display for Code{
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.code {
                $(
                    $num => f.write_str(stringify!($name)),
                )+
                    other => write!(f, "{:#x}", other),
                }
            }
        }
    }


}

codes! {
    /// Datagram or capsule parse error
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-5.2>
    (0x33, H3_DATAGRAM_ERROR);
    /// No error. This is used when the connection or stream needs to be
    /// closed, but there is no error to signal.
    (0x100, H3_NO_ERROR);

    /// Peer violated protocol requirements in a way that does not match a more
    /// specific error code, or endpoint declines to use the more specific
    /// error code.
    (0x101, H3_GENERAL_PROTOCOL_ERROR);

    /// An internal error has occurred in the HTTP stack.
    (0x102, H3_INTERNAL_ERROR);

    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    (0x103, H3_STREAM_CREATION_ERROR);

    /// A stream required by the HTTP/3 connection was closed or reset.
    (0x104, H3_CLOSED_CRITICAL_STREAM);

    /// A frame was received that was not permitted in the current state or on
    /// the current stream.
    (0x105, H3_FRAME_UNEXPECTED);

    /// A frame that fails to satisfy layout requirements or with an invalid
    /// size was received.
    (0x106, H3_FRAME_ERROR);

    /// The endpoint detected that its peer is exhibiting a behavior that might
    /// be generating excessive load.
    (0x107, H3_EXCESSIVE_LOAD);

    /// A Stream ID or Push ID was used incorrectly, such as exceeding a limit,
    /// reducing a limit, or being reused.
    (0x108, H3_ID_ERROR);

    /// An endpoint detected an error in the payload of a SETTINGS frame.
    (0x109, H3_SETTINGS_ERROR);

    /// No SETTINGS frame was received at the beginning of the control stream.
    (0x10a, H3_MISSING_SETTINGS);

    /// A server rejected a request without performing any application
    /// processing.
    (0x10b, H3_REQUEST_REJECTED);

    /// The request or its response (including pushed response) is cancelled.
    (0x10c, H3_REQUEST_CANCELLED);

    /// The client's stream terminated without containing a fully-formed
    /// request.
    (0x10d, H3_REQUEST_INCOMPLETE);

    /// An HTTP message was malformed and cannot be processed.
    (0x10e, H3_MESSAGE_ERROR);

    /// The TCP connection established in response to a CONNECT request was
    /// reset or abnormally closed.
    (0x10f, H3_CONNECT_ERROR);

    /// The requested operation cannot be served over HTTP/3. The peer should
    /// retry over HTTP/1.1.
    (0x110, H3_VERSION_FALLBACK);

    /// The decoder failed to interpret an encoded field section and is not
    /// able to continue decoding that field section.
    (0x200, QPACK_DECOMPRESSION_FAILED);

    /// The decoder failed to interpret an encoder instruction received on the
    /// encoder stream.
    (0x201, QPACK_ENCODER_STREAM_ERROR);

    /// The encoder failed to interpret a decoder instruction received on the
    /// decoder stream.
    (0x202, QPACK_DECODER_STREAM_ERROR);
}

impl From<Code> for u64 {
    fn from(code: Code) -> u64 {
        code.code
    }
}

impl From<u64> for Code {
    fn from(code: u64) -> Code {
        Code { code }
    }
}
