use std::io;
use std::task::{Context, Poll};

use crate::async_stream::AsyncStream;
use crate::crypto::CryptoTlsStream;

/// The record boundary and directional handoff operations required by Vision.
pub(crate) trait VisionTransport: AsyncStream {
    fn is_client(&self) -> bool;
    fn is_server(&self) -> bool;
    fn require_record_framing(&self) -> io::Result<()>;
    fn allow_streaming_reads(&mut self);
    fn start_raw_read(&mut self) -> io::Result<()>;
    fn start_raw_write(&mut self, final_plaintext: &[u8]) -> io::Result<()>;
    fn poll_drain_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl<IO: AsyncStream> VisionTransport for CryptoTlsStream<IO> {
    fn is_client(&self) -> bool {
        self.is_client()
    }

    fn is_server(&self) -> bool {
        self.is_server()
    }

    fn require_record_framing(&self) -> io::Result<()> {
        self.require_record_framing()
    }

    fn allow_streaming_reads(&mut self) {
        self.allow_streaming_reads();
    }

    fn start_raw_read(&mut self) -> io::Result<()> {
        self.start_raw_read()
    }

    fn start_raw_write(&mut self, final_plaintext: &[u8]) -> io::Result<()> {
        self.start_raw_write(final_plaintext)
    }

    fn poll_drain_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_drain_tls(cx)
    }
}
