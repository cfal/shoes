//! Adapter that wraps a SnellUdpClientStream with a fixed target.
//! This converts AsyncSourcedMessageStream to AsyncMessageStream by:
//! - On write: adding the fixed target to each message
//! - On read: stripping the source address from responses

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncSourcedMessageStream, AsyncWriteMessage,
};

pub struct SnellFixedTargetStream<S> {
    stream: S,
    target: NetLocation,
}

impl<S: AsyncSourcedMessageStream> SnellFixedTargetStream<S> {
    pub fn new(stream: S, target: NetLocation) -> Self {
        Self { stream, target }
    }
}

impl<S: AsyncSourcedMessageStream> AsyncReadMessage for SnellFixedTargetStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Reads the message and discards the source address.
        match Pin::new(&mut this.stream).poll_read_sourced_message(cx, buf) {
            Poll::Ready(Ok(_source)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncSourcedMessageStream> AsyncWriteMessage for SnellFixedTargetStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Writes the message with the fixed target.
        Pin::new(&mut this.stream).poll_write_targeted_message(cx, buf, &this.target)
    }
}

impl<S: AsyncSourcedMessageStream> AsyncFlushMessage for SnellFixedTargetStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush_message(cx)
    }
}

impl<S: AsyncSourcedMessageStream> AsyncShutdownMessage for SnellFixedTargetStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown_message(cx)
    }
}

impl<S: AsyncSourcedMessageStream> AsyncPing for SnellFixedTargetStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl<S: AsyncSourcedMessageStream> AsyncMessageStream for SnellFixedTargetStream<S> {}
