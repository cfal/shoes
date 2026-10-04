use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::{AsyncPing, AsyncStream};

pub struct QuicStream {
    send_stream: SendStream,
    recv_stream: RecvStream,
}

impl QuicStream {
    pub fn from(send_stream: quinn::SendStream, recv_stream: quinn::RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.recv_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.send_stream)
            .poll_write(cx, buf)
            .map_err(|err| err.into())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // this is a no-op, so return ready directly
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // TODO: this was previously disabled because, because it caused a panic with a mutex poison error in quinn.
        // ref: https://github.com/quinn-rs/quinn/issues/1298
        let this = self.get_mut();
        Pin::new(&mut this.send_stream).poll_shutdown(cx)
    }
}

impl AsyncPing for QuicStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncStream for QuicStream {}
