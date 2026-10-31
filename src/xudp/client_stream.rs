use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frame::{FrameMetadata, FrameOption, SessionStatus, TargetNetwork};
use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

/// One XUDP association on an owned carrier; session IDs never cross carriers.
pub(crate) struct XudpClientStream {
    inner: Box<dyn AsyncStream>,
    target: NetLocation,
    read: BytesMut,
    write: BytesMut,
    pending_read: Option<BytesMut>,
    started: bool,
    read_ended: bool,
    closing: bool,
}

impl XudpClientStream {
    pub(crate) fn new(inner: Box<dyn AsyncStream>, target: NetLocation) -> Self {
        Self {
            inner,
            target,
            read: BytesMut::new(),
            write: BytesMut::new(),
            pending_read: None,
            started: false,
            read_ended: false,
            closing: false,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write.is_empty() {
            let count = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write))?;
            if count == 0 {
                return Poll::Ready(Err(ErrorKind::WriteZero.into()));
            }
            self.write.advance(count);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWriteMessage for XudpClientStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closing || this.read_ended {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        // Xray's XUDP writer reserves space for metadata in an 8192-byte buffer.
        if data.len() > 7526 {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidInput,
                "XUDP payload exceeds 7526 bytes",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(()));
        }
        ready!(this.drain(cx))?;
        let mut frame = BytesMut::new();
        FrameMetadata {
            session_id: 0,
            status: if this.started {
                SessionStatus::Keep
            } else {
                SessionStatus::New
            },
            option: FrameOption::new().with_data(),
            target: Some(this.target.clone()),
            network: Some(TargetNetwork::Udp),
        }
        .encode(&mut frame)?;
        frame.put_u16(data.len() as u16);
        frame.extend_from_slice(data);
        this.write = frame;
        this.started = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for XudpClientStream {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(data) = &this.pending_read {
                if output.remaining() < data.len() {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "XUDP output buffer is too small",
                    )));
                }
                output.put_slice(data);
                this.pending_read = None;
                return Poll::Ready(Ok(()));
            }
            if this.read_ended {
                return Poll::Ready(Ok(()));
            }
            if let Some((metadata, data)) = super::frame::decode_frame(&mut this.read)? {
                if metadata.session_id != 0 {
                    continue;
                }
                if metadata.option.has_error() {
                    this.read_ended = true;
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::ConnectionReset,
                        "XUDP peer rejected session",
                    )));
                }
                if metadata.status == SessionStatus::End {
                    this.read_ended = true;
                } else if matches!(metadata.status, SessionStatus::New | SessionStatus::Keep)
                    && !data.is_empty()
                {
                    this.pending_read = Some(data);
                }
                continue;
            }
            let mut bytes = [0; 8192];
            let mut input = ReadBuf::new(&mut bytes);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                this.read_ended = true;
                return Poll::Ready(if this.read.is_empty() {
                    Ok(())
                } else {
                    Err(ErrorKind::UnexpectedEof.into())
                });
            }
            this.read.extend_from_slice(input.filled());
        }
    }
}

impl AsyncFlushMessage for XudpClientStream {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

impl AsyncShutdownMessage for XudpClientStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.closing {
            ready!(self.drain(cx))?;
            self.closing = true;
            if self.started {
                FrameMetadata {
                    session_id: 0,
                    status: SessionStatus::End,
                    option: FrameOption::new(),
                    target: None,
                    network: None,
                }
                .encode(&mut self.write)?;
            }
        }
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncPing for XudpClientStream {
    fn supports_ping(&self) -> bool {
        self.inner.supports_ping()
    }
    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.inner).poll_write_ping(cx)
    }
}

impl AsyncMessageStream for XudpClientStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn new_keep_end_survive_backpressure_without_duplicate_messages() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (inner, mut peer) = tokio::io::duplex(3);
            let target = NetLocation::from_str("127.0.0.1:443", None).unwrap();
            let mut stream = XudpClientStream::new(Box::new(inner), target);
            let reader = tokio::spawn(async move {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            });
            for payload in [b"first\x16".as_slice(), b"second\x16\x03\x03"] {
                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, payload))
                    .await
                    .unwrap();
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .unwrap();
            assert_eq!(
                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"late"))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::BrokenPipe
            );
            let mut bytes = BytesMut::from(reader.await.unwrap().as_slice());
            let (new, data) = super::super::frame::decode_frame(&mut bytes)
                .unwrap()
                .unwrap();
            assert_eq!(new.status, SessionStatus::New);
            assert_eq!(new.target.unwrap().port(), 443);
            assert_eq!(&data[..], b"first\x16");
            let (keep, data) = super::super::frame::decode_frame(&mut bytes)
                .unwrap()
                .unwrap();
            assert_eq!(keep.status, SessionStatus::Keep);
            assert_eq!(&data[..], b"second\x16\x03\x03");
            let (end, data) = super::super::frame::decode_frame(&mut bytes)
                .unwrap()
                .unwrap();
            assert_eq!(end.status, SessionStatus::End);
            assert!(data.is_empty() && bytes.is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fragmented_responses_keep_small_buffer_data_and_skip_controls() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (inner, mut peer) = tokio::io::duplex(1);
            let mut stream = XudpClientStream::new(Box::new(inner), NetLocation::UNSPECIFIED);
            let writer = tokio::spawn(async move {
                // KeepAlive with a payload, then a Keep carrying the actual reply, then End.
                peer.write_all(&[
                    0, 4, 0, 0, 4, 1, 0, 1, 99, 0, 4, 0, 0, 2, 1, 0, 3, 1, 2, 3, 0, 4, 0, 0, 3, 0,
                ])
                .await
                .unwrap();
            });
            let mut tiny = [0; 1];
            let mut buf = ReadBuf::new(&mut tiny);
            assert_eq!(
                poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidInput
            );
            let mut storage = [0; 16];
            let mut buf = ReadBuf::new(&mut storage);
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert_eq!(buf.filled(), &[1, 2, 3]);
            buf.clear();
            poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut buf))
                .await
                .unwrap();
            assert!(buf.filled().is_empty());
            writer.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejected_encoding_does_not_poison_next_message() {
        let (inner, _peer) = tokio::io::duplex(128);
        let mut stream = XudpClientStream::new(
            Box::new(inner),
            NetLocation::new(crate::address::Address::Hostname("x".repeat(256)), 53),
        );
        assert!(
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"bad"))
                .await
                .is_err()
        );
        assert!(stream.write.is_empty() && !stream.started);
        stream.target = NetLocation::from_str("127.0.0.1:53", None).unwrap();
        assert!(
            poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &[0; 7527]))
                .await
                .is_err()
        );
        poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, b"good"))
            .await
            .unwrap();
        assert_eq!(stream.write[4], SessionStatus::New as u8);
    }
}
