use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

#[cfg(target_family = "unix")]
use tokio::net::UnixStream;

use crate::address::NetLocation;

pub trait AsyncPing {
    fn supports_ping(&self) -> bool;

    // Write a ping message to the stream, if supported.
    // This should end up calling the highest level stream abstraction that supports
    // pings, and should only result in a single message.
    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>>;
}

pub trait AsyncReadMessage {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncWriteMessage {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncFlushMessage {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>>;
}

pub trait AsyncShutdownMessage {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncReadTargetedMessage {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>>;
}

pub trait AsyncWriteTargetedMessage {
    fn poll_write_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>>;
}

pub trait AsyncReadSourcedMessage {
    fn poll_read_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>>;
}

pub trait AsyncWriteSourcedMessage {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

/// Session-based message reading trait. Used by protocols like XUDP that have session IDs.
/// Returns (session_id, data, source_addr) tuples.
pub trait AsyncReadSessionMessage {
    fn poll_read_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>>;
}

/// Session-based message writing trait. Used by protocols like XUDP that have session IDs.
/// Writes data for a specific session ID to a target address.
pub trait AsyncWriteSessionMessage {
    fn poll_write_session_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>>;
}

impl AsyncReadMessage for UdpSocket {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.poll_recv(cx, buf)
    }
}

impl AsyncWriteMessage for UdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        // TODO: send back an error if the whole buf.len() wasn't sent?
        self.poll_send(cx, buf).map(|result| result.map(|_| ()))
    }
}

impl AsyncFlushMessage for UdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for UdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send {}

pub trait AsyncMessageStream:
    AsyncReadMessage
    + AsyncWriteMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Server stream trait connected to proxy clients, where received messages have a target address,
/// and we write forwarded messages along with the source address we received them from.
pub trait AsyncTargetedMessageStream:
    AsyncReadTargetedMessage
    + AsyncWriteSourcedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Client stream trait connected directly to targets or to proxy servers, where received messages
/// come with a source address, and we write where we want messages to be sent.
pub trait AsyncSourcedMessageStream:
    AsyncReadSourcedMessage
    + AsyncWriteTargetedMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

/// Session-based stream trait for protocols like XUDP that multiplex sessions over a single connection.
/// Reads return (session_id, data, source_addr) and writes target (session_id, data, target_addr).
pub trait AsyncSessionMessageStream:
    AsyncReadSessionMessage
    + AsyncWriteSessionMessage
    + AsyncFlushMessage
    + AsyncShutdownMessage
    + AsyncPing
    + Unpin
    + Send
{
}

impl AsyncPing for TcpStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncStream for TcpStream {}

#[cfg(target_family = "unix")]
impl AsyncPing for UnixStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

#[cfg(target_family = "unix")]
impl AsyncStream for UnixStream {}

impl AsyncPing for UdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        unimplemented!();
    }
}

impl AsyncMessageStream for UdpSocket {}

// pattern copied from deref_async_read macro: https://docs.rs/tokio/latest/src/tokio/io/async_read.rs.html#60
impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for Box<T> {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for &mut T {
    fn supports_ping(&self) -> bool {
        (**self).supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut **self).poll_write_ping(cx)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for Box<T> {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadMessage + Unpin> AsyncReadMessage for &mut T {
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_read_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for Box<T> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteMessage + Unpin> AsyncWriteMessage for &mut T {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for Box<T> {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncFlushMessage + Unpin> AsyncFlushMessage for &mut T {
    fn poll_flush_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_flush_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for Box<T> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncShutdownMessage + Unpin> AsyncShutdownMessage for &mut T {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_shutdown_message(cx)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for Box<T> {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadTargetedMessage + Unpin> AsyncReadTargetedMessage for &mut T {
    fn poll_read_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        Pin::new(&mut **self).poll_read_targeted_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for Box<T> {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncWriteTargetedMessage + Unpin> AsyncWriteTargetedMessage for &mut T {
    fn poll_write_targeted_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_targeted_message(cx, buf, target)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for Box<T> {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadSourcedMessage + Unpin> AsyncReadSourcedMessage for &mut T {
    fn poll_read_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<SocketAddr>> {
        Pin::new(&mut **self).poll_read_sourced_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for Box<T> {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncWriteSourcedMessage + Unpin> AsyncWriteSourcedMessage for &mut T {
    fn poll_write_sourced_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_sourced_message(cx, buf, source)
    }
}

impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for Box<T> {}
impl<T: ?Sized + AsyncStream + Unpin> AsyncStream for &mut T {}

impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for Box<T> {}
impl<T: ?Sized + AsyncMessageStream + Unpin> AsyncMessageStream for &mut T {}

impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncTargetedMessageStream + Unpin> AsyncTargetedMessageStream for &mut T {}

impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSourcedMessageStream + Unpin> AsyncSourcedMessageStream for &mut T {}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for Box<T> {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncReadSessionMessage + Unpin> AsyncReadSessionMessage for &mut T {
    fn poll_read_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<(u16, SocketAddr)>> {
        Pin::new(&mut **self).poll_read_session_message(cx, buf)
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for Box<T> {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }
}

impl<T: ?Sized + AsyncWriteSessionMessage + Unpin> AsyncWriteSessionMessage for &mut T {
    fn poll_write_session_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        session_id: u16,
        buf: &[u8],
        target: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut **self).poll_write_session_message(cx, session_id, buf, target)
    }
}

impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for Box<T> {}
impl<T: ?Sized + AsyncSessionMessageStream + Unpin> AsyncSessionMessageStream for &mut T {}
