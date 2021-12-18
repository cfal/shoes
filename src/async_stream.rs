use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl AsyncStream for TcpStream {}
