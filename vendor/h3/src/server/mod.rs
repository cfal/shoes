//! This module provides methods to create a http/3 Server.
//!
//! It allows to accept incoming requests, and send responses.
//!
//! # Examples
//!
//! ## Simple example
//! ```rust
//! async fn doc<C>(conn: C)
//! where
//! C: h3::quic::Connection<bytes::Bytes> + 'static,
//! <C as h3::quic::OpenStreams<bytes::Bytes>>::BidiStream: Send + 'static
//! {
//!     let mut server_builder = h3::server::builder();
//!     // Build the Connection
//!     let mut h3_conn = server_builder.build(conn).await.unwrap();
//!     loop {
//!         // Accept incoming requests
//!         match h3_conn.accept().await {
//!             Ok(Some(resolver)) => {
//!                 // spawn a new task to handle the request
//!                 tokio::spawn(async move {
//!                     // get the request
//!                     let (req, mut stream) = resolver.resolve_request().await.unwrap();
//!                     // build a http response
//!                     let response = http::Response::builder().status(http::StatusCode::OK).body(()).unwrap();
//!                     // send the response to the wire
//!                     stream.send_response(response).await.unwrap();
//!                     // send some date
//!                     stream.send_data(bytes::Bytes::from("test")).await.unwrap();
//!                     // finnish the stream
//!                     stream.finish().await.unwrap();
//!                 });
//!             }
//!             Ok(None) => {
//!                 // break if no Request is accepted
//!                 break;
//!             }
//!             Err(err) => {
//!                 break;
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## File server
//! A ready-to-use example of a file server is available [here](https://github.com/hyperium/h3/blob/master/examples/server.rs)

mod builder;
mod connection;
mod request;
mod stream;

pub use builder::builder;
pub use builder::Builder;
pub use connection::Connection;
pub use request::RequestResolver;
pub use stream::RequestStream;
