use std::io;

use http::{Method, Request, StatusCode, Version};
use rand::RngExt;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::http2::client::{H2ClientSession, format_authority};

use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, generate_padding_header,
};

#[derive(Clone)]
pub struct NaiveClientSession(H2ClientSession);

impl NaiveClientSession {
    pub async fn new(stream: Box<dyn AsyncStream>) -> io::Result<Self> {
        Ok(Self(H2ClientSession::new(stream).await?))
    }

    pub fn is_ready(&self) -> bool {
        self.0.is_ready()
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        self.0.same_generation(&other.0)
    }

    pub async fn open_stream(
        &mut self,
        target: &NetLocation,
        auth_header: &str,
        padding_enabled: bool,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(format_authority(target))
            .version(Version::HTTP_2)
            .header("proxy-authorization", auth_header);
        if padding_enabled {
            request = request
                .header(
                    "padding",
                    generate_padding_header(rand::rng().random_range(16..=32)),
                )
                .header("padding-type-request", "1, 0");
        }
        let request = request.body(()).map_err(io::Error::other)?;
        let (response, stream) = self.0.open(request).await?;
        if response.status != StatusCode::OK {
            return Err(io::Error::other(format!(
                "CONNECT failed with status: {}",
                response.status
            )));
        }
        let padding_type = if !padding_enabled {
            PaddingType::None
        } else if let Some(reply) = response.headers.get("padding-type-reply") {
            reply
                .to_str()
                .unwrap_or("1")
                .trim()
                .parse::<u8>()
                .ok()
                .and_then(PaddingType::from_u8)
                .unwrap_or(PaddingType::Variant1)
        } else if response.headers.contains_key("padding") {
            PaddingType::Variant1
        } else {
            PaddingType::None
        };
        Ok(if padding_type == PaddingType::None {
            Box::new(stream)
        } else {
            Box::new(NaivePaddingStream::new(
                stream,
                PaddingDirection::Client,
                padding_type,
            ))
        })
    }
}
