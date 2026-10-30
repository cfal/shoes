use std::{io, sync::Arc};

use async_trait::async_trait;

use crate::{
    address::ResolvedLocation,
    async_stream::{AsyncMessageStream, AsyncStream},
    resolver::Resolver,
    tcp::tcp_handler::{
        TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
    },
};

use super::{Prepared, Role, stream::SudokuStream};

#[derive(Debug)]
pub(crate) struct ClientHandler {
    pub config: Arc<Prepared>,
    pub inner: Box<dyn TcpClientHandler>,
}

#[async_trait]
impl TcpClientHandler for ClientHandler {
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> io::Result<ResolvedLocation> {
        self.inner.prepare_target(target, resolver).await
    }

    fn validate_alpn(&self, alpn: Option<&[u8]>) -> io::Result<()> {
        self.inner.validate_alpn(alpn)
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> io::Result<Option<TcpClientSetupResult>> {
        self.inner.try_reuse_tcp_stream(target).await
    }

    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        self.inner
            .setup_client_tcp_stream(
                Box::new(SudokuStream::new(stream, self.config.clone(), Role::Client)),
                target,
            )
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.inner.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.inner
            .setup_client_udp_bidirectional(
                Box::new(SudokuStream::new(stream, self.config.clone(), Role::Client)),
                target,
            )
            .await
    }
}

#[derive(Debug)]
pub(crate) struct ServerHandler {
    pub config: Arc<Prepared>,
    pub inner: Box<dyn TcpServerHandler>,
}

#[async_trait]
impl TcpServerHandler for ServerHandler {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        let mut result = self
            .inner
            .setup_server_stream(Box::new(SudokuStream::new(
                stream,
                self.config.clone(),
                Role::Server,
            )))
            .await?;
        result.set_need_initial_flush(true);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        async_stream::{AsyncFlushMessage, test_streams::FlushGatedStream},
        client_proxy_selector::ClientProxySelector,
        h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT},
        resolver::NativeResolver,
        vless::vless_server_handler::VlessTcpServerHandler,
    };

    #[tokio::test]
    async fn socks_negotiation_flushes_through_client_and_server_masks() {
        use crate::{
            address::NetLocation,
            socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler},
        };

        for auth in [None, Some(("user".to_owned(), "pass".to_owned()))] {
            for layers in [1, 2] {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    let target = NetLocation::from_str("127.0.0.1:443", None).unwrap();
                    let mut client: Box<dyn TcpClientHandler> =
                        Box::new(SocksTcpClientHandler::new(auth.clone()));
                    let mut server: Box<dyn TcpServerHandler> =
                        Box::new(SocksTcpServerHandler::new(
                            auth.clone(),
                            false,
                            "0.0.0.0".parse().unwrap(),
                            Arc::new(ClientProxySelector::new(vec![])),
                            Arc::new(NativeResolver::new()),
                        ));
                    for layer in 0..layers {
                        let config = super::super::tests::config(
                            serde_json::json!({"password":format!("layer-{layer}")}),
                        );
                        client = Box::new(ClientHandler {
                            config: config.clone(),
                            inner: client,
                        });
                        server = Box::new(ServerHandler {
                            config,
                            inner: server,
                        });
                    }
                    let (client_io, server_io) = tokio::io::duplex(64);
                    let connect = async {
                        let mut setup = client
                            .setup_client_tcp_stream(
                                Box::new(FlushGatedStream::new(client_io)),
                                target.clone().into(),
                            )
                            .await
                            .unwrap();
                        let mut tail = Vec::new();
                        setup.client_stream.read_to_end(&mut tail).await.unwrap();
                        assert!(tail.is_empty());
                    };
                    let accept = async {
                        let TcpServerSetupResult::TcpForward {
                            remote_location,
                            mut stream,
                            connection_success_response,
                            need_initial_flush,
                            ..
                        } = server
                            .setup_server_stream(Box::new(FlushGatedStream::new(server_io)))
                            .await
                            .unwrap()
                        else {
                            panic!("expected TCP forwarding")
                        };
                        assert_eq!(remote_location, target);
                        assert!(need_initial_flush);
                        stream
                            .write_all(&connection_success_response.unwrap())
                            .await
                            .unwrap();
                        stream.flush().await.unwrap();
                    };
                    tokio::join!(connect, accept);
                })
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "SOCKS handshake stalled: auth={}, layers={layers}",
                        auth.is_some()
                    )
                });
            }
        }
    }

    #[tokio::test]
    async fn forwarding_and_session_handoffs_flush_through_stacked_masks() {
        const USER_ID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";
        for (command, session) in [(1, false), (1, true), (2, false), (3, false)] {
            for layers in [1, 2] {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    let mut handler: Box<dyn TcpServerHandler> = Box::new(
                        VlessTcpServerHandler::new(
                            USER_ID,
                            true,
                            Arc::new(ClientProxySelector::new(vec![])),
                            Arc::new(NativeResolver::new()),
                            None,
                            None,
                            false,
                        )
                        .unwrap(),
                    );
                    let config = super::super::tests::config(serde_json::json!({}));
                    let (io, peer) = tokio::io::duplex(1);
                    let mut peer: Box<dyn AsyncStream> = Box::new(FlushGatedStream::new(peer));
                    for _ in 0..layers {
                        handler = Box::new(ServerHandler {
                            config: config.clone(),
                            inner: handler,
                        });
                        peer = Box::new(SudokuStream::new(peer, config.clone(), Role::Client));
                    }
                    let server = async {
                        match handler
                            .setup_server_stream(Box::new(FlushGatedStream::new(io)))
                            .await
                            .unwrap()
                        {
                            TcpServerSetupResult::TcpForward {
                                mut stream,
                                need_initial_flush,
                                connection_success_response,
                                ..
                            } => {
                                assert_eq!(command, 1);
                                assert!(!session);
                                assert!(need_initial_flush);
                                stream
                                    .write_all(&connection_success_response.unwrap())
                                    .await
                                    .unwrap();
                                stream.flush().await.unwrap();
                            }
                            TcpServerSetupResult::BidirectionalUdp {
                                mut stream,
                                need_initial_flush,
                                ..
                            } => {
                                assert_eq!(command, 2);
                                assert!(need_initial_flush);
                                futures::future::poll_fn(|cx| {
                                    Pin::new(&mut stream).poll_flush_message(cx)
                                })
                                .await
                                .unwrap();
                            }
                            TcpServerSetupResult::SessionBasedUdp {
                                mut stream,
                                need_initial_flush,
                                ..
                            } => {
                                assert_eq!(command, 3);
                                assert!(need_initial_flush);
                                futures::future::poll_fn(|cx| {
                                    Pin::new(&mut stream).poll_flush_message(cx)
                                })
                                .await
                                .unwrap();
                            }
                            TcpServerSetupResult::Session(_) => assert!(session),
                            _ => panic!("unexpected setup result"),
                        }
                    };
                    let client = async {
                        let mut request = vec![0];
                        request.extend_from_slice(&crate::uuid_util::parse_uuid(USER_ID).unwrap());
                        request.extend_from_slice(&[0, command]);
                        if session {
                            request.extend_from_slice(&MUX_DESTINATION_PORT.to_be_bytes());
                            request.extend_from_slice(&[2, MUX_DESTINATION_HOST.len() as u8]);
                            request.extend_from_slice(MUX_DESTINATION_HOST.as_bytes());
                        } else if command != 3 {
                            request.extend_from_slice(&[1, 187, 1, 127, 0, 0, 1]);
                        }
                        peer.write_all(&request).await.unwrap();
                        peer.flush().await.unwrap();
                        // Drain framing bytes too, so the one-byte transport can finish flushing.
                        let mut response = Vec::new();
                        peer.read_to_end(&mut response).await.unwrap();
                        assert_eq!(response, [0, 0]);
                    };
                    tokio::join!(server, client);
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("handoff stalled: command={command}, session={session}, layers={layers}")
                });
            }
        }
    }
}
