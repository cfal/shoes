use super::*;
use crate::resources::Budget;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn h2_readiness_and_established_receive_preserve_transport_causes() {
    use crate::http2::transport::tests::{cases, peer};
    tokio::time::timeout(Duration::from_secs(5), async {
        for ready in [false, true] {
            for (make_error, local) in cases() {
                let (client, fault, mut sends, driver) = peer(make_error);
                if !ready {
                    fault.inject();
                }
                let result = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192).await;
                let error = if ready {
                    let carrier = result.unwrap();
                    let tasks = Tasks::new();
                    let memory = Memory::new(Arc::new(Budget::new(Some(16384))), Some(16384));
                    let request = Request::get("http://example.com/")
                        .body(Body::Empty)
                        .unwrap();
                    let mut response = carrier
                        .request(request, memory, &tasks, Duration::from_secs(1))
                        .await
                        .unwrap()
                        .into_body();
                    let _send = sends.recv().await.unwrap();
                    assert_eq!(response.read_u8().await.unwrap(), b'x');
                    fault.inject();
                    response.read_u8().await.unwrap_err()
                } else {
                    result.err().expect("readiness PING must fail")
                };
                assert_eq!(
                    crate::clash_api::probes::local_failure(&error),
                    local,
                    "ready={ready}: {error:?}"
                );
                driver.abort();
                let _ = driver.await;
            }
        }
    })
    .await
    .unwrap();
}

async fn h2_peer() -> (
    Arc<Carrier>,
    tokio::sync::mpsc::UnboundedReceiver<(
        Request<h2::RecvStream>,
        h2::server::SendResponse<Bytes>,
    )>,
    Tasks,
) {
    let (client, peer) = tokio::io::duplex(4096);
    let tasks = Tasks::new();
    let (requests, received) = tokio::sync::mpsc::unbounded_channel();
    tasks.spawn(async move {
        let mut connection = h2::server::Builder::new()
            .initial_window_size(1024)
            .handshake(peer)
            .await
            .unwrap();
        while let Some(request) = connection.accept().await {
            if requests.send(request.unwrap()).is_err() {
                break;
            }
        }
    });
    let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192)
        .await
        .unwrap();
    (carrier, received, tasks)
}

#[tokio::test]
async fn h2_early_response_drains_after_no_error_reset() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for blocked_upload in [false, true] {
            for response_len in [0, 48 * 1024] {
                let (carrier, mut requests, _server) = h2_peer().await;
                let tasks = Tasks::new();
                let budget = Arc::new(Budget::new(Some(16 * 1024)));
                let memory = Memory::new(budget.clone(), Some(16 * 1024));
                let (mut upload, body) = pipe(memory.clone());
                let data = vec![7; if blocked_upload { 2048 } else { 1024 }];
                upload.write_all(&data).await.unwrap();
                let expected: Vec<_> = (0..response_len).map(|i| (i % 251) as u8).collect();
                let request = Request::post("http://localhost/stream-one")
                    .body(Body::stream(body))
                    .unwrap();
                let (response, ()) = tokio::join!(
                    carrier.request(request, memory.clone(), &tasks, Duration::from_secs(1)),
                    async {
                        let (request, mut respond) = requests.recv().await.unwrap();
                        let mut incoming = request.into_body();
                        assert_eq!(incoming.data().await.unwrap().unwrap(), &data[..1024]);
                        // Leave the upload open, including its exhausted window in the blocked case.
                        let mut send = respond
                            .send_response(Response::new(()), expected.is_empty())
                            .unwrap();
                        if !expected.is_empty() {
                            send.send_data(Bytes::copy_from_slice(&expected), true)
                                .unwrap();
                        }
                        // h2 queues NO_ERROR after the complete response when these handles drop.
                    }
                );
                let mut response = response.unwrap().into_body();
                upload.closed().await;
                assert!(upload.write_all(b"after reset").await.is_err());
                let mut actual = Vec::new();
                response.read_to_end(&mut actual).await.unwrap();
                assert_eq!(actual, expected);
                tasks.wait().await;
                assert!(!tasks.cancel.is_cancelled());
                drop(response);
                drop(upload);
                assert_eq!(budget.snapshot().active, 0);

                // The reset belongs to one stream, not the pooled connection.
                let probe_tasks = Tasks::new();
                let (probe, ()) = tokio::join!(
                    carrier.request(
                        Request::get("http://localhost/probe")
                            .body(Body::Empty)
                            .unwrap(),
                        memory,
                        &probe_tasks,
                        Duration::from_secs(1),
                    ),
                    async {
                        let (_, mut respond) = requests.recv().await.unwrap();
                        let mut send = respond.send_response(Response::new(()), false).unwrap();
                        send.send_data(Bytes::from_static(b"reused"), true).unwrap();
                    }
                );
                let mut actual = Vec::new();
                probe
                    .unwrap()
                    .into_body()
                    .read_to_end(&mut actual)
                    .await
                    .unwrap();
                assert_eq!(actual, b"reused");
                probe_tasks.wait().await;
                assert_eq!(budget.snapshot().active, 0);
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_upload_failures_and_truncated_responses_are_not_eof() {
    enum Failure {
        Reset(h2::Reason),
        Body,
        Cancel,
        Disconnect,
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        for failure in [
            Failure::Reset(h2::Reason::NO_ERROR),
            Failure::Reset(h2::Reason::CANCEL),
            Failure::Reset(h2::Reason::INTERNAL_ERROR),
            Failure::Body,
            Failure::Cancel,
            Failure::Disconnect,
        ] {
            let (carrier, mut requests, server) = h2_peer().await;
            let tasks = Tasks::new();
            let memory = Memory::new(Arc::new(Budget::new(Some(16 * 1024))), Some(16 * 1024));
            let (mut upload, body) = pipe(memory.clone());
            let request = Request::post("http://localhost/stream-one")
                .body(Body::stream(body))
                .unwrap();
            let (response, mut send) = tokio::join!(
                carrier.request(request, memory, &tasks, Duration::from_secs(1)),
                async {
                    let (_request, mut respond) = requests.recv().await.unwrap();
                    let mut send = respond.send_response(Response::new(()), false).unwrap();
                    send.send_data(Bytes::from_static(b"prefix"), false)
                        .unwrap();
                    send
                }
            );
            let mut response = response.unwrap().into_body();
            let mut prefix = [0; 6];
            response.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"prefix");
            match failure {
                Failure::Reset(reason) => send.send_reset(reason),
                Failure::Body => upload.fail(io::ErrorKind::UnexpectedEof.into()).await,
                Failure::Cancel => tasks.cancel.cancel(),
                Failure::Disconnect => server.cancel.cancel(),
            }
            upload.closed().await;
            assert!(response.read(&mut [0; 1]).await.is_err());
            tasks.wait().await;
            let quiet = matches!(failure, Failure::Reset(h2::Reason::NO_ERROR));
            assert_eq!(tasks.cancel.is_cancelled(), !quiet);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_no_error_goaway_does_not_complete_a_truncated_response() {
    use bytes::{BufMut, BytesMut};

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Bytes {
        let mut frame = BytesMut::new();
        frame.put_uint(payload.len() as u64, 3);
        frame.put_u8(kind);
        frame.put_u8(flags);
        frame.put_u32(stream);
        frame.extend_from_slice(payload);
        frame.freeze()
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut peer) = tokio::io::duplex(4096);
        let server = Tasks::new();
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let release_peer = CancellationToken::new();
        let release = release_peer.clone();
        server.spawn(async move {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            peer.write_all(&frame(4, 0, 0, &[])).await.unwrap();
            loop {
                let mut header = [0; 9];
                peer.read_exact(&mut header).await.unwrap();
                let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                let mut payload = vec![0; len];
                peer.read_exact(&mut payload).await.unwrap();
                match (header[3], header[4] & 1) {
                    // Acknowledge SETTINGS and the carrier's readiness PING.
                    (4, 0) => peer.write_all(&frame(4, 1, 0, &[])).await.unwrap(),
                    (6, 0) => peer.write_all(&frame(6, 1, 0, &payload)).await.unwrap(),
                    (1, _) => {
                        assert_eq!(&header[5..], &1_u32.to_be_bytes());
                        break;
                    }
                    _ => {}
                }
            }
            // HEADERS (:status 200) and DATA without END_STREAM.
            peer.write_all(&frame(1, 4, 1, &[0x88])).await.unwrap();
            peer.write_all(&frame(0, 0, 1, b"prefix")).await.unwrap();
            stop.cancelled().await;
            // Exclude stream 1 from GOAWAY so it receives NO_ERROR, not transport EOF.
            peer.write_all(&frame(7, 0, 0, &[0; 8])).await.unwrap();
            release.cancelled().await;
            drop(peer);
        });
        let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192)
            .await
            .unwrap();
        let tasks = Tasks::new();
        let memory = Memory::new(Arc::new(Budget::new(Some(16 * 1024))), Some(16 * 1024));
        let (upload, body) = pipe(memory.clone());
        let mut response = carrier
            .request(
                Request::post("http://localhost/stream-one")
                    .body(Body::stream(body))
                    .unwrap(),
                memory,
                &tasks,
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .into_body();
        let mut prefix = [0; 6];
        response.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"prefix");
        shutdown.cancel();
        let error = response.read(&mut [0; 1]).await.unwrap_err();
        let error = error
            .get_ref()
            .unwrap()
            .downcast_ref::<h2::Error>()
            .unwrap();
        assert!(error.is_go_away());
        assert_eq!(error.reason(), Some(h2::Reason::NO_ERROR));
        upload.closed().await;
        tasks.wait().await;
        assert!(!tasks.cancel.is_cancelled());
        release_peer.cancel();
        server.wait().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_early_response_does_not_acknowledge_incomplete_packet() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (carrier, mut requests, _server) = h2_peer().await;
        let tasks = Tasks::new();
        let budget = Arc::new(Budget::new(Some(16 * 1024)));
        let memory = Memory::new(budget.clone(), Some(16 * 1024));
        let (signal, written) = UploadSignal::channel();
        let request = Request::post("http://localhost/packet/0")
            .extension(signal)
            .body(Body::Chunks(vec![memory.copy(&[7; 2048]).unwrap()].into()))
            .unwrap();
        let reservation = carrier.reserve().await.unwrap();
        let (response, ()) = tokio::join!(
            carrier.request_reserved(
                request,
                memory,
                &tasks,
                Timeouts::packet(Duration::from_secs(1), Duration::from_secs(1)),
                reservation,
            ),
            async {
                let (request, mut respond) = requests.recv().await.unwrap();
                let mut incoming = request.into_body();
                assert_eq!(incoming.data().await.unwrap().unwrap().len(), 1024);
                respond.send_response(Response::new(()), true).unwrap();
            }
        );
        assert!(response.is_err());
        assert!(written.await.is_err());
        tasks.wait().await;
        assert!(tasks.cancel.is_cancelled());
        assert_eq!(budget.snapshot().active, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_no_error_does_not_hide_body_errors_or_finish_server_sends() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (carrier, mut requests, _server) = h2_peer().await;
        let Sender::H2 { sender, .. } = &carrier.sender else {
            unreachable!()
        };
        let mut sender = sender.clone().ready().await.unwrap();
        let (response, mut send) = sender
            .send_request(
                Request::post("http://localhost/stream-one")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let (request, mut respond) = requests.recv().await.unwrap();
        respond.send_response(Response::new(()), true).unwrap();
        drop((request, respond));
        let reason = futures::future::poll_fn(|cx| send.poll_reset(cx))
            .await
            .unwrap();
        assert_eq!(reason, h2::Reason::NO_ERROR);

        assert!(
            futures::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .is_none()
        );
        let error = H2SendError::Stream(io::ErrorKind::BrokenPipe.into());
        assert!(error.peer_sent_no_error(&mut send));
        // A reset can arrive between the body EOF poll and sending the final DATA frame.
        let error = H2SendError::Stream(io::Error::other(
            send.send_data(Bytes::new(), true).unwrap_err(),
        ));
        assert!(error.peer_sent_no_error(&mut send));
        let error = H2SendError::Local(io::ErrorKind::UnexpectedEof.into());
        assert!(!error.peer_sent_no_error(&mut send));
        assert!(send_h2(Body::Empty, send).await.is_err());
        assert!(response.await.unwrap().into_body().data().await.is_none());
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn packet_response_wait_requires_upload_completion_and_observes_cancellation() {
    let timeouts = Timeouts::packet(Duration::from_secs(1), Duration::from_secs(10));
    let (upload, watch) = Upload::channel();
    let cancel = CancellationToken::new();
    let mut response =
        Box::pin(timeouts.response(async { Ok(Response::new(())) }, Some(watch), &cancel));
    assert!(futures::poll!(&mut response).is_pending());
    for _ in 0..5 {
        tokio::time::advance(Duration::from_secs(9)).await;
        upload.activity.touch();
        assert!(futures::poll!(&mut response).is_pending());
    }
    tokio::time::advance(Duration::from_millis(9999)).await;
    assert!(futures::poll!(&mut response).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(response.await.unwrap_err().kind(), io::ErrorKind::TimedOut);

    let (mut upload, watch) = Upload::channel();
    upload.finish();
    let mut response = Box::pin(timeouts.response(
        std::future::pending::<io::Result<Response<()>>>(),
        Some(watch),
        &cancel,
    ));
    assert!(futures::poll!(&mut response).is_pending());
    tokio::time::advance(Duration::from_secs(1000)).await;
    assert!(futures::poll!(&mut response).is_pending());
    cancel.cancel();
    assert_eq!(
        response.await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );

    let (_upload, watch) = Upload::channel();
    let error = timeouts
        .response(
            async { Ok(Response::builder().status(413).body(()).unwrap()) },
            Some(watch),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("413"));
}
