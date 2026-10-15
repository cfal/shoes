// identity_op: we write out how test values are computed
#![allow(clippy::identity_op)]

use std::{borrow::BorrowMut, time::Duration};

use assert_matches::assert_matches;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use http::{Request, Response, StatusCode};
use tokio::sync::oneshot::{self};

use crate::client::SendRequest;
use crate::error::{Code, ConnectionError, LocalError, StreamError};
use crate::quic::ConnectionErrorIncoming;
use crate::tests::get_stream_blocking;
use crate::{client, server, ConnectionState};
use crate::{
    proto::{
        coding::Encode as _,
        frame::{Frame, Settings},
        push::PushId,
        stream::StreamType,
        varint::VarInt,
    },
    quic::{self, SendStream},
};

use super::h3_quinn;
use super::{init_tracing, Pair};

#[tokio::test]
async fn connect() {
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut drive, _client) = client::new(pair.client().await).await.expect("client init");
        assert_matches!(
            future::poll_fn(|cx| drive.poll_close(cx)).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let _server = server::Connection::new(conn).await.unwrap();
    };

    tokio::select!(() = server_fut => (), () = client_fut => panic!("client resolved first"));
}

#[tokio::test]
async fn accept_request_end_on_client_close() {
    let mut pair = Pair::default();
    let mut server = pair.server();
    let client = pair.client();
    let (tx, rx) = oneshot::channel::<()>();
    let client_fut = async move {
        let client = client.await;
        let (mut driver, client) = client::new(client).await.expect("client init");
        let driver = async move {
            let _ = future::poll_fn(|cx: &mut std::task::Context<'_>| driver.poll_close(cx)).await;
        };

        let client_fut = async move {
            // wait for the server to accept the connection
            rx.await.unwrap();
            // client is dropped, it will send H3_NO_ERROR
            drop(client);
        };
        tokio::join!(driver, client_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        tx.send(()).unwrap();
        assert_matches!(
            incoming.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };
    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn server_drop_close() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        let conn = server.next().await;
        let _ = server::Connection::new(conn).await.unwrap();
    };

    let client_fut = async {
        let (mut conn, mut send) = client::new(pair.client().await).await.expect("client init");
        let request_fut = async move {
            let mut request_stream = send
                .send_request(Request::get("http://no.way").body(()).unwrap())
                .await
                .unwrap();
            let response = request_stream.recv_response().await;

            assert_matches!(
                response.unwrap_err(),
                StreamError::ConnectionError(ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                    error_code: code,
                    ..
                }))
                if code == Code::H3_NO_ERROR.value()
            );
        };

        let drive_fut = async {
            let drive = future::poll_fn(|cx| conn.poll_close(cx)).await;
            assert_matches!(drive, ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value());
        };
        tokio::join! {request_fut,drive_fut}
    };
    tokio::join!(server_fut, client_fut);
}

// In this test the client calls send_data() without doing a finish(),
// i.e client keeps the body stream open. And client expects server to
// read_data() and send a response
#[tokio::test]
async fn server_send_data_without_finish() {
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (_driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        let mut req = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let data = vec![0; 100];
        req.send_data(bytes::Bytes::copy_from_slice(&data))
            .await
            .unwrap();
        let _ = req.recv_response().await.unwrap();
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let request_resolver = incoming.accept().await.unwrap().unwrap();
        let (_, mut stream) = request_resolver.resolve_request().await.unwrap();
        let mut data = stream.recv_data().await.unwrap().unwrap();
        let data = data.copy_to_bytes(data.remaining());
        assert_eq!(data.len(), 100);
        response(stream).await;
        server.endpoint.wait_idle().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn client_close_only_on_last_sender_drop() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let (_, mut stream) = incoming
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);

        let (_, mut stream) = incoming
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);

        assert_matches!(
            incoming.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let client_fut = async {
        let (mut conn, mut send1) = client::new(pair.client().await).await.expect("client init");
        let mut send2 = send1.clone();
        let mut request_stream_1 = send1
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();

        assert_matches!(
            request_stream_1.recv_response().await,
            Err(StreamError::RemoteTerminate{
                code
            }) if code == Code::H3_REQUEST_CANCELLED.value()
        );

        let _ = request_stream_1.finish().await.unwrap();

        let mut request_stream_2 = send2
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();

        assert_matches!(
            request_stream_2.recv_response().await,
            Err(StreamError::RemoteTerminate{
                code
            }) if code == Code::H3_REQUEST_CANCELLED.value()
        );
        let _ = request_stream_2.finish().await.unwrap();

        drop(send1);
        drop(send2);

        let drive = future::poll_fn(|cx| conn.poll_close(cx)).await;
        assert_matches!(
            drive,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_NO_ERROR,
                    ..
                }
            }
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn settings_exchange_client() {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
    //= type=test
    //# After the QUIC connection is
    //# established, a SETTINGS frame MUST be sent by each endpoint as the
    //# initial frame of their respective HTTP control stream.

    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, client) = client::new(pair.client().await).await.expect("client init");
        let settings_change = async {
            for _ in 0..10 {
                if client.settings().max_field_section_size == 12 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            panic!("peer's max_field_section_size didn't change");
        };

        let drive = async move {
            assert_matches!(future::poll_fn(|cx| conn.poll_close(cx)).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value());
        };

        tokio::select! { _ = settings_change => (), _ = drive => panic!("driver resolved first") };
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::builder()
            .max_field_section_size(12)
            .build(conn)
            .await
            .unwrap();
        incoming.accept().await.unwrap()
    };

    tokio::select! { _ = server_fut => panic!("server resolved first"), _ = client_fut => () };
}

#[tokio::test]
async fn settings_exchange_server() {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
    //= type=test
    //# After the QUIC connection is
    //# established, a SETTINGS frame MUST be sent by each endpoint as the
    //# initial frame of their respective HTTP control stream.

    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, _client) = client::builder()
            .max_field_section_size(12)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");
        let drive = async move {
            assert_matches!(
                future::poll_fn(|cx| conn.poll_close(cx)).await,
                ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                    error_code: code,
                    ..
                }) if code == Code::H3_NO_ERROR.value()
            );
        };

        drive.await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let state = incoming.inner.shared.clone();
        let accept = async { incoming.accept().await.unwrap() };

        let settings_change = async {
            for _ in 0..10 {
                if state.settings().max_field_section_size == 12 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            panic!("peer's max_field_section_size didn't change");
        };
        tokio::select! { _ = accept => panic!("server resolved first"), _ = settings_change => () };
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn client_error_on_bidi_recv() {
    let mut pair = Pair::default();
    let server = pair.server();

    let client_fut = async {
        let (mut conn, mut send) = client::new(pair.client().await).await.expect("client init");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
        //= type=test
        //# Clients MUST treat
        //# receipt of a server-initiated bidirectional stream as a connection
        //# error of type H3_STREAM_CREATION_ERROR unless such an extension has
        //# been negotiated.
        let driver = future::poll_fn(|cx| conn.poll_close(cx));
        assert_matches!(
            driver.await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    reason: reason_string
                }
            } if reason_string.starts_with("client received a server-initiated bidirectional stream")
        );
        assert_matches!(send.send_request(Request::get("http://no.way").body(()).unwrap())
            .await.map(|_| ()).unwrap_err(),
            StreamError::ConnectionError(
                ConnectionError::Local { error: LocalError::Application { code: Code::H3_STREAM_CREATION_ERROR, reason: reason_string } }
            )
            if reason_string.starts_with("client received a server-initiated bidirectional stream")
        );
    };

    let server_fut = async {
        let connection = server.endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        for _ in 0..100 {
            match send.write(b"I'm not really a server").await {
                Err(quinn::WriteError::ConnectionLost(
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code,
                        ..
                    }),
                )) if Code::H3_STREAM_CREATION_ERROR == error_code.into_inner() => return,
                Err(e) => panic!("got err: {}", e),
                Ok(_) => (),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("did not get the expected error");
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn two_control_streams() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# Only one control stream per peer is permitted;
        //# receipt of a second stream claiming to be a control stream MUST be
        //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
        for _ in 0..=1 {
            let mut control_stream = connection.open_uni().await.unwrap();
            let mut buf = BytesMut::new();
            StreamType::CONTROL.encode(&mut buf);
            control_stream.write_all(&buf[..]).await.unwrap();
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_STREAM_CREATION_ERROR,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn control_close_send_error() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# If either control
        //# stream is closed at any point, this MUST be treated as a connection
        //# error of type H3_CLOSED_CRITICAL_STREAM.
        control_stream.finish().unwrap(); // close the client control stream immediately

        // create the Connection manually, so it does not open a second Control stream

        let connection_error = loop {
            let accepted = connection.accept_bi().await;
            match accepted {
                // do nothing with the stream
                Ok(_) => continue,
                Err(err) => break err,
            }
        };

        let err_code = match connection_error {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) => error_code.into_inner(),
            e => panic!("unexpected error: {:?}", e),
        };
        assert_eq!(err_code, Code::H3_CLOSED_CRITICAL_STREAM.value());
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        // Driver detects that the receiving side of the control stream has been closed
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    reason: reason_string
                }
            }
            if reason_string.starts_with("control stream was closed"));
        // Poll it once again returns the previously stored error
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_CLOSED_CRITICAL_STREAM,
                    reason: reason_string
                }
            }
            if reason_string.starts_with("control stream was closed"));
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn missing_settings() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=test
        //# If the first frame of the control stream is any other frame
        //# type, this MUST be treated as a connection error of type
        //# H3_MISSING_SETTINGS.
        Frame::<Bytes>::CancelPush(PushId(0)).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_MISSING_SETTINGS,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn control_stream_frame_unexpected() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        // Send a Settings frame or we get a H3_MISSING_SETTINGS instead of H3_FRAME_UNEXPECTED
        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        Frame::Settings::<Bytes>(Settings::default()).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
        //= type=test
        //# If
        //# a DATA frame is received on a control stream, the recipient MUST
        //# respond with a connection error of type H3_FRAME_UNEXPECTED.
        let mut buf = BytesMut::new();
        Frame::Data(Bytes::from("")).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_FRAME_UNEXPECTED,
                    ..
                }
            }
        );
    };

    tokio::select! { _ = server_fut => (), _ = client_fut => panic!("client resolved first") };
}

#[tokio::test]
async fn timeout_on_control_frame_read() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(10));

    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, _send_request) = client::new(pair.client().await).await.unwrap();
        let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Timeout
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn goaway_from_server_not_request_id() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();
        control_stream.finish().unwrap(); // close the client control stream immediately

        let (mut driver, _send) = client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();

        assert_matches!(
            future::poll_fn(|cx| driver.poll_close(cx)).await,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_ID_ERROR,
                    ..
                }
            }
        )
    };

    let server_fut = async {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut control_stream = conn.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);
        Frame::<Bytes>::Settings(Settings::default()).encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
        //= type=test
        //# A client MUST treat receipt of a GOAWAY frame containing a stream ID
        //# of any other type as a connection error of type H3_ID_ERROR.

        // StreamId(index=0 << 2 | dir=Uni << 1 | initiator=Server as u64)
        Frame::<Bytes>::Goaway(VarInt(0u64 << 2 | 0 << 1 | 1)).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    tokio::select! { _ = server_fut => panic!("client resolved first"), _ = client_fut => () };
}

#[tokio::test]
async fn graceful_shutdown_server_rejects() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (_driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        let mut first = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let mut rejected = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let first = first.recv_response().await;
        let rejected = rejected.recv_response().await;

        assert_matches!(first, Ok(_));
        assert_matches!(
            rejected.unwrap_err(),
            StreamError::RemoteTerminate {
                code: Code::H3_REQUEST_REJECTED
            }
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let request_resolver = incoming.accept().await.unwrap().unwrap();
        let (_, stream) = request_resolver.resolve_request().await.unwrap();
        response(stream).await;
        incoming.shutdown(0).await.unwrap();
        assert_matches!(incoming.accept().await.map(|x| x.map(|_| ())), Ok(None));
        server.endpoint.wait_idle().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn graceful_shutdown_grace_interval() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        // Sent as the connection is not shutting down
        let mut first = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        // Sent as the connection is shutting down, but GoAway has not been received yet
        let mut in_flight = send_request
            .send_request(Request::get("http://no.way").body(()).unwrap())
            .await
            .unwrap();
        let first = first.recv_response().await;
        let in_flight = in_flight.recv_response().await;

        // Will not be sent as client's driver already received the GoAway
        let too_late = async move {
            tokio::time::sleep(Duration::from_millis(15)).await;
            request(send_request).await
        };
        let driver = future::poll_fn(|cx| driver.poll_close(cx));

        let (too_late, driver) = tokio::join!(too_late, driver);
        assert_matches!(first, Ok(_));
        assert_matches!(in_flight, Ok(_));
        assert_matches!(too_late.unwrap_err(), StreamError::RemoteClosing);
        assert_matches!(
            driver,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_NO_ERROR,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let (_, first) = get_stream_blocking(&mut incoming).await.unwrap();
        incoming.shutdown(1).await.unwrap();
        let (_, in_flight) = get_stream_blocking(&mut incoming).await.unwrap();
        response(first).await;
        response(in_flight).await;

        while let Some((_, stream)) = get_stream_blocking(&mut incoming).await {
            response(stream).await;
        }

        // Ensure `too_late` request is executed as the connection is still
        // closing (no QUIC `Close` frame has been fired yet)
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn graceful_shutdown_closes_when_idle() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut send_request) = client::new(pair.client().await).await.unwrap();

        // Make continuous requests, ignoring GoAway because the connection is not driven
        while request(&mut send_request).await.is_ok() {
            tokio::task::yield_now().await;
        }
        assert_matches!(
            future::poll_fn(|cx| { driver.poll_close(cx) }).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();

        let mut count = 0;

        while let Some((_, stream)) = get_stream_blocking(&mut incoming).await {
            count += 1;
            if count == 4 {
                incoming.shutdown(2).await.unwrap();
            }

            response(stream).await;
        }
    };

    tokio::select! {
        _ = client_fut => (),
        r = tokio::time::timeout(Duration::from_millis(100), server_fut)
            => assert_matches!(r, Ok(())),
    };
}

#[tokio::test]
async fn graceful_shutdown_client() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut _send_request) = client::new(pair.client().await).await.unwrap();
        driver.shutdown(0).await.unwrap();
        assert_matches!(
            future::poll_fn(|cx| { driver.poll_close(cx) }).await,
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                error_code: code,
                ..
            }) if code == Code::H3_NO_ERROR.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        assert!(incoming.accept().await.unwrap().is_none());
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
// This test is to ensure that the server does still process requests even if a stream is started but has not sent any data
async fn server_not_blocking_on_idle_request() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        // create a Connection
        let connection = pair.client_inner().await;
        let mut control_stream = connection.open_uni().await.unwrap();

        let mut buf = BytesMut::new();
        StreamType::CONTROL.encode(&mut buf);

        Frame::<Bytes>::Settings(Settings::default()).encode(&mut buf);
        control_stream.write_all(&buf[..]).await.unwrap();

        let mut control_recv = connection.accept_uni().await.unwrap();
        // create a Request stream which is idle
        let mut request_stream = connection.open_bi().await.unwrap();

        let mut buf = BytesMut::new();
        Frame::<Bytes>::headers(Bytes::from("test")).encode(&mut buf);
        request_stream.0.write_all(&buf[..]).await.unwrap();

        let mut buf = BytesMut::new();
        // send a wrong frame to control stream
        Frame::<Bytes>::Data(Bytes::from(
            "this frame should cause the server to respond with an error",
        ))
        .encode(&mut buf);
        tokio::time::sleep(Duration::from_millis(10)).await;

        control_stream.write_all(&buf[..]).await.unwrap();

        let mut buf2 = BytesMut::new();
        control_recv.read(buf2.as_mut()).await.unwrap();

        // no bidirectional stream is started by the server
        // this will fail when server sends the error
        let err = connection
            .accept_bi()
            .await
            .err()
            .expect("connection should error after sending wrong data on control stream");

        assert_matches!(err,
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose { error_code, .. })
            if error_code.into_inner() == Code::H3_FRAME_UNEXPECTED.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let resolver = incoming.accept().await.unwrap().unwrap();
        let req1 = async move {
            let _ = resolver
                .resolve_request()
                .await
                .err()
                .expect("server should close connection");
        };

        let server = async move {
            let err = incoming.accept().await.err().expect("Connection Error");
            assert_matches!(
                err,
                ConnectionError::Local {
                    error: LocalError::Application {
                        code: Code::H3_FRAME_UNEXPECTED,
                        ..
                    }
                }
            );
        };

        tokio::join!(req1, server);
    };

    let join = async {
        tokio::join!(server_fut, client_fut);
    };

    tokio::select!(
        _ = join => (),
         _ = tokio::time::sleep(Duration::from_secs(100)) => panic!("timeout")
    );
}
async fn request<T, O, B>(mut send_request: T) -> Result<Response<()>, StreamError>
where
    T: BorrowMut<SendRequest<O, B>>,
    O: quic::OpenStreams<B>,
    B: Buf,
{
    let mut request_stream = send_request
        .borrow_mut()
        .send_request(Request::get("http://no.way").body(()).unwrap())
        .await?;
    request_stream.recv_response().await
}

async fn response<S, B>(mut stream: server::RequestStream<S, B>)
where
    S: quic::RecvStream + SendStream<B>,
    B: Buf,
{
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::IM_A_TEAPOT)
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();
}
