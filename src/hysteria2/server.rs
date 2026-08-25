use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Monotonic epoch for UDP-session idle tracking. A session's `last_activity`
/// stores whole seconds elapsed since this point, which is enough resolution for
/// a 60s idle timeout and lets both the receive loop and the spawned
/// remote-to-local task update it through a single atomic.
static ACTIVITY_EPOCH: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

fn activity_secs() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_secs()
}

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use rand::RngExt;
use rand::distr::Alphanumeric;
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Default is 3 seconds per sing-box reference implementation.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);

/// HTTP/3 error code for normal closure.
/// Per official hysteria reference: https://github.com/apernet/hysteria/blob/master/core/server/server.go#L20
const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::quic_stream::QuicStream;
use crate::quic_transport::fragments::Defragmenter;
use crate::quic_transport::{
    QuicListenerSettings, QuicTransportParams, effective_mtu, start_quic_listeners,
};
use crate::resolver::{Resolver, ResolverCache};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_forward::connect_client_tcp_stream;
use crate::util::allocate_vec;

use super::frame::{
    FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LEN, MAX_PADDING_LEN, decode_varint_slice,
    encode_tcp_response, encode_varint, random_padding, read_varint,
};

async fn process_connection(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
    udp_enabled: bool,
) -> std::io::Result<()> {
    let connection = conn.await?;

    // Create a cancellation token for the entire connection lifecycle.
    // When cancelled, all spawned tasks (UDP sessions) will terminate gracefully.
    let cancel_token = CancellationToken::new();

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    //
    // we keep this function waiting for the tcp and udp tasks both to finish before dropping,
    // instead of passing the connection to one of the two loops, incase one finishes first.
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("H3 connection setup failed: {e}")))?;

    // Per sing-box reference, authentication timeout is 3 seconds
    match timeout(
        AUTH_TIMEOUT,
        auth_connection(&mut h3_conn, password, udp_enabled),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth failed");
            return Err(e);
        }
        Err(_elapsed) => {
            error!("Authentication timeout");
            connection.close(CLOSE_ERR_CODE_OK.into(), b"auth timeout");
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "authentication timeout",
            ));
        }
    }

    let udp_connection = connection.clone();
    let udp_client_proxy_selector = client_proxy_selector.clone();
    let udp_resolver = resolver.clone();
    let udp_cancel_token = cancel_token.clone();

    let uni_connection = connection.clone();

    // Use try_join! to run all loops concurrently within the same task, like Quinn's perf example.
    // This reduces task count and avoids spawning separate tasks for the main loops.
    let udp_loop = async {
        if udp_enabled {
            run_udp_local_to_remote_loop(
                udp_connection,
                udp_client_proxy_selector,
                udp_resolver,
                udp_cancel_token,
            )
            .await
        } else {
            Ok(())
        }
    };

    let uni_loop = async {
        // Depending on the client, unidirectional streams could still be sent, accept and drop.
        loop {
            match uni_connection.accept_uni().await {
                Ok(mut recv_stream) => {
                    let _ = recv_stream.stop(0u32.into());
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(e) => {
                    return Err(std::io::Error::other(format!(
                        "unidirectional loop error: {e}"
                    )));
                }
            }
        }
        Ok(())
    };

    let tcp_connection = connection.clone();
    let tcp_loop = run_tcp_loop(tcp_connection, client_proxy_selector, resolver);

    let result = tokio::try_join!(udp_loop, uni_loop, tcp_loop);

    cancel_token.cancel();

    // Per sing-box reference (service.go:277-293), close connection on error
    if let Err(ref e) = result {
        error!("Connection failed: {e}");
        connection.close(CLOSE_ERR_CODE_OK.into(), b"");
    }

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// The response to a client whose password was accepted.
fn auth_response(udp_enabled: bool) -> http::Response<()> {
    http::Response::builder()
        .status(http::status::StatusCode::from_u16(233).unwrap())
        .header("Hysteria-UDP", if udp_enabled { "true" } else { "false" })
        // "auto" is the server telling the client to run its own congestion
        // control. "0" means "no limit", which an official client reads as
        // permission to use Brutal at its configured rate against a server that
        // has installed no rate control at all.
        .header("Hysteria-CC-RX", "auto")
        .header("Hysteria-Padding", generate_ascii_string())
        .body(())
        .expect("every part of this response is a constant or a generated string")
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::other(format!(
            "unexpected uri: {}",
            req.uri()
        )));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::other(format!(
            "unexpected method: {}",
            req.method()
        )));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::other("missing auth header"));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|e| std::io::Error::other(format!("invalid auth header value: {e}")))?;

    // Constant time, and the rejection says nothing about what was sent: an
    // error carrying the attempted password puts a credential — quite possibly
    // a correct one for some other server — into the logs.
    if auth_str.as_bytes().ct_eq(password.as_bytes()).unwrap_u8() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "incorrect auth password",
        ));
    }

    Ok(())
}

fn generate_ascii_string() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

async fn auth_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    password: &str,
    udp_enabled: bool,
) -> std::io::Result<()> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|e| std::io::Error::other(format!("H3 accept failed: {e}")))?
        {
            Some(resolver) => {
                let (req, mut stream) = resolver.resolve_request().await.map_err(|err| {
                    std::io::Error::other(format!("Failed to resolve request: {err}"))
                })?;
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = auth_response(udp_enabled);

                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send auth response: {e}"))
                        })?;

                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish auth stream: {e}"))
                        })?;

                        return Ok(());
                    }
                    Err(e) => {
                        error!("Received non-hysteria2 auth http3 request: {e}");
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream.send_response(resp).await.map_err(|e| {
                            std::io::Error::other(format!("failed to send reject response: {e}"))
                        })?;
                        stream.finish().await.map_err(|e| {
                            std::io::Error::other(format!("failed to finish reject stream: {e}"))
                        })?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

struct UdpSession {
    fragments: Defragmenter,
    /// The address the fragment that started the in-flight packet carried.
    ///
    /// The protocol repeats the address in every fragment, but only the first
    /// one decides where the reassembled packet goes - upstream reads it off
    /// the message that opened the packet (`core/server/udp.go:137`). Kept
    /// beside the reassembler rather than inside it because the client end has
    /// one fixed address per session and would carry this for nothing.
    pending_location: Option<NetLocation>,
    send_socket: Arc<UdpSocket>,
    // we cache the last location in case of mid-session address changes, and
    // don't want to have to call ClientProxySelector::judge on every packet.
    last_location: NetLocation,
    last_socket_addr: SocketAddr,
    override_remote_write_address: Option<SocketAddr>,
    // Shared with the spawned remote-to-local task so that reply traffic counts as
    // activity too; otherwise a download-only session would be reaped mid-transfer.
    last_activity: Arc<AtomicU64>,
    cancel_token: CancellationToken,
}

impl Drop for UdpSession {
    /// Cancelling here rather than at each removal is what keeps the removal
    /// paths from diverging. There are three of them - the idle sweep, a failed
    /// `send_to`, and the map dropping when the connection ends - and one of
    /// them used to forget, leaving the reply loop parked on its socket for the
    /// life of the connection.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

impl UdpSession {
    // TODO: remove this function completely and inline?
    #[allow(clippy::too_many_arguments)]
    fn start(
        session_id: u32,
        connection: quinn::Connection,
        client_socket: Arc<UdpSocket>,
        initial_location: NetLocation,
        initial_socket_addr: SocketAddr,
        override_local_write_location: Option<NetLocation>,
        override_remote_write_address: Option<SocketAddr>,
        parent_cancel_token: &CancellationToken,
    ) -> Self {
        // Create a child token so this session is cancelled when the parent (connection) is cancelled
        let session_cancel_token = parent_cancel_token.child_token();

        let last_activity = Arc::new(AtomicU64::new(activity_secs()));

        let session = UdpSession {
            fragments: Defragmenter::new(),
            pending_location: None,
            send_socket: client_socket.clone(),
            last_location: initial_location,
            last_socket_addr: initial_socket_addr,
            override_remote_write_address,
            last_activity: last_activity.clone(),
            cancel_token: session_cancel_token.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = run_udp_remote_to_local_loop(
                session_id,
                connection,
                client_socket,
                override_local_write_location,
                last_activity,
                session_cancel_token,
            )
            .await
            {
                error!("UDP remote-to-local write loop ended with error: {e}");
            }
        });

        session
    }
}

/// Why a session can take UDP from a client but never answer it.
///
/// Not a failure of the peer and not one we can work around here. quinn will
/// not send a datagram to a peer that omitted `max_datagram_frame_size`
/// (`quinn-proto-0.11.17/src/connection/datagrams.rs:32-34`) and has no
/// equivalent of upstream's `AssumePeerMaxDatagramFrameSize`, so such a client
/// gets one-way UDP from us.
///
/// Narrower than it looks. The official client asks its QUIC library to omit
/// the parameter, but its Chrome parroting - on by default - overrides that,
/// because Chrome always advertises it and one parameter short of Chrome's set
/// is a fingerprint (`apernet/quic-go config.go:107-114`). Verified live: the
/// stock client's UDP works against us, and the same client with
/// `disableChromeParrot: true` receives but never gets a reply.
///
/// The message exists so that shows up in the operator's log as a named cause
/// rather than as a session that simply never replies.
fn no_datagram_support(session_id: u32) -> std::io::Error {
    std::io::Error::other(format!(
        "UDP session {session_id} can receive but never reply: the client did not \
         advertise max_datagram_frame_size, and quinn will not send datagrams to a \
         peer that omitted it. An official Hysteria2 client does this only with \
         Chrome parroting disabled. See \
         docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md"
    ))
}

/// What splitting a reply across datagrams came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentPlan {
    /// Send it: this many payload bytes per fragment, in this many fragments.
    Send {
        available_payload: usize,
        fragment_count: u8,
    },
    /// This one reply will not fit the 255 fragments the protocol counts.
    ///
    /// A property of the reply, not of the session - the next one may well be
    /// small enough - so it costs a dropped packet and nothing more. Upstream
    /// does the same (`core/internal/frag/frag.go:13-15`).
    TooManyFragments { needed: usize },
}

/// How a reply payload is split across datagrams.
///
/// Both inputs are the peer's: `max_datagram_size` is what it advertised, and
/// `header_overhead` includes the reply address it chose, up to
/// `MAX_ADDRESS_LEN`. Neither may be able to panic us, which is what an
/// `assert!` here used to allow, and neither may silently produce a fragment
/// count that does not fit the byte the protocol gives it.
///
/// The `Err` is reserved for the one condition that cannot improve: a datagram
/// with no room for a payload after the header is a constant of the connection,
/// so a session that hits it can only fail. A reply needing too many fragments
/// is the other kind of problem and comes back as a value.
///
/// `frame::build_datagrams` does the same arithmetic for the client. Merging
/// the two encoders is the spec's phase 3 item; this one deliberately holds no
/// framing so that the merge is a deletion.
fn fragment_plan(
    max_datagram_size: usize,
    header_overhead: usize,
    payload_len: usize,
) -> std::io::Result<FragmentPlan> {
    let available_payload = max_datagram_size
        .checked_sub(header_overhead)
        .filter(|available| *available > 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "a datagram of {max_datagram_size} bytes has no room for a payload after a \
                     {header_overhead} byte header"
                ),
            )
        })?;

    // An empty UDP packet is still a packet, and `div_ceil` gives zero for it.
    let fragment_count = payload_len.div_ceil(available_payload).max(1);
    if fragment_count > u8::MAX as usize {
        return Ok(FragmentPlan::TooManyFragments {
            needed: fragment_count,
        });
    }

    Ok(FragmentPlan::Send {
        available_payload,
        fragment_count: fragment_count as u8,
    })
}

async fn run_udp_remote_to_local_loop(
    session_id: u32,
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    override_local_write_address: Option<NetLocation>,
    last_activity: Arc<AtomicU64>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let max_datagram_size = connection
        .max_datagram_size()
        .ok_or_else(|| no_datagram_support(session_id))?;

    let original_address_bytes: Option<(Bytes, Bytes)> = match override_local_write_address {
        Some(a) => {
            // The wire form, not Display: an IPv6 literal needs its brackets
            // or the peer's SplitHostPort refuses the whole datagram.
            let address_bytes: Bytes = a.to_wire_string().into_bytes().into();
            let address_len = address_bytes.len();
            let address_len_bytes = encode_varint(address_len as u64)?;
            Some((address_bytes, address_len_bytes.into()))
        }
        None => None,
    };

    let mut next_packet_id: u16 = 0;
    let mut buf = allocate_vec(65535);
    let mut loop_count: u8 = 0;
    // The reply source address is serialized into every datagram header, but for
    // the common single-peer flow it never changes. Cache the encoded address and
    // its length varint so the steady state is a refcount bump, not a to_string()
    // plus a varint allocation per packet. Only used when there is no override.
    let mut cached_src: Option<(SocketAddr, Bytes, Bytes)> = None;

    loop {
        let (payload_len, src_addr) = match socket.try_recv_from(&mut buf) {
            Ok(res) => res,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        return Ok(());
                    }
                    result = socket.readable() => {
                        result?;
                        continue;
                    }
                }
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to receive from UDP socket: {e}"
                )));
            }
        };

        // A reply from the remote target keeps the session alive, so a download-only
        // flow (client silent, server streaming) is not reaped by the idle sweep.
        last_activity.store(activity_secs(), Ordering::Relaxed);

        // Yield periodically to allow quinn's internal tasks to run (keepalives, ACKs, etc.)
        // This prevents starvation during heavy UDP traffic.
        loop_count = loop_count.wrapping_add(1);
        if loop_count == 0 {
            tokio::task::yield_now().await;
        }

        let packet_id = next_packet_id;
        next_packet_id = next_packet_id.wrapping_add(1);

        let (address_bytes, address_len_bytes) = match original_address_bytes {
            Some((ref a, ref b)) => (a.clone(), b.clone()),
            None => {
                if cached_src.as_ref().is_none_or(|(a, _, _)| *a != src_addr) {
                    let address_bytes: Bytes = src_addr.to_string().into_bytes().into();
                    // no need to do a length check since this is a socket address and an IP.
                    let address_len_bytes: Bytes =
                        encode_varint(address_bytes.len() as u64)?.into();
                    cached_src = Some((src_addr, address_bytes, address_len_bytes));
                }
                let (_, a, b) = cached_src.as_ref().unwrap();
                (a.clone(), b.clone())
            }
        };

        // session_id(4) + packet_id(2) + fragment id(1) + fragment count(1) + address length varint + address bytes
        let header_overhead = 4 + 2 + 1 + 1 + address_len_bytes.len() + address_bytes.len();

        let (available_payload, fragment_count) =
            match fragment_plan(max_datagram_size, header_overhead, payload_len)? {
                FragmentPlan::Send {
                    available_payload,
                    fragment_count,
                } => (available_payload, fragment_count),
                FragmentPlan::TooManyFragments { needed } => {
                    // One reply the session cannot carry, not a session that
                    // cannot carry replies. Ending the loop here would leave the
                    // session in the map with its socket and no reply path, and
                    // the client's own traffic would keep refreshing its
                    // activity so the idle sweep never reaped it - a permanent
                    // one-way session, which is the leak this file just closed.
                    warn!(
                        "Dropping a {payload_len} byte reply for session {session_id}: it needs \
                         {needed} fragments, over the 255 the protocol allows"
                    );
                    continue;
                }
            };

        for fragment_id in 0..fragment_count {
            let start = (fragment_id as usize) * available_payload;
            let end = std::cmp::min(start + available_payload, payload_len);
            let mut datagram = BytesMut::with_capacity(header_overhead + (end - start));
            datagram.extend_from_slice(&session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&[fragment_id, fragment_count]);
            datagram.extend_from_slice(&address_len_bytes);
            datagram.extend_from_slice(&address_bytes);
            datagram.extend_from_slice(&buf[start..end]);

            connection.send_datagram(datagram.freeze()).map_err(|e| {
                std::io::Error::other(format!(
                    "Failed to send datagram fragment {fragment_id}: {e}"
                ))
            })?;
        }
    }
}

/// How often idle sessions are looked for, whether or not traffic is arriving.
///
/// Upstream runs a 1s ticker independent of the receive path
/// (`core/server/udp.go:277-288`). Ours used to sweep only at the top of the
/// receive loop, so a client that fell silent kept every session it had opened,
/// each with a socket and a parked task, until the connection ended.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

/// How long a session may go without traffic in either direction.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Drop every session that has been silent longer than `idle_timeout_secs`.
///
/// `now_secs` and the sessions' stored activity are both counts of whole
/// seconds since `ACTIVITY_EPOCH`, and the subtraction saturates: a stored
/// value ahead of `now_secs` reads as zero idle time rather than as an
/// enormous one.
fn sweep_idle_sessions(
    sessions: &mut FxHashMap<u32, UdpSession>,
    now_secs: u64,
    idle_timeout_secs: u64,
) {
    sessions.retain(|session_id, session| {
        let idle = now_secs.saturating_sub(session.last_activity.load(Ordering::Relaxed));
        if idle > idle_timeout_secs {
            // Dropping the session cancels its reply loop; see `Drop`.
            debug!("Removing inactive UDP session {session_id}");
            false
        } else {
            true
        }
    });
}

async fn run_udp_local_to_remote_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    cancel_token: CancellationToken,
) -> std::io::Result<()> {
    let mut resolver_cache = ResolverCache::new(resolver.clone());
    let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();

    let mut cleanup = tokio::time::interval(CLEANUP_INTERVAL);
    // The first tick of an interval completes immediately, and a sweep of an
    // empty map is not worth a branch to skip.
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let data = tokio::select! {
            _ = cleanup.tick() => {
                sweep_idle_sessions(&mut sessions, activity_secs(), IDLE_TIMEOUT.as_secs());
                continue;
            }
            // Cancel-safe: `ReadDatagram::poll` takes a datagram out of quinn's
            // queue only on the poll that returns Ready, and it checks that
            // queue before it registers for a notification
            // (`quinn-0.11.11/src/connection.rs:803-828`). Dropping the future
            // to serve a tick therefore cannot lose a datagram or a wakeup.
            data = connection.read_datagram() => {
                data.map_err(|err| {
                    std::io::Error::other(format!("failed to read datagram: {err}"))
                })?
            }
        };

        // Per official hysteria reference (server.go:332-353), parse errors are ignored
        // and we continue waiting for the next message. Only connection errors are fatal.
        if data.len() < 9 {
            debug!("Ignoring short datagram (len={})", data.len());
            continue;
        }
        let session_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let fragment_id = data[6];
        let fragment_count = data[7];

        let (address_len, next_index) = match decode_varint_slice(&data[8..]) {
            Some((value, consumed)) => (value as usize, 8 + consumed),
            None => {
                debug!("Ignoring datagram with a truncated address length");
                continue;
            }
        };

        if address_len == 0 {
            debug!("Ignoring packet with empty address");
            continue;
        }

        if address_len > MAX_ADDRESS_LEN as usize {
            debug!("Ignoring packet with address length {address_len}");
            continue;
        }

        if data.len() < next_index + address_len {
            debug!("Ignoring datagram with truncated address");
            continue;
        }
        let address_bytes = &data[next_index..next_index + address_len];
        let payload_fragment = data.slice(next_index + address_len..);

        let addr_str = match str::from_utf8(address_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!("Invalid UTF-8 in address: {e}");
                continue;
            }
        };

        let remote_location = match NetLocation::from_str(addr_str, None) {
            Ok(loc) => loc,
            Err(e) => {
                debug!("Failed to parse address '{addr_str}': {e}");
                continue;
            }
        };

        let mut session_entry = sessions.entry(session_id);
        let session = match session_entry {
            Entry::Vacant(entry) => {
                let action = client_proxy_selector
                    .judge(remote_location.clone().into(), &resolver)
                    .await;

                let (_chain_group, updated_location) = match action {
                    Ok(ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    }) => (chain_group, remote_location),
                    Ok(ConnectDecision::Block) => {
                        warn!("Blocked UDP forward to {remote_location}");
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to judge UDP forward to {remote_location}: {e}");
                        continue;
                    }
                };

                // the remote location specified at the beginning of a session is assumed
                // to be the remote location for the entire session iif it does not match
                // the resolved address, as per the official client - which is only if
                // it's a hostname. in our case, we also have to handle when the remote
                // location is replaced by a different location in the rules.
                //
                // it's possible that when we receive packets on the client socket,
                // it could be the resolved hostname versus what was initially provided,
                // and we need to write datagrams back to the user using their provided
                // address so that they know where it's from.
                //
                // it would be much simpler to always replace, or never, but we stick to
                // the official client behavior for now.
                //
                // ref: https://github.com/apernet/hysteria/blob/5520bcc405ee11a47c164c75bae5c40fc2b1d99d/core/server/udp.go#L137

                let resolved_address = match resolver_cache
                    .resolve_location(updated_location.location())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to resolve initial remote location {remote_location}: {e}");
                        continue;
                    }
                };

                let (override_remote_write_address, override_local_write_location) =
                    if resolved_address.to_string() != remote_location.to_string() {
                        (Some(resolved_address), Some(remote_location.clone()))
                    } else {
                        (None, None)
                    };

                // even if the remote location is ipv4, a future location could be ipv6.
                // TODO: the configured client socket is for the current remote_location, but
                // the remote_location could be changed later on with a different client_socket
                // configuration.
                // Use IPv6 dual-stack socket for direct UDP
                let client_socket = crate::socket_util::new_udp_socket(true, None)?;

                let session = UdpSession::start(
                    session_id,
                    connection.clone(),
                    Arc::new(client_socket),
                    remote_location.clone(),
                    resolved_address,
                    override_local_write_location,
                    override_remote_write_address,
                    &cancel_token,
                );
                entry.insert(session)
            }
            Entry::Occupied(ref mut entry) => entry.get_mut(),
        };

        // An inbound datagram from the client is activity for this session.
        session
            .last_activity
            .store(activity_secs(), Ordering::Relaxed);

        let (complete_payload, remote_location) = if fragment_count == 0 {
            error!("Ignoring empty UDP fragment for session {session_id}");
            continue;
        } else if fragment_id >= fragment_count {
            // fragment_id indexes a slot vec of length fragment_count below;
            // both fields are peer-supplied, so an out-of-range id would panic.
            error!("Ignoring out-of-range UDP fragment for session {session_id}");
            continue;
        } else if fragment_count == 1 {
            // Returns before the reassembler is touched, so an unfragmented
            // packet cannot clear the pending location out from under a
            // fragmented one that is still arriving.
            (payload_fragment, remote_location)
        } else {
            // A fragment that restarts assembly starts a new packet, and the
            // address it carries is the one that whole packet goes to. The
            // reassembler is asked rather than told: the same id with a
            // different count restarts it too, and comparing only ids here
            // would forward the packet to the address of an abandoned one.
            if session
                .fragments
                .starts_new_packet(packet_id, fragment_count)
            {
                session.pending_location = Some(remote_location.clone());
            }
            match session
                .fragments
                .push(packet_id, fragment_id, fragment_count, &payload_fragment)
            {
                Some(packet) => {
                    // Emptied on completion, so the next fragment of a new
                    // packet is always seen as starting one.
                    let location = session.pending_location.take().unwrap_or(remote_location);
                    (Bytes::from(packet), location)
                }
                None => continue,
            }
        };

        let socket_addr = match session.override_remote_write_address {
            Some(addr) => addr,
            None => {
                if remote_location == session.last_location {
                    session.last_socket_addr
                } else {
                    warn!(
                        "Location changed during ongoing UDP session: {}",
                        remote_location.clone()
                    );
                    let action = client_proxy_selector
                        .judge(remote_location.clone().into(), &resolver)
                        .await;
                    let updated_location = match action {
                        Ok(ConnectDecision::Allow {
                            chain_group: _,
                            remote_location,
                        }) => remote_location,
                        Ok(ConnectDecision::Block) => {
                            warn!("Blocked UDP forward to {remote_location}");
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to judge UDP forward to {remote_location}: {e}");
                            continue;
                        }
                    };
                    let updated_socket_addr = match resolver_cache
                        .resolve_location(updated_location.location())
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                "Failed to resolve updated remote location {}: {e}",
                                updated_location.location()
                            );
                            continue;
                        }
                    };
                    session.last_location = updated_location.into_location();
                    session.last_socket_addr = updated_socket_addr;
                    updated_socket_addr
                }
            }
        };

        // send_socket is dual-stack IPv6, so an IPv4 target must be sent as an
        // IPv4-mapped address (a bare v4 destination fails with EINVAL on macOS/BSD).
        let socket_addr = crate::socket_util::dual_stack_dest(socket_addr);
        if let Err(e) = session
            .send_socket
            .send_to(&complete_payload, socket_addr)
            .await
        {
            error!("Failed to forward UDP payload for session {session_id}: {e}");
            // Removing it drops it, and dropping it cancels its reply loop.
            sessions.remove(&session_id);
        }
    }
}

async fn run_tcp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                break;
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "failed to accept bidirectional stream: {e}"
                )));
            }
        };

        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) =
                process_tcp_stream(client_proxy_selector, resolver, send_stream, recv_stream).await
            {
                error!("Failed to process streams: {e}");
            }
        });
    }
    Ok(())
}

/// Read the client's TCP request.
///
/// Deliberately writes nothing back. The response carries a status and a
/// message and there is nothing truthful to put in either until the dial has
/// resolved, which is what upstream does too
/// (`core/server/server.go:310-324`).
async fn handle_tcp_header(
    recv: &mut quinn::RecvStream,
) -> std::io::Result<(NetLocation, StreamReader)> {
    let mut stream_reader = StreamReader::new_with_buffer_size(8192);

    // Read the TCP request frame type as a QUIC varint per protocol spec.
    // The value 0x401 can be encoded in multiple valid ways (e.g., [0x44, 0x01] as 2-byte form).
    let tcp_request_id = read_varint(recv, &mut stream_reader).await?;
    if tcp_request_id != FRAME_TYPE_TCP_REQUEST {
        return Err(std::io::Error::other(format!(
            "invalid tcp request id: expected {:#x}, got {:#x}",
            FRAME_TYPE_TCP_REQUEST, tcp_request_id
        )));
    }

    let address_len = read_varint(recv, &mut stream_reader).await?;
    if address_len > MAX_ADDRESS_LEN {
        return Err(std::io::Error::other("invalid address length"));
    }
    let address_bytes = stream_reader.read_slice(recv, address_len as usize).await?;
    let address = std::str::from_utf8(address_bytes)
        .map_err(|e| std::io::Error::other(format!("invalid address encoding: {e}")))?;
    let remote_location = NetLocation::from_str(address, None)?;

    let padding_len = read_varint(recv, &mut stream_reader).await?;
    if padding_len > MAX_PADDING_LEN {
        return Err(std::io::Error::other("invalid padding length"));
    }
    stream_reader.read_slice(recv, padding_len as usize).await?;

    Ok((remote_location, stream_reader))
}

/// What the client is told about a dial that failed.
///
/// Upstream returns the dial error's own text (`core/server/server.go:313`),
/// and for a server that only ever dials directly that is the same thing as
/// this. Ours can dial through a chain, and those errors name the upstream hop:
/// `LiveConnection`'s "no resolved address for {server} could be connected"
/// carries the address of the next proxy. A client asking for a target has no
/// business learning our topology from a failure, so it gets the kind, and the
/// operator's log keeps the rest.
fn refusal_reason(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "connection refused",
        TimedOut => "timed out",
        HostUnreachable | NetworkUnreachable | AddrNotAvailable => "unreachable",
        NotFound => "no such host",
        PermissionDenied => "not permitted",
        _ => "connection failed",
    }
}

/// Answer the client's TCP request, once the outcome is actually known.
async fn write_tcp_response(
    stream: &mut Box<dyn AsyncStream>,
    outcome: Result<(), &str>,
) -> std::io::Result<()> {
    let response = encode_tcp_response(outcome, &random_padding())?;
    stream.write_all(&response).await?;
    stream.flush().await
}

async fn process_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    let (remote_location, stream_reader) = match handle_tcp_header(&mut recv).await {
        Ok(res) => res,
        Err(e) => {
            let _ = send.shutdown().await;
            return Err(e);
        }
    };

    let mut server_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));

    // `connect_client_tcp_stream`, not `setup_client_tcp_stream`: the latter
    // writes the chain's early data into the requester's stream as soon as it
    // has it, which here would put the target's first bytes *in front of* our
    // response. The client would then parse the target's greeting as a status
    // byte and a message length. The early data is written below, after the
    // response it belongs behind.
    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        connect_client_tcp_stream(
            client_proxy_selector,
            resolver,
            remote_location.clone().into(),
        ),
    );

    // Every arm below answers before it gives up. A client that is told
    // nothing sees a stream that opened and closed, and cannot tell a refused
    // target from a server that fell over.
    let (mut client_stream, early_data) = match setup_client_stream_future.await {
        Ok(Ok(Some(pair))) => pair,
        Ok(Ok(None)) => {
            // Must have been blocked. The rule that blocked it is ours and
            // stays ours; the client is told the request was refused.
            let _ = write_tcp_response(&mut server_stream, Err("connection not permitted")).await;
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = write_tcp_response(&mut server_stream, Err(refusal_reason(&e))).await;
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = write_tcp_response(&mut server_stream, Err("timed out")).await;
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    write_tcp_response(&mut server_stream, Ok(())).await?;

    // Now, and not before: these are the target's bytes and they belong behind
    // the response.
    if let Some(data) = early_data {
        server_stream.write_all(&data).await?;
        server_stream.flush().await?;
    }

    let unparsed_data = stream_reader.unparsed_data();
    let client_requires_flush = if unparsed_data.is_empty() {
        false
    } else {
        let len = unparsed_data.len();
        let mut i = 0;
        while i < len {
            let count = client_stream
                .write(&unparsed_data[i..len])
                .await
                .map_err(|e| std::io::Error::other(format!("H3 stream write failed: {e}")))?;
            i += count;
        }
        true
    };
    drop(stream_reader);

    // Use 32KB buffers to match hysteria2/sing-box reference implementations
    let copy_result = copy_bidirectional_with_sizes(
        &mut server_stream,
        &mut client_stream,
        // no need to flush even through we wrote this response since it's quic
        false,
        client_requires_flush,
        32768,
        32768,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

pub async fn start_hysteria2_server(
    listener: QuicListenerSettings,
    hysteria2_password: &'static str,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    udp_enabled: bool,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let params = QuicTransportParams {
        max_concurrent_bidi_streams: 4096,
        // HTTP/3 QPACK updates arrive on client-opened uni streams.
        max_concurrent_uni_streams: 1024,
        max_idle_timeout: Duration::from_secs(30),
        keep_alive_interval: Duration::from_secs(10),
        mtu: effective_mtu(listener.obfs.as_ref().map(|o| o.overhead())),
        enable_segmentation_offload: listener.obfs.is_none(),
    };

    start_quic_listeners(listener, params, move |conn| {
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        async move {
            process_connection(
                client_proxy_selector,
                resolver,
                hysteria2_password,
                conn,
                udp_enabled,
            )
            .await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_request(password: &str) -> http::Request<()> {
        http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", password)
            .body(())
            .unwrap()
    }

    /// The one divergence in this round that has no fix available: quinn
    /// refuses to send datagrams to a peer that omitted
    /// `max_datagram_frame_size` and offers no way to assume one. What is
    /// within reach is that the operator can tell this apart from a session
    /// that is merely idle, so the diagnosis is pinned here against being
    /// quietly shortened back to "datagram not supported by remote endpoint".
    ///
    /// The last assertion is there because the first version of this message
    /// said "every official Hysteria2 client omits it", which a live run
    /// disproved: Chrome parroting makes the stock client advertise it.
    #[test]
    fn test_a_peer_that_cannot_take_datagrams_is_named_as_the_cause() {
        let message = no_datagram_support(7).to_string();
        assert!(message.contains("session 7"), "{message}");
        assert!(message.contains("max_datagram_frame_size"), "{message}");
        assert!(
            message.contains("never reply"),
            "the consequence has to be in the message, not just the cause: {message}"
        );
        assert!(
            message.contains("Chrome parroting disabled"),
            "the message must name the narrow case, not blame every client: {message}"
        );
    }

    /// `0` does not mean "we are not rate limiting you". PROTOCOL.md defines it
    /// as "no bandwidth limit; the client MAY transmit at any rate", and an
    /// official client reading it falls through to fixed-rate Brutal
    /// congestion control at whatever `up:` it was configured with
    /// (`core/client/client.go:156-162`) - against a server running ordinary
    /// congestion control, because we never read the client's declared
    /// bandwidth and never install Brutal ourselves.
    ///
    /// `auto` is the value for exactly that case, and it is what upstream sends
    /// when the server ignores the client's rate
    /// (`core/server/server.go:172,206`).
    #[test]
    fn test_the_server_asks_the_client_to_run_its_own_congestion_control() {
        let response = auth_response(true);
        assert_eq!(response.headers()["Hysteria-CC-RX"], "auto");
    }

    #[test]
    fn test_the_auth_response_reports_whether_udp_is_available() {
        assert_eq!(auth_response(true).headers()["Hysteria-UDP"], "true");
        assert_eq!(auth_response(false).headers()["Hysteria-UDP"], "false");
    }

    /// 233 is the protocol's success status, chosen precisely because it is not
    /// a status any ordinary web server would answer with.
    #[test]
    fn test_the_auth_response_carries_the_protocol_status_and_padding() {
        let response = auth_response(true);
        assert_eq!(response.status().as_u16(), 233);
        assert!(!response.headers()["Hysteria-Padding"].is_empty());
    }

    #[test]
    fn test_auth_accepts_the_configured_password() {
        assert!(validate_auth_request(auth_request("hunter2"), "hunter2").is_ok());
    }

    #[test]
    fn test_auth_rejects_a_wrong_password() {
        assert!(validate_auth_request(auth_request("wrong"), "hunter2").is_err());
    }

    #[test]
    fn test_auth_rejects_a_prefix_of_the_password() {
        // A comparison that stopped at the first difference would take longer
        // for this than for a password differing in byte one; the rejection
        // itself is what this pins.
        assert!(validate_auth_request(auth_request("hunter"), "hunter2").is_err());
        assert!(validate_auth_request(auth_request("hunter23"), "hunter2").is_err());
    }

    /// A rejection must not repeat what was sent. The attempt may well be a
    /// valid credential for somewhere else, and it ends up in the log either
    /// way.
    #[test]
    fn test_auth_rejection_does_not_echo_the_credential() {
        let err = validate_auth_request(auth_request("s3cret-elsewhere"), "hunter2")
            .unwrap_err()
            .to_string();
        assert!(
            !err.contains("s3cret-elsewhere"),
            "the error repeated the presented credential: {err}"
        );
    }

    #[test]
    fn test_auth_rejects_a_missing_header() {
        let request = http::Request::post("https://hysteria/auth")
            .body(())
            .unwrap();
        assert!(validate_auth_request(request, "hunter2").is_err());
    }

    #[test]
    fn test_auth_rejects_the_wrong_uri_and_method() {
        let wrong_uri = http::Request::post("https://hysteria/other")
            .header("Hysteria-Auth", "hunter2")
            .body(())
            .unwrap();
        assert!(validate_auth_request(wrong_uri, "hunter2").is_err());

        let wrong_method = http::Request::get("https://hysteria/auth")
            .header("Hysteria-Auth", "hunter2")
            .body(())
            .unwrap();
        assert!(validate_auth_request(wrong_method, "hunter2").is_err());
    }

    /// Build a session with no connection behind it. `UdpSession::start` needs
    /// a live quinn connection to spawn its reply loop; nothing here does.
    async fn detached_session(parent: &CancellationToken, idle_since_secs: u64) -> UdpSession {
        let socket = crate::socket_util::new_udp_socket(true, None).unwrap();
        let location = NetLocation::from_str("127.0.0.1:9", None).unwrap();
        UdpSession {
            fragments: Defragmenter::new(),
            pending_location: None,
            send_socket: Arc::new(socket),
            last_location: location,
            last_socket_addr: "127.0.0.1:9".parse().unwrap(),
            override_remote_write_address: None,
            last_activity: Arc::new(AtomicU64::new(idle_since_secs)),
            cancel_token: parent.child_token(),
        }
    }

    /// The reply loop holds a UDP socket and parks on `recv_from` forever; the
    /// only thing that ends it is its token. Dropping the session is therefore
    /// the last moment anything can cancel it, so that is where the cancel
    /// goes - not in each of the callers that happen to remove a session today.
    #[tokio::test]
    async fn test_dropping_a_session_cancels_its_reply_loop() {
        let parent = CancellationToken::new();
        let session = detached_session(&parent, 0).await;
        let token = session.cancel_token.clone();

        assert!(!token.is_cancelled());
        drop(session);
        assert!(
            token.is_cancelled(),
            "a dropped session must not leave its task parked on a socket"
        );
    }

    /// The path that had the bug: a failed `send_to` removes the session from
    /// the map, and that removal must end the task like every other one.
    #[tokio::test]
    async fn test_removing_a_session_from_the_map_cancels_it() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        sessions.insert(1, detached_session(&parent, 0).await);
        let token = sessions.get(&1).unwrap().cancel_token.clone();

        sessions.remove(&1);

        assert!(
            token.is_cancelled(),
            "removal is how the send-failure path drops a session"
        );
    }

    /// Extracted from the receive loop so it can be tested at all: while it
    /// lived inside `run_udp_local_to_remote_loop` the only way to reach it was
    /// a live quinn connection, which is why it went without one.
    #[tokio::test]
    async fn test_the_sweep_removes_only_the_idle_session() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        // now = 1000, timeout = 60: session 1 last spoke at 900, session 2 at 990.
        sessions.insert(1, detached_session(&parent, 900).await);
        sessions.insert(2, detached_session(&parent, 990).await);
        let idle_token = sessions.get(&1).unwrap().cancel_token.clone();
        let live_token = sessions.get(&2).unwrap().cancel_token.clone();

        sweep_idle_sessions(&mut sessions, 1000, 60);

        assert!(!sessions.contains_key(&1), "100s idle is past the timeout");
        assert!(sessions.contains_key(&2), "10s idle is well inside it");
        assert!(
            idle_token.is_cancelled(),
            "the reaped session must be ended"
        );
        assert!(!live_token.is_cancelled(), "the live one must be untouched");
    }

    /// A clock that has not yet passed the timeout must not reap anything - the
    /// subtraction runs on a monotonic epoch and saturates rather than wrapping.
    #[tokio::test]
    async fn test_the_sweep_keeps_a_session_whose_activity_is_in_the_future() {
        let parent = CancellationToken::new();
        let mut sessions: FxHashMap<u32, UdpSession> = FxHashMap::default();
        sessions.insert(1, detached_session(&parent, 5000).await);

        sweep_idle_sessions(&mut sessions, 1000, 60);

        assert!(sessions.contains_key(&1));
    }

    /// Both operands come from the peer: the datagram size it advertised, and
    /// the length of the address it asked us to reply from. A peer must not be
    /// able to choose a pair of them that aborts the process.
    #[test]
    fn test_a_header_that_does_not_fit_the_datagram_is_an_error_not_a_panic() {
        let err = fragment_plan(64, 64, 100).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("64"), "both sizes belong in it: {message}");

        let err = fragment_plan(64, 200, 100).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
    }

    /// The protocol counts fragments in one byte. A payload needing more than
    /// 255 of them cannot be sent, and must not be sent as a wrapped count -
    /// which would tell the receiver to expect a few and then hand it fragment
    /// ids past the number it was given.
    ///
    /// It comes back as a value rather than an error because it is a property
    /// of one reply. Making it an `Err` ends the session's reply loop while the
    /// session stays in the map, and the client's own traffic keeps its
    /// activity fresh, so the idle sweep never reaps it: a permanent one-way
    /// session holding a socket. Upstream drops the packet and carries on.
    #[test]
    fn test_a_payload_needing_more_than_255_fragments_is_dropped_not_fatal() {
        // 10 bytes of payload per fragment, 65535 bytes to send: 6554 fragments.
        assert_eq!(
            fragment_plan(60, 50, 65535).unwrap(),
            FragmentPlan::TooManyFragments { needed: 6554 }
        );
    }

    fn sends(max_datagram_size: usize, header_overhead: usize, payload_len: usize) -> (usize, u8) {
        match fragment_plan(max_datagram_size, header_overhead, payload_len).unwrap() {
            FragmentPlan::Send {
                available_payload,
                fragment_count,
            } => (available_payload, fragment_count),
            other => panic!("expected a sendable plan, got {other:?}"),
        }
    }

    #[test]
    fn test_a_payload_that_fits_one_datagram_is_one_fragment() {
        assert_eq!(sends(1200, 200, 500), (1000, 1));
        // Exactly filling it is still one fragment.
        assert_eq!(sends(1200, 200, 1000), (1000, 1));
        // One byte over is two.
        assert_eq!(sends(1200, 200, 1001), (1000, 2));
    }

    /// A zero-length UDP packet is a packet. `div_ceil` gives zero fragments
    /// for it, which would drop it silently, so the count floors at one.
    #[test]
    fn test_an_empty_payload_still_takes_one_fragment() {
        assert_eq!(sends(1200, 200, 0), (1000, 1));
    }

    #[test]
    fn test_the_largest_sendable_payload_is_accepted() {
        // 255 fragments of 1000 bytes is exactly the limit.
        assert_eq!(sends(1200, 200, 255_000), (1000, 255));
        assert_eq!(
            fragment_plan(1200, 200, 255_001).unwrap(),
            FragmentPlan::TooManyFragments { needed: 256 },
            "one byte past the limit is a dropped reply, not a dead session"
        );
    }
}
