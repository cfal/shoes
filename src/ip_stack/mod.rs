use log::{error, trace};
use smoltcp::{
    iface::SocketHandle,
    socket::tcp::{CongestionControl, Socket as TcpSocket, SocketBuffer, State as TcpState},
    time::{Duration as SmolDuration, Instant as SmolInstant},
};
use tcp_conn::{TcpConnectionControl, TcpSocketState};

pub(crate) mod driver;
pub(crate) mod packet;
pub(crate) mod tcp_conn;
#[cfg(test)]
pub(crate) mod test_gate;
#[cfg(test)]
mod tests;
pub(crate) mod udp;
pub(crate) mod wake;

// Matches Linux tcp_keepalive_time and shadowsocks-rust.
const TCP_PEER_SILENCE_TIMEOUT: SmolDuration = SmolDuration::from_secs(7200);
// Bounds orphaned FIN exchanges independently of traffic refreshing smoltcp's silence timer.
const TCP_ORPHAN_TIMEOUT: SmolDuration = SmolDuration::from_secs(60);

pub(crate) fn tcp_poll_delay<'a>(
    now: SmolInstant,
    stack_delay: Option<SmolDuration>,
    controls: impl Iterator<Item = &'a TcpConnectionControl>,
) -> Option<SmolDuration> {
    controls
        .filter_map(TcpConnectionControl::orphan_deadline)
        .map(|deadline| deadline.max(now) - now)
        .chain(stack_delay)
        .min()
}

pub(crate) fn tcp_socket(buffer_size: usize) -> TcpSocket<'static> {
    let mut socket = TcpSocket::new(
        SocketBuffer::new(vec![0; buffer_size]),
        SocketBuffer::new(vec![0; buffer_size]),
    );
    // Matches netstack-smoltcp's congestion and keepalive settings.
    socket.set_congestion_control(CongestionControl::Cubic);
    socket.set_keep_alive(Some(SmolDuration::from_secs(28)));
    socket.set_timeout(Some(TCP_PEER_SILENCE_TIMEOUT));
    socket.set_nagle_enabled(false);
    socket.set_ack_delay(None);
    socket
}

pub(crate) fn pump_tcp(
    handle: SocketHandle,
    socket: &mut TcpSocket<'_>,
    control: &TcpConnectionControl,
    now: SmolInstant,
) {
    if let Some(deadline) = control.orphan_deadline() {
        // A completed write shutdown must finish its FIN exchange, unless unread data is discarded.
        if now >= deadline || control.should_abort() || socket.can_recv() {
            socket.abort();
        } else {
            socket.set_keep_alive(None);
            socket.close();
        }
        return;
    }

    if socket.state() == TcpState::Closed {
        return;
    }

    // Waits for both send queues to drain before scheduling FIN.
    if control.send_state() == TcpSocketState::Close
        && socket.send_queue() == 0
        && control.send_buffer_empty()
    {
        trace!(
            "socket {:?}: closing write half, state={:?}",
            handle,
            socket.state()
        );
        socket.close();
        control.set_send_state(TcpSocketState::Closing);
        control.wake_sender();
    }

    let mut wake_receiver = false;
    while socket.can_recv() && !control.recv_buffer_full() {
        match socket.recv(|data| {
            let n = control.enqueue_recv_data(data);
            (n, n)
        }) {
            Ok(n) if n > 0 => {
                wake_receiver = true;
            }
            Ok(_) => break,
            Err(e) => {
                error!(
                    "socket {:?} recv error: {:?}, state={:?}",
                    handle,
                    e,
                    socket.state()
                );
                socket.abort();
                if control.recv_state() == TcpSocketState::Normal {
                    control.set_recv_state(TcpSocketState::Closed);
                }
                wake_receiver = true;
                break;
            }
        }
    }

    if control.recv_state() == TcpSocketState::Normal
        && !socket.may_recv()
        && !matches!(
            socket.state(),
            TcpState::Listen
                | TcpState::SynSent
                | TcpState::SynReceived
                | TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
        )
    {
        trace!(
            "socket {:?}: recv half closed, state={:?}",
            handle,
            socket.state()
        );
        control.set_recv_state(TcpSocketState::Closed);
        wake_receiver = true;
    }

    if wake_receiver {
        control.wake_receiver();
    }

    let mut wake_sender = false;
    while socket.can_send() && !control.send_buffer_empty() {
        match socket.send(|buf| {
            let n = control.dequeue_send_data(buf);
            (n, n)
        }) {
            Ok(n) if n > 0 => {
                wake_sender = true;
            }
            Ok(_) => break,
            Err(e) => {
                error!(
                    "socket {:?} send error: {:?}, state={:?}",
                    handle,
                    e,
                    socket.state()
                );
                socket.abort();
                if control.send_state() == TcpSocketState::Normal {
                    control.set_send_state(TcpSocketState::Closed);
                }
                wake_sender = true;
                break;
            }
        }
    }

    if wake_sender {
        control.wake_sender();
    }
}
