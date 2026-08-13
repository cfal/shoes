use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(unix)]
use std::mem::ManuallyDrop;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_family = "unix")]
use std::path::Path;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Create an outbound UDP socket.
///
/// Excluded from the VPN route where a protector is installed — see
/// [`crate::socket_protector`]. Every caller of this function dials outward,
/// which is why the protection lives here rather than at each of them. The
/// socket2 constructors below are the listener-side primitives and are left
/// alone; an outbound built on one of those has to protect itself.
pub fn new_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = new_socket2_udp_socket(
        is_ipv6,
        bind_interface,
        Some(get_unspecified_socket_addr(is_ipv6)),
        false,
    )?;

    protect_outbound(&socket)?;

    into_tokio_udp_socket(socket)
}

/// Exclude a socket from the VPN route before it carries anything.
///
/// Binding is harmless; sending is not, so this runs after construction and
/// before the socket is handed back. Exposed for the few outbound paths that
/// build their socket themselves rather than through the constructors here.
pub(crate) fn protect_outbound<S>(socket: &S) -> std::io::Result<()>
where
    S: AsRawFdCompat,
{
    crate::socket_protector::protect_socket(socket.raw_fd())
}

/// The one thing `protect_outbound` needs from a socket, across platforms.
pub(crate) trait AsRawFdCompat {
    #[cfg(unix)]
    fn raw_fd(&self) -> std::os::fd::RawFd;
    #[cfg(not(unix))]
    fn raw_fd(&self) -> i32;
}

#[cfg(unix)]
impl<S: AsRawFd> AsRawFdCompat for S {
    fn raw_fd(&self) -> std::os::fd::RawFd {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S: std::os::windows::io::AsRawSocket> AsRawFdCompat for S {
    fn raw_fd(&self) -> i32 {
        self.as_raw_socket() as i32
    }
}

fn get_unspecified_socket_addr(is_ipv6: bool) -> SocketAddr {
    if !is_ipv6 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
    } else {
        "[::]:0".parse().unwrap()
    }
}

pub fn new_socket2_udp_socket(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
) -> std::io::Result<socket2::Socket> {
    new_socket2_udp_socket_with_buffer_size(is_ipv6, bind_interface, bind_address, reuse_port, None)
}

pub fn new_socket2_udp_socket_with_buffer_size(
    is_ipv6: bool,
    bind_interface: Option<String>,
    bind_address: Option<SocketAddr>,
    reuse_port: bool,
    buffer_size: Option<usize>,
) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;

    // Set socket buffer sizes if specified.
    // This helps prevent packet drops during bursts for high-throughput connections.
    if let Some(size) = buffer_size {
        // Ignore errors - kernel may cap the value
        let _ = socket.set_recv_buffer_size(size);
        let _ = socket.set_send_buffer_size(size);
    }

    if reuse_port {
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;

        #[cfg(any(not(unix), target_os = "solaris", target_os = "illumos"))]
        panic!("Cannot support reuse sockets");
    }

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    if let Some(bind_address) = bind_address {
        socket.bind(&SockAddr::from(bind_address))?;
    }

    Ok(socket)
}

fn into_tokio_udp_socket(socket: socket2::Socket) -> std::io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        let raw_fd = socket.into_raw_fd();
        let std_udp_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
    #[cfg(windows)]
    {
        let std_udp_socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(std_udp_socket)
    }
}

/// Create an outbound TCP socket.
///
/// Excluded from the VPN route where a protector is installed, for the reason
/// given on [`new_udp_socket`].
pub fn new_tcp_socket(
    bind_interface: Option<String>,
    is_ipv6: bool,
) -> std::io::Result<tokio::net::TcpSocket> {
    let tcp_socket = if is_ipv6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };

    if let Some(_b) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        tcp_socket.bind_device(Some(_b.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    protect_outbound(&tcp_socket)?;

    Ok(tcp_socket)
}

#[cfg(test)]
mod protection_tests {
    use super::*;
    use crate::socket_protector::{SocketProtector, protect_socket, set_global_socket_protector};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

    /// The protector is process-wide, so these tests take turns. Without this
    /// one test's recorder replaces another's between its install and its
    /// socket, and the assertion fails for a reason that has nothing to do
    /// with the code under test.
    fn serialise() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK.get_or_init(|| Mutex::new(()));
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Both protectors below act only for the thread that installed them.
    ///
    /// The protector is process-wide, but the rest of the suite runs in
    /// parallel and creates sockets of its own. A recorder that logged those
    /// would make its own assertions ambiguous, and a refuser that failed them
    /// would break unrelated tests — which it did, intermittently, before this
    /// guard existed. A test body runs on its own thread, so this scopes the
    /// effect to exactly the sockets the test created.
    fn is_our_thread(owner: std::thread::ThreadId) -> bool {
        std::thread::current().id() == owner
    }

    struct Recorder {
        owner: std::thread::ThreadId,
        seen: Mutex<Vec<i32>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                owner: std::thread::current().id(),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn saw(&self, fd: i32) -> bool {
            self.seen.lock().unwrap().contains(&fd)
        }
    }

    impl SocketProtector for Recorder {
        fn protect(&self, fd: i32) -> std::io::Result<()> {
            if is_our_thread(self.owner) {
                self.seen.lock().unwrap().push(fd);
            }
            Ok(())
        }
    }

    struct Refuser {
        owner: std::thread::ThreadId,
    }

    impl Refuser {
        fn new() -> Self {
            Self {
                owner: std::thread::current().id(),
            }
        }
    }

    impl SocketProtector for Refuser {
        fn protect(&self, _fd: i32) -> std::io::Result<()> {
            if is_our_thread(self.owner) {
                Err(std::io::Error::other("the platform refused to protect it"))
            } else {
                Ok(())
            }
        }
    }

    fn install<P: SocketProtector + 'static>(protector: P) -> Arc<P> {
        let protector = Arc::new(protector);
        set_global_socket_protector(protector.clone());
        protector
    }

    /// Restore the unprotected state other tests expect to find.
    fn uninstall() {
        set_global_socket_protector(Arc::new(crate::socket_protector::NoOpSocketProtector));
    }

    #[test]
    fn test_outbound_tcp_socket_is_protected() {
        let _guard = serialise();
        let recorder = install(Recorder::new());

        let socket = new_tcp_socket(None, false).unwrap();
        let fd = socket.as_raw_fd();

        assert!(
            recorder.saw(fd),
            "an outbound TCP socket must be excluded from the VPN route"
        );
        uninstall();
    }

    // new_udp_socket hands the socket to tokio, which needs a reactor.
    #[tokio::test]
    async fn test_outbound_udp_socket_is_protected() {
        let _guard = serialise();
        let recorder = install(Recorder::new());

        let socket = new_udp_socket(false, None).unwrap();
        let fd = socket.as_raw_fd();

        assert!(
            recorder.saw(fd),
            "an outbound UDP socket must be excluded from the VPN route"
        );
        uninstall();
    }

    /// A socket the platform would not protect is one whose traffic re-enters
    /// the tunnel. Handing it back would be worse than failing.
    #[tokio::test]
    async fn test_a_refused_protection_fails_socket_creation() {
        let _guard = serialise();
        install(Refuser::new());

        assert!(new_tcp_socket(None, false).is_err());
        assert!(new_udp_socket(false, None).is_err());

        uninstall();
    }

    #[test]
    fn test_protection_is_a_no_op_without_a_protector() {
        let _guard = serialise();
        // Whatever ran before, prove the unset path is harmless.
        assert!(protect_socket(-1).is_ok());
        assert!(new_tcp_socket(None, false).is_ok());
    }
}

pub fn set_tcp_keepalive(
    tcp_stream: &tokio::net::TcpStream,
    idle_time: std::time::Duration,
    send_interval: std::time::Duration,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let raw_fd = tcp_stream.as_raw_fd();
        let socket2_socket = ManuallyDrop::new(unsafe { Socket::from_raw_fd(raw_fd) });
        if idle_time.is_zero() && send_interval.is_zero() {
            socket2_socket.set_keepalive(false)?;
        } else {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(idle_time)
                .with_interval(send_interval);
            socket2_socket.set_keepalive(true)?;
            socket2_socket.set_tcp_keepalive(&keepalive)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = (tcp_stream, idle_time, send_interval);
        Ok(())
    }
}

// TODO: change backlog to Option<u32> and make configuration, backlog -1 uses somaxconn on linux
// https://github.com/rust-lang/rust/blob/3534594029ed1495290e013647a1f53da561f7f1/library/std/src/os/unix/net/listener.rs#L93
pub fn new_tcp_listener(
    bind_address: SocketAddr,
    backlog: u32,
    bind_interface: Option<String>,
) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if bind_address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    if let Some(ref interface) = bind_interface {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        socket.bind_device(Some(interface.as_bytes()))?;

        // This should be handled during config validation.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        panic!("Could not bind to device, unsupported platform.")
    }

    socket.bind(&SockAddr::from(bind_address))?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(target_family = "unix")]
pub fn new_unix_listener<P: AsRef<Path>>(
    path: P,
    backlog: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    let path = path.as_ref();

    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;

    let addr = SockAddr::unix(path)?;
    socket.bind(&addr)?;

    let backlog = backlog.try_into().unwrap_or(4096);
    socket.listen(backlog)?;

    let std_listener: std::os::unix::net::UnixListener = socket.into();
    tokio::net::UnixListener::from_std(std_listener)
}
