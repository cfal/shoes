use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::test]
async fn shutdown_tolerates_an_already_disconnected_socket() {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_nonblocking(true).unwrap();
    let stream = TcpStream::from_std(socket.into()).unwrap();
    assert_eq!(
        socket2::SockRef::from(&stream)
            .shutdown(Shutdown::Write)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    shutdown_write(&stream).unwrap();
}

async fn pair(ipv6: bool) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let client = client.unwrap();
    let server = server.unwrap().0;
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server)
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8 ^ seed)
        .collect()
}

async fn exchange(mut socket: TcpStream, send: &[u8], expected: &[u8]) {
    let (mut reader, mut writer) = socket.split();
    let ((), data) = tokio::join!(
        async {
            writer.write_all(send).await.unwrap();
            writer.shutdown().await.unwrap();
        },
        async {
            let mut data = Vec::new();
            reader.read_to_end(&mut data).await.unwrap();
            data
        }
    );
    assert_eq!(data, expected);
}

#[tokio::test]
async fn duplex_and_half_closes_ipv4_ipv6() {
    for ipv6 in [false, true] {
        for (left_size, right_size) in [(0, 400_003), (400_003, 0), (2_000_003, 3_000_007)] {
            let (left, a) = pair(ipv6).await;
            let (b, right) = pair(ipv6).await;
            let up = payload(left_size, 17);
            let down = payload(right_size, 239);
            timeout(Duration::from_secs(10), async {
                let (result, (), ()) = tokio::join!(
                    copy_bidirectional(&a, &b),
                    exchange(left, &up, &down),
                    exchange(right, &down, &up)
                );
                result.unwrap();
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn response_after_request_eof() {
    let (mut left, a) = pair(false).await;
    let (b, mut right) = pair(false).await;
    timeout(Duration::from_secs(10), async {
        let (result, (), ()) = tokio::join!(
            copy_bidirectional(&a, &b),
            async {
                left.write_all(b"request").await.unwrap();
                left.shutdown().await.unwrap();
                let mut reply = Vec::new();
                left.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"response");
            },
            async {
                let mut request = Vec::new();
                right.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"request");
                tokio::time::sleep(Duration::from_millis(30)).await;
                right.write_all(b"response").await.unwrap();
                right.shutdown().await.unwrap();
            }
        );
        result.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn saturated_pipe_budget_falls_back_and_recovers() {
    if std::env::var_os("SHOES_SPLICE_SATURATION_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "splice::tests::saturated_pipe_budget_falls_back_and_recovers",
                "--nocapture",
            ])
            .env("SHOES_SPLICE_SATURATION_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    struct Saturated(AtomicUsize);
    impl Operations for Saturated {
        fn pipe(&self) -> io::Result<Pipe> {
            self.0.fetch_add(1, Ordering::Relaxed);
            let error = Pipe::new().err().expect("pipe budget was not exhausted");
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            Err(error)
        }

        fn splice(&self, _: RawFd, _: RawFd, _: usize) -> io::Result<usize> {
            panic!("saturated relay must use buffered I/O");
        }
    }

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            assert_eq!(PIPE_BUDGET.available_permits(), 128);
            let pipes: Vec<_> = (0..128).map(|_| Pipe::new().unwrap()).collect();
            let descriptors: Vec<_> = pipes
                .iter()
                .flat_map(|pipe| [pipe.read.as_raw_fd(), pipe.write.as_raw_fd()])
                .collect();
            assert_eq!(PIPE_BUDGET.available_permits(), 0);
            assert_eq!(Pipe::new().err().unwrap().kind(), io::ErrorKind::WouldBlock);

            let (mut left, a) = pair(false).await;
            let (b, mut right) = pair(false).await;
            let request = payload(256_123, 17);
            let response = payload(300_007, 239);
            let operations = Saturated(AtomicUsize::new(0));
            timeout(Duration::from_secs(10), async {
                left.write_all(&request[..BUFFER_SIZE]).await.unwrap();
                let (result, (), ()) = tokio::join!(
                    async {
                        tokio::try_join!(
                            copy_direction(&a, &b, &operations),
                            copy_direction(&b, &a, &operations)
                        )
                    },
                    async {
                        left.write_all(&request[BUFFER_SIZE..]).await.unwrap();
                        left.shutdown().await.unwrap();
                        let mut received = Vec::new();
                        left.read_to_end(&mut received).await.unwrap();
                        assert_eq!(received, response);
                    },
                    async {
                        let mut received = Vec::new();
                        right.read_to_end(&mut received).await.unwrap();
                        assert_eq!(received, request);
                        right.write_all(&response).await.unwrap();
                        right.shutdown().await.unwrap();
                    }
                );
                result.unwrap();
            })
            .await
            .unwrap();
            assert_eq!(operations.0.load(Ordering::Relaxed), 2);
            assert_eq!(PIPE_BUDGET.available_permits(), 0);

            drop(pipes);
            assert_eq!(PIPE_BUDGET.available_permits(), 128);
            for fd in descriptors {
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            }
            let recovered: Vec<_> = (0..128).map(|_| Pipe::new().unwrap()).collect();
            assert_eq!(PIPE_BUDGET.available_permits(), 0);
            drop(recovered);
            assert_eq!(PIPE_BUDGET.available_permits(), 128);
        });
}

struct Faults {
    error_at: usize,
    error: i32,
    calls: AtomicUsize,
    pipe_error: bool,
    max_chunk: usize,
    pipe_reads: Mutex<Vec<RawFd>>,
    pending: AtomicUsize,
    pending_at_fault: AtomicUsize,
    pipes: Mutex<Vec<std::path::PathBuf>>,
}

impl Faults {
    fn new(error_at: usize, error: i32) -> Self {
        Self {
            error_at,
            error,
            calls: AtomicUsize::new(0),
            pipe_error: false,
            max_chunk: 997,
            pipe_reads: Mutex::new(Vec::new()),
            pending: AtomicUsize::new(0),
            pending_at_fault: AtomicUsize::new(0),
            pipes: Mutex::new(Vec::new()),
        }
    }
}

impl Operations for Faults {
    fn pipe(&self) -> io::Result<Pipe> {
        if self.pipe_error {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let pipe = Pipe::new()?;
        self.pipe_reads.lock().unwrap().push(pipe.read.as_raw_fd());
        self.pipes
            .lock()
            .unwrap()
            .push(std::fs::read_link(format!("/proc/self/fd/{}", pipe.read.as_raw_fd())).unwrap());
        Ok(pipe)
    }

    fn splice(&self, from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
        if self.calls.fetch_add(1, Ordering::Relaxed) + 1 == self.error_at {
            self.pending_at_fault
                .store(self.pending.load(Ordering::Relaxed), Ordering::Relaxed);
            if self.error == 0 {
                return Ok(0);
            }
            return Err(io::Error::from_raw_os_error(self.error));
        }
        let draining = self.pipe_reads.lock().unwrap().contains(&from);
        let limit = if draining { 101 } else { self.max_chunk };
        let n = Native.splice(from, to, len.min(limit))?;
        if draining {
            self.pending.fetch_sub(n, Ordering::Relaxed);
        } else {
            self.pending.fetch_add(n, Ordering::Relaxed);
        }
        Ok(n)
    }
}

fn assert_pipes_closed(operations: &Faults) {
    let open: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .collect();
    for pipe in operations.pipes.lock().unwrap().iter() {
        assert!(!open.contains(pipe), "pipe leaked: {pipe:?}");
    }
}

#[tokio::test]
async fn interrupted_partial_and_unsupported_io_preserves_bytes() {
    for (at, error) in [
        (1, libc::EINTR),
        (2, libc::EINTR),
        (1, libc::EINVAL),
        (2, libc::EINVAL),
        (3, libc::EINVAL),
        (1, libc::EPERM),
        (2, libc::EPERM),
        (3, libc::EPERM),
        (1, libc::EACCES),
        (2, libc::EACCES),
        (3, libc::EACCES),
        (1, libc::ENOMEM),
        (2, libc::ENOMEM),
        (3, libc::ENOMEM),
        (5, libc::ENOSYS),
        (6, libc::EOPNOTSUPP),
        (0, 0),
    ] {
        let mut operations = Faults::new(at, error);
        operations.pipe_error = at == 0;
        let (mut left, a) = pair(false).await;
        let (b, mut right) = pair(false).await;
        let data = payload(256_123, 81);
        let source = crate::control::flows::test_guard();
        let destination = crate::control::flows::test_guard();
        timeout(Duration::from_secs(5), async {
            let (result, (), received) = tokio::join!(
                copy_direction_tracked(
                    &a,
                    &b,
                    &operations,
                    Accounting {
                        source: Some(&source.entry),
                        destination: Some(&destination.entry),
                    }
                ),
                async {
                    left.write_all(&data).await.unwrap();
                    left.shutdown().await.unwrap();
                },
                async {
                    let mut received = Vec::new();
                    right.read_to_end(&mut received).await.unwrap();
                    received
                }
            );
            result.unwrap();
            assert_eq!(received, data, "fault {error} at {at}");
            assert_eq!(source.entry.counters.totals(), (0, data.len() as u64));
            assert_eq!(destination.entry.counters.totals(), (data.len() as u64, 0));
        })
        .await
        .unwrap();
        assert!(operations.calls.load(Ordering::Relaxed) >= at);
        if matches!(error, libc::EACCES | libc::ENOMEM) {
            let pending = operations.pending_at_fault.load(Ordering::Relaxed);
            match at {
                1 => assert_eq!(pending, 0),
                2 => assert_eq!(pending, operations.max_chunk),
                3 => assert_eq!(pending, operations.max_chunk - 101),
                _ => unreachable!(),
            }
        }
        assert_pipes_closed(&operations);
    }
}

#[tokio::test]
async fn cancellation_and_destination_errors_release_occupied_pipes() {
    for error in [0, libc::ECONNRESET, libc::EPIPE] {
        let operations = Faults::new(2, error);
        let (mut left, a) = pair(false).await;
        let (b, _right) = pair(false).await;
        left.write_all(&vec![7; BUFFER_SIZE + 128]).await.unwrap();
        let source = crate::control::flows::test_guard();
        let destination = crate::control::flows::test_guard();
        let result = timeout(
            Duration::from_secs(2),
            copy_direction_tracked(
                &a,
                &b,
                &operations,
                Accounting {
                    source: Some(&source.entry),
                    destination: Some(&destination.entry),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        if error == 0 {
            assert_eq!(result.kind(), io::ErrorKind::WriteZero);
        } else {
            assert_eq!(result.raw_os_error(), Some(error));
        }
        assert_eq!(
            source.entry.counters.totals(),
            (0, (BUFFER_SIZE + 128) as u64)
        );
        assert_eq!(destination.entry.counters.totals(), (BUFFER_SIZE as u64, 0));
        assert_pipes_closed(&operations);
    }
    let operations = Faults::new(usize::MAX, 0);
    let (mut left, a) = pair(false).await;
    let (b, mut right) = pair(false).await;
    socket2::SockRef::from(&b)
        .set_send_buffer_size(4096)
        .unwrap();
    let sender = tokio::spawn(async move { left.write_all(&vec![7; 8 * 1024 * 1024]).await });
    let source = crate::control::flows::test_guard();
    let destination = crate::control::flows::test_guard();
    let (result, _) = tokio::join!(
        timeout(
            Duration::from_millis(100),
            copy_direction_tracked(
                &a,
                &b,
                &operations,
                Accounting {
                    source: Some(&source.entry),
                    destination: Some(&destination.entry),
                }
            )
        ),
        async { right.read_exact(&mut vec![0; BUFFER_SIZE]).await.unwrap() }
    );
    assert!(result.is_err());
    assert!(!operations.pipes.lock().unwrap().is_empty());
    assert!(operations.pending.load(Ordering::Relaxed) > 0);
    shutdown_write(&b).unwrap();
    let mut remaining = Vec::new();
    timeout(Duration::from_secs(2), right.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    let delivered = (BUFFER_SIZE + remaining.len()) as u64;
    let pending = operations.pending.load(Ordering::Relaxed) as u64;
    assert_eq!(source.entry.counters.totals(), (0, delivered + pending));
    assert_eq!(destination.entry.counters.totals(), (delivered, 0));
    assert_pipes_closed(&operations);
    sender.abort();
    let _ = sender.await;
}

#[tokio::test]
async fn capabilities_do_not_unwrap_buffered_streams() {
    use crate::async_stream::AsyncStream;
    let (socket, _peer) = pair(false).await;
    let mut boxed: Box<dyn AsyncStream> = Box::new(socket);
    assert!(boxed.plain_tcp().is_some());
    assert!(<&mut Box<dyn AsyncStream> as AsyncStream>::plain_tcp(&&mut boxed).is_some());
    let prepend = crate::prepend_stream::PrependStream::new(boxed, Some(Box::from(&b"prefix"[..])));
    assert!(prepend.plain_tcp().is_none());
    let empty = crate::prepend_stream::PrependStream::new(prepend, None);
    assert!(empty.plain_tcp().is_none());
}

#[tokio::test]
async fn idle_directions_release_their_pipes_before_waiting() {
    let operations = Faults::new(usize::MAX, 0);
    let (mut left, a) = pair(false).await;
    let (b, mut right) = pair(false).await;
    let burst = vec![7; BUFFER_SIZE + 128];
    left.write_all(&burst).await.unwrap();
    a.readable().await.unwrap();
    b.writable().await.unwrap();
    let direction = copy_direction(&a, &b, &operations);
    tokio::pin!(direction);
    assert!(futures::poll!(direction.as_mut()).is_pending());
    let mut data = vec![0; burst.len()];
    right.read_exact(&mut data).await.unwrap();
    assert_eq!(data, burst);
    assert!(!operations.pipes.lock().unwrap().is_empty());
    assert_pipes_closed(&operations);
}

#[tokio::test]
async fn ready_splice_yields_at_the_byte_quota() {
    struct Ready(AtomicUsize);
    impl Operations for Ready {
        fn splice(&self, _: RawFd, _: RawFd, len: usize) -> io::Result<usize> {
            let n = len.min(700_001);
            self.0.fetch_add(n, Ordering::Relaxed);
            Ok(n)
        }
    }
    let (mut left, a) = pair(false).await;
    let (b, _right) = pair(false).await;
    left.write_all(&vec![7; BUFFER_SIZE]).await.unwrap();
    a.readable().await.unwrap();
    b.writable().await.unwrap();
    let operations = Ready(AtomicUsize::new(0));
    let direction = tokio::task::unconstrained(copy_direction(&a, &b, &operations));
    tokio::pin!(direction);
    assert!(futures::poll!(direction.as_mut()).is_pending());
    assert_eq!(
        operations.0.load(Ordering::Relaxed),
        2 * (MAX_COPY_BYTES_PER_POLL - BUFFER_SIZE)
    );
}

#[tokio::test]
async fn small_bursts_do_not_allocate_pipes() {
    let operations = Faults::new(usize::MAX, 0);
    let (mut left, a) = pair(false).await;
    let (b, mut right) = pair(false).await;
    left.write_all(b"small").await.unwrap();
    left.shutdown().await.unwrap();
    copy_direction(&a, &b, &operations).await.unwrap();
    let mut data = Vec::new();
    right.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"small");
    assert!(operations.pipes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn urgent_marks_do_not_stall_or_truncate_normal_data() {
    for fin in [false, true] {
        let (mut left, a) = pair(false).await;
        let (b, mut right) = pair(false).await;
        let prefix = vec![7; 64 * 1024];
        left.write_all(&prefix).await.unwrap();
        assert_eq!(
            unsafe { libc::send(left.as_raw_fd(), b"!".as_ptr().cast(), 1, libc::MSG_OOB) },
            1
        );
        left.write_all(b"tail").await.unwrap();
        if fin {
            left.shutdown().await.unwrap();
        }
        let relay = tokio::spawn(async move { copy_direction(&a, &b, &Native).await });
        timeout(Duration::from_secs(2), async {
            let mut received = vec![0; prefix.len() + 4];
            right.read_exact(&mut received).await.unwrap();
            assert_eq!(&received[..prefix.len()], &prefix);
            assert_eq!(&received[prefix.len()..], b"tail");
            if !fin {
                left.shutdown().await.unwrap();
            }
            assert_eq!(right.read(&mut [0]).await.unwrap(), 0);
        })
        .await
        .unwrap();
        relay.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn pipe_recovery_preserves_the_remaining_byte_budget() {
    let pipe = Pipe::new().unwrap();
    let data = [7u8; 120];
    assert_eq!(
        unsafe { libc::write(pipe.write.as_raw_fd(), data.as_ptr().cast(), data.len()) },
        120
    );
    let (destination, mut peer) = pair(false).await;
    destination.writable().await.unwrap();
    let mut copied = MAX_COPY_BYTES_PER_POLL - 100;
    let mut buffer = [0; 120];
    {
        let draining = drain_buffered(
            &pipe,
            &destination,
            data.len(),
            &mut copied,
            &mut buffer,
            Accounting::default(),
        );
        tokio::pin!(draining);
        assert!(futures::poll!(draining.as_mut()).is_pending());
        let mut received = [0; 100];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, [7; 100]);
        draining.await.unwrap();
    }
    assert_eq!(copied, 20);
    let mut tail = [0; 20];
    peer.read_exact(&mut tail).await.unwrap();
    assert_eq!(tail, [7; 20]);
}

fn cpu_seconds() -> f64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) },
        0
    );
    time.tv_sec as f64 + time.tv_nsec as f64 / 1e9
}

#[tokio::test]
#[ignore = "alternating small-exchange latency benchmark; run alone in release mode"]
async fn benchmark_small_exchanges() {
    for round in 0..6 {
        let splice = round % 2 == 1;
        let (mut left, mut a) = pair(false).await;
        let (mut b, mut right) = pair(false).await;
        let mut samples = Vec::new();
        let (relay, (), ()) = tokio::join!(
            async {
                if splice {
                    copy_bidirectional(&a, &b).await
                } else {
                    crate::copy_bidirectional::copy_bidirectional_with_sizes(
                        &mut a, &mut b, false, false, 16384, 16384,
                    )
                    .await
                }
            },
            async {
                let mut reply = [0; 64];
                for _ in 0..10000 {
                    let start = Instant::now();
                    left.write_all(&[7; 64]).await.unwrap();
                    left.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, [7; 64]);
                    samples.push(start.elapsed().as_nanos());
                }
                left.shutdown().await.unwrap();
            },
            async {
                let mut data = [0; 64];
                while right.read_exact(&mut data).await.is_ok() {
                    right.write_all(&data).await.unwrap();
                }
                right.shutdown().await.unwrap();
            }
        );
        relay.unwrap();
        samples.sort_unstable();
        eprintln!(
            "relay_latency splice={splice} p50_ns={} p95_ns={} p99_ns={}",
            samples[5000], samples[9500], samples[9900]
        );
    }
}

#[tokio::test]
#[ignore = "alternating loopback A/B benchmark; run alone in release mode"]
async fn benchmark_copy_and_splice() {
    let bytes = 128 * 1024 * 1024;
    for flows in [1, 8, 32] {
        for round in 0..6 {
            let splice = round % 2 == 1;
            let cpu = cpu_seconds();
            let start = Instant::now();
            let mut jobs = tokio::task::JoinSet::new();
            for _ in 0..flows {
                jobs.spawn(async move {
                    let (mut left, mut a) = pair(false).await;
                    let (mut b, mut right) = pair(false).await;
                    let (relay, sent, received) = tokio::join!(
                        async {
                            if splice {
                                copy_bidirectional(&a, &b).await
                            } else {
                                crate::copy_bidirectional::copy_bidirectional_with_sizes(
                                    &mut a, &mut b, false, false, 16384, 16384,
                                )
                                .await
                            }
                        },
                        async {
                            let chunk = vec![73; 64 * 1024];
                            for _ in 0..bytes / flows / chunk.len() {
                                left.write_all(&chunk).await?;
                            }
                            left.shutdown().await
                        },
                        async {
                            let mut received = 0;
                            let mut chunk = vec![0; 64 * 1024];
                            loop {
                                let n = right.read(&mut chunk).await?;
                                if n == 0 {
                                    break;
                                }
                                assert!(chunk[..n].iter().all(|v| *v == 73));
                                received += n;
                            }
                            right.shutdown().await?;
                            Ok::<_, io::Error>(received)
                        }
                    );
                    relay.unwrap();
                    sent.unwrap();
                    assert_eq!(received.unwrap(), bytes / flows);
                });
            }
            while let Some(result) = jobs.join_next().await {
                result.unwrap();
            }
            eprintln!(
                "relay_bench flows={flows} splice={splice} seconds={:.6} cpu_seconds={:.6}",
                start.elapsed().as_secs_f64(),
                cpu_seconds() - cpu
            );
        }
    }
}
