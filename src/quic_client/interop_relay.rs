use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::net::UdpSocket;
use tokio_util::task::AbortOnDropHandle;

#[derive(Default)]
struct Observed {
    paths: parking_lot::Mutex<HashSet<(u16, SocketAddr)>>,
    dropped: [AtomicUsize; 2],
    refused: tokio::sync::Notify,
}

pub(super) struct Relay {
    pub ports: Vec<u16>,
    observed: Arc<Observed>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

impl Relay {
    pub async fn start(server: SocketAddr, count: usize, impaired: bool) -> Self {
        let mut ports = Vec::new();
        let mut tasks = Vec::new();
        let observed = Arc::new(Observed::default());
        let bind = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        for _ in 0..count {
            let front = UdpSocket::bind(bind).await.unwrap();
            // Each destination port has a distinct upstream path: migration is
            // visible to the real server, not hidden behind a single NAT socket.
            let back = UdpSocket::bind(bind).await.unwrap();
            back.connect(server).await.unwrap();
            let port = front.local_addr().unwrap().port();
            ports.push(port);
            let observed = observed.clone();
            tasks.push(AbortOnDropHandle::new(tokio::spawn(async move {
                let mut client = None;
                let mut upstream = vec![0; 65536];
                let mut downstream = vec![0; 65536];
                let mut sent = 0;
                let mut received = 0;
                loop {
                    tokio::select! {
                        result = front.recv_from(&mut upstream) => {
                            let (length, source) = result.unwrap();
                            client = Some(source);
                            observed.paths.lock().insert((port, source));
                            if forward(impaired, &mut sent, &observed.dropped[0]).await {
                                let _ = tolerate_refusal(back.send(&upstream[..length]).await, &observed);
                            }
                        }
                        result = back.recv(&mut downstream) => {
                            let Some(length) = tolerate_refusal(result, &observed) else { continue };
                            if forward(impaired, &mut received, &observed.dropped[1]).await {
                                front.send_to(&downstream[..length], client.unwrap()).await.unwrap();
                            }
                        }
                    }
                }
            })));
        }
        Self {
            ports,
            observed,
            _tasks: tasks,
        }
    }

    pub fn paths_seen(&self) -> (usize, usize) {
        let paths = self.observed.paths.lock();
        let destinations = paths.iter().map(|(port, _)| port).collect::<HashSet<_>>();
        (paths.len(), destinations.len())
    }

    pub fn dropped(&self) -> [usize; 2] {
        std::array::from_fn(|index| self.observed.dropped[index].load(Ordering::Relaxed))
    }
}

fn tolerate_refusal(result: io::Result<usize>, observed: &Observed) -> Option<usize> {
    match result {
        Ok(length) => Some(length),
        // The readiness inbound can open before the peer's QUIC listener.
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            observed.refused.notify_one();
            None
        }
        Err(error) => panic!("UDP relay failed: {error}"),
    }
}

async fn forward(impaired: bool, packets: &mut usize, dropped: &AtomicUsize) -> bool {
    if !impaired {
        return true;
    }
    *packets += 1;
    if (*packets).is_multiple_of(11) {
        dropped.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // Serializes both directions; this is a slow relay, not a fixed-latency
    // link. Kernel queueing can add delay and losses beyond the counted drops.
    tokio::time::sleep(Duration::from_millis(2)).await;
    true
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn relay_survives_a_peer_that_starts_after_the_first_packet() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let reservation = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        let server = SocketAddr::from(([127, 0, 0, 1], port));
        drop(reservation);
        let relay = Relay::start(server, 1, false).await;
        let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        client.connect(("127.0.0.1", relay.ports[0])).await.unwrap();
        client.send(b"before").await.unwrap();
        relay.observed.refused.notified().await;

        let peer = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
        client.send(b"after").await.unwrap();
        let mut buffer = [0; 64];
        let (length, source) = peer.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"after");
        peer.send_to(&buffer[..length], source).await.unwrap();
        let length = client.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"after");
    })
    .await
    .unwrap();
}
