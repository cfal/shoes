//! An AsyncUdpSocket that obfuscates every datagram.

use std::cell::RefCell;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

use super::Obfuscator;

/// Initial size of the send scratch buffer. Larger datagrams grow it; QUIC
/// datagrams are far below this in practice.
const SCRATCH_CAPACITY: usize = 2048;

thread_local! {
    /// Scratch space for the send path. `Transmit::contents` is an immutable
    /// slice, so obfuscation needs somewhere to write. A thread-local avoids
    /// both an allocation per packet and a lock that would serialise sends.
    static SEND_SCRATCH: RefCell<Vec<u8>> = RefCell::new(vec![0u8; SCRATCH_CAPACITY]);
}

/// Deobfuscate the first `count` datagrams of a received batch in place,
/// dropping any that is not ours and compacting the survivors to the front.
///
/// Returns how many datagrams survived. Buffers past the returned count are
/// left as they are; quinn only reads the first `kept` entries.
///
/// `deobfuscate` reads and writes different offsets of the same logical packet,
/// and the borrow checker will not allow one buffer to be both, so it goes
/// through a scratch Vec.
fn deobfuscate_batch(
    obfs: &dyn Obfuscator,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    count: usize,
) -> usize {
    let mut kept = 0;
    for i in 0..count {
        let len = meta[i].len;

        // We report max_receive_segments() == 1, so a buffer holding more than
        // one datagram means GRO coalesced them behind our back. Deobfuscating
        // that as a single packet would corrupt all of them, so drop it.
        if meta[i].stride != len {
            log::debug!(
                "dropping a {len}-byte coalesced datagram from {} (stride {})",
                meta[i].addr,
                meta[i].stride
            );
            continue;
        }

        match obfs.deobfuscate_in_place(&mut bufs[i][..len]) {
            Some(decoded_len) => {
                // quinn pairs meta[n] with bufs[n], so a survivor that moves
                // forward in the metadata must have its bytes move with it.
                if kept != i {
                    meta[kept] = meta[i];
                    let (left, right) = bufs.split_at_mut(i);
                    left[kept][..decoded_len].copy_from_slice(&right[0][..decoded_len]);
                }
                meta[kept].len = decoded_len;
                meta[kept].stride = decoded_len;
                kept += 1;
            }
            None => {
                log::debug!(
                    "dropping {len}-byte datagram from {} that is not obfuscated for us",
                    meta[i].addr
                );
            }
        }
    }
    kept
}

/// Wraps quinn's own UDP socket and applies an obfuscator to every datagram.
///
/// Segmentation and receive offload are reported as unavailable. With GSO a
/// single `sendmsg` carries several QUIC packets, and an obfuscator that treats
/// the buffer as one unit produces something the peer cannot split apart again.
#[derive(Debug)]
pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Arc<dyn Obfuscator>,
}

impl ObfuscatedUdpSocket {
    /// Wrap a std socket. quinn's own `UdpSocketState::new` puts it into
    /// non-blocking mode, so the caller does not have to.
    pub fn new(socket: std::net::UdpSocket, obfs: Arc<dyn Obfuscator>) -> std::io::Result<Self> {
        Ok(Self {
            inner: TokioRuntime.wrap_udp_socket(socket)?,
            obfs,
        })
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // We report max_transmit_segments() == 1, so quinn must never hand us a
        // batched transmit. If that promise is ever broken, scrambling the
        // whole buffer as one unit would corrupt every packet in it silently,
        // so refuse instead.
        if transmit.segment_size.is_some() {
            return Err(std::io::Error::other(
                "obfuscated sockets cannot send segmented transmits",
            ));
        }

        SEND_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            let needed = transmit.contents.len() + self.obfs.overhead();
            if scratch.len() < needed {
                scratch.resize(needed, 0);
            }
            let written = self
                .obfs
                .obfuscate(transmit.contents, &mut scratch)
                .ok_or_else(|| std::io::Error::other("obfuscation buffer too small"))?;

            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &scratch[..written],
                segment_size: None,
                src_ip: transmit.src_ip,
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let kept = deobfuscate_batch(self.obfs.as_ref(), bufs, meta, count);

            // Every datagram in this batch was garbage; wait for the next one
            // rather than reporting zero, which quinn reads as "nothing to do".
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_transport::obfs::Salamander;

    fn wrap(std_socket: std::net::UdpSocket) -> Arc<ObfuscatedUdpSocket> {
        let obfs: Arc<dyn Obfuscator> = Arc::new(Salamander::new(b"a password").unwrap());
        Arc::new(ObfuscatedUdpSocket::new(std_socket, obfs).unwrap())
    }

    fn bind() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    /// Poll until one datagram arrives, returning its length.
    async fn recv_one(socket: &ObfuscatedUdpSocket, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut meta = [RecvMeta::default()];
        let count = std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await?;
        assert_eq!(count, 1);
        assert_eq!(meta[0].stride, meta[0].len);
        Ok(meta[0].len)
    }

    /// Send one datagram, waiting for writability the way quinn does.
    ///
    /// `try_send` is allowed to return WouldBlock until tokio has observed the
    /// socket as writable, and the contract says the caller must then poll the
    /// socket's own `UdpPoller`. Doing that here also exercises the poller we
    /// delegate to the inner socket.
    async fn send(socket: &Arc<ObfuscatedUdpSocket>, destination: SocketAddr, contents: &[u8]) {
        let mut poller = socket.clone().create_io_poller();
        loop {
            match socket.try_send(&Transmit {
                destination,
                ecn: None,
                contents,
                segment_size: None,
                src_ip: None,
            }) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                        .await
                        .unwrap();
                }
                Err(e) => panic!("try_send failed: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn test_round_trip_between_two_wrapped_sockets() {
        let a = wrap(bind());
        let b = wrap(bind());
        let b_addr = b.local_addr().unwrap();

        let payload = b"a quic packet would go here";
        send(&a, b_addr, payload).await;

        let mut buf = [0u8; 2048];
        let len = recv_one(&b, &mut buf).await.unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(&buf[..len], payload);
    }

    #[tokio::test]
    async fn test_offload_is_disabled() {
        let a = wrap(bind());
        assert_eq!(a.max_transmit_segments(), 1);
        assert_eq!(a.max_receive_segments(), 1);
    }

    #[tokio::test]
    async fn test_segmented_transmit_is_refused() {
        let a = wrap(bind());
        let b_addr = wrap(bind()).local_addr().unwrap();
        let err = a
            .try_send(&Transmit {
                destination: b_addr,
                ecn: None,
                contents: &[0u8; 100],
                segment_size: Some(50),
                src_ip: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("segmented"), "{err}");
    }

    #[tokio::test]
    async fn test_garbage_datagram_is_dropped_not_returned() {
        let receiver = wrap(bind());
        let addr = receiver.local_addr().unwrap();

        // A plain sender: whatever it sends cannot deobfuscate to anything we
        // would accept, because it carries no salt we agreed on.
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        plain.send_to(&[0u8; 4], addr).await.unwrap();

        // Then a well-formed packet, which must still arrive.
        let good = wrap(bind());
        send(&good, addr, b"real").await;

        let mut buf = [0u8; 2048];
        let len = recv_one(&receiver, &mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"real");
    }

    fn obfuscator() -> Salamander {
        Salamander::new(b"a password").unwrap()
    }

    /// Lay out a batch of raw buffers and their metadata the way the inner
    /// socket would hand them over.
    fn batch(packets: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<RecvMeta>) {
        let storage: Vec<Vec<u8>> = packets
            .iter()
            .map(|p| {
                let mut buf = vec![0u8; 2048];
                buf[..p.len()].copy_from_slice(p);
                buf
            })
            .collect();
        let meta = packets
            .iter()
            .enumerate()
            .map(|(i, p)| RecvMeta {
                addr: format!("127.0.0.1:{}", 1000 + i).parse().unwrap(),
                len: p.len(),
                stride: p.len(),
                ecn: None,
                dst_ip: None,
            })
            .collect();
        (storage, meta)
    }

    fn wire(obfs: &Salamander, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; payload.len() + obfs.overhead()];
        let written = obfs.obfuscate(payload, &mut out).unwrap();
        out.truncate(written);
        out
    }

    #[test]
    fn test_batch_keeps_every_valid_datagram() {
        let obfs = obfuscator();
        let packets = vec![wire(&obfs, b"one"), wire(&obfs, b"two")];
        let (mut storage, mut meta) = batch(&packets);
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        let kept = deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2);

        assert_eq!(kept, 2);
        assert_eq!(&bufs[0][..meta[0].len], b"one");
        assert_eq!(&bufs[1][..meta[1].len], b"two");
    }

    /// The case the compaction exists for: a stray packet ahead of a real one
    /// in the same recvmmsg batch. quinn pairs meta[n] with bufs[n], so the
    /// survivor's bytes have to end up in the buffer its metadata names.
    #[test]
    fn test_batch_compacts_payload_and_metadata_together() {
        let obfs = obfuscator();
        let packets = vec![vec![0u8; 4], wire(&obfs, b"the real payload")];
        let (mut storage, mut meta) = batch(&packets);
        let good_addr = meta[1].addr;
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        let kept = deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2);

        assert_eq!(kept, 1);
        assert_eq!(meta[0].addr, good_addr, "metadata moved forward");
        assert_eq!(meta[0].len, b"the real payload".len());
        assert_eq!(
            &bufs[0][..meta[0].len],
            b"the real payload",
            "the payload must move with its metadata"
        );
    }

    #[test]
    fn test_batch_drops_a_coalesced_datagram() {
        let obfs = obfuscator();
        let packets = vec![wire(&obfs, b"coalesced")];
        let (mut storage, mut meta) = batch(&packets);
        // GRO would report a buffer longer than one datagram's stride.
        meta[0].stride = meta[0].len / 2;
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        assert_eq!(deobfuscate_batch(&obfs, &mut bufs, &mut meta, 1), 0);
    }

    #[test]
    fn test_batch_drops_everything_when_nothing_is_ours() {
        let obfs = obfuscator();
        let packets = vec![vec![0u8; 4], vec![1u8; 6]];
        let (mut storage, mut meta) = batch(&packets);
        let mut bufs: Vec<IoSliceMut<'_>> =
            storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();

        assert_eq!(deobfuscate_batch(&obfs, &mut bufs, &mut meta, 2), 0);
    }

    #[tokio::test]
    async fn test_an_obfuscated_packet_is_not_readable_in_the_clear() {
        let sender = wrap(bind());
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();

        let payload = b"plaintext marker";
        send(&sender, plain_addr, payload).await;

        let mut buf = [0u8; 2048];
        let (len, _) = plain.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, payload.len() + 8, "salt is prefixed on the wire");
        assert!(
            !buf[..len].windows(payload.len()).any(|w| w == payload),
            "the payload must not appear verbatim on the wire"
        );
    }
}
