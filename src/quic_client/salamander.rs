use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use rand::Rng;

use crate::config::quic_client::Secret;

pub(crate) const OVERHEAD: u16 = 8;

#[derive(Debug)]
pub(crate) struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Secret,
}

fn key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Blake2b::<U32>::new();
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}

fn xor(data: &mut [u8], key: &[u8; 32]) {
    for chunk in data.chunks_mut(32) {
        for (byte, key) in chunk.iter_mut().zip(key) {
            *byte ^= key;
        }
    }
}

fn decode(password: &str, data: &mut [u8]) -> Option<usize> {
    let size = data
        .len()
        .checked_sub(OVERHEAD as usize)
        .filter(|size| *size > 0)?;
    let key = key(password, &data[..8]);
    data.copy_within(8.., 0);
    xor(&mut data[..size], &key);
    Some(size)
}

// GRO may combine datagrams even when transmit segmentation is disabled.
fn decode_segments(password: &str, data: &mut [u8], stride: usize) -> Option<(usize, usize)> {
    if stride == 0 || stride >= data.len() {
        let length = decode(password, data)?;
        return Some((length, length));
    }
    let decoded_stride = stride.checked_sub(8).filter(|size| *size > 0)?;
    let mut out = 0;
    for start in (0..data.len()).step_by(stride) {
        let end = (start + stride).min(data.len());
        if let Some(size) = decode(password, &mut data[start..end]) {
            data.copy_within(start..start + size, out);
            out += size;
        } else if end != data.len() {
            return None;
        }
    }
    (out > 0).then_some((out, decoded_stride))
}

fn decode_batch(
    password: &str,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    count: usize,
) -> usize {
    let mut kept = 0;
    for index in 0..count {
        let Some((length, stride)) = decode_segments(
            password,
            &mut bufs[index][..meta[index].len],
            meta[index].stride,
        ) else {
            continue;
        };
        if kept != index {
            let (before, after) = bufs.split_at_mut(index);
            before[kept][..length].copy_from_slice(&after[0][..length]);
            meta[kept] = meta[index];
        }
        meta[kept].len = length;
        meta[kept].stride = stride;
        kept += 1;
    }
    kept
}

impl Salamander {
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>, password: Secret) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(Self { inner, password })
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| size < transmit.contents.len())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander transmit segmentation disabled",
            ));
        }
        let mut data = vec![0; transmit.contents.len() + 8];
        rand::rng().fill_bytes(&mut data[..8]);
        let key = key(&self.password.0, &data[..8]);
        data[8..].copy_from_slice(transmit.contents);
        xor(&mut data[8..], &key);
        self.inner.try_send(&Transmit {
            contents: &data,
            segment_size: None,
            ..*transmit
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Bound work under a flood of malformed packets without losing a wakeup.
        for _ in 0..32 {
            let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let kept = decode_batch(&self.password.0, bufs, meta, count);
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(data: &[u8]) -> Vec<u8> {
        let mut wire = vec![1; 8];
        wire.extend_from_slice(data);
        xor(&mut wire[8..], &key("password", &[1; 8]));
        wire
    }

    #[test]
    fn coalesced_receive_compacts_payloads_and_metadata() {
        let mut bad = [0; 8];
        let mut good = [wire(&[1; 100]), wire(&[2; 100]), wire(&[3; 40])].concat();
        // Receive buffers supplied by Quinn have equal capacity.
        let mut first = vec![0; good.len()];
        first[..8].copy_from_slice(&bad);
        let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut good)];
        let mut meta = [
            RecvMeta {
                len: 8,
                stride: 8,
                ..Default::default()
            },
            RecvMeta {
                len: 264,
                stride: 108,
                addr: "127.0.0.1:443".parse().unwrap(),
                ..Default::default()
            },
        ];
        assert_eq!(decode_batch("password", &mut bufs, &mut meta, 2), 1);
        assert_eq!(
            (meta[0].len, meta[0].stride, meta[0].addr.port()),
            (240, 100, 443)
        );
        assert_eq!(
            &bufs[0][..240],
            [&[1; 100][..], &[2; 100], &[3; 40]].concat()
        );
        assert!(decode("password", &mut bad).is_none());
    }
}
