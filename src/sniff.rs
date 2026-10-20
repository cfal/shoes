use std::io;
use std::net::IpAddr;
use std::time::Duration;

use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};

mod http;

pub(crate) const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_INSPECTED_BYTES: usize = 64 * 1024;

pub(crate) struct SniffResult {
    pub hostname: Option<String>,
    pub prefix: Vec<u8>,
}

pub(crate) struct StreamProbe {
    prefix: Vec<u8>,
    acceptor: Option<Box<Acceptor>>,
    fed: usize,
    finished: bool,
    hostname: Option<String>,
    http: http::HttpProbe,
}

impl StreamProbe {
    pub fn from_prefix(prefix: Vec<u8>) -> Self {
        let mut probe = Self {
            prefix,
            acceptor: None,
            fed: 0,
            finished: false,
            hostname: None,
            http: http::HttpProbe::default(),
        };
        probe.inspect();
        probe
    }

    pub fn needs_more(&self) -> bool {
        !self.finished
    }

    fn inspect(&mut self) {
        if self.finished || self.prefix.is_empty() {
            return;
        }
        let limit = self.prefix.len().min(MAX_INSPECTED_BYTES);
        if self.prefix[0] != 0x16 {
            if let http::Inspection::Finished(hostname) = self.http.inspect(&self.prefix[..limit]) {
                self.hostname = hostname;
                self.finished = true;
            }
            self.finished |= limit == MAX_INSPECTED_BYTES;
            return;
        }
        let acceptor = self.acceptor.get_or_insert_with(Box::default);
        while self.fed < limit {
            // An exhausted slice signals EOF to rustls, not a temporary read boundary.
            match acceptor.read_tls(&mut &self.prefix[self.fed..limit]) {
                Ok(0) | Err(_) => {
                    self.finished = true;
                    break;
                }
                Ok(read) => self.fed += read,
            }
            match acceptor.accept() {
                Ok(None) => {}
                Ok(Some(accepted)) => {
                    self.hostname = accepted
                        .client_hello()
                        .server_name()
                        .filter(|name| name.trim_end_matches('.').parse::<IpAddr>().is_err())
                        .map(str::to_owned);
                    self.finished = true;
                    break;
                }
                Err(_) => {
                    // This is passive inspection: never send the returned TLS alert.
                    self.finished = true;
                    break;
                }
            }
        }
        self.finished |= limit == MAX_INSPECTED_BYTES;
        if self.finished {
            self.acceptor = None;
        }
    }

    pub async fn finish<R: AsyncRead + Unpin + ?Sized>(
        mut self,
        reader: &mut R,
        budget: Duration,
    ) -> io::Result<SniffResult> {
        let deadline = Instant::now() + budget;
        let mut buf = Vec::new();
        while self.needs_more() && Instant::now() < deadline {
            if buf.is_empty() {
                buf.resize(4096, 0);
            }
            let capacity = buf.len().min(MAX_INSPECTED_BYTES - self.prefix.len());
            // The timed read borrows scratch storage; retained bytes outlive its cancellation.
            match timeout_at(deadline, reader.read(&mut buf[..capacity])).await {
                Err(_) | Ok(Ok(0)) => break,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(read)) => self.prefix.extend_from_slice(&buf[..read]),
            }
            self.inspect();
        }
        Ok(SniffResult {
            hostname: self.hostname,
            prefix: self.prefix,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWriteExt, ReadBuf};

    #[test]
    fn probe_and_capture_future_do_not_embed_large_buffers() {
        assert!(std::mem::size_of::<StreamProbe>() < 256);
        let probe = StreamProbe::from_prefix(Vec::new());
        let mut reader = tokio::io::empty();
        let future = probe.finish(&mut reader, SNIFF_TIMEOUT);
        assert!(std::mem::size_of_val(&future) < 1024);
    }

    pub(crate) fn hello(version: &'static rustls::SupportedProtocolVersion, sni: bool) -> Vec<u8> {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        config.enable_sni = sni;
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), "sniff.example".try_into().unwrap())
                .unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        bytes
    }

    fn records(bytes: &[u8], chunk: usize) -> Vec<u8> {
        let mut handshake = Vec::new();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
            handshake.extend_from_slice(&remaining[5..5 + len]);
            remaining = &remaining[5 + len..];
        }
        let mut result = Vec::new();
        for fragment in handshake.chunks(chunk) {
            result.extend_from_slice(&[0x16, 3, 1]);
            result.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            result.extend_from_slice(fragment);
        }
        result
    }

    fn extend_hello(mut bytes: Vec<u8>, extensions: &[u8]) -> Vec<u8> {
        assert_eq!(
            bytes.len(),
            5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize
        );
        let mut offset = 5 + 4 + 2 + 32;
        offset += 1 + bytes[offset] as usize;
        offset += 2 + u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 1 + bytes[offset] as usize;
        let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        bytes[offset..offset + 2].copy_from_slice(&((len + extensions.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(extensions);
        let body_len = bytes.len() - 9;
        bytes[6..9].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
        let record_len = bytes.len() - 5;
        bytes[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        records(&bytes, 16384)
    }

    struct NoRead;

    pub(crate) fn http_request() -> Vec<u8> {
        b"POST / HTTP/1.1\r\nHost: sniff.example\r\nContent-Length: 4\r\n\r\nbody".to_vec()
    }

    #[tokio::test]
    async fn http_capture_all_splits_preserve_body_and_later_requests() {
        let mut bytes = http_request();
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\nHost: later.example\r\n\r\n");
        let header_end = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        for split in 0..=bytes.len() {
            let probe = StreamProbe::from_prefix(bytes[..split].to_vec());
            assert_eq!(probe.needs_more(), split < header_end);
            let mut reader = &bytes[split..];
            let result = probe.finish(&mut reader, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
            let mut replay = result.prefix;
            replay.extend_from_slice(reader);
            assert_eq!(replay, bytes);
        }
        let result = StreamProbe::from_prefix(bytes.clone())
            .finish(&mut NoRead, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.prefix, bytes);
    }

    #[tokio::test(start_paused = true)]
    async fn http_capture_timeout_eof_and_zero_budget_preserve_partial_headers() {
        let prefix = b"GET / HTTP/1.1\r\nHost: sniff.example\r\n".to_vec();
        let (_writer, mut reader) = tokio::io::duplex(64);
        let start = Instant::now();
        let result = StreamProbe::from_prefix(prefix.clone())
            .finish(&mut reader, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(Instant::now() - start, SNIFF_TIMEOUT);
        assert_eq!(result.hostname, None);
        assert_eq!(result.prefix, prefix);
        for budget in [Duration::ZERO, SNIFF_TIMEOUT] {
            let result = StreamProbe::from_prefix(prefix.clone())
                .finish(&mut tokio::io::empty(), budget)
                .await
                .unwrap();
            assert_eq!(result.hostname, None);
            assert_eq!(result.prefix, prefix);
        }
    }

    #[tokio::test]
    async fn http_capture_byte_limit_and_large_prefixes() {
        for length in [
            MAX_INSPECTED_BYTES - 1,
            MAX_INSPECTED_BYTES,
            MAX_INSPECTED_BYTES + 1,
        ] {
            let mut bytes = b"GET / HTTP/1.1\r\nHost: sniff.example\r\nX: ".to_vec();
            bytes.resize(length - 4, b'a');
            bytes.extend_from_slice(b"\r\n\r\n");
            let mut reader = bytes.as_slice();
            let result = StreamProbe::from_prefix(Vec::new())
                .finish(&mut reader, SNIFF_TIMEOUT)
                .await
                .unwrap();
            assert_eq!(
                result.hostname.as_deref(),
                (length <= MAX_INSPECTED_BYTES).then_some("sniff.example")
            );
            assert_eq!(result.prefix.len(), length.min(MAX_INSPECTED_BYTES));
            let mut replay = result.prefix;
            replay.extend_from_slice(reader);
            assert_eq!(replay, bytes);
            let result = StreamProbe::from_prefix(bytes.clone())
                .finish(&mut NoRead, SNIFF_TIMEOUT)
                .await
                .unwrap();
            assert_eq!(result.prefix, bytes);
        }
        let mut bytes = http_request();
        bytes.resize(MAX_INSPECTED_BYTES + 100, 0xff);
        let result = StreamProbe::from_prefix(bytes.clone())
            .finish(&mut NoRead, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
        assert_eq!(result.prefix, bytes);
    }

    impl AsyncRead for NoRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("unexpected sniff read");
        }
    }

    #[tokio::test]
    async fn complete_prefix_and_non_tls_do_not_read() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let mut bytes = hello(version, true);
            bytes.extend_from_slice(b"trailing data");
            let probe = StreamProbe::from_prefix(bytes.clone());
            assert!(!probe.needs_more());
            let result = probe.finish(&mut NoRead, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
            assert_eq!(result.prefix, bytes);
        }
        for bytes in [
            b"SSH-2.0\r\n".to_vec(),
            hello(&rustls::version::TLS13, false),
        ] {
            let probe = StreamProbe::from_prefix(bytes.clone());
            assert!(!probe.needs_more());
            let result = probe.finish(&mut NoRead, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(result.hostname, None);
            assert_eq!(result.prefix, bytes);
        }
    }

    #[tokio::test]
    async fn all_tcp_splits_and_record_boundaries() {
        let bytes = hello(&rustls::version::TLS13, true);
        for bytes in [bytes.clone(), records(&bytes, 2), records(&bytes, 137)] {
            for split in 0..bytes.len() {
                let probe = StreamProbe::from_prefix(bytes[..split].to_vec());
                assert!(probe.needs_more(), "split {split}");
                let result = probe
                    .finish(&mut &bytes[split..], SNIFF_TIMEOUT)
                    .await
                    .unwrap();
                assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
                assert_eq!(result.prefix, bytes);
            }
        }
    }

    #[tokio::test]
    async fn zero_budget_eof_and_oversized_prefix_preserve_bytes() {
        let bytes = hello(&rustls::version::TLS13, true);
        let prefix = bytes[..bytes.len() / 2].to_vec();
        let result = StreamProbe::from_prefix(prefix.clone())
            .finish(&mut NoRead, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(result.hostname, None);
        assert_eq!(result.prefix, prefix);
        let result = StreamProbe::from_prefix(prefix.clone())
            .finish(&mut tokio::io::empty(), SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.prefix, prefix);

        let mut oversized = bytes;
        oversized.resize(MAX_INSPECTED_BYTES + 100, 0);
        let result = StreamProbe::from_prefix(oversized.clone())
            .finish(&mut NoRead, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
        assert_eq!(result.prefix, oversized);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_absolute_and_replays_a_stalled_fragment() {
        let bytes = hello(&rustls::version::TLS13, true);
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let started = Instant::now();
        let sender = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            writer.write_all(&bytes[1..8]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let probe = StreamProbe::from_prefix(bytes[..1].to_vec());
        let capture = async {
            let result = probe.finish(&mut reader, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(Instant::now() - started, SNIFF_TIMEOUT);
            assert_eq!(result.hostname, None);
            assert_eq!(result.prefix, bytes[..8]);
        };
        tokio::join!(sender, capture);
    }

    #[tokio::test]
    async fn fatal_transport_errors_are_not_sniff_misses() {
        struct Failed;
        impl AsyncRead for Failed {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            }
        }
        let result = StreamProbe::from_prefix(Vec::new())
            .finish(&mut Failed, SNIFF_TIMEOUT)
            .await;
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionReset));
        for bytes in [hello(&rustls::version::TLS13, true), http_request()] {
            let mut reader = (&bytes[..8]).chain(Failed);
            let result = StreamProbe::from_prefix(Vec::new())
                .finish(&mut reader, SNIFF_TIMEOUT)
                .await;
            assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionReset));
        }
    }

    #[tokio::test]
    async fn rustls_and_capture_caps_preserve_complete_prefixes() {
        let base = hello(&rustls::version::TLS13, true);
        for wire_len in [
            MAX_INSPECTED_BYTES - 1,
            MAX_INSPECTED_BYTES,
            MAX_INSPECTED_BYTES + 1,
        ] {
            let padding_size = wire_len - base.len() - 15 - 4;
            let mut extension = vec![0xff, 0xa5];
            extension.extend_from_slice(&(padding_size as u16).to_be_bytes());
            extension.resize(padding_size + 4, 0);
            let bytes = extend_hello(base.clone(), &extension);
            assert_eq!(bytes.len(), wire_len);
            let probe = StreamProbe::from_prefix(bytes.clone());
            assert!(!probe.needs_more());
            let result = probe.finish(&mut NoRead, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(
                result.hostname.as_deref(),
                // rustls's incomplete-handshake buffer itself is limited to 0xffff.
                (wire_len < MAX_INSPECTED_BYTES).then_some("sniff.example")
            );
            assert_eq!(result.prefix, bytes);
        }
    }

    #[tokio::test]
    async fn coalesced_capture_replays_hello_and_trailing_traffic_exactly_once() {
        let mut bytes = hello(&rustls::version::TLS13, true);
        bytes.extend_from_slice(&vec![42; 8192]);
        let mut reader = bytes.as_slice();
        let mut result = StreamProbe::from_prefix(Vec::new())
            .finish(&mut reader, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
        assert!(!reader.is_empty());
        result.prefix.extend_from_slice(reader);
        assert_eq!(result.prefix, bytes);
    }

    #[tokio::test]
    async fn rejected_legacy_duplicate_and_invalid_sni_are_terminal_misses() {
        let bytes = hello(&rustls::version::TLS12, true);
        let mut offset = 5 + 4 + 2 + 32;
        offset += 1 + bytes[offset] as usize;
        offset += 2 + u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 1 + bytes[offset] as usize;
        offset += 2;
        let mut legacy = bytes.clone();
        let mut duplicate = None;
        while offset < bytes.len() {
            let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let end =
                offset + 4 + u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            if kind == 13 {
                legacy[offset..offset + 2].copy_from_slice(&[0xff, 0xa5]);
            }
            if kind == 0 {
                duplicate = Some(extend_hello(bytes.clone(), &bytes[offset..end]));
            }
            offset = end;
        }
        let mut invalid = bytes.clone();
        let name = invalid
            .windows(b"sniff.example".len())
            .position(|s| s == b"sniff.example")
            .unwrap();
        invalid[name] = b'/';
        for bytes in [legacy, duplicate.unwrap(), invalid] {
            let probe = StreamProbe::from_prefix(bytes.clone());
            assert!(!probe.needs_more());
            let result = probe.finish(&mut NoRead, SNIFF_TIMEOUT).await.unwrap();
            assert_eq!(result.hostname, None);
            assert_eq!(result.prefix, bytes);
        }
    }

    #[tokio::test]
    async fn capture_stops_at_wire_cap_without_consuming_the_tail() {
        let mut handshake = vec![0u8; 65534];
        handshake[..4].copy_from_slice(&[1, 0, 0xff, 0xfa]);
        let mut bytes = Vec::new();
        for fragment in handshake.chunks(16384) {
            bytes.extend_from_slice(&[0x16, 3, 1]);
            bytes.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            bytes.extend_from_slice(fragment);
        }
        let mut reader = bytes.as_slice();
        let result = StreamProbe::from_prefix(Vec::new())
            .finish(&mut reader, SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.hostname, None);
        assert_eq!(result.prefix.len(), MAX_INSPECTED_BYTES);
        assert_eq!(result.prefix, bytes[..MAX_INSPECTED_BYTES]);
        assert_eq!(reader, &bytes[MAX_INSPECTED_BYTES..]);
    }

    #[tokio::test]
    async fn malformed_and_mutated_prefixes_never_emit_or_lose_bytes() {
        let bytes = hello(&rustls::version::TLS13, true);
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 0xff;
            let result = StreamProbe::from_prefix(changed.clone())
                .finish(&mut NoRead, Duration::ZERO)
                .await
                .unwrap();
            assert_eq!(result.prefix, changed);
        }
        let mut not_hello = bytes;
        not_hello[5] = 2;
        let probe = StreamProbe::from_prefix(not_hello.clone());
        assert!(!probe.needs_more());
        let result = probe.finish(&mut NoRead, SNIFF_TIMEOUT).await.unwrap();
        assert_eq!(result.hostname, None);
        assert_eq!(result.prefix, not_hello);
    }

    #[tokio::test]
    async fn one_byte_reads_preserve_trailing_traffic() {
        struct OneByte<'a>(&'a [u8]);
        impl AsyncRead for OneByte<'_> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if !self.0.is_empty() && buf.remaining() > 0 {
                    buf.put_slice(&self.0[..1]);
                    self.0 = &self.0[1..];
                }
                Poll::Ready(Ok(()))
            }
        }
        let mut http = http_request();
        http.truncate(http.len() - 4);
        for head in [hello(&rustls::version::TLS13, true), http] {
            let mut bytes = head.clone();
            bytes.extend_from_slice(b"later application data");
            let mut reader = OneByte(&bytes);
            let result = StreamProbe::from_prefix(Vec::new())
                .finish(&mut reader, SNIFF_TIMEOUT)
                .await
                .unwrap();
            assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
            assert_eq!(result.prefix, head);
            assert_eq!(reader.0, b"later application data");
        }
    }

    #[tokio::test]
    async fn large_padded_hello_and_ech_extension_use_the_visible_name() {
        let mut extensions = vec![0xff, 0xa5, 0x80, 0];
        extensions.resize(32768 + 4, 0);
        // A framed GREASE ECH outer payload is inspected without decrypting it.
        extensions.extend_from_slice(&[0x2a, 0x2a, 0, 0, 0xfe, 0x0d, 0, 74]);
        extensions.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 32]);
        extensions.extend_from_slice(&[1; 32]);
        extensions.extend_from_slice(&[0, 32]);
        extensions.extend_from_slice(&[2; 32]);
        let bytes = extend_hello(hello(&rustls::version::TLS13, true), &extensions);
        assert!(bytes.len() > 32768);
        let result = StreamProbe::from_prefix(Vec::new())
            .finish(&mut bytes.as_slice(), SNIFF_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.hostname.as_deref(), Some("sniff.example"));
        assert_eq!(result.prefix, bytes);
    }
}
