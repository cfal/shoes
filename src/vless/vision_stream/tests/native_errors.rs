use super::*;

#[derive(Default)]
struct Backend {
    output: Vec<u8>,
    writes: usize,
    fail_after: usize,
    fail_direct: bool,
}

impl AsyncRead for Backend {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Backend {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.output.extend_from_slice(buf);
        this.writes += 1;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Backend {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncStream for Backend {}
impl VisionTransport for Backend {
    fn is_client(&self) -> bool {
        true
    }
    fn is_server(&self) -> bool {
        false
    }
    fn require_record_framing(&self) -> io::Result<()> {
        Ok(())
    }
    fn allow_streaming_reads(&mut self) {}
    fn start_raw_read(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn start_raw_write(&mut self, final_plaintext: &[u8]) -> io::Result<()> {
        if self.fail_direct {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.output.extend_from_slice(final_plaintext);
        self.writes += 1;
        Ok(())
    }
    fn poll_drain_encrypted(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.writes >= self.fail_after {
            self.fail_after = usize::MAX;
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

fn client(policy: VisionWriteErrorPolicy, fail_after: usize) -> VisionStream<Backend> {
    VisionStream::new_client(
        Backend {
            fail_after,
            ..Default::default()
        },
        [7; 16],
    )
    .unwrap()
    .with_write_error_policy(policy)
}

fn write(stream: &mut VisionStream<Backend>, data: &[u8]) -> io::Result<usize> {
    match Pin::new(stream).poll_write(&mut Context::from_waker(noop_waker_ref()), data) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpected Pending"),
    }
}

fn hello() -> Vec<u8> {
    let mut record = vec![0x16, 3, 3, 0, 40, 1];
    record.resize(45, 0);
    record
}

fn assert_latched(stream: &mut VisionStream<Backend>) {
    let output = stream.tls.output.clone();
    assert_eq!(
        write(stream, b"replacement").unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let mut cx = Context::from_waker(noop_waker_ref());
    assert!(matches!(
        Pin::new(&mut *stream).poll_flush(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut *stream).poll_shutdown(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut *stream).poll_write_ping(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert_eq!(stream.tls.output, output);
    assert!(
        Pin::new(stream)
            .poll_read(&mut cx, &mut ReadBuf::new(&mut [0; 1]))
            .is_pending()
    );
}

#[test]
fn invalid_tls_tail_acknowledges_every_current_byte() {
    for policy in [
        VisionWriteErrorPolicy::Legacy,
        VisionWriteErrorPolicy::AcknowledgeAccepted,
    ] {
        for retained_header in [false, true] {
            let mut stream = client(policy, 2);
            let mut expected = hello();
            let data = if retained_header {
                assert_eq!(write(&mut stream, &expected).unwrap(), 45);
                assert_eq!(write(&mut stream, &[0x16, 3, 3]).unwrap(), 3);
                expected.extend_from_slice(&[0x16, 3, 3]);
                vec![0xff, 0xff, 1, 0, 0, 0, 0, 0, 0, 0]
            } else {
                let mut data = expected.clone();
                data.extend_from_slice(&[0x16, 3, 3, 0xff, 0xff, 1, 0, 0, 0, 0]);
                expected.clear();
                data
            };
            expected.extend_from_slice(&data);
            let result = write(&mut stream, &data);
            if policy == VisionWriteErrorPolicy::Legacy {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
                assert!(stream.write_error.is_none());
            } else {
                assert_eq!(result.unwrap(), if retained_header { 10 } else { 55 });
                assert_latched(&mut stream);
            }
            let decoded = VisionUnpadder::new([7; 16])
                .unpad(&stream.tls.output)
                .unwrap();
            assert_eq!(decoded.content, expected);
            assert_eq!(decoded.command, Some(UnpadCommand::End));
        }
    }
}

#[test]
fn padded_record_failure_excludes_discarded_tail() {
    let mut stream = client(VisionWriteErrorPolicy::AcknowledgeAccepted, 1);
    let mut data = hello();
    data.extend_from_slice(&[0x16, 3, 3]);
    assert_eq!(write(&mut stream, &data).unwrap(), 45);
    assert_eq!(stream.inner_write_deframer.pending_bytes(), 0);
    assert_latched(&mut stream);
    assert_eq!(
        VisionUnpadder::new([7; 16])
            .unpad(&stream.tls.output)
            .unwrap()
            .content,
        hello()
    );
}

#[test]
fn unknown_prefix_end_failure_uses_saturating_current_prefix() {
    for short_prefix in [false, true] {
        let mut stream = client(VisionWriteErrorPolicy::AcknowledgeAccepted, 1);
        if short_prefix {
            assert_eq!(write(&mut stream, &[0x16, 3, 3, 0x16, 3]).unwrap(), 5);
        }
        for _ in 0..7 {
            stream.filter.decrement_filter_count();
        }
        if short_prefix {
            assert_eq!(
                write(&mut stream, &[3]).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        } else {
            assert_eq!(write(&mut stream, b"hello").unwrap(), 5);
        }
        assert_latched(&mut stream);
    }
}

#[test]
fn direct_transition_and_drain_failures_acknowledge_only_processed_records() {
    for fail_direct in [false, true] {
        let mut stream = client(VisionWriteErrorPolicy::AcknowledgeAccepted, 2);
        assert_eq!(write(&mut stream, &hello()).unwrap(), 45);
        stream.filter.filter_record(&inner_server_hello());
        assert!(stream.filter.supports_xtls());
        stream.tls.fail_direct = fail_direct;
        let data = [0x17, 3, 3, 0, 1, 42, 0x17, 3, 3];
        assert_eq!(write(&mut stream, &data).unwrap(), 6);
        assert_latched(&mut stream);
    }
}

#[test]
fn entry_drain_failure_accepts_no_current_bytes() {
    let mut stream = client(VisionWriteErrorPolicy::AcknowledgeAccepted, 0);
    assert_eq!(
        write(&mut stream, &hello()).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(stream.tls.output.is_empty());
    assert_eq!(stream.inner_write_deframer.pending_bytes(), 0);
}
