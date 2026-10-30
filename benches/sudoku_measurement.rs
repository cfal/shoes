use super::super::{SudokuStream, tests};
use super::*;
use crate::async_stream::{AsyncPing, AsyncStream};
use futures::task::noop_waker_ref;
use rand::SeedableRng;
use serde_json::json;
use std::{
    hint::black_box,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Wire {
    bytes: Vec<u8>,
    position: usize,
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = output.remaining().min(self.bytes.len() - self.position);
        output.put_slice(&self.bytes[self.position..self.position + n]);
        self.position += n;
        if self.position == self.bytes.len() {
            self.position = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        black_box(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for Wire {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for Wire {}

fn variable(name: &str, default: usize) -> usize {
    std::env::var(name)
        .map(|value| value.parse().unwrap())
        .unwrap_or(default)
}

fn measure(name: &str, bytes: usize, mut operation: impl FnMut()) {
    let filter = std::env::var("SUDOKU_BENCH_FILTER").unwrap_or_default();
    if !name.contains(&filter) {
        return;
    }
    let duration = Duration::from_millis(variable("SUDOKU_BENCH_MS", 500) as u64);
    for _ in 0..16 {
        operation();
    }
    for sample in 0..variable("SUDOKU_BENCH_SAMPLES", 7) {
        let start = Instant::now();
        let mut iterations = 0;
        while start.elapsed() < duration {
            for _ in 0..16 {
                operation();
            }
            iterations += 16;
        }
        let seconds = start.elapsed().as_secs_f64();
        println!(
            "SUDOKU,{name},{sample},{iterations},{:.3},{:.3}",
            seconds * 1e9 / iterations as f64,
            bytes as f64 * iterations as f64 / seconds / 1048576.0,
        );
    }
}

#[test]
#[ignore = "manual release-mode Sudoku codec and stream measurement"]
#[expect(
    clippy::assertions_on_constants,
    reason = "Compile the ignored benchmark in debug, but require release when running it."
)]
fn sudoku_measurement() {
    assert!(!cfg!(debug_assertions), "use --release");
    let plain: Vec<_> = (0..3072).map(|i| (i * 37 + i / 256) as u8).collect();
    for layout in ["entropy", "ascii", "custom", "rotating"] {
        for padding in [0, 10] {
            let mut options = json!({
                "password": "sudoku-perf",
                "padding_min": padding,
                "padding_max": padding,
            });
            if layout == "rotating" {
                options["custom_tables"] = json!(["", "xpxvvpvv", "vxpvxvvp"]);
            } else if layout == "custom" {
                options["custom_table"] = json!("xpxvvpvv");
            } else {
                options["ascii"] = json!(layout);
            }
            let config = tests::config(options);
            for (mode, write, read) in [
                ("classic", Role::Client, Role::Server),
                ("packed", Role::Server, Role::Client),
            ] {
                let name = format!("{layout}/{mode}/pad{padding}");
                let mut encoder = Encoder::new(config.clone(), write);
                encoder.rng = StdRng::seed_from_u64(42);
                let mut buffer = vec![0; plain.len() * 9 + 8];
                // Three writes return both codecs to layout zero for the rotating case.
                let mut wire = Vec::new();
                for _ in 0..3 {
                    let n = encoder.encode(&plain, &mut buffer);
                    wire.extend_from_slice(&buffer[..n]);
                }
                if matches!(layout, "entropy" | "ascii")
                    && let Some(directory) = std::env::var_os("SUDOKU_BENCH_WIRE_DIR")
                {
                    let path = std::path::Path::new(&directory)
                        .join(format!("{layout}-{mode}-pad{padding}.bin"));
                    wire = std::fs::read(path).unwrap().repeat(3);
                }
                measure(&format!("{name}/codec_encode"), plain.len(), || {
                    let n = encoder.encode(black_box(&plain), &mut buffer);
                    black_box(&buffer[..n]);
                });

                let mut decoder = Decoder::new(config.clone(), read);
                let mut output = vec![0; plain.len() * 3 + 1];
                let decoded = decoder.decode(&wire, &mut output);
                assert!(decoded.error.is_none());
                assert_eq!(decoded.consumed, wire.len());
                assert_eq!(&output[..decoded.written], plain.repeat(3));
                measure(&format!("{name}/codec_decode"), plain.len() * 3, || {
                    let decoded = decoder.decode(black_box(&wire), &mut output);
                    assert!(decoded.error.is_none());
                    assert_eq!(decoded.consumed, wire.len());
                    black_box(&output[..decoded.written]);
                });

                let mut cx = Context::from_waker(noop_waker_ref());
                let mut writer = SudokuStream::new(
                    Box::new(Wire {
                        bytes: Vec::new(),
                        position: 0,
                    }),
                    config.clone(),
                    write,
                );
                measure(&format!("{name}/stream_encode"), plain.len(), || {
                    let Poll::Ready(Ok(n)) =
                        Pin::new(&mut writer).poll_write(&mut cx, black_box(&plain))
                    else {
                        panic!("discard transport must accept the write");
                    };
                    assert_eq!(n, plain.len());
                });

                let mut reader = SudokuStream::new(
                    Box::new(Wire {
                        bytes: wire,
                        position: 0,
                    }),
                    config.clone(),
                    read,
                );
                let mut read_plain = || {
                    let mut result = ReadBuf::new(&mut output[..plain.len()]);
                    while result.remaining() != 0 {
                        let before = result.filled().len();
                        let Poll::Ready(Ok(())) =
                            Pin::new(&mut reader).poll_read(&mut cx, &mut result)
                        else {
                            panic!("memory transport must produce plaintext");
                        };
                        assert!(result.filled().len() > before);
                    }
                    black_box(result.filled());
                };
                read_plain();
                measure(&format!("{name}/stream_decode"), plain.len(), read_plain);
            }
        }
    }
}
