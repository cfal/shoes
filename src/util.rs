use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncShutdownMessageExt;

pub(crate) const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) async fn shutdown_stream<T: AsyncWriteExt + Unpin + ?Sized>(stream: &mut T) {
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, stream.shutdown()).await;
}

pub(crate) async fn shutdown_message_stream<T: AsyncShutdownMessageExt + Unpin + ?Sized>(
    stream: &mut T,
) {
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, stream.shutdown_message()).await;
}

pub(crate) async fn timeout_stream_setup<T>(
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(std::time::Duration::from_secs(60), future)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "stream setup timed out"))?
}

#[inline]
pub fn allocate_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

// a cancellable alternative to AsyncWriteExt::write_all
#[inline]
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        i += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_bytes_are_initialized() {
        assert!(allocate_vec(0).is_empty());
        assert_eq!(allocate_vec(1024), vec![0; 1024]);
    }

    #[tokio::test]
    async fn write_all_rejects_zero_progress() {
        let mut storage = [0; 2];
        let mut writer = std::io::Cursor::new(storage.as_mut_slice());
        let err = write_all(&mut writer, b"abcd").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(writer.into_inner(), b"ab");
    }

    #[tokio::test]
    async fn write_all_preserves_contents() {
        let mut writer = Vec::new();
        write_all(&mut writer, b"abcd").await.unwrap();
        write_all(&mut writer, b"").await.unwrap();
        assert_eq!(writer, b"abcd");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_stream_setup_times_out() {
        let start = tokio::time::Instant::now();
        let error = timeout_stream_setup(std::future::pending::<std::io::Result<()>>())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), std::time::Duration::from_secs(60));
        assert_eq!(timeout_stream_setup(async { Ok(42) }).await.unwrap(), 42);
    }
}
