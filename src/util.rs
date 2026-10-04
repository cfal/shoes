use tokio::io::AsyncWriteExt;

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
}
