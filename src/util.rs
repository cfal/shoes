use tokio::io::AsyncWriteExt;

#[inline]
#[allow(clippy::uninit_vec)]
pub fn allocate_vec<T>(len: usize) -> Vec<T> {
    let mut ret = Vec::with_capacity(len);
    unsafe {
        ret.set_len(len);
    }
    ret
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
        let written = stream.write(&buf[i..]).await?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write_all: write returned 0 bytes",
            ));
        }
        i += written;
    }
    Ok(())
}
