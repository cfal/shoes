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

#[inline]
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    let mut first_nibble: Option<u8> = None;
    for &c in uuid_str.as_bytes() {
        let hex = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b'-' => continue,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid uuid: {}", uuid_str),
                ));
            }
        };
        if let Some(first) = first_nibble.take() {
            bytes.push((first << 4) | hex);
        } else {
            first_nibble = Some(hex);
        }
    }
    if first_nibble.is_some() || bytes.len() != 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid uuid: {}", uuid_str),
        ));
    }
    Ok(bytes)
}

// a cancellable alternative to AsyncWriteExt::write_all
pub async fn write_all<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut i = 0;
    let n = buf.len();
    while i < n {
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}
