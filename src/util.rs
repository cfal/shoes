use std::time::SystemTime;

use tokio::io::AsyncWriteExt;

/// Seconds since the Unix epoch.
///
/// Several protocols stamp a handshake with the current time and reject a peer
/// whose clock is too far off. A clock set before 1970 is a broken clock rather
/// than something to panic over: these run on every connection, and the mobile
/// profile is built with `panic = "abort"`, where a panic ends the process
/// rather than the connection. A broken clock fails the handshake either way,
/// so an error says the same thing and says it usefully.
#[inline]
pub fn unix_time_secs() -> std::io::Result<u64> {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .map(|since_epoch| since_epoch.as_secs())
        .map_err(|e| std::io::Error::other(format!("system clock is before the Unix epoch: {e}")))
}

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
        let n = stream.write(&buf[i..]).await?;
        i += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seconds, not milliseconds. Protocols compare this against a peer's
    /// stamp within a window of tens of seconds, so the wrong unit would put
    /// every handshake outside it - and the unit is invisible in a u64.
    #[test]
    fn test_unix_time_secs_is_in_seconds() {
        let now = unix_time_secs().expect("this machine's clock is after 1970");
        // 2020-01-01 and 2100-01-01.
        assert!(
            (1_577_836_800..4_102_444_800).contains(&now),
            "{now} is not a plausible time in seconds"
        );
    }
}
