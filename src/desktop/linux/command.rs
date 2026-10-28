use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DEADLINE: Duration = Duration::from_secs(10);
const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

pub(super) fn executable(name: &str) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let path = Path::new(directory).join(name);
        let Ok(metadata) = std::fs::metadata(&path) else {
            continue;
        };
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
        {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("managed TUN requires a trusted system {name} executable"),
    ))
}

// Mutating callers await completion without selecting against cancellation.
pub(super) async fn run(
    lease: BorrowedFd<'_>,
    executable: &str,
    args: &[&str],
    input: &[u8],
) -> io::Result<Vec<u8>> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(args)
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let lease = lease.as_raw_fd();
    // Surviving helpers retain the flock after SIGKILL, serializing recovery with their commit.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(lease, libc::F_GETFD);
            if flags < 0 || libc::fcntl(lease, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap().take(OUTPUT_LIMIT + 1);
    let mut stderr = child.stderr.take().unwrap().take(OUTPUT_LIMIT + 1);
    let mut output = Vec::new();
    let mut error = Vec::new();
    let result = tokio::time::timeout(DEADLINE, async {
        tokio::try_join!(
            async {
                stdin.write_all(input).await?;
                drop(stdin);
                Ok::<_, io::Error>(())
            },
            stdout.read_to_end(&mut output),
            stderr.read_to_end(&mut error),
        )?;
        child.wait().await
    })
    .await
    .unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{executable} timed out; completion requires reconciliation"),
        ))
    });
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
    };
    if output.len() as u64 > OUTPUT_LIMIT || error.len() as u64 > OUTPUT_LIMIT {
        return Err(io::Error::other(format!(
            "{executable} output exceeded limit"
        )));
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "{executable} failed ({status}): {}",
            String::from_utf8_lossy(&error).trim()
        )));
    }
    Ok(output)
}

pub(super) async fn nft(
    lease: BorrowedFd<'_>,
    executable: &str,
    batch: serde_json::Value,
) -> io::Result<()> {
    let input = encode_nft(batch)?;
    run(lease, executable, &["-j", "-f", "-"], &input).await?;
    Ok(())
}

pub(super) fn encode_nft(batch: serde_json::Value) -> io::Result<Vec<u8>> {
    let typed: nftables::schema::Nftables<'_> =
        serde_json::from_value(batch).map_err(io::Error::other)?;
    serde_json::to_vec(&typed).map_err(io::Error::other)
}
