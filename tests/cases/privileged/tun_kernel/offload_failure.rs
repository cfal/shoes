use super::*;
use shoes_test_support::process::spawn_privileged_process;
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;

fn start_filtered_server(
    config: &str,
    request: u32,
    directory: &Path,
) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    let mut config_file = tempfile::NamedTempFile::new_in(directory)?;
    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;
    let log = File::create(directory.join("server.log"))?;
    let stderr = log.try_clone()?;
    let guard = spawn_privileged_process(
        &std::env::current_exe()?,
        "offload-filtered-shoes",
        |command| {
            command
                .args([
                    "--exact",
                    "tun_kernel::offload_failure::filtered_server",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SHOES_TEST_OFFLOAD_CONFIG", config_file.path())
                .env("SHOES_TEST_OFFLOAD_IOCTL", request.to_string())
                .env("SHOES_TEST_OFFLOAD_RESULT", directory.join("exit"))
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(stderr));
        },
    )?;
    Ok((guard, config_file))
}

#[test]
#[ignore = "privileged subprocess entry point, invoked by the offload failure test"]
fn filtered_server() -> io::Result<()> {
    let config = std::env::var_os("SHOES_TEST_OFFLOAD_CONFIG").expect("missing child config");
    let request: u32 = std::env::var("SHOES_TEST_OFFLOAD_IOCTL")
        .expect("missing denied ioctl")
        .parse()
        .unwrap();
    let result = std::env::var_os("SHOES_TEST_OFFLOAD_RESULT").expect("missing child result path");
    let result = Path::new(&result);

    // Handoff must work even when sudo creates root-only files by default.
    unsafe { libc::umask(0o077) };

    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let equal = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let argument = std::mem::offset_of!(libc::seccomp_data, args)
        + std::mem::size_of::<u64>()
        + if cfg!(target_endian = "big") { 4 } else { 0 };
    let mut filter = [
        instruction(
            load,
            0,
            0,
            std::mem::offset_of!(libc::seccomp_data, nr) as u32,
        ),
        instruction(equal, 0, 3, libc::SYS_ioctl as u32),
        instruction(load, 0, 0, argument as u32),
        instruction(equal, 0, 1, request),
        instruction(ret, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EACCES as u32),
        instruction(ret, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // Install after sudo, on the isolated test thread that spawns Shoes.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let probe = File::open("/dev/null")?;
    assert_eq!(
        unsafe { libc::ioctl(probe.as_raw_fd(), request as _, 0) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::EACCES)
    );
    publish_handoff(&result.with_extension("armed"), &request.to_string())?;

    let status = Command::new(env!("CARGO_BIN_EXE_shoes"))
        .args(["-t", "2", "--no-reload"])
        .arg(config)
        .env("RUST_LOG", "info")
        .status()?;
    publish_handoff(result, &status.code().unwrap_or(-1).to_string())
}

fn publish_handoff(path: &Path, contents: &str) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))?;
    fs::rename(temporary, path)
}

async fn wait_for_exit(directory: &Path) -> io::Result<i32> {
    timeout(Duration::from_secs(10), async {
        loop {
            match fs::read_to_string(directory.join("exit")) {
                Ok(code) => {
                    return code
                        .parse()
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| {
        io::Error::other(format!(
            "filtered Shoes did not exit: {}",
            fs::read_to_string(directory.join("server.log")).unwrap_or_default()
        ))
    })?
}

fn assert_filter_armed(directory: &Path, request: u32) -> io::Result<()> {
    assert_eq!(
        fs::read_to_string(directory.join("exit.armed"))?,
        request.to_string()
    );
    Ok(())
}

fn assert_interface_removed(name: &str) -> io::Result<()> {
    assert!(
        !Path::new("/sys/class/net").join(name).try_exists()?,
        "leaked TUN {name}"
    );
    Ok(())
}

#[tokio::test]
async fn negotiation_failure_obeys_startup_policy() -> io::Result<()> {
    let peer = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
    for request in [
        libc::TUNSETVNETHDRSZ,
        libc::TUNSETVNETLE,
        libc::TUNSETOFFLOAD,
        libc::TUNGETVNETHDRSZ,
    ] {
        let request = request as u32;
        for offload in [None, Some(false)] {
            let directory = tempfile::tempdir()?;
            let tun = KernelTun::start_with(false, offload, 1500, 32768, |config| {
                start_filtered_server(config, request, directory.path())
            })
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; ioctl={request:#x}, offload={offload:?}: {}",
                        fs::read_to_string(directory.path().join("server.log")).unwrap_or_default()
                    ),
                )
            })?;
            assert_filter_armed(directory.path(), request)?;
            let flags = fs::read_to_string(format!("/sys/class/net/{}/tun_flags", tun.name))?;
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            assert_eq!(flags & libc::IFF_VNET_HDR as u32, 0);
            timeout(TEST_TIMEOUT, async {
                let connection = tun.connect_tcp(peer.local_addr().port()).await?;
                bulk_echo(connection, 4 * 1024 * 1024 + 7, 0).await
            })
            .await??;
            let log = fs::read_to_string(directory.path().join("server.log"))?;
            assert_eq!(
                log.contains("TUN transmit offload unavailable"),
                offload.is_none()
            );
            let name = tun.name.clone();
            drop(tun);
            assert_interface_removed(&name)?;
        }

        let directory = tempfile::tempdir()?;
        let name = format!("shdeny{:08x}", rand::random::<u32>());
        let config = format!(
            "- device_name: {name}\n  address: 10.203.254.1\n  netmask: 255.255.255.255\n  segmentation_offload: true\n"
        );
        let (process, _config) = start_filtered_server(&config, request, directory.path())?;
        let code = wait_for_exit(directory.path()).await?;
        let log = fs::read_to_string(directory.path().join("server.log"))?;
        assert_filter_armed(directory.path(), request)?;
        assert_eq!(code, 1, "required offload must fail startup: {log}");
        assert!(
            log.contains("Permission denied"),
            "wrong startup failure: {log}"
        );
        assert!(
            !log.contains("Servers ready"),
            "startup falsely succeeded: {log}"
        );
        assert_interface_removed(&name)?;
        drop(process);
    }
    Ok(())
}
