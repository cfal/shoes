use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const PROCESS_GROUP_TERM_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const PROCESS_GROUP_KILL_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const PROCESS_GROUP_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(target_os = "linux")]
const PRIVILEGED_START_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const PRIVILEGED_SESSION_SCRIPT: &str = r#"
set -eu
pid_file=$1
ack_file=$2
ready_file=$3
handoff_dir=$4
shift 4
trap ':' TERM
printf '%s\n' "$$" > "$pid_file"
while :; do
    [ -d "$handoff_dir" ] || exit 125
    if [ -f "$ack_file" ]; then
        acknowledgement=$(cat "$ack_file") || continue
        [ "$acknowledgement" = continue ] || exit 125
        break
    fi
    sleep 0.05 || true
done
"$@" &
service=$!
printf 'ready\n' > "$ready_file" || true
wait "$service" || true
while :; do
    sleep 3600 &
    wait "$!" || true
done
"#;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum CleanupTarget {
    Child,
    ProcessGroup { id: i32, use_sudo: bool },
}

/// Kills and reaps an owned child process when dropped.
pub struct ProcessGuard {
    process: Option<Child>,
    name: String,
    #[cfg(target_os = "linux")]
    cleanup_target: CleanupTarget,
}

impl ProcessGuard {
    pub fn new(process: Child, name: impl Into<String>) -> Self {
        let name = name.into();
        eprintln!("[GUARD] Created guard for {} (PID: {})", name, process.id());
        Self {
            process: Some(process),
            name,
            #[cfg(target_os = "linux")]
            cleanup_target: CleanupTarget::Child,
        }
    }

    #[cfg(target_os = "linux")]
    fn with_process_group(
        process: Child,
        name: impl Into<String>,
        process_group_id: i32,
        use_sudo: bool,
    ) -> Self {
        let name = name.into();
        eprintln!(
            "[GUARD] Created guard for {} (supervisor PID: {}, process group: {})",
            name,
            process.id(),
            process_group_id
        );
        Self {
            process: Some(process),
            name,
            cleanup_target: CleanupTarget::ProcessGroup {
                id: process_group_id,
                use_sudo,
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn child_mut(&mut self) -> &mut Child {
        self.process.as_mut().expect("process guard has no child")
    }

    #[cfg(all(test, target_os = "linux"))]
    fn disarm_process_group(&mut self) {
        self.cleanup_target = CleanupTarget::Child;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let Some(mut process) = self.process.take() else {
            return;
        };

        let pid = process.id();
        eprintln!(
            "[GUARD] Dropping guard for {} (PID: {}), killing process...",
            self.name, pid
        );

        #[cfg(target_os = "linux")]
        let process_group = match self.cleanup_target {
            CleanupTarget::ProcessGroup { id, use_sudo } => Some((id, use_sudo)),
            CleanupTarget::Child => None,
        };
        #[cfg(target_os = "linux")]
        if let Some((id, use_sudo)) = process_group {
            terminate_process_group(id, use_sudo, &self.name);
        }

        match process.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = process.kill()
                    && error.kind() != io::ErrorKind::InvalidInput
                {
                    eprintln!("[GUARD] Could not kill {}: {}", self.name, error);
                }
            }
            Err(error) => eprintln!("[GUARD] Could not inspect {}: {}", self.name, error),
        }
        if let Err(error) = process.wait() {
            eprintln!("[GUARD] Could not reap {}: {}", self.name, error);
        }
        #[cfg(target_os = "linux")]
        if let Some((id, use_sudo)) = process_group {
            report_lingering_process_group(id, use_sudo, &self.name);
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn spawn_privileged_process(
    program: &Path,
    name: impl Into<String>,
    configure: impl FnOnce(&mut Command),
) -> io::Result<ProcessGuard> {
    let startup_directory = tempfile::tempdir()?;
    let process_group_file = startup_directory.path().join("process-group");
    let acknowledgement_file = startup_directory.path().join("continue");
    let ready_file = startup_directory.path().join("ready");
    fs::write(&process_group_file, [])?;
    fs::write(&ready_file, [])?;

    let mut command = Command::new("sudo");
    command
        .args(["-n", "-E", "--", "setsid", "--wait", "sh", "-c"])
        .arg(PRIVILEGED_SESSION_SCRIPT)
        .arg("shoes-test-session")
        .arg(&process_group_file)
        .arg(&acknowledgement_file)
        .arg(&ready_file)
        .arg(startup_directory.path())
        .arg(program);
    configure(&mut command);

    let mut process = command.spawn()?;
    let process_group_id = match wait_for_session_process_group(
        &mut process,
        &process_group_file,
        PRIVILEGED_START_TIMEOUT,
    ) {
        Ok(process_group_id) => process_group_id,
        Err(error) => {
            cancel_privileged_start(&mut process, &acknowledgement_file);
            return Err(error);
        }
    };
    let mut guard = ProcessGuard::with_process_group(process, name, process_group_id, true);
    publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
    wait_for_startup_marker(guard.child_mut(), &ready_file, PRIVILEGED_START_TIMEOUT)?;

    Ok(guard)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn spawn_privileged_process(
    _program: &Path,
    _name: impl Into<String>,
    _configure: impl FnOnce(&mut Command),
) -> io::Result<ProcessGuard> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "privileged test processes are supported only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn wait_for_startup_marker(
    supervisor: &mut Child,
    path: &Path,
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(contents) if contents == "ready\n" => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if child_exited_without_reaping(supervisor.id() as i32)? {
            return Err(io::Error::other(
                "privileged process supervisor exited before acknowledgement",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out acknowledging privileged process startup",
            ));
        }
        thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn terminate_and_reap_child(process: &mut Child) {
    if process.try_wait().ok().flatten().is_none() {
        let _ = process.kill();
    }
    let _ = process.wait();
}

#[cfg(target_os = "linux")]
fn cancel_privileged_start(process: &mut Child, acknowledgement_file: &Path) {
    cancel_privileged_start_with_timeout(process, acknowledgement_file, PRIVILEGED_START_TIMEOUT);
}

#[cfg(target_os = "linux")]
fn cancel_privileged_start_with_timeout(
    process: &mut Child,
    acknowledgement_file: &Path,
    timeout: Duration,
) {
    let _ = publish_startup_acknowledgement(acknowledgement_file, "cancel");
    let deadline = Instant::now() + timeout;
    loop {
        match process.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
    terminate_and_reap_child(process);
}

#[cfg(target_os = "linux")]
fn publish_startup_acknowledgement(path: &Path, value: &str) -> io::Result<()> {
    let pending_path = path.with_extension("pending");
    fs::write(&pending_path, format!("{value}\n"))?;
    fs::rename(pending_path, path)
}

#[cfg(target_os = "linux")]
fn child_exited_without_reaping(process_id: i32) -> io::Result<bool> {
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            process_id as libc::id_t,
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok(unsafe { information.si_pid() } != 0)
}

#[cfg(target_os = "linux")]
fn wait_for_session_process_group(
    supervisor: &mut Child,
    process_group_file: &Path,
    timeout: Duration,
) -> io::Result<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        let contents = fs::read_to_string(process_group_file)?;
        if !contents.trim().is_empty() {
            let process_group_id = contents.trim().parse::<i32>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid privileged process group ID: {error}"),
                )
            })?;
            if process_group_id <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "privileged process group ID must be positive",
                ));
            }

            let actual_process_group = unsafe { libc::getpgid(process_group_id) };
            let actual_session = unsafe { libc::getsid(process_group_id) };
            if actual_process_group != process_group_id || actual_session != process_group_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "privileged process {process_group_id} did not become its own session and process-group leader"
                    ),
                ));
            }
            return Ok(process_group_id);
        }

        if child_exited_without_reaping(supervisor.id() as i32)? {
            return Err(io::Error::other(
                "privileged process supervisor exited before startup",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for privileged process startup",
            ));
        }
        thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn terminate_process_group(process_group_id: i32, use_sudo: bool, name: &str) {
    if let Err(error) = signal_process_group(process_group_id, libc::SIGTERM, use_sudo)
        && process_group_exists(process_group_id, use_sudo).unwrap_or(true)
    {
        eprintln!("[GUARD] Could not terminate process group for {name}: {error}");
    }

    if wait_for_process_group_exit(process_group_id, use_sudo, PROCESS_GROUP_TERM_TIMEOUT) {
        return;
    }

    if let Err(error) = signal_process_group(process_group_id, libc::SIGKILL, use_sudo)
        && process_group_exists(process_group_id, use_sudo).unwrap_or(true)
    {
        eprintln!("[GUARD] Could not kill process group for {name}: {error}");
    }
}

#[cfg(target_os = "linux")]
fn report_lingering_process_group(process_group_id: i32, use_sudo: bool, name: &str) {
    if !wait_for_process_group_exit(process_group_id, use_sudo, PROCESS_GROUP_KILL_TIMEOUT) {
        eprintln!("[GUARD] Process group {process_group_id} for {name} still exists after cleanup");
    }
}

#[cfg(target_os = "linux")]
fn signal_process_group(process_group_id: i32, signal: i32, use_sudo: bool) -> io::Result<()> {
    if use_sudo {
        let signal = match signal {
            libc::SIGTERM => "-TERM",
            libc::SIGKILL => "-KILL",
            _ => return Err(io::Error::other("unsupported process-group signal")),
        };
        let output = sudo_kill(&[signal, "--", &format!("-{process_group_id}")])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    } else {
        let result = unsafe { libc::kill(-process_group_id, signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "linux")]
fn process_group_exists(process_group_id: i32, use_sudo: bool) -> io::Result<bool> {
    if use_sudo {
        let output = sudo_kill(&["-0", "--", &format!("-{process_group_id}")])?;
        if output.status.success() {
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such process") {
                Ok(false)
            } else {
                Err(io::Error::other(stderr.trim().to_string()))
            }
        }
    } else {
        let result = unsafe { libc::kill(-process_group_id, 0) };
        if result == 0 {
            Ok(true)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else if error.raw_os_error() == Some(libc::EPERM) {
                Ok(true)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn sudo_kill(arguments: &[&str]) -> io::Result<std::process::Output> {
    Command::new("sudo")
        .args(["-n", "kill"])
        .args(arguments)
        .env("LC_ALL", "C")
        .output()
}

#[cfg(target_os = "linux")]
fn wait_for_process_group_exit(process_group_id: i32, use_sudo: bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match process_group_exists(process_group_id, use_sudo) {
            Ok(false) => return true,
            Ok(true) => {}
            Err(error) => {
                eprintln!("[GUARD] Could not inspect process group {process_group_id}: {error}");
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingBoxCapability {
    Standard,
    NaiveOutbound,
}

pub fn find_singbox_binary() -> io::Result<PathBuf> {
    find_singbox_binary_with(SingBoxCapability::Standard)
}

pub fn find_singbox_naive_binary() -> io::Result<PathBuf> {
    find_singbox_binary_with(SingBoxCapability::NaiveOutbound)
}

pub fn find_singbox_binary_with(capability: SingBoxCapability) -> io::Result<PathBuf> {
    let override_name = match capability {
        SingBoxCapability::Standard => "SHOES_TEST_SING_BOX_BIN",
        SingBoxCapability::NaiveOutbound => "SHOES_TEST_SING_BOX_NAIVE_BIN",
    };

    if let Some(path) = std::env::var_os(override_name) {
        let path = PathBuf::from(path);
        validate_singbox_binary(&path, capability).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("invalid {override_name} value {}: {error}", path.display()),
            )
        })?;
        return Ok(path);
    }

    if capability == SingBoxCapability::NaiveOutbound
        && let Some(path) = std::env::var_os("SHOES_TEST_SING_BOX_BIN")
    {
        let path = PathBuf::from(path);
        validate_singbox_binary(&path, capability).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "invalid SHOES_TEST_SING_BOX_BIN value {}: {error}",
                    path.display()
                ),
            )
        })?;
        return Ok(path);
    }

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut candidates = Vec::new();
    if capability == SingBoxCapability::NaiveOutbound {
        candidates.push(PathBuf::from("/sing-box/sing-box-naive"));
    }
    candidates.extend([
        PathBuf::from("/sing-box/sing-box"),
        PathBuf::from("sing-box"),
    ]);
    if let Some(home) = home {
        candidates.push(home.join("go/bin/sing-box"));
        candidates.push(home.join(".asdf/shims/sing-box"));
    }
    candidates.extend([
        PathBuf::from("/usr/local/bin/sing-box"),
        PathBuf::from("/usr/bin/sing-box"),
    ]);

    let mut failures = Vec::new();
    for path in candidates {
        match validate_singbox_binary(&path, capability) {
            Ok(version) => {
                eprintln!(
                    "[SING_BOX] Using {} ({})",
                    path.display(),
                    version.lines().next().unwrap_or("version unknown")
                );
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!("{}: {error}", path.display())),
        }
    }

    let requirement = match capability {
        SingBoxCapability::Standard => "a working sing-box executable",
        SingBoxCapability::NaiveOutbound => "sing-box built with with_naive_outbound",
    };
    let details = if failures.is_empty() {
        String::new()
    } else {
        format!("; rejected candidates: {}", failures.join(", "))
    };
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "could not find {requirement}; set {override_name} to an explicit executable{details}"
        ),
    ))
}

fn validate_singbox_binary(path: &Path, capability: SingBoxCapability) -> io::Result<String> {
    let output = Command::new(path).arg("version").output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "`{} version` failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }

    let version = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if capability == SingBoxCapability::NaiveOutbound && !version.contains("with_naive_outbound") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "missing with_naive_outbound build tag",
        ));
    }
    Ok(version)
}

pub fn start_singbox_server(config: &str) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    start_singbox_server_with(config, SingBoxCapability::Standard, &[])
}

pub fn start_singbox_server_with(
    config: &str,
    capability: SingBoxCapability,
    environment: &[(&str, &str)],
) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    let binary = find_singbox_binary_with(capability)?;
    start_singbox_server_with_binary(config, &binary, environment)
}

pub fn start_singbox_server_with_binary<K, V>(
    config: &str,
    binary: &Path,
    environment: &[(K, V)],
) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)>
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    eprintln!("========== SING-BOX CONFIG ==========");
    eprintln!("{config}");
    eprintln!("========== END CONFIG ==========");

    let mut config_file = tempfile::NamedTempFile::new()?;
    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;

    let mut command = Command::new(binary);
    command
        .arg("run")
        .arg("-c")
        .arg(config_file.path())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (name, value) in environment {
        command.env(name, value);
    }

    let child = command.spawn()?;
    Ok((ProcessGuard::new(child, "sing-box"), config_file))
}

pub fn find_mihomo_binary() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SHOES_TEST_MIHOMO_BIN") {
        let path = PathBuf::from(path);
        validate_mihomo_binary(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "invalid SHOES_TEST_MIHOMO_BIN value {}: {error}",
                    path.display()
                ),
            )
        })?;
        return Ok(path);
    }

    let mut candidates = vec![PathBuf::from("mihomo")];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        candidates.push(home.join("go/bin/mihomo"));
        candidates.push(home.join(".asdf/shims/mihomo"));
    }
    candidates.extend([
        PathBuf::from("/usr/local/bin/mihomo"),
        PathBuf::from("/usr/bin/mihomo"),
    ]);

    for path in candidates {
        match validate_mihomo_binary(&path) {
            Ok(version) => {
                eprintln!(
                    "[MIHOMO] Using {} ({})",
                    path.display(),
                    version.lines().next().unwrap_or("version unknown")
                );
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not find a working mihomo executable; set SHOES_TEST_MIHOMO_BIN",
    ))
}

fn validate_mihomo_binary(path: &Path) -> io::Result<String> {
    let output = Command::new(path).arg("-v").output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "`{} -v` failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

pub fn start_mihomo_server(config: &str) -> io::Result<(ProcessGuard, tempfile::NamedTempFile)> {
    let mut config_file = tempfile::NamedTempFile::new()?;
    config_file.write_all(config.as_bytes())?;
    config_file.flush()?;

    let child = Command::new(find_mihomo_binary()?)
        .arg("-f")
        .arg(config_file.path())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok((ProcessGuard::new(child, "mihomo"), config_file))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::sync::mpsc;

    const NESTED_SERVICE_SCRIPT: &str = r#"
set -eu
descendant_file=$1
trap '' TERM
sh -c '
    set -eu
    descendant_file=$1
    trap "" TERM
    sleep 30 &
    leaf=$!
    printf "%s\n" "$leaf" > "$descendant_file"
    wait "$leaf"
' nested-child "$descendant_file" &
middle=$!
wait "$middle"
"#;

    #[test]
    fn process_group_guard_kills_term_resistant_nested_descendants() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        let descendant_file = tempfile::NamedTempFile::new()?;
        fs::write(&process_group_file, [])?;
        fs::write(&ready_file, [])?;

        let supervisor = Command::new("sh")
            .arg("-c")
            .arg("setsid --wait \"$@\" & wait")
            .arg("process-supervisor")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("nested-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("sh")
            .arg("-c")
            .arg(NESTED_SERVICE_SCRIPT)
            .arg("nested-service")
            .arg(descendant_file.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "nested-process-test",
            Duration::from_secs(2),
        )?;
        publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
        wait_for_startup_marker(guard.child_mut(), &ready_file, Duration::from_secs(2))?;
        let descendant_id = wait_for_pid_file(descendant_file.path(), Duration::from_secs(2))?;
        assert_eq!(unsafe { libc::getpgid(descendant_id) }, process_group_id);

        drop(guard);

        assert!(!process_exists(descendant_id));
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    #[test]
    fn cancelled_startup_never_executes_service() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        let service_marker = startup_directory.path().join("service-executed");
        fs::write(&process_group_file, [])?;

        let delayed_script = format!("sleep 0.2\n{PRIVILEGED_SESSION_SCRIPT}");
        let mut supervisor = Command::new("setsid")
            .arg("--wait")
            .arg("sh")
            .arg("-c")
            .arg(delayed_script)
            .arg("delayed-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("sh")
            .arg("-c")
            .arg("printf 'executed\\n' > \"$1\"")
            .arg("service")
            .arg(&service_marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let result = wait_for_session_process_group(
            &mut supervisor,
            &process_group_file,
            Duration::from_millis(50),
        );
        cancel_privileged_start(&mut supervisor, &acknowledgement_file);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        assert!(!ready_file.exists());
        assert!(!service_marker.exists());
        Ok(())
    }

    #[test]
    fn session_leader_reserves_process_group_after_service_exit() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        fs::write(&process_group_file, [])?;
        fs::write(&ready_file, [])?;

        let supervisor = Command::new("setsid")
            .arg("--wait")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("persistent-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "persistent-session-test",
            Duration::from_secs(2),
        )?;
        publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
        wait_for_startup_marker(guard.child_mut(), &ready_file, Duration::from_secs(2))?;
        thread::sleep(Duration::from_millis(100));

        assert!(!child_exited_without_reaping(guard.child_mut().id() as i32)?);
        assert!(process_group_exists(process_group_id, false)?);
        assert_eq!(unsafe { libc::getsid(process_group_id) }, process_group_id);

        drop(guard);
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    #[test]
    fn readiness_failure_keeps_process_group_reserved() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        fs::write(&process_group_file, [])?;

        let supervisor = Command::new("setsid")
            .arg("--wait")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("readiness-failure-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg("/dev/full")
            .arg(startup_directory.path())
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        let supervisor_pid = supervisor.id() as i32;
        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "readiness-failure-test",
            Duration::from_secs(2),
        )?;
        assert_eq!(supervisor_pid, process_group_id);
        let stderr = guard
            .child_mut()
            .stderr
            .take()
            .expect("missing supervisor stderr");
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr_reader = thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::BufReader::new(stderr)
                .read_line(&mut line)
                .map(|_| line);
            let _ = stderr_tx.send(result);
        });
        publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
        let readiness_error = stderr_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))??;
        stderr_reader
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))?;

        assert!(readiness_error.contains("printf"), "{readiness_error:?}");
        observe_child_running_without_reaping(process_group_id, Duration::from_millis(500))?;
        assert!(process_group_exists(process_group_id, false)?);
        assert_eq!(unsafe { libc::getsid(process_group_id) }, process_group_id);

        drop(guard);
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    #[test]
    fn session_leader_survives_term_before_acknowledgement() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        let service_marker = startup_directory.path().join("service-executed");
        fs::write(&process_group_file, [])?;
        fs::write(&ready_file, [])?;

        let supervisor = Command::new("setsid")
            .arg("--wait")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("term-before-ack-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("sh")
            .arg("-c")
            .arg("printf 'executed\\n' > \"$1\"")
            .arg("service")
            .arg(&service_marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "term-before-ack-test",
            Duration::from_secs(2),
        )?;

        signal_process_group(process_group_id, libc::SIGTERM, false)?;
        thread::sleep(Duration::from_millis(100));
        assert!(process_group_exists(process_group_id, false)?);
        publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
        wait_for_startup_marker(guard.child_mut(), &ready_file, Duration::from_secs(2))?;
        wait_for_nonempty_file(&service_marker, Duration::from_secs(2))?;

        drop(guard);
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    #[test]
    fn cancelled_stalled_leader_exits_after_handoff_removal() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        fs::write(&process_group_file, [])?;
        fs::write(&ready_file, [])?;

        let supervisor = Command::new("sh")
            .arg("-c")
            .arg("setsid --wait \"$@\" & wait")
            .arg("process-supervisor")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("stalled-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "stalled-session-test",
            Duration::from_secs(2),
        )?;
        let stop_result = unsafe { libc::kill(process_group_id, libc::SIGSTOP) };
        if stop_result != 0 {
            return Err(io::Error::last_os_error());
        }

        cancel_privileged_start_with_timeout(
            guard.child_mut(),
            &acknowledgement_file,
            Duration::from_millis(50),
        );
        drop(startup_directory);
        let continue_result = unsafe { libc::kill(process_group_id, libc::SIGCONT) };
        if continue_result != 0 {
            return Err(io::Error::last_os_error());
        }
        wait_for_process_exit(process_group_id, Duration::from_secs(2))?;

        guard.disarm_process_group();
        drop(guard);
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    #[test]
    fn session_leader_survives_term_without_changing_service_handling() -> io::Result<()> {
        let startup_directory = tempfile::tempdir()?;
        let process_group_file = startup_directory.path().join("process-group");
        let acknowledgement_file = startup_directory.path().join("continue");
        let ready_file = startup_directory.path().join("ready");
        let service_pid_file = startup_directory.path().join("service-pid");
        fs::write(&process_group_file, [])?;
        fs::write(&ready_file, [])?;
        fs::write(&service_pid_file, [])?;

        let supervisor = Command::new("setsid")
            .arg("--wait")
            .arg("sh")
            .arg("-c")
            .arg(PRIVILEGED_SESSION_SCRIPT)
            .arg("term-session")
            .arg(&process_group_file)
            .arg(&acknowledgement_file)
            .arg(&ready_file)
            .arg(startup_directory.path())
            .arg("sh")
            .arg("-c")
            .arg("printf '%s\\n' \"$$\" > \"$1\"; exec sleep 30")
            .arg("service")
            .arg(&service_pid_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let (mut guard, process_group_id) = acquire_test_process_group(
            supervisor,
            &process_group_file,
            &acknowledgement_file,
            "term-session-test",
            Duration::from_secs(2),
        )?;
        publish_startup_acknowledgement(&acknowledgement_file, "continue")?;
        wait_for_startup_marker(guard.child_mut(), &ready_file, Duration::from_secs(2))?;
        let service_pid = wait_for_pid_file(&service_pid_file, Duration::from_secs(2))?;

        signal_process_group(process_group_id, libc::SIGTERM, false)?;
        wait_for_process_exit(service_pid, Duration::from_secs(2))?;
        assert!(!child_exited_without_reaping(guard.child_mut().id() as i32)?);
        assert!(process_group_exists(process_group_id, false)?);

        drop(guard);
        assert!(!process_group_exists(process_group_id, false)?);
        Ok(())
    }

    fn acquire_test_process_group(
        mut supervisor: Child,
        process_group_file: &Path,
        acknowledgement_file: &Path,
        name: &str,
        timeout: Duration,
    ) -> io::Result<(ProcessGuard, i32)> {
        match wait_for_session_process_group(&mut supervisor, process_group_file, timeout) {
            Ok(process_group_id) => Ok((
                ProcessGuard::with_process_group(supervisor, name, process_group_id, false),
                process_group_id,
            )),
            Err(error) => {
                cancel_privileged_start(&mut supervisor, acknowledgement_file);
                Err(error)
            }
        }
    }

    fn wait_for_pid_file(path: &Path, timeout: Duration) -> io::Result<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            let contents = fs::read_to_string(path)?;
            if !contents.trim().is_empty() {
                return contents.trim().parse::<i32>().map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("invalid PID: {error}"))
                });
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for descendant PID",
                ));
            }
            thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
        }
    }

    fn wait_for_nonempty_file(path: &Path, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match fs::read(path) {
                Ok(contents) if !contents.is_empty() => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for file contents",
                ));
            }
            thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
        }
    }

    fn process_exists(process_id: i32) -> bool {
        let result = unsafe { libc::kill(process_id, 0) };
        result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn wait_for_process_exit(process_id: i32, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while process_exists(process_id) {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("process {process_id} did not exit"),
                ));
            }
            thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
        }
        Ok(())
    }

    fn observe_child_running_without_reaping(
        process_id: i32,
        duration: Duration,
    ) -> io::Result<()> {
        let deadline = Instant::now() + duration;
        loop {
            if child_exited_without_reaping(process_id)? {
                return Err(io::Error::other(format!(
                    "process {process_id} exited during the observation window"
                )));
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(PROCESS_GROUP_POLL_INTERVAL);
        }
    }
}
