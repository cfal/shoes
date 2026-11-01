//! Curl helper utilities for integration tests

use std::process::Output;

/// Options for configuring curl requests
pub struct CurlOptions {
    /// HTTP proxy to use (e.g., "http://127.0.0.1:8080")
    pub proxy: Option<String>,
    /// Network interface to use (e.g., "eth0", "tun0")
    pub interface: Option<String>,
    /// Accept insecure/self-signed TLS certificates
    pub insecure: bool,
    /// Force specific TLS version (e.g., "1.2" or "1.3")
    pub tls_version: Option<String>,
    /// Maximum TLS version (e.g., "1.2" to force exactly TLS 1.2)
    pub tls_max_version: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u32,
    /// Custom HTTP headers
    pub headers: Vec<(String, String)>,
    /// Binary data to POST (sent via stdin using --data-binary @-)
    pub post_data: Option<Vec<u8>>,
    /// HTTP method (e.g., "GET", "POST", "PUT", etc.)
    pub method: Option<String>,
    /// DNS resolve entries (e.g., "example.com:443:127.0.0.1")
    pub resolve: Vec<String>,
    /// Discard output (pipe to /dev/null) - for benchmarking large transfers
    pub discard_output: bool,
    /// Fail on HTTP error responses (4xx, 5xx) - uses curl --fail
    pub fail_on_http_error: bool,
    /// Force HTTP version: "1.1" or "2"
    pub http_version: Option<String>,
    /// Include HTTP response headers in output (-i)
    pub include_headers: bool,
    /// Write response headers to stderr (-D /dev/stderr)
    pub headers_to_stderr: bool,
}

impl Default for CurlOptions {
    fn default() -> Self {
        Self {
            proxy: None,
            interface: None,
            insecure: false,
            tls_version: None,
            tls_max_version: None,
            timeout_secs: 10,
            headers: Vec::new(),
            post_data: None,
            method: None,
            resolve: Vec::new(),
            discard_output: false,
            fail_on_http_error: false,
            http_version: None,
            include_headers: false,
            headers_to_stderr: false,
        }
    }
}

impl CurlOptions {
    /// Create new curl options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set HTTP proxy
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Set network interface to use (e.g., "tun0", "eth0")
    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    /// Accept insecure TLS certificates
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Force specific TLS version
    pub fn tls_version(mut self, version: impl Into<String>) -> Self {
        self.tls_version = Some(version.into());
        self
    }

    /// Set maximum TLS version
    pub fn tls_max_version(mut self, version: impl Into<String>) -> Self {
        self.tls_max_version = Some(version.into());
        self
    }

    /// Set request timeout
    pub fn timeout(mut self, secs: u32) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Add a custom HTTP header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set binary data to POST (will be sent via stdin to curl using --data-binary @-)
    pub fn post_data(mut self, data: Vec<u8>) -> Self {
        self.post_data = Some(data);
        self
    }

    /// Set HTTP method (e.g., "GET", "POST", "PUT", etc.)
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Set request body (alias for post_data for consistency)
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.post_data = Some(data);
        self
    }

    /// Add a DNS resolve entry (e.g., "example.com:443:127.0.0.1")
    pub fn resolve(mut self, entry: impl Into<String>) -> Self {
        self.resolve.push(entry.into());
        self
    }

    /// Discard output (pipe to /dev/null) - useful for benchmarking large transfers
    pub fn discard_output(mut self, discard: bool) -> Self {
        self.discard_output = discard;
        self
    }

    /// Fail on HTTP error responses (4xx, 5xx) - uses curl --fail
    pub fn fail_on_http_error(mut self, fail: bool) -> Self {
        self.fail_on_http_error = fail;
        self
    }

    /// Force HTTP version ("1.1" or "2")
    pub fn http_version(mut self, version: impl Into<String>) -> Self {
        self.http_version = Some(version.into());
        self
    }

    /// Include HTTP response headers in output (-i)
    pub fn include_headers(mut self, include: bool) -> Self {
        self.include_headers = include;
        self
    }

    /// Write HTTP response headers to stderr (-D /dev/stderr)
    pub fn headers_to_stderr(mut self, enabled: bool) -> Self {
        self.headers_to_stderr = enabled;
        self
    }
}

/// Run curl command with the given options
///
/// Dropping the request future requests termination of the direct curl child.
/// Cancellation reaping is best effort and may complete after the future is dropped.
/// Normal completion and stdin errors await child cleanup.
/// Handles common curl options including:
/// - HTTP proxy support
/// - TLS configuration
/// - Timeout handling
/// - POST data via stdin (using --data-binary @-)
/// - Automatic --noproxy="" to ignore no_proxy env var
///
/// # Arguments
/// * `url` - Target URL to fetch
/// * `options` - Curl configuration options
///
/// # Returns
/// Command output with stdout/stderr
pub async fn run_curl(url: &str, options: CurlOptions) -> std::io::Result<Output> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let curl = std::env::var_os("SHOES_TEST_CURL_BIN").unwrap_or_else(|| {
        if std::path::Path::new("/usr/bin/curl").is_file() {
            "/usr/bin/curl".into()
        } else {
            "curl".into()
        }
    });
    let mut cmd = tokio::process::Command::new(curl);
    cmd.arg("-q").kill_on_drop(true);

    // Explicitly unset proxy environment variables to prevent interference
    // as setting --noproxy is not sufficient
    cmd.env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("all_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("no_proxy")
        .env_remove("NO_PROXY");

    // Add proxy if specified
    if let Some(proxy) = &options.proxy {
        cmd.arg("--proxy").arg(proxy);
    }

    // Add interface if specified
    if let Some(iface) = &options.interface {
        cmd.arg("--interface").arg(iface);
    }

    // Add TLS options
    if options.insecure {
        cmd.arg("--insecure");
    }

    if let Some(version) = &options.tls_version {
        cmd.arg(format!("--tlsv{}", version));
    }

    if let Some(max_version) = &options.tls_max_version {
        cmd.arg("--tls-max").arg(max_version);
    }

    // Add custom headers
    for (name, value) in &options.headers {
        cmd.arg("-H").arg(format!("{}: {}", name, value));
    }

    // Add DNS resolve entries
    for entry in &options.resolve {
        cmd.arg("--resolve").arg(entry);
    }

    // Set HTTP method if specified
    if let Some(ref method) = options.method {
        cmd.arg("-X").arg(method);
    }

    // If POST data is provided, read from stdin using --data-binary @-
    if let Some(ref _data) = options.post_data {
        cmd.arg("--data-binary").arg("@-");
        cmd.stdin(Stdio::piped());
    }

    // Common curl options
    cmd.arg("--silent")
        .arg("--show-error")
        .arg("--no-buffer") // Disable output buffering for more realistic traffic patterns
        .arg("--max-time")
        .arg(options.timeout_secs.to_string());

    // Fail on HTTP error responses (4xx, 5xx)
    if options.fail_on_http_error {
        cmd.arg("--fail");
    }

    // Discard output to /dev/null for benchmarking (avoids memory buffering)
    if options.discard_output {
        cmd.arg("-o").arg("/dev/null");
    }

    // Force HTTP version
    if let Some(ref version) = options.http_version {
        match version.as_str() {
            "1.1" => cmd.arg("--http1.1"),
            "2" => cmd.arg("--http2"),
            _ => &mut cmd,
        };
    }

    // Include HTTP response headers in output
    if options.include_headers {
        cmd.arg("-i");
    }

    // Write headers to stderr
    if options.headers_to_stderr {
        cmd.arg("-D").arg("/dev/stderr");
    }

    cmd.arg(url);

    // Execute curl
    if let Some(data) = options.post_data {
        // Spawn with stdin pipe
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Write data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let written = async {
                stdin.write_all(&data).await?;
                stdin.flush().await
            }
            .await;
            drop(stdin);
            if let Err(error) = written {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(error);
            }
        }

        // Wait for completion and collect output
        child.wait_with_output().await
    } else {
        // Regular GET request
        cmd.stdin(Stdio::null()).output().await
    }
}

/// Extracts the last HTTP status from headers emitted by curl.
pub fn response_status(output: &Output) -> Option<u16> {
    response_status_from_headers(
        output
            .stderr
            .split(|byte| *byte == b'\n')
            .chain(output.stdout.split(|byte| *byte == b'\n')),
    )
}

fn response_status_from_headers<'a>(lines: impl Iterator<Item = &'a [u8]>) -> Option<u16> {
    lines
        .filter_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            let mut fields = line.trim_end_matches('\r').split_ascii_whitespace();
            fields.next()?.starts_with("HTTP/").then_some(())?;
            fields.next()?.parse().ok()
        })
        .last()
}

/// Convenient wrapper for simple HTTP GET requests through a proxy
pub async fn curl_via_proxy(proxy_url: &str, target_url: &str) -> std::io::Result<Output> {
    run_curl(target_url, CurlOptions::new().proxy(proxy_url).timeout(10)).await
}

/// Convenient wrapper for HTTPS GET requests through a proxy with insecure flag
pub async fn curl_https_insecure_via_proxy(
    proxy_url: &str,
    target_url: &str,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .insecure(true)
            .timeout(10),
    )
    .await
}

/// Convenient wrapper for TLS 1.2 HTTPS GET requests through a proxy
pub async fn curl_https_tls12_via_proxy(
    proxy_url: &str,
    target_url: &str,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .insecure(true)
            .tls_version("1.2")
            .tls_max_version("1.2")
            .timeout(10),
    )
    .await
}

/// Convenient wrapper for direct HTTP GET (no proxy)
pub async fn curl_direct(target_url: &str) -> std::io::Result<Output> {
    run_curl(target_url, CurlOptions::new().timeout(5)).await
}

/// Convenient wrapper for direct HTTPS GET with insecure flag (no proxy)
pub async fn curl_https_insecure_direct(target_url: &str) -> std::io::Result<Output> {
    run_curl(target_url, CurlOptions::new().insecure(true).timeout(5)).await
}

/// Convenient wrapper for direct HTTPS GET with TLS 1.2 (no proxy)
pub async fn curl_https_tls12_direct(target_url: &str) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .insecure(true)
            .tls_version("1.2")
            .tls_max_version("1.2")
            .timeout(5),
    )
    .await
}

/// Convenient wrapper for POST requests via proxy
pub async fn curl_post_via_proxy(
    proxy_url: &str,
    target_url: &str,
    data: Vec<u8>,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .post_data(data)
            .timeout(30),
    )
    .await
}

/// Convenient wrapper for POST requests via proxy over HTTPS
pub async fn curl_post_https_via_proxy(
    proxy_url: &str,
    target_url: &str,
    data: Vec<u8>,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .insecure(true)
            .post_data(data)
            .timeout(30),
    )
    .await
}

/// Convenient wrapper for POST requests via proxy over HTTPS/TLS 1.3
pub async fn curl_post_https_tls13_via_proxy(
    proxy_url: &str,
    target_url: &str,
    data: Vec<u8>,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .insecure(true)
            .tls_version("1.3")
            .tls_max_version("1.3")
            .post_data(data)
            .timeout(30),
    )
    .await
}

/// Convenient wrapper for POST requests via proxy over HTTPS/TLS 1.2
pub async fn curl_post_https_tls12_via_proxy(
    proxy_url: &str,
    target_url: &str,
    data: Vec<u8>,
) -> std::io::Result<Output> {
    run_curl(
        target_url,
        CurlOptions::new()
            .proxy(proxy_url)
            .insecure(true)
            .tls_version("1.2")
            .tls_max_version("1.2")
            .post_data(data)
            .timeout(30),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn post_body_closes_stdin_and_preserves_response_bytes() {
        let server = crate::test_servers::start_local_http_server("0.0.0.0", 0)
            .await
            .unwrap();
        let payload: Vec<_> = (0..131071).map(|index| (index * 37) as u8).collect();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            run_curl(
                &format!("http://127.0.0.1:{}/echo", server.local_addr().port()),
                CurlOptions::new()
                    .post_data(payload.clone())
                    .fail_on_http_error(true)
                    .timeout(5),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, payload);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cancellation_terminates_curl_during_output_and_stdin_waits() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        use std::time::Duration;

        const CHILD: &str = "SHOES_CURL_CANCEL_CHILD";
        const PID: &str = "SHOES_TEST_CURL_PID";
        if std::env::var_os(CHILD).is_none() {
            let directory = tempfile::tempdir().unwrap();
            let script = directory.path().join("curl");
            std::fs::write(
                &script,
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$SHOES_TEST_CURL_PID\"\nexec sleep 30\n",
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "curl::tests::cancellation_terminates_curl_during_output_and_stdin_waits",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("SHOES_TEST_CURL_BIN", script)
                .env(PID, directory.path().join("pid"))
                .output()
                .unwrap();
            crate::isolated::assert_one_test_passed(&output);
            return;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pid_file = std::path::PathBuf::from(std::env::var_os(PID).unwrap());
        for post in [false, true] {
            const BODY_SIZE: usize = 2 << 20;
            let options = if post {
                CurlOptions::new().post_data(vec![0; BODY_SIZE])
            } else {
                CurlOptions::new()
            };
            let mut request = Box::pin(run_curl("http://127.0.0.1/", options));
            let pid: libc::pid_t = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::select! {
                        result = &mut request => panic!("curl exited before cancellation: {result:?}"),
                        pid = async {
                            loop {
                                if let Ok(value) = std::fs::read_to_string(&pid_file)
                                    && let Some(value) = value.strip_suffix('\n')
                                    && let Ok(pid) = value.parse() {
                                    break pid;
                                }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        } => pid,
                    }
                }).await.unwrap()
            });
            let capacity = post.then(|| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(format!("/proc/{pid}/fd/0"))
                    .map(|stdin| unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_GETPIPE_SZ) })
            });
            let pending = runtime.block_on(async { futures::poll!(&mut request).is_pending() });
            drop(request);
            let exited = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                        let result = unsafe {
                            libc::waitid(
                                libc::P_PID,
                                pid as libc::id_t,
                                information.as_mut_ptr(),
                                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                            )
                        };
                        if result != 0 {
                            break std::io::Error::last_os_error().raw_os_error()
                                == Some(libc::ECHILD);
                        }
                        if unsafe { information.assume_init().si_pid() } == pid {
                            break true;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
            });
            // Reaps the observed exit, or disposes the still-owned child before failing.
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == 0 {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
            }
            assert!(
                pending,
                "post={post}: request completed before cancellation"
            );
            if let Some(capacity) = capacity {
                let capacity = capacity.unwrap();
                assert!(capacity > 0 && (capacity as usize) < BODY_SIZE);
            }
            assert_eq!(exited, Ok(true), "post={post}: curl survived cancellation");
            std::fs::remove_file(&pid_file).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_stdin_failure_terminates_and_reaps_curl() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        const CHILD: &str = "SHOES_CURL_STDIN_FAILURE_CHILD";
        const PID: &str = "SHOES_TEST_CURL_PID";
        if std::env::var_os(CHILD).is_none() {
            let directory = tempfile::tempdir().unwrap();
            let script = directory.path().join("curl");
            let pid_file = directory.path().join("pid");
            std::fs::write(
                &script,
                "#!/bin/sh\nprintf '%s' \"$$\" > \"$SHOES_TEST_CURL_PID\"\nexec 0<&-\nexec sleep 30\n",
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "curl::tests::post_stdin_failure_terminates_and_reaps_curl",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("SHOES_TEST_CURL_BIN", script)
                .env(PID, pid_file)
                .output()
                .unwrap();
            crate::isolated::assert_one_test_passed(&output);
            return;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = Instant::now();
        let result = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                run_curl(
                    "http://127.0.0.1/",
                    CurlOptions::new().post_data(vec![0; 1 << 20]),
                ),
            )
            .await
        });
        let elapsed = started.elapsed();
        let pid: libc::pid_t = std::fs::read_to_string(std::env::var_os(PID).unwrap())
            .unwrap()
            .parse()
            .unwrap();
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        let wait_error = std::io::Error::last_os_error().raw_os_error();
        // Cleans up the deliberately persistent fixture even when testing a broken helper.
        if waited == 0 {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
        }
        assert_eq!(
            result
                .expect("curl stdin failure stalled")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(!alive, "curl child survived the stdin error");
        assert_eq!(waited, -1, "curl child was not reaped before helper return");
        assert_eq!(wait_error, Some(libc::ECHILD));
        assert!(elapsed < Duration::from_secs(5));
    }

    #[test]
    fn extracts_last_response_status() {
        let headers = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/2 200\r\n";
        assert_eq!(
            response_status_from_headers(headers.split(|b| *b == b'\n')),
            Some(200)
        );
    }

    #[test]
    fn ignores_non_header_numbers() {
        let headers = b"response 500\ncurl completed in 200ms";
        assert_eq!(
            response_status_from_headers(headers.split(|b| *b == b'\n')),
            None
        );
    }
}
