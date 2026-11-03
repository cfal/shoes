use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

fn raw_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[track_caller]
fn assert_system_clock() {
    let corrected = crate::clock::unix_seconds().unwrap();
    assert!(corrected.abs_diff(raw_seconds()) <= 1);
}

#[tokio::test]
async fn ntp_ffi_cancellation_errors_abort_and_restart_release_the_clock() {
    const CHILD: &str = "SHOES_FFI_NTP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        shoes_test_support::isolated::run_isolated(
            "ffi::common::ntp_tests::ntp_ffi_cancellation_errors_abort_and_restart_release_the_clock",
            CHILD,
            "1",
        );
        return;
    }
    let (_peer, tun) = UnixDatagram::pair().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = format!(
        "- global_settings: {{ntp: {{server: '{}', timeout_secs: 30}}}}\n- device_fd: {}\n",
        socket.local_addr().unwrap(),
        tun.as_raw_fd(),
    );
    let (shutdown, receiver) = oneshot::channel();
    let source = config.clone();
    let task = tokio::spawn(async move { start_from_config(&source, receiver).await });
    let mut request = [0; 48];
    timeout(Duration::from_secs(3), socket.recv_from(&mut request))
        .await
        .unwrap()
        .unwrap();
    shutdown.send(()).unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_system_clock();

    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let responder = tokio::spawn(async move {
        loop {
            let (_, peer) = socket.recv_from(&mut request).await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let mut response = [0; 48];
            response[0] = 0x24;
            response[1] = 1;
            response[3] = (-20i8) as u8;
            response[24..32].copy_from_slice(&request[40..48]);
            let timestamp = u64::from_be_bytes(request[40..48].try_into().unwrap())
                .wrapping_add(600u64 << 32)
                .to_be_bytes();
            response[32..40].copy_from_slice(&timestamp);
            response[40..48].copy_from_slice(&timestamp);
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let invalid = format!(
        "{config}- path: '{}'\n  protocol: {{type: http}}\n",
        directory.path().join("missing/listener.sock").display()
    );
    let (_shutdown, receiver) = oneshot::channel();
    assert!(start_from_config(&invalid, receiver).await.is_err());
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    assert_system_clock();

    for abort in [false, true] {
        let (shutdown, receiver) = oneshot::channel();
        let source = config.clone();
        let task = tokio::spawn(async move { start_from_config(&source, receiver).await });
        timeout(Duration::from_secs(3), async {
            while crate::clock::unix_seconds()
                .unwrap()
                .abs_diff(raw_seconds() + 600)
                > 2
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if abort {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            shutdown.send(()).unwrap();
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        assert_system_clock();
    }
    let disabled = format!("- device_fd: {}\n", tun.as_raw_fd());
    let (shutdown, receiver) = oneshot::channel();
    let task = tokio::spawn(async move { start_from_config(&disabled, receiver).await });
    sleep(Duration::from_millis(50)).await;
    assert_system_clock();
    shutdown.send(()).unwrap();
    task.await.unwrap().unwrap();
    responder.abort();
    let _ = responder.await;
}
