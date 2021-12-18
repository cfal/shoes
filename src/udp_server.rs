use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use futures::join;
use log::{debug, error, warn};
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use crate::address::Location;
use crate::config::ServerConfig;
use crate::protocol_handler::{
    DecryptUdpMessageResult, EncryptUdpMessageResult, UdpMessageHandler,
};
use crate::resolver::{NativeResolver, Resolver};

const MAX_UDP_PACKET_SIZE: usize = 65536;

#[inline]
fn get_timestamp_secs() -> u32 {
    SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() as u32
}

enum UdpAction {
    Block,
    Forward(Box<dyn UdpForwarder>),
}

trait UdpForwarder: Send + Sync {
    fn try_send(&self, data: &[u8]) -> std::io::Result<()>;
    fn maybe_stop(&self, current_timestamp: u32) -> bool;
}

struct DirectForwarder {
    tx: Sender<Box<[u8]>>,
    join_handle: JoinHandle<std::io::Result<()>>,
    last_active_time_secs: Arc<AtomicU32>,
}

impl DirectForwarder {
    fn new(
        user_address: SocketAddr,
        server_socket: Arc<UdpSocket>,
        server_handler: Arc<dyn UdpMessageHandler>,
        resolver: Arc<dyn Resolver>,
        remote_location: Location,
    ) -> Self {
        let (tx, rx) = channel::<Box<[u8]>>(1024);

        let last_active_time_secs = Arc::new(AtomicU32::new(get_timestamp_secs()));

        let join_handle = {
            let cloned_time_secs = last_active_time_secs.clone();
            tokio::spawn(async move {
                let remote_address = resolver.resolve_location(&remote_location).await?;

                let remote_socket = UdpSocket::bind("0.0.0.0:0").await?;
                remote_socket.connect(remote_address).await?;

                let remote_socket = Arc::new(remote_socket);

                join!(
                    Self::forward_to_remote_task(
                        rx,
                        remote_socket.clone(),
                        cloned_time_secs.clone()
                    ),
                    Self::forward_from_remote_task(
                        remote_address,
                        remote_socket,
                        server_handler,
                        server_socket,
                        user_address,
                        cloned_time_secs
                    ),
                );
                Ok(())
            })
        };

        Self {
            tx,
            join_handle,
            last_active_time_secs,
        }
    }

    async fn forward_to_remote_task(
        mut rx: Receiver<Box<[u8]>>,
        remote_socket: Arc<UdpSocket>,
        last_active_time_secs: Arc<AtomicU32>,
    ) {
        while let Some(decrypted_data) = rx.recv().await {
            if let Err(e) = remote_socket.send(&decrypted_data).await {
                error!("Failed to forward data directly: {}", e);
            }
            last_active_time_secs.store(get_timestamp_secs(), Ordering::Relaxed);
        }
    }

    async fn forward_from_remote_task(
        remote_address: SocketAddr,
        remote_socket: Arc<UdpSocket>,
        server_handler: Arc<dyn UdpMessageHandler>,
        server_socket: Arc<UdpSocket>,
        user_address: SocketAddr,
        last_active_time_secs: Arc<AtomicU32>,
    ) {
        let mut buf = [0u8; MAX_UDP_PACKET_SIZE];
        while let Ok(len) = remote_socket.recv(&mut buf).await {
            match server_handler.encrypt_udp_message(&remote_address, &mut buf[0..len]) {
                Ok(EncryptUdpMessageResult { encrypted_data }) => {
                    if let Err(e) = server_socket.send_to(&encrypted_data, &user_address).await {
                        error!("Failed to forward encrypted data back to server: {}", e);
                    }
                    last_active_time_secs.store(get_timestamp_secs(), Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed to encrypt udp message: {}", e);
                }
            }
        }
    }
}

impl UdpForwarder for DirectForwarder {
    fn try_send(&self, data: &[u8]) -> std::io::Result<()> {
        // TODO: if the error is that the channel is full, no-op.
        // if the error is that the channel is closed, return an error.
        let _ = self.tx.try_send(data.to_vec().into_boxed_slice());
        Ok(())
    }

    fn maybe_stop(&self, current_timestamp: u32) -> bool {
        let last_active_time_secs = self.last_active_time_secs.load(Ordering::SeqCst);
        current_timestamp - last_active_time_secs >= DEFAULT_ASSOCIATION_TIMEOUT_SECS
    }
}

impl Drop for DirectForwarder {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

struct UdpProxyForwarder {
    tx: Sender<Box<[u8]>>,
    join_handle: JoinHandle<std::io::Result<()>>,
    last_active_time_secs: Arc<AtomicU32>,
}

impl UdpProxyForwarder {
    fn new(
        user_address: SocketAddr,
        server_socket: Arc<UdpSocket>,
        server_handler: Arc<dyn UdpMessageHandler>,
        proxy_address: SocketAddr,
        resolver: Arc<dyn Resolver>,
        remote_location: Location,
        client_handler: Arc<dyn UdpMessageHandler>,
    ) -> Self {
        let (tx, rx) = channel::<Box<[u8]>>(1024);

        let last_active_time_secs = Arc::new(AtomicU32::new(get_timestamp_secs()));

        let join_handle = {
            let cloned_time_secs = last_active_time_secs.clone();
            tokio::spawn(async move {
                let remote_address = resolver.resolve_location(&remote_location).await?;

                let proxy_socket = UdpSocket::bind("0.0.0.0:0").await?;
                proxy_socket.connect(proxy_address).await?;
                let proxy_socket = Arc::new(proxy_socket);

                join!(
                    Self::forward_to_proxy_task(
                        rx,
                        remote_address,
                        proxy_socket.clone(),
                        client_handler.clone(),
                        cloned_time_secs.clone()
                    ),
                    Self::forward_from_proxy_task(
                        proxy_socket,
                        client_handler,
                        server_socket,
                        server_handler,
                        user_address,
                        cloned_time_secs
                    ),
                );
                Ok(())
            })
        };

        Self {
            tx,
            join_handle,
            last_active_time_secs,
        }
    }

    async fn forward_to_proxy_task(
        mut rx: Receiver<Box<[u8]>>,
        remote_address: SocketAddr,
        proxy_socket: Arc<UdpSocket>,
        client_handler: Arc<dyn UdpMessageHandler>,
        last_active_time_secs: Arc<AtomicU32>,
    ) {
        while let Some(mut decrypted_data) = rx.recv().await {
            match client_handler.encrypt_udp_message(&remote_address, &mut decrypted_data) {
                Ok(EncryptUdpMessageResult { encrypted_data }) => {
                    if let Err(e) = proxy_socket.send(&encrypted_data).await {
                        error!("Failed to forward encrypted data: {}", e);
                    }
                    last_active_time_secs.store(get_timestamp_secs(), Ordering::Relaxed);
                }
                Err(e) => {
                    error!("Failed to encrypt remote address: {}", e);
                    continue;
                }
            }
        }
    }

    async fn forward_from_proxy_task(
        proxy_socket: Arc<UdpSocket>,
        client_handler: Arc<dyn UdpMessageHandler>,
        server_socket: Arc<UdpSocket>,
        server_handler: Arc<dyn UdpMessageHandler>,
        user_address: SocketAddr,
        last_active_time_secs: Arc<AtomicU32>,
    ) {
        let mut buf = [0u8; MAX_UDP_PACKET_SIZE];
        while let Ok(len) = proxy_socket.recv(&mut buf).await {
            match client_handler.decrypt_udp_message(&mut buf[0..len]) {
                Ok(DecryptUdpMessageResult {
                    mut decrypted_data,
                    decrypted_data_start_index,
                    decrypted_data_end_index_exclusive,
                    remote_location,
                }) => {
                    match server_handler.encrypt_udp_message(
                        &remote_location.to_socket_addr().unwrap(),
                        &mut decrypted_data
                            [decrypted_data_start_index..decrypted_data_end_index_exclusive],
                    ) {
                        Ok(EncryptUdpMessageResult { encrypted_data }) => {
                            if let Err(e) =
                                server_socket.send_to(&encrypted_data, &user_address).await
                            {
                                error!("Failed to forward re-encrypted data back to server: {}", e);
                            }
                            last_active_time_secs.store(get_timestamp_secs(), Ordering::Relaxed);
                        }
                        Err(e) => {
                            error!("Failed to re-encrypt udp message: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to decrypt remote message: {}", e);
                }
            }
        }
    }
}

impl UdpForwarder for UdpProxyForwarder {
    fn try_send(&self, data: &[u8]) -> std::io::Result<()> {
        // TODO: if the error is that the channel is full, no-op.
        // if the error is that the channel is closed, return an error.
        let _ = self.tx.try_send(data.to_vec().into_boxed_slice());
        Ok(())
    }

    fn maybe_stop(&self, current_timestamp: u32) -> bool {
        let last_active_time_secs = self.last_active_time_secs.load(Ordering::SeqCst);
        current_timestamp - last_active_time_secs >= DEFAULT_ASSOCIATION_TIMEOUT_SECS
    }
}

impl Drop for UdpProxyForwarder {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

// Informed by https://stackoverflow.com/questions/14856639/udp-hole-punching-timeout
const DEFAULT_ASSOCIATION_TIMEOUT_SECS: u32 = 200;

fn start_cleanup_task(associations: Arc<Mutex<HashMap<(SocketAddr, Location), UdpAction>>>) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60 * 5)).await;
            let current_timestamp = get_timestamp_secs();
            associations.lock().retain(|k, val| {
                if let UdpAction::Forward(ref forwarder) = val {
                    if forwarder.maybe_stop(current_timestamp) {
                        debug!("Removing association: {:?}", k);
                        return false;
                    }
                }
                true
            });
        }
    });
}

pub async fn run_udp_server(
    bind_address: SocketAddr,
    server_handler: Arc<dyn UdpMessageHandler>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let server_socket = Arc::new(tokio::net::UdpSocket::bind(bind_address).await?);
    let associations = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = [0u8; MAX_UDP_PACKET_SIZE];

    start_cleanup_task(associations.clone());

    loop {
        let (len, user_address) = server_socket
            .recv_from(&mut buf)
            .await
            .expect("Could not read from server socket");
        match server_handler.decrypt_udp_message(&mut buf[0..len]) {
            Ok(DecryptUdpMessageResult {
                decrypted_data,
                decrypted_data_start_index,
                decrypted_data_end_index_exclusive,
                remote_location,
            }) => {
                let key = (user_address, remote_location.clone());
                match associations.lock().entry(key) {
                    Entry::Occupied(o) => match o.get() {
                        UdpAction::Block => {
                            continue;
                        }
                        UdpAction::Forward(forwarder) => {
                            forwarder.try_send(
                                &decrypted_data[decrypted_data_start_index
                                    ..decrypted_data_end_index_exclusive],
                            );
                        }
                    },
                    Entry::Vacant(v) => {
                        // TODO: calculate proxy action
                        debug!(
                            "Creating new association: {:?} -> {:?}",
                            &user_address, &remote_location
                        );
                        let forwarder = DirectForwarder::new(
                            user_address,
                            server_socket.clone(),
                            server_handler.clone(),
                            resolver.clone(),
                            remote_location,
                        );
                        forwarder.try_send(
                            &decrypted_data
                                [decrypted_data_start_index..decrypted_data_end_index_exclusive],
                        );
                        v.insert(UdpAction::Forward(Box::new(forwarder)));
                    }
                }
            }
            Err(e) => {
                error!("Failed to decrypt udp message: {}", e);
            }
        }
    }
}

pub async fn start_udp_server(config: ServerConfig) -> std::io::Result<Option<JoinHandle<()>>> {
    // TODO: handle proxies
    let ServerConfig {
        bind_address,
        server_protocols: _,
        server_proxy_config,
        ..
    } = config;

    let udp_handler_result: std::io::Result<Arc<dyn UdpMessageHandler>> =
        server_proxy_config.try_into();

    match udp_handler_result {
        Ok(udp_handler) => {
            println!("Starting UDP server at {}", &bind_address);
            Ok(Some(tokio::spawn(async move {
                run_udp_server(bind_address, udp_handler).await.unwrap()
            })))
        }
        Err(_) => {
            warn!("Unable to start UDP handler for {}", &bind_address);
            Ok(None)
        }
    }
}
