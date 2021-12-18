#[cfg(all(feature = "tls-native", feature = "tls-rustls"))]
compile_error!("only one of tls-native or tls-rustls can be enabled.");

#[cfg(feature = "tls-native")]
mod native_tls;

#[cfg(feature = "tls-rustls")]
mod rustls;

#[cfg(feature = "tls-native")]
fn create_tls_factory() -> native_tls::NativeTlsFactory {
    native_tls::NativeTlsFactory::new()
}

#[cfg(feature = "tls-rustls")]
fn create_tls_factory() -> rustls::RustlsFactory {
    rustls::RustlsFactory::new()
}

use crate::async_tls::AsyncTlsFactory;
use std::lazy::SyncOnceCell;
use std::sync::Arc;

pub fn get_tls_factory() -> Arc<dyn AsyncTlsFactory> {
    static INSTANCE: SyncOnceCell<Arc<dyn AsyncTlsFactory>> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| Arc::new(create_tls_factory()))
        .clone()
}
