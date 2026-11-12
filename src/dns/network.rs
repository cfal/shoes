use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use crate::network_tasks::NetworkTasks;
use crate::resolver::{DnsExchangeFuture, ResolveFuture, Resolver};

#[derive(Debug)]
struct NetworkResolver {
    inner: Arc<dyn Resolver>,
    network: NetworkTasks,
}

pub(super) fn scoped(inner: Arc<dyn Resolver>) -> Arc<dyn Resolver> {
    match NetworkTasks::current() {
        Some(network) => Arc::new(NetworkResolver { inner, network }),
        None => inner,
    }
}

impl NetworkResolver {
    fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(Arc<dyn Resolver>) -> Pin<Box<dyn Future<Output = io::Result<T>> + Send>>
        + Send
        + 'static,
    ) -> Pin<Box<dyn Future<Output = io::Result<T>> + Send>> {
        let inner = self.inner.clone();
        let network = self.network.clone();
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = network.cancelled.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "DNS network retired")),
                result = network.scope(async move { operation(inner).await }) => result,
            }
        })
    }
}

impl Resolver for NetworkResolver {
    fn resolve_location(&self, location: &crate::address::NetLocation) -> ResolveFuture {
        let location = location.clone();
        self.run(move |inner| inner.resolve_location(&location))
    }

    fn exchange(&self, request: Vec<u8>) -> DnsExchangeFuture {
        self.run(move |inner| inner.exchange(request))
    }

    fn exchange_with_deadline(
        &self,
        request: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> DnsExchangeFuture {
        self.run(move |inner| inner.exchange_with_deadline(request, deadline))
    }

    fn fake_dns_context(&self) -> Option<Arc<super::DnsContext>> {
        self.inner.fake_dns_context()
    }
}
