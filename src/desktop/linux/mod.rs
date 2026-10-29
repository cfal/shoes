mod command;
mod ingress;
mod journal;
mod nft;
mod resolved;
mod routes;
pub(crate) mod spec;
#[cfg(test)]
mod tests;

use std::io;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use futures::StreamExt;
use rtnetlink::{Handle, LinkUnspec, MulticastGroup};
use tokio_util::task::AbortOnDropHandle;

pub(crate) use ingress::Ingress;
use journal::{Journal, Record};
pub(crate) use spec::Spec;

pub(crate) struct Session {
    journal: Journal,
    record: Record,
    handle: Handle,
    nft: String,
    resolved: Option<resolved::Resolved>,
    ingress: Option<Arc<Ingress>>,
    redirect_ports: [Option<u16>; 2],
    on_link: Vec<ipnetwork::IpNetwork>,
    active: bool,
    started: bool,
    _policy: crate::socket_policy::SocketPolicy,
    _connection: AbortOnDropHandle<()>,
    _events: AbortOnDropHandle<()>,
    changes: tokio::sync::mpsc::Receiver<()>,
    reconcile_after: tokio::time::Instant,
}

impl Session {
    pub(crate) async fn prepare(spec: Spec) -> io::Result<Self> {
        let journal = Journal::lock()?;
        let nft = command::executable("nft")?;
        let (connection, handle, mut events) = rtnetlink::new_multicast_connection(&[
            MulticastGroup::Link,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
            MulticastGroup::Ipv4Rule,
            MulticastGroup::Ipv6Rule,
        ])
        .map_err(io::Error::other)?;
        let connection = AbortOnDropHandle::new(tokio::spawn(connection));
        let (changed, changes) = tokio::sync::mpsc::channel(1);
        let events = AbortOnDropHandle::new(tokio::spawn(async move {
            while events.next().await.is_some() {
                let _ = changed.try_send(());
            }
        }));
        if let Some(record) = journal.load()? {
            recover(&handle, &nft, &journal, &record).await?;
        }
        routes::preflight(&handle, &spec).await?;
        let resolved = if spec.auto_dns {
            match resolved::Resolved::preflight(journal.lease()).await {
                Ok(resolved) => Some(resolved),
                Err(error) => {
                    log::warn!(
                        "Automatic DNS unavailable; leaving DNS externally managed: {error}"
                    );
                    None
                }
            }
        } else {
            None
        };
        let bootstrap = crate::dns::controlled_bootstrap(&spec.bootstrap_dns)?;
        let policy = crate::socket_policy::SocketPolicy::install(
            spec.name.clone(),
            spec.linux.bypass_mark,
            spec.linux.mark_mask,
            spec.addresses.clone(),
            bootstrap,
        )?;
        for endpoint in &spec.bootstrap_dns {
            crate::socket_policy::check_dns_endpoint(endpoint.ip())?;
        }
        let mut token = [0u8; 16];
        SystemRandom::new()
            .fill(&mut token)
            .map_err(|_| io::Error::other("failed to generate network ownership token"))?;
        let token = token.iter().map(|byte| format!("{byte:02x}")).collect();
        let record = Record {
            version: 1,
            namespace: journal.namespace.clone(),
            token,
            spec,
            ifindex: None,
            dns_pending: false,
            firewall_pending: false,
        };
        Ok(Self {
            journal,
            record,
            handle,
            nft,
            resolved,
            ingress: None,
            redirect_ports: [None, None],
            on_link: Vec::new(),
            active: false,
            started: false,
            _policy: policy,
            _connection: connection,
            _events: events,
            changes,
            reconcile_after: tokio::time::Instant::now(),
        })
    }

    pub(crate) async fn prepare_network(&mut self) -> io::Result<()> {
        self.journal.save(&self.record)?;
        self.started = true;
        let spec = &self.record.spec;
        let device = crate::tun::RetainedDevice::create(&spec.name, spec.offload)?;
        let index = routes::link(&self.handle, &spec.name)
            .await?
            .ok_or_else(|| io::Error::other("new TUN not found"))?
            .header
            .index;
        routes::request(
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(index)
                        .alias(self.record.alias())
                        .build(),
                )
                .execute(),
        )
        .await?;
        self.record.ifindex = Some(index);
        self.journal.save(&self.record)?;
        let ingress = self
            .ingress
            .insert(Arc::new(Ingress::new(&self.record.spec, device)?));
        self.redirect_ports = ingress.ports()?;
        self.on_link = routes::on_link(&self.handle, index).await?;
        routes::configure(&self.handle, &self.record.spec, index, &self.record.alias()).await?;
        let bytes = command::encode_nft(self.firewall_policy())?;
        command::run(
            self.journal.lease(),
            &self.nft,
            &["--check", "-j", "-f", "-"],
            &bytes,
        )
        .await?;
        Ok(())
    }

    pub(crate) fn ingress(&self) -> Option<Arc<Ingress>> {
        self.ingress.clone()
    }

    fn firewall_policy(&self) -> serde_json::Value {
        nft::install(
            &self.record.spec,
            &self.record.table(),
            &self.record.token,
            &self.on_link,
            self.redirect_ports,
        )
    }

    pub(crate) fn validate(&self, configs: &[crate::config::Config]) -> io::Result<()> {
        if Spec::from_configs(configs)?.as_ref() != Some(&self.record.spec) {
            return Err(spec::invalid(
                "managed TUN topology changes require a restart",
            ));
        }
        Ok(())
    }

    pub(crate) async fn activate(&mut self) -> io::Result<()> {
        routes::check(
            &self.handle,
            &self.record.spec,
            self.record.ifindex.unwrap(),
            &self.record.alias(),
        )
        .await?;
        self.record.firewall_pending = true;
        self.journal.save(&self.record)?;
        command::nft(self.journal.lease(), &self.nft, self.firewall_policy()).await?;
        check_firewall(self.journal.lease(), &self.nft, &self.record).await?;
        if let Some(resolved) = &self.resolved {
            self.record.dns_pending = true;
            self.journal.save(&self.record)?;
            if let Err(error) = resolved.activate(&self.handle, &self.record).await {
                log::warn!(
                    "Automatic DNS setup failed; continuing without guaranteed system DNS routing: {error}"
                );
            }
        }
        self.active = true;
        Ok(())
    }

    pub(crate) async fn changed(&mut self) {
        tokio::time::sleep_until(self.reconcile_after).await;
        tokio::select! {
            _ = self.changes.recv() => {},
            _ = tokio::time::sleep(Duration::from_secs(10)) => {},
        }
    }

    pub(crate) async fn reconcile(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        while self.changes.try_recv().is_ok() {}
        let index = self.record.ifindex.unwrap();
        for endpoint in &self.record.spec.bootstrap_dns {
            crate::socket_policy::check_dns_endpoint(endpoint.ip())?;
        }
        routes::check(&self.handle, &self.record.spec, index, &self.record.alias()).await?;
        check_firewall(self.journal.lease(), &self.nft, &self.record).await?;
        let networks = routes::on_link(&self.handle, index).await?;
        if networks != self.on_link {
            command::nft(
                self.journal.lease(),
                &self.nft,
                nft::update_onlink(&self.record.table(), &networks),
            )
            .await?;
            self.on_link = networks;
        }
        self.reconcile_after = tokio::time::Instant::now() + Duration::from_secs(1);
        Ok(())
    }

    pub(crate) async fn deactivate(&mut self) -> io::Result<()> {
        if !self.started {
            return Ok(());
        }
        let mut errors = Vec::new();
        if self.record.firewall_pending {
            match remove_firewall(self.journal.lease(), &self.nft, &self.record).await {
                Ok(()) => self.record.firewall_pending = false,
                Err(error) => errors.push(error.to_string()),
            }
        }
        if self.record.dns_pending
            && let Some(resolved) = &self.resolved
        {
            match resolved.revert(&self.handle, &self.record).await {
                Ok(()) => self.record.dns_pending = false,
                Err(error) => log::warn!("Automatic DNS cleanup failed: {error}"),
            }
        }
        self.active = false;
        self.journal.save(&self.record)?;
        failures(errors)
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        if !self.started {
            return Ok(());
        }
        let mut errors = Vec::new();
        if let Err(error) = self.deactivate().await {
            errors.push(error.to_string());
        }
        remove_routing(&self.handle, &self.record, &mut errors).await;
        self.ingress = None;
        if errors.is_empty() {
            self.journal.clear()?;
            self.started = false;
        }
        failures(errors)
    }
}

fn failures(errors: Vec<String>) -> io::Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(errors.join("; ")))
    }
}

async fn firewall_exists(
    lease: BorrowedFd<'_>,
    executable: &str,
    record: &Record,
) -> io::Result<bool> {
    let tables = command::run(lease, executable, &["-j", "list", "tables"], &[]).await?;
    let tables: serde_json::Value = serde_json::from_slice(&tables).map_err(io::Error::other)?;
    let entries = tables
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| io::Error::other("invalid nft table listing"))?;
    let name = record.table();
    Ok(entries.iter().any(|entry| {
        entry
            .get("table")
            .is_some_and(|table| table["family"] == "inet" && table["name"] == name)
    }))
}

async fn check_firewall(
    lease: BorrowedFd<'_>,
    executable: &str,
    record: &Record,
) -> io::Result<()> {
    if firewall_exists(lease, executable, record).await? {
        Ok(())
    } else {
        Err(io::Error::other("managed nft table disappeared"))
    }
}

async fn remove_firewall(
    lease: BorrowedFd<'_>,
    executable: &str,
    record: &Record,
) -> io::Result<()> {
    if firewall_exists(lease, executable, record).await? {
        command::nft(lease, executable, nft::remove(&record.table())).await?;
    }
    Ok(())
}

async fn remove_link(handle: &Handle, record: &Record) -> io::Result<()> {
    let Some(link) = routes::link(handle, &record.spec.name).await? else {
        return Ok(());
    };
    if !record
        .ifindex
        .is_some_and(|index| routes::owned_link(&link, index, &record.spec.name, &record.alias()))
    {
        return Err(io::Error::other(
            "refusing to remove a replacement TUN interface",
        ));
    }
    routes::request(handle.link().del(link.header.index).execute()).await
}

async fn remove_routing(handle: &Handle, record: &Record, errors: &mut Vec<String>) {
    if let Err(error) = routes::check_cleanup_routes(handle, &record.spec, record.ifindex).await {
        errors.push(error.to_string());
    }
    if let Err(error) = routes::remove_rules(handle, &record.spec).await {
        errors.push(error.to_string());
    }
    if let Err(error) = remove_link(handle, record).await {
        errors.push(error.to_string());
    }
}

async fn recover(handle: &Handle, nft: &str, journal: &Journal, record: &Record) -> io::Result<()> {
    let mut errors = Vec::new();
    if record.firewall_pending
        && let Err(error) = remove_firewall(journal.lease(), nft, record).await
    {
        errors.push(error.to_string());
    }
    if record.dns_pending {
        match resolved::Resolved::preflight(journal.lease()).await {
            Ok(resolved) => {
                if let Err(error) = resolved.revert(handle, record).await {
                    log::warn!("Automatic DNS recovery failed: {error}");
                }
            }
            Err(error) => log::warn!("Automatic DNS recovery unavailable: {error}"),
        }
    }
    remove_routing(handle, record, &mut errors).await;
    failures(errors)?;
    journal.clear()
}

pub(crate) async fn cleanup() -> io::Result<()> {
    let journal = Journal::lock()?;
    let Some(record) = journal.load()? else {
        return Ok(());
    };
    let (connection, handle, _) = rtnetlink::new_connection().map_err(io::Error::other)?;
    let _connection = AbortOnDropHandle::new(tokio::spawn(connection));
    recover(&handle, &command::executable("nft")?, &journal, &record).await
}
