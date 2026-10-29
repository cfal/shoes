use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

use serde_json::Value;

use super::{command, journal::Record, routes};

pub(super) struct Resolved {
    busctl: String,
    lease: OwnedFd,
    owner: String,
}

const LINK_MODES: [&str; 4] = [
    "SetLinkDNSOverTLS",
    "SetLinkDNSSEC",
    "SetLinkLLMNR",
    "SetLinkMulticastDNS",
];

impl Resolved {
    pub(super) async fn preflight(lease: BorrowedFd<'_>) -> io::Result<Self> {
        single_pid_namespace("self")?;
        let bus = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::UnixStream::connect("/run/dbus/system_bus_socket"),
        )
        .await??;
        let pid = bus
            .peer_cred()?
            .pid()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| io::Error::other("system bus is outside this PID namespace"))?;
        // Standard system buses run in their socket listener's PID namespace.
        single_pid_namespace(&pid.to_string())?;
        let mut backend = Self {
            busctl: command::executable("busctl")?,
            lease: lease.try_clone_to_owned()?,
            owner: String::new(),
        };
        let owner = backend
            .call(&[
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetNameOwner",
                "s",
                "org.freedesktop.resolve1",
            ])
            .await?;
        backend.owner = owner["data"][0]
            .as_str()
            .filter(|name| name.starts_with(':'))
            .ok_or_else(|| io::Error::other("resolved returned an invalid bus owner"))?
            .to_owned();
        let credentials = backend
            .call(&[
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixProcessID",
                "s",
                &backend.owner,
            ])
            .await?;
        let pid = credentials["data"][0]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u32::MAX as u64)
            .ok_or_else(|| io::Error::other("resolved returned an invalid process ID"))?;
        let local = std::fs::metadata("/proc/self/net/dev")?;
        let remote = std::fs::metadata(format!("/proc/{pid}/net/dev"))?;
        if (local.dev(), local.ino()) != (remote.dev(), remote.ino()) {
            return Err(io::Error::other(
                "resolved is in a different network namespace",
            ));
        }
        backend
            .call(&[
                "get-property",
                &backend.owner,
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                "DNS",
            ])
            .await?;
        Ok(backend)
    }

    async fn call(&self, arguments: &[&str]) -> io::Result<Value> {
        let mut args = vec![
            "--address=unix:path=/run/dbus/system_bus_socket",
            "--json=short",
            "--no-pager",
            "--allow-interactive-authorization=no",
            "--auto-start=no",
        ];
        args.extend_from_slice(arguments);
        let output = command::run(self.lease.as_fd(), &self.busctl, &args, &[]).await?;
        if output.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&output).map_err(io::Error::other)
    }

    async fn manager(&self, method: &str, signature: &str, arguments: &[String]) -> io::Result<()> {
        let mut args = vec![
            "call",
            &self.owner,
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            method,
            signature,
        ];
        args.extend(arguments.iter().map(String::as_str));
        self.call(&args).await?;
        Ok(())
    }

    async fn owned(handle: &rtnetlink::Handle, record: &Record) -> io::Result<Option<u32>> {
        let Some(link) = routes::link(handle, &record.spec.name).await? else {
            return Ok(None);
        };
        let Some(index) = record.ifindex else {
            return Err(io::Error::other("resolved link has no recorded identity"));
        };
        if !routes::owned_link(&link, index, &record.spec.name, &record.alias()) {
            return Err(io::Error::other(
                "refusing to modify DNS on a replacement interface",
            ));
        }
        Ok(Some(index))
    }

    pub(super) async fn activate(
        &self,
        handle: &rtnetlink::Handle,
        record: &Record,
    ) -> io::Result<()> {
        let index = Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared before DNS activation"))?
            .to_string();
        let addresses = record.spec.dns_addresses()?;
        let mut args = vec![index.clone(), addresses.len().to_string()];
        for address in addresses {
            let (family, bytes) = match address {
                std::net::IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
                std::net::IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
            };
            args.extend([family.to_string(), bytes.len().to_string()]);
            args.extend(bytes.into_iter().map(|byte| byte.to_string()));
        }
        for method in LINK_MODES {
            Self::owned(handle, record)
                .await?
                .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
            self.manager(method, "is", &[index.clone(), "no".into()])
                .await?;
        }
        self.manager("SetLinkDNS", "ia(iay)", &args).await?;
        Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
        self.manager(
            "SetLinkDomains",
            "ia(sb)",
            &[index.clone(), "1".into(), ".".into(), "true".into()],
        )
        .await?;
        Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
        self.manager("SetLinkDefaultRoute", "ib", &[index, "true".into()])
            .await
    }

    pub(super) async fn revert(
        &self,
        handle: &rtnetlink::Handle,
        record: &Record,
    ) -> io::Result<()> {
        let Some(index) = Self::owned(handle, record).await? else {
            return Ok(());
        };
        self.manager("RevertLink", "i", &[index.to_string()]).await
    }
}

fn single_pid_namespace(pid: &str) -> io::Result<()> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let ids = status.lines().find_map(|line| line.strip_prefix("NSpid:"));
    if ids.is_none_or(|ids| ids.split_whitespace().count() != 1) {
        return Err(io::Error::other(
            "automatic DNS requires procfs and the system bus in the same PID namespace",
        ));
    }
    Ok(())
}
