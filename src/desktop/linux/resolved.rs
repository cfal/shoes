use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use serde_json::{Value, json};

use super::{command, journal::Record, routes};

pub(super) async fn ready(record: &Record) -> io::Result<()> {
    use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // An empty question is rejected locally, without publishing fake answers or querying upstreams.
    let query = Message::query();
    let id = query.id;
    let query = query.to_vec().map_err(io::Error::other)?;
    for address in record.spec.dns_addresses()? {
        let endpoint = std::net::SocketAddr::new(address, 53);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let udp = crate::socket_util::new_udp_socket(address.is_ipv6(), None)?;
            udp.connect(endpoint).await?;
            let mut bytes = vec![0; 4096];
            let length = loop {
                udp.send(&query).await?;
                if let Ok(result) = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    udp.recv(&mut bytes),
                )
                .await
                {
                    break result?;
                }
            };
            let check = |bytes: &[u8]| -> io::Result<()> {
                let response = Message::from_vec(bytes).map_err(io::Error::other)?;
                if response.message_type != MessageType::Response
                    || response.response_code != ResponseCode::FormErr
                    || response.id != id
                {
                    return Err(io::Error::other(
                        "unexpected managed DNS readiness response",
                    ));
                }
                Ok(())
            };
            check(&bytes[..length])?;
            let mut tcp = crate::socket_util::new_tcp_socket(None, address.is_ipv6())?
                .connect(endpoint)
                .await?;
            tcp.write_u16(query.len() as u16).await?;
            tcp.write_all(&query).await?;
            let length = tcp.read_u16().await? as usize;
            bytes.resize(length, 0);
            tcp.read_exact(&mut bytes).await?;
            check(&bytes)?;
            tcp.shutdown().await?;
            if tcp.read(&mut [0]).await? != 0 {
                return Err(io::Error::other(
                    "unexpected trailing DNS readiness response",
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("managed DNS endpoint {endpoint} is not ready"),
            )
        })??;
    }
    Ok(())
}

pub(super) struct Resolved {
    busctl: String,
    lease: OwnedFd,
}

const LINK_MODES: [(&str, &str); 4] = [
    ("SetLinkDNSOverTLS", "DNSOverTLS"),
    ("SetLinkDNSSEC", "DNSSEC"),
    ("SetLinkLLMNR", "LLMNR"),
    ("SetLinkMulticastDNS", "MulticastDNS"),
];

impl Resolved {
    pub(super) async fn preflight(lease: BorrowedFd<'_>) -> io::Result<Self> {
        let backend = Self {
            busctl: command::executable("busctl")?,
            lease: lease.try_clone_to_owned()?,
        };
        backend
            .call(&[
                "get-property",
                "org.freedesktop.resolve1",
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                "DNS",
            ])
            .await?;
        Ok(backend)
    }

    async fn call(&self, arguments: &[&str]) -> io::Result<Value> {
        let mut args = vec![
            "--system",
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

    async fn mutate(&self, method: &str, signature: &str, arguments: &[String]) -> io::Result<()> {
        let mut args = vec![
            "call",
            "org.freedesktop.resolve1",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            method,
            signature,
        ];
        args.extend(arguments.iter().map(String::as_str));
        self.call(&args).await?;
        Ok(())
    }

    async fn current(&self, index: u32, property: &str) -> io::Result<Value> {
        let link = self
            .call(&[
                "call",
                "org.freedesktop.resolve1",
                "/org/freedesktop/resolve1",
                "org.freedesktop.resolve1.Manager",
                "GetLink",
                "i",
                &index.to_string(),
            ])
            .await?;
        let path = link
            .get("data")
            .and_then(Value::as_array)
            .and_then(|data| data.first())
            .and_then(Value::as_str)
            .filter(|path| path.starts_with("/org/freedesktop/resolve1/link/"))
            .ok_or_else(|| io::Error::other("resolved returned an invalid link path"))?;
        let property = self
            .call(&[
                "get-property",
                "org.freedesktop.resolve1",
                path,
                "org.freedesktop.resolve1.Link",
                property,
            ])
            .await?;
        property
            .get("data")
            .cloned()
            .ok_or_else(|| io::Error::other("resolved returned an invalid property"))
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

    fn expected_dns(record: &Record) -> io::Result<Value> {
        Ok(Value::Array(
            record
                .spec
                .dns_addresses()?
                .into_iter()
                .map(|address| match address {
                    std::net::IpAddr::V4(ip) => json!([libc::AF_INET, ip.octets()]),
                    std::net::IpAddr::V6(ip) => json!([libc::AF_INET6, ip.octets()]),
                })
                .collect(),
        ))
    }

    async fn settings(&self, index: u32) -> io::Result<Value> {
        let mut values = serde_json::Map::new();
        for property in ["DNS", "Domains", "DefaultRoute"]
            .into_iter()
            .chain(LINK_MODES.map(|(_, property)| property))
        {
            values.insert(property.to_owned(), self.current(index, property).await?);
        }
        Ok(Value::Object(values))
    }

    fn expected(record: &Record) -> io::Result<Value> {
        let mut values = json!({
            "DNS": Self::expected_dns(record)?,
            "Domains": [[".", true]],
            "DefaultRoute": true,
        });
        for (_, property) in LINK_MODES {
            values[property] = json!("no");
        }
        Ok(values)
    }

    pub(super) async fn snapshot(
        &self,
        handle: &rtnetlink::Handle,
        record: &Record,
    ) -> io::Result<Value> {
        let index = Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared before DNS preparation"))?;
        let settings = self.settings(index).await?;
        if settings["DNS"] != json!([]) || settings["Domains"] != json!([]) {
            return Err(io::Error::other(
                "new TUN already has external DNS configuration",
            ));
        }
        Ok(settings)
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
        for (method, _) in LINK_MODES {
            Self::owned(handle, record)
                .await?
                .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
            self.mutate(method, "is", &[index.clone(), "no".into()])
                .await?;
        }
        self.mutate("SetLinkDNS", "ia(iay)", &args).await?;
        Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
        self.mutate(
            "SetLinkDomains",
            "ia(sb)",
            &[index.clone(), "1".into(), ".".into(), "true".into()],
        )
        .await?;
        Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("TUN disappeared during DNS activation"))?;
        self.mutate("SetLinkDefaultRoute", "ib", &[index, "true".into()])
            .await?;
        self.check(handle, record).await
    }

    pub(super) async fn check(
        &self,
        handle: &rtnetlink::Handle,
        record: &Record,
    ) -> io::Result<()> {
        let index = Self::owned(handle, record)
            .await?
            .ok_or_else(|| io::Error::other("managed DNS interface disappeared"))?;
        if self.settings(index).await? != Self::expected(record)? {
            return Err(io::Error::other(
                "managed resolved settings changed externally",
            ));
        }
        Ok(())
    }

    pub(super) async fn revert(
        &self,
        handle: &rtnetlink::Handle,
        record: &Record,
    ) -> io::Result<()> {
        let Some(index) = Self::owned(handle, record).await? else {
            return Ok(());
        };
        let current = self.settings(index).await?;
        let before = record
            .dns_before
            .as_ref()
            .ok_or_else(|| io::Error::other("missing pre-activation DNS settings"))?;
        let expected = Self::expected(record)?;
        if current
            .as_object()
            .unwrap()
            .iter()
            .any(|(key, value)| value != &before[key] && value != &expected[key])
        {
            return Err(io::Error::other(
                "refusing to revert externally changed resolved settings",
            ));
        }
        self.mutate("RevertLink", "i", &[index.to_string()]).await?;
        Ok(())
    }
}
