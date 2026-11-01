---
title: "Hot Reloading"
description: shoes hot reloading configuration.
---

Configuration changes are automatically detected. The CLI also watches referenced
outbound TLS/QUIC client certificates and keys, client-auth CA bundles, local
ShadowTLS certificates/keys, and ACME custom `ca_cert` files. Changing ACME trust
roots replaces the affected renewal worker after successful preparation, while
retaining its account and issued certificate.

Automatic full reloads wait for **5 seconds of quiet after the last relevant
filesystem event**. Writes to config, rule, or reload-only PEM dependencies share
that debounce window. Separate certificate/key writes are coalesced; an invalid
or incomplete candidate is rejected without retiring the running listeners.
Active and parseable candidate dependencies remain watched, so repairing or
creating a missing PEM file retries the reload without another config edit.
Unix SIGHUP bypasses debounce; shutdown also interrupts it immediately.

`--no-reload` disables automatic full-reload watches, not live server-certificate
rotation or ACME renewal. On Unix, SIGHUP still requests a reload. Embedded/FFI
instances use the same live server-certificate watcher, but have no full config
reload loop: reload-only PEM changes require restarting the embedded instance.

On Linux, if directory permissions prevent watching a readable configuration's parent, startup falls back to direct file watches and logs a warning. In-place edits remain detectable, but atomic replacements may be missed; use SIGHUP or grant directory read permission when replacing files.

Replacement configurations, certificates, and DNS resolvers are prepared while
the current listeners continue serving. A preparation failure leaves the current
configuration running. Unchanged fixed TCP listen addresses retain their sockets
across generations. New-generation TCP and Unix listeners accept queued
connections only after activation completes; connections may wait in the kernel
backlog during that interval.

If activation fails, shoes stops the candidate services and restores the previous
configuration, including control state, resource limits, DNS ownership, and
certificate workers. A successful rollback keeps the process running; if rollback
also fails, shoes exits with status 1 rather than serving a partial generation.
Existing TCP connections begin draining when their old listeners retire, for up
to `global_settings.reload_grace_secs`. That deadline still applies after rollback.
TUN, WireGuard, and QUIC services are stopped and restarted; their existing
sessions are not migrated or restored by rollback.

Certificate-source file changes and ACME renewal do not trigger this full reload.
They rotate live without replacing listeners or closing QUIC connections; see
[Certificate Sources](/security/certificates/).

QUIC listener sockets must finish closing before replacements bind. Closing endpoints get up to one second for best-effort close delivery, then their drivers are stopped locally so peer-controlled timers cannot delay reloads. If the previous generation's sockets do not retire within the five-second socket-release guard, shoes exits with an error rather than announcing a partially ready generation.

Candidate QUIC buffer sizes are used during DNS preparation, but `global_settings` admission caps change only at activation. DNS bootstrap over HTTP/3 or QUIC proxy chains therefore needs headroom under the live cap. A cap-increasing reload may require a restart if preparation cannot fit. Lowering a cap does not revoke existing reservations, including those made during preparation; new admissions are blocked until usage falls sufficiently. At cold startup, preparation uses the initial unlimited admission caps.

On macOS, edit the configured file path or use SIGHUP when writing through a hard-link alias in another directory. Automatic detection of such alias writes is backend-dependent. System-volume directory symlinks are resolved without watching their immutable links.

SIGINT/SIGTERM (or Ctrl-C on Windows) stop listeners and exit with status 0. Process shutdown does not wait for the TCP reload grace period.
