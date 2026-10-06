#[path = "cases/privileged/naiveproxy_interop.rs"]
mod naiveproxy_interop;
#[path = "cases/privileged/naiveproxy_uot_integration.rs"]
mod naiveproxy_uot;
#[path = "cases/privileged/tun_integration.rs"]
mod tun;
#[cfg(target_os = "linux")]
#[path = "cases/privileged/tun_kernel.rs"]
mod tun_kernel;
