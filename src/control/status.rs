//! What a host asks the service about itself.
//!
//! The FFI answers with a bool and an optional string, which cannot separate
//! starting from running, or a stop the user asked for from a stack that died.
//! A GUI needs that separation: one of those gets a red banner and the other
//! gets nothing.

/// Why a service is no longer running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The host asked it to stop.
    Requested,
    /// The stack returned an error. Carries the message the host displays.
    Failed(String),
}

/// Where a service is in its lifecycle.
///
/// `#[non_exhaustive]` on purpose. A `Starting` state is worth having — a GUI
/// that shows "connected" the instant `start` returns is lying, because the
/// stack is still bringing the device up — but nothing can report it yet:
/// `start` returns as soon as the task is spawned, and the stack has no
/// readiness signal to offer. Adding one is a change to `run_tun_from_config`,
/// not to this enum, so the variant waits until it can be produced rather than
/// shipping as a state a host will never observe. Same for `Stopping`, which
/// `stop` could never expose anyway since it consumes the handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    Running,
    Stopped { reason: StopReason },
}

/// A point-in-time reading. Cheap enough to poll at a GUI's frame rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub status: Status,
    /// How long the service has been up, or `None` once it is not running.
    pub uptime: Option<std::time::Duration>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GUI renders a failure differently from a requested stop, so the two
    /// must not both arrive as plain "stopped".
    #[test]
    fn test_a_failure_is_distinguishable_from_a_requested_stop() {
        let requested = Status::Stopped {
            reason: StopReason::Requested,
        };
        let failed = Status::Stopped {
            reason: StopReason::Failed("bind: address in use".to_string()),
        };
        assert_ne!(requested, failed);
        assert!(
            matches!(failed, Status::Stopped { reason: StopReason::Failed(ref m) }
                if m.contains("address in use"))
        );
    }

    /// Running is not stopped, whatever the reason attached to the stop.
    #[test]
    fn test_running_is_not_stopped() {
        assert_ne!(
            Status::Running,
            Status::Stopped {
                reason: StopReason::Requested
            }
        );
    }
}
