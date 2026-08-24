//! What happened when a service was asked to stop.
//!
//! Unconditional, unlike `status`: the FFI's `stop_service` calls
//! `stop_handle` on every platform and has to interpret what comes back.

/// The result of stopping a service.
///
/// This is not a `Result`. `TimedOut` is a successful report of an unwelcome
/// fact, and typing it as an error would invite a host to `?` it and skip the
/// descriptor decision it exists to force.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// The stack confirmed it released the device. Safe to close a borrowed
    /// descriptor.
    Released,
    /// The wait expired. The device may still be in use, so a borrowed
    /// descriptor must not be closed — a host that closes it anyway is racing
    /// a thread that is still reading from it.
    TimedOut { waited: std::time::Duration },
}

impl StopOutcome {
    /// Whether the host may now close a descriptor it lent to the service.
    pub fn device_released(&self) -> bool {
        matches!(self, StopOutcome::Released)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two outcomes carry different obligations, so a caller must not be
    /// able to treat them alike by accident.
    #[test]
    fn test_only_released_permits_closing_a_borrowed_descriptor() {
        assert!(StopOutcome::Released.device_released());
        assert!(
            !StopOutcome::TimedOut {
                waited: std::time::Duration::from_secs(5)
            }
            .device_released()
        );
    }

    /// The wait is worth reporting: a host that timed out after five seconds
    /// is in a different position from one that gave up immediately, and a
    /// support log wants the number.
    #[test]
    fn test_a_timeout_carries_how_long_it_waited() {
        let outcome = StopOutcome::TimedOut {
            waited: std::time::Duration::from_millis(4980),
        };
        let StopOutcome::TimedOut { waited } = outcome else {
            panic!("expected a timeout");
        };
        assert!(waited.as_millis() >= 4000);
    }
}
