use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

pub(super) struct TestGate {
    entered: SyncSender<()>,
    resume: Receiver<()>,
}

pub(super) struct GateControl {
    entered: Receiver<()>,
    resume: SyncSender<()>,
}

impl TestGate {
    pub fn new() -> (Self, GateControl) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = mpsc::sync_channel(1);
        (
            Self {
                entered: entered_tx,
                resume: resume_rx,
            },
            GateControl {
                entered: entered_rx,
                resume: resume_tx,
            },
        )
    }

    pub fn pause(self) {
        if self.entered.send(()).is_ok() {
            self.resume
                .recv_timeout(Duration::from_secs(5))
                .expect("test did not release the TUN gate");
        }
    }
}

impl GateControl {
    pub fn wait(&self) {
        self.entered
            .recv_timeout(Duration::from_secs(5))
            .expect("TUN thread did not reach the test gate");
    }
}

impl Drop for GateControl {
    fn drop(&mut self) {
        let _ = self.resume.try_send(());
    }
}
