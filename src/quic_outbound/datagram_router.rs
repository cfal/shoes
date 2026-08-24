//! Routes one connection's incoming QUIC datagrams to the session they belong to.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use log::debug;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::sync::mpsc;

/// How many datagrams may queue for one session before the rest are dropped.
const SESSION_CAPACITY: usize = 64;

/// Reads the session key out of a datagram's header.
///
/// Supplied by the protocol, because only the protocol knows its own framing.
/// `None` drops the datagram: it is malformed, or it is something the protocol
/// does not route by session at all.
pub type SessionKeyFn = fn(&[u8]) -> Option<u32>;

/// One demultiplexer per QUIC connection.
///
/// `quinn::Connection::read_datagram` pops from a single queue, so a reader per
/// session wins only its share and discards the rest: with N sessions each one
/// loses about (N-1)/N of its traffic, and with two it can lose all of it. The
/// Hysteria2 reference runs exactly one demultiplexer per connection and
/// dispatches by session id (`core/client/udp.go:126-142`); this is that.
///
/// The router belongs to a single connection rather than to the outbound, so
/// that ending it can fail every session on it without touching sessions that
/// have since been registered against a replacement connection.
#[derive(Debug, Default)]
struct Sessions {
    queues: HashMap<u32, mpsc::Sender<Bytes>>,
    /// Set when the reader has stopped, which it only does when the connection
    /// is gone. Lives under the same lock as the map so that registering and
    /// terminating cannot interleave.
    terminated: bool,
}

#[derive(Debug)]
pub struct DatagramRouter {
    key_of: SessionKeyFn,
    sessions: Mutex<Sessions>,
}

impl DatagramRouter {
    pub fn new(key_of: SessionKeyFn) -> Self {
        Self {
            key_of,
            sessions: Mutex::new(Sessions::default()),
        }
    }

    /// Take a fresh session id and the receiving end of its queue.
    ///
    /// The id is allocated here rather than by the caller because this map is
    /// the only thing that knows which ids are in use. A caller drawing its own
    /// random id would eventually draw one already registered and quietly take
    /// over that session's datagrams - which is the failure this type exists to
    /// remove, reintroduced by the back door.
    pub fn register(&self) -> (u32, mpsc::Receiver<Bytes>) {
        let (sender, receiver) = mpsc::channel(SESSION_CAPACITY);
        let mut sessions = self.sessions.lock();
        let mut rng = rand::rng();
        let session_id = loop {
            let candidate = rng.random::<u32>();
            if !sessions.queues.contains_key(&candidate) {
                break candidate;
            }
        };

        // A caller can be handed a connection that dies before it registers:
        // `get` checks the connection under its own lock and the reader stops
        // afterwards. Keeping the sender out of the map is what makes that
        // session report end-of-stream on its first read instead of waiting on
        // a queue nothing will ever fill. The id is still allocated, so nothing
        // odd goes on the wire if the session tries to write.
        if !sessions.terminated {
            sessions.queues.insert(session_id, sender);
        }
        (session_id, receiver)
    }

    pub fn deregister(&self, session_id: u32) {
        self.sessions.lock().queues.remove(&session_id);
    }

    /// Hand one datagram to its session.
    ///
    /// A full queue drops the datagram instead of waiting. This runs on the
    /// single reader for the whole connection, so blocking for one slow session
    /// would stall every other session sharing it. UDP loses packets by design
    /// and a drop is the honest outcome; a stall is not.
    fn dispatch(&self, datagram: Bytes) {
        let Some(session_id) = (self.key_of)(&datagram) else {
            return;
        };

        let mut sessions = self.sessions.lock();
        let Some(sender) = sessions.queues.get(&session_id) else {
            // Nothing is listening. Dropped here once, rather than by every
            // session's reader in turn.
            return;
        };

        match sender.try_send(datagram) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("QUIC session {session_id} is not draining its datagrams; dropping one");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                sessions.queues.remove(&session_id);
            }
        }
    }

    /// Read this connection's datagrams until it ends.
    pub async fn run(self: Arc<Self>, connection: quinn::Connection) {
        loop {
            match connection.read_datagram().await {
                Ok(datagram) => self.dispatch(datagram),
                Err(e) => {
                    debug!("QUIC datagram reader stopping: {e}");
                    // The connection is gone, so every session on it is over.
                    // Dropping the senders is what turns that into an error in
                    // each session's next read: without it they would wait on a
                    // queue nothing can ever fill again. The flag closes the
                    // same door for a session that has not registered yet.
                    let mut sessions = self.sessions.lock();
                    sessions.terminated = true;
                    sessions.queues.clear();
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Hysteria2 shape: a session id in the first four bytes.
    fn first_four(datagram: &[u8]) -> Option<u32> {
        Some(u32::from_be_bytes(datagram.get(0..4)?.try_into().ok()?))
    }

    fn datagram(session_id: u32, tag: u8) -> Bytes {
        let mut out = session_id.to_be_bytes().to_vec();
        out.push(tag);
        Bytes::from(out)
    }

    #[tokio::test]
    async fn test_each_session_gets_only_its_own_datagrams() {
        let router = DatagramRouter::new(first_four);
        let (first_id, mut first) = router.register();
        let (second_id, mut second) = router.register();

        router.dispatch(datagram(first_id, 1));
        router.dispatch(datagram(second_id, 2));
        router.dispatch(datagram(first_id, 3));

        assert_eq!(first.recv().await.unwrap()[4], 1);
        assert_eq!(first.recv().await.unwrap()[4], 3);
        assert_eq!(second.recv().await.unwrap()[4], 2);
        assert!(
            first.try_recv().is_err(),
            "the first session was handed a datagram that was not its own"
        );
    }

    #[tokio::test]
    async fn test_register_never_hands_out_a_live_session_id() {
        let router = DatagramRouter::new(first_four);
        let mut ids = std::collections::HashSet::new();
        let mut held = Vec::new();
        for _ in 0..64 {
            let (id, receiver) = router.register();
            assert!(ids.insert(id), "session id {id} was handed out twice");
            held.push(receiver);
        }
    }

    #[tokio::test]
    async fn test_a_datagram_for_an_unknown_session_is_dropped() {
        let router = DatagramRouter::new(first_four);
        let (id, mut session) = router.register();
        router.dispatch(datagram(id.wrapping_add(1), 9));
        assert!(session.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_a_deregistered_session_stops_receiving() {
        let router = DatagramRouter::new(first_four);
        let (id, mut session) = router.register();
        router.deregister(id);
        router.dispatch(datagram(id, 1));
        assert!(session.try_recv().is_err());
    }

    /// A session whose reader has stopped must not hold its queue open for the
    /// life of the connection.
    #[tokio::test]
    async fn test_a_closed_session_is_forgotten_on_the_next_datagram() {
        let router = DatagramRouter::new(first_four);
        let (id, session) = router.register();
        drop(session);
        router.dispatch(datagram(id, 1));
        assert!(!router.sessions.lock().queues.contains_key(&id));
    }

    /// A caller can be handed a connection that dies before it registers:
    /// `get` checks the connection under its own lock, and the reader stops
    /// afterwards. Such a session must be told the connection is gone rather
    /// than waiting on a queue nothing will fill - which is what it did while
    /// `run` only cleared the map and left no mark.
    #[tokio::test]
    async fn test_registering_after_the_connection_died_reports_end_of_stream() {
        let router = DatagramRouter::new(first_four);
        router.sessions.lock().terminated = true;

        let (_id, mut session) = router.register();

        // Bounded on purpose. The failure this guards against is a wait that
        // never ends, and a bare `recv().await` would express that by hanging
        // the whole suite instead of failing this test.
        let ended = tokio::time::timeout(std::time::Duration::from_secs(2), session.recv())
            .await
            .expect("a session on a dead connection must end, not wait");
        assert!(ended.is_none(), "it must end, not deliver");
    }

    /// A malformed datagram is not routable and must not be charged to
    /// whichever session happens to be registered.
    #[tokio::test]
    async fn test_a_datagram_too_short_to_key_is_dropped() {
        let router = DatagramRouter::new(first_four);
        let (_id, mut session) = router.register();
        router.dispatch(Bytes::from_static(&[0u8; 3]));
        assert!(session.try_recv().is_err());
    }
}
