use std::collections::HashMap;

use tokio::sync::mpsc;
use uuid::Uuid;

use crate::proto::ServerFrame;

pub type Outgoing = mpsc::Sender<ServerFrame>;

#[derive(Default)]
pub struct ConnectionManager {
    senders: HashMap<Uuid, Outgoing>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, user_id: Uuid, tx: Outgoing) {
        self.senders.insert(user_id, tx);
    }

    pub fn remove(&mut self, user_id: &Uuid) {
        self.senders.remove(user_id);
    }

    /// Snapshot of `(user_id, sender)` pairs. Callers send without holding the lock.
    pub fn snapshot(&self) -> Vec<(Uuid, Outgoing)> {
        self.senders
            .iter()
            .map(|(id, tx)| (*id, tx.clone()))
            .collect()
    }
}
