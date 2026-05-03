use std::collections::VecDeque;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::proto::{HISTORY_LEN, RoomMessage};

/// Per-session message-send cap, sliding-window. Authenticated DoS guard:
/// without this, one client at line rate triggers O(N) broadcast work per
/// message across every other peer in the room.
pub const MSG_RATE_MAX: usize = 30;
pub const MSG_RATE_WINDOW: Duration = Duration::from_secs(10);
/// Minimum gap between `/clear` operations from a single session. `/clear`
/// is destructive and broadcast-amplified, so a short cooldown stops
/// griefing without breaking legitimate use.
pub const CLEAR_COOLDOWN: Duration = Duration::from_secs(30);

pub struct MessageStore {
    history: VecDeque<RoomMessage>,
}

impl MessageStore {
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(HISTORY_LEN),
        }
    }

    pub fn push(&mut self, msg: RoomMessage) {
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(msg);
    }

    pub fn snapshot(&self) -> Vec<RoomMessage> {
        self.history.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }
}

impl Default for MessageStore {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UserSession {
    pub user_id: Uuid,
    pub username: String,
    pub last_active: Instant,
    /// Highest accepted `MessageAd.counter` for this session. New messages
    /// must strictly exceed this to be accepted (replay protection).
    pub last_counter: u64,
    /// Sliding window of recent `Message` send timestamps. Capped at
    /// `MSG_RATE_MAX` per `MSG_RATE_WINDOW`.
    pub message_window: VecDeque<Instant>,
    /// When this session last issued `/clear`. Used to enforce
    /// `CLEAR_COOLDOWN` on a destructive, broadcast-amplified op.
    pub last_clear: Option<Instant>,
}

pub struct UserSessionStore {
    sessions: std::collections::HashMap<Uuid, UserSession>,
    timeout: Duration,
}

impl UserSessionStore {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            timeout,
        }
    }

    pub fn insert(&mut self, user_id: Uuid, username: String) {
        self.sessions.insert(
            user_id,
            UserSession {
                user_id,
                username,
                last_active: Instant::now(),
                last_counter: 0,
                message_window: VecDeque::with_capacity(MSG_RATE_MAX),
                last_clear: None,
            },
        );
    }

    pub fn touch(&mut self, user_id: Uuid) {
        if let Some(s) = self.sessions.get_mut(&user_id) {
            s.last_active = Instant::now();
        }
    }

    /// If `counter` is strictly greater than the session's `last_counter`,
    /// updates and returns true; otherwise leaves it and returns false.
    pub fn try_advance_counter(&mut self, user_id: Uuid, counter: u64) -> bool {
        match self.sessions.get_mut(&user_id) {
            Some(s) if counter > s.last_counter => {
                s.last_counter = counter;
                true
            }
            _ => false,
        }
    }

    /// Records a `Message` send for the given session. Returns true if it
    /// fits inside the sliding window (`MSG_RATE_MAX` per `MSG_RATE_WINDOW`),
    /// false if the cap is exceeded.
    pub fn try_consume_message_quota(&mut self, user_id: Uuid) -> bool {
        let Some(s) = self.sessions.get_mut(&user_id) else {
            return false;
        };
        let now = Instant::now();
        while s
            .message_window
            .front()
            .is_some_and(|t| now.duration_since(*t) > MSG_RATE_WINDOW)
        {
            s.message_window.pop_front();
        }
        if s.message_window.len() >= MSG_RATE_MAX {
            return false;
        }
        s.message_window.push_back(now);
        true
    }

    /// True if `/clear` is allowed for this session right now (first time
    /// ever, or last clear was longer than `CLEAR_COOLDOWN` ago). Records
    /// the new clear timestamp on success.
    pub fn try_consume_clear(&mut self, user_id: Uuid) -> bool {
        let Some(s) = self.sessions.get_mut(&user_id) else {
            return false;
        };
        let now = Instant::now();
        if let Some(prev) = s.last_clear
            && now.duration_since(prev) < CLEAR_COOLDOWN
        {
            return false;
        }
        s.last_clear = Some(now);
        true
    }

    pub fn remove(&mut self, user_id: &Uuid) -> Option<UserSession> {
        self.sessions.remove(user_id)
    }

    pub fn stale(&self) -> Vec<Uuid> {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_active) > self.timeout)
            .map(|(id, _)| *id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::proto::MessageAd;

    fn msg(text: &str) -> RoomMessage {
        RoomMessage {
            from: Uuid::new_v4(),
            username: "x".into(),
            ad: MessageAd {
                from: Uuid::nil(),
                username: "x".into(),
                counter: 1,
                timestamp_ms: 0,
            },
            ciphertext: text.as_bytes().to_vec(),
        }
    }

    #[test]
    fn history_caps_at_limit() {
        let mut s = MessageStore::new();
        for i in 0..(HISTORY_LEN + 5) {
            s.push(msg(&format!("{i}")));
        }
        let snap = s.snapshot();
        assert_eq!(snap.len(), HISTORY_LEN);
        assert_eq!(snap.first().unwrap().ciphertext, b"5");
        assert_eq!(
            snap.last().unwrap().ciphertext,
            format!("{}", HISTORY_LEN + 4).as_bytes()
        );
    }
}
