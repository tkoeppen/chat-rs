use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ErrorKind;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 64 * 1024;
pub const HISTORY_LEN: usize = 15;
/// Bound on `ClientFrame::Hello { username }`. Keeps a misbehaving client from
/// amplifying broadcast and history memory by sending huge usernames.
pub const MAX_USERNAME_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientFrame {
    Hello { username: String },
    Message { ad: MessageAd, ciphertext: Vec<u8> },
    Clear,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerFrame {
    Hello {
        room_salt: [u8; 32],
        server_version: u16,
    },
    Welcome {
        user_id: Uuid,
        history: Vec<RoomMessage>,
    },
    Message(RoomMessage),
    Cleared {
        by: Uuid,
    },
    Error {
        reason: ErrorKind,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMessage {
    pub from: Uuid,
    pub username: String,
    pub ad: MessageAd,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAd {
    pub from: Uuid,
    pub timestamp_ms: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
