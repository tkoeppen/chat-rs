use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ErrorKind;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 64 * 1024;
pub const HISTORY_LEN: usize = 15;
/// Bound on `ClientFrame::Hello { username }`. Keeps a misbehaving client from
/// amplifying broadcast and history memory by sending huge usernames.
pub const MAX_USERNAME_LEN: usize = 32;
/// Bound on `ClientFrame::RoomSelect { room }`. Same rationale as
/// MAX_USERNAME_LEN; also prevents oversized HashMap key churn server-side.
pub const MAX_ROOM_ID_LEN: usize = 32;
/// Bound on `ClientFrame::Message.ciphertext`. Sized so the worst-case
/// `ServerFrame::Welcome { history: [HISTORY_LEN of these] }` still fits
/// inside `MAX_FRAME_LEN` after Noise framing — otherwise a busy room with
/// large messages would lock new joiners out (Welcome would exceed the
/// 64 KiB frame cap). Includes the 24-byte XChaCha20-Poly1305 nonce + 16-byte
/// tag, so plaintext payload tops out around 4 KiB.
pub const MAX_CIPHERTEXT_LEN: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Pre-Noise plaintext frame: client tells the server which room it wants.
    /// Server uses this to look up the room's PSK before sending its Hello.
    RoomSelect {
        room: String,
    },
    Hello {
        username: String,
    },
    Message {
        ad: MessageAd,
        ciphertext: Vec<u8>,
    },
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
        username: String,
    },
    Error {
        reason: ErrorKind,
    },
}

/// Server-broadcast message frame. The outer `from` / `username` and the
/// inner `ad.from` / `ad.username` carry the same values: the server sets
/// the outer fields to the session-validated identity, and `ad` is bound
/// into the AEAD AAD so the receiver re-verifies the inner copies on
/// decrypt. The duplication is redundant — only the AAD-bound fields are
/// actually authenticated — and could be flattened in a future wire-break.
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
    /// Display name of the sender. Bound into the AEAD AAD so a malicious
    /// server cannot relabel messages without breaking decryption.
    pub username: String,
    /// Per-sender monotonic counter. Bound into the AEAD AAD; used by both
    /// server and clients to reject replays. Starts at 1 for the first
    /// message a client sends in its session.
    pub counter: u64,
    pub timestamp_ms: u64,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn roundtrips<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) {
        let bytes = postcard::to_stdvec(v).unwrap();
        let back: T = postcard::from_bytes(&bytes).unwrap();
        // Re-serialize since the enums lack PartialEq.
        assert_eq!(postcard::to_stdvec(&back).unwrap(), bytes);
    }

    #[test]
    fn client_frame_roundtrip() {
        roundtrips(&ClientFrame::RoomSelect {
            room: "main".into(),
        });
        roundtrips(&ClientFrame::Hello {
            username: "alice".into(),
        });
        roundtrips(&ClientFrame::Message {
            ad: MessageAd {
                from: Uuid::nil(),
                username: "alice".into(),
                counter: 1,
                timestamp_ms: 1234,
            },
            ciphertext: vec![1, 2, 3, 4],
        });
        roundtrips(&ClientFrame::Clear);
    }

    #[test]
    fn server_frame_roundtrip() {
        let rm = RoomMessage {
            from: Uuid::nil(),
            username: "alice".into(),
            ad: MessageAd {
                from: Uuid::nil(),
                username: "alice".into(),
                counter: 1,
                timestamp_ms: 1234,
            },
            ciphertext: vec![5, 6, 7],
        };
        roundtrips(&ServerFrame::Hello {
            room_salt: [7u8; 32],
            server_version: PROTOCOL_VERSION,
        });
        roundtrips(&ServerFrame::Welcome {
            user_id: Uuid::nil(),
            history: vec![rm.clone()],
        });
        roundtrips(&ServerFrame::Message(rm));
        roundtrips(&ServerFrame::Cleared {
            by: Uuid::nil(),
            username: "alice".into(),
        });
        roundtrips(&ServerFrame::Error {
            reason: ErrorKind::AuthFailed,
        });
    }
}
