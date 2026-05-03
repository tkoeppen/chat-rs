//! Rooms config — one `RoomConfig { name, password }` per room.
//!
//! Format: line-oriented `name=password`. Blank lines and `#`-prefixed
//! comments are ignored. The room name is validated to `[A-Za-z0-9_-]{1,32}`;
//! the password must be at least `MIN_PW_LEN` bytes (matching the CLI floor).
//!
//! Source: the multi-line `CHAT_RS_ROOMS` env var (typically populated from
//! a `.env` file). Example value:
//! ```text
//! # rooms
//! dev = changeme
//! ops = anothersecret
//! ```

use crate::error::{Error, Result};
use crate::proto::MAX_ROOM_ID_LEN;

/// Same floor as `cli::MIN_PW_LEN`. Duplicated here so the rooms parser
/// doesn't depend on `cli` (which would invert the module dependency).
const MIN_PW_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct RoomConfig {
    pub name: String,
    pub password: String,
}

pub fn parse(text: &str) -> Result<Vec<RoomConfig>> {
    let mut rooms = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, password) = line
            .split_once('=')
            .ok_or(Error::Protocol("rooms config: line missing '='"))?;
        let name = name.trim().to_string();
        let password = password.trim().to_string();
        validate_name(&name)?;
        if password.len() < MIN_PW_LEN {
            return Err(Error::Protocol("rooms config: password too short"));
        }
        if !seen.insert(name.clone()) {
            return Err(Error::Protocol("rooms config: duplicate room name"));
        }
        rooms.push(RoomConfig { name, password });
    }
    if rooms.is_empty() {
        return Err(Error::Protocol("rooms config: no rooms"));
    }
    Ok(rooms)
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_ROOM_ID_LEN {
        return Err(Error::Protocol("invalid room name length"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::Protocol("room name must match [A-Za-z0-9_-]"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn parses_two_rooms_with_comments() {
        let text = "
            # dev environment
            dev = changeme-12c
            # ops
            ops = anothersecret
        ";
        let r = parse(text).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].name, "dev");
        assert_eq!(r[0].password, "changeme-12c");
        assert_eq!(r[1].name, "ops");
    }

    #[test]
    fn rejects_short_password() {
        assert!(parse("dev=short1\n").is_err());
    }

    #[test]
    fn rejects_invalid_name() {
        assert!(parse("dev/ops=changeme-12c\n").is_err());
        assert!(parse("=changeme-12c\n").is_err());
    }

    #[test]
    fn rejects_duplicate_room() {
        assert!(parse("dev=changeme-12c\ndev=changeme-other\n").is_err());
    }

    #[test]
    fn rejects_empty_config() {
        assert!(parse("# only comments\n").is_err());
    }
}
