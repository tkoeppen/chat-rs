use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2sMac256;
use blake2::digest::Mac;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
const ARGON2_M_KIB: u32 = 64 * 1024;
/// Iterations. Bumped from 3 → 4 to roughly 1.33× the per-guess cost for an
/// offline attacker who has captured a `room_salt` (the salt is shipped in
/// the plaintext server-hello, so anyone who can connect can grab it).
/// Server-side cost is paid once at startup per room, so this is essentially
/// free for the defender.
const ARGON2_T: u32 = 4;
const ARGON2_P: u32 = 1;

const PSK_LABEL: &[u8] = b"chat-rs/v1/psk";
const ROOM_LABEL: &[u8] = b"chat-rs/v1/room";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub psk: [u8; KEY_LEN],
    pub room_key: [u8; KEY_LEN],
}

pub fn derive_keys(password: &[u8], room_salt: &[u8; 32]) -> Result<DerivedKeys> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(password, room_salt, master.as_mut())?;

    Ok(DerivedKeys {
        psk: blake2s_kdf(master.as_ref(), PSK_LABEL)?,
        room_key: blake2s_kdf(master.as_ref(), ROOM_LABEL)?,
    })
}

/// Keyed BLAKE2s-256: distinct labels yield independent 32-byte keys from the
/// same Argon2 master. Same role HKDF-Expand played before, with one less
/// crate in the tree (BLAKE2s is already pulled in by argon2 + snow).
fn blake2s_kdf(master: &[u8], label: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut mac = <Blake2sMac256 as Mac>::new_from_slice(master).map_err(|_| Error::Kdf)?;
    mac.update(label);
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&out);
    Ok(k)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = [7u8; 32];
        let a = derive_keys(b"hunter2", &salt).unwrap();
        let b = derive_keys(b"hunter2", &salt).unwrap();
        assert_eq!(a.psk, b.psk);
        assert_eq!(a.room_key, b.room_key);
    }

    #[test]
    fn different_passwords_diverge() {
        let salt = [7u8; 32];
        let a = derive_keys(b"hunter2", &salt).unwrap();
        let b = derive_keys(b"hunter3", &salt).unwrap();
        assert_ne!(a.psk, b.psk);
        assert_ne!(a.room_key, b.room_key);
    }

    #[test]
    fn different_salts_diverge() {
        let a = derive_keys(b"hunter2", &[1u8; 32]).unwrap();
        let b = derive_keys(b"hunter2", &[2u8; 32]).unwrap();
        assert_ne!(a.psk, b.psk);
    }

    #[test]
    fn psk_and_room_key_differ() {
        let keys = derive_keys(b"hunter2", &[7u8; 32]).unwrap();
        assert_ne!(keys.psk, keys.room_key);
    }
}
