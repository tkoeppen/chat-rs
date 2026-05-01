use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Result;

pub const KEY_LEN: usize = 32;
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

const PSK_INFO: &[u8] = b"chat-rs/v1/psk";
const ROOM_INFO: &[u8] = b"chat-rs/v1/room";

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

    let hk = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut psk = [0u8; KEY_LEN];
    let mut room_key = [0u8; KEY_LEN];
    hk.expand(PSK_INFO, &mut psk)?;
    hk.expand(ROOM_INFO, &mut room_key)?;

    Ok(DerivedKeys { psk, room_key })
}

#[cfg(test)]
mod tests {
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
