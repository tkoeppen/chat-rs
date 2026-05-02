use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::error::{Error, Result};
use crate::proto::MessageAd;

pub const NONCE_LEN: usize = 24;

pub fn seal(room_key: &[u8; 32], plaintext: &[u8], ad: &MessageAd) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(room_key.into());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
    let aad = postcard::to_stdvec(ad)?;
    let ct = cipher.encrypt(
        XNonce::from_slice(&nonce),
        Payload {
            msg: plaintext,
            aad: &aad,
        },
    )?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(room_key: &[u8; 32], ciphertext: &[u8], ad: &MessageAd) -> Result<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN {
        return Err(Error::Aead);
    }
    let (nonce, ct) = ciphertext.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(room_key.into());
    let aad = postcard::to_stdvec(ad)?;
    let pt = cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ad() -> MessageAd {
        MessageAd {
            from: Uuid::nil(),
            username: "alice".into(),
            counter: 1,
            timestamp_ms: 1000,
        }
    }

    #[test]
    fn roundtrip() {
        let key = [9u8; 32];
        let ct = seal(&key, b"hello", &ad()).unwrap();
        let pt = open(&key, &ct, &ad()).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = seal(&[1u8; 32], b"hello", &ad()).unwrap();
        assert!(open(&[2u8; 32], &ct, &ad()).is_err());
    }

    #[test]
    fn ad_tampering_fails() {
        let key = [9u8; 32];
        let ct = seal(&key, b"hello", &ad()).unwrap();
        let mut tampered = ad();
        tampered.timestamp_ms += 1;
        assert!(open(&key, &ct, &tampered).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = [9u8; 32];
        let ct = seal(&key, b"hello", &ad()).unwrap();
        assert!(open(&key, &ct[..NONCE_LEN], &ad()).is_err());
    }
}
