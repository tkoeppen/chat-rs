use serde::{Serialize, de::DeserializeOwned};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Result;
use crate::wire::{FramedStream, recv_bytes, send_bytes};

const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const NOISE_BUF: usize = 65535;

fn params() -> NoiseParams {
    PATTERN.parse().expect("static noise pattern")
}

pub fn initiator(psk: &[u8; 32], prologue: &[u8]) -> Result<HandshakeState> {
    Ok(Builder::new(params())
        .prologue(prologue)?
        .psk(0, psk)?
        .build_initiator()?)
}

pub fn responder(psk: &[u8; 32], prologue: &[u8]) -> Result<HandshakeState> {
    Ok(Builder::new(params())
        .prologue(prologue)?
        .psk(0, psk)?
        .build_responder()?)
}

/// `prologue` is mixed into the handshake hash on both sides so any in-flight
/// tampering with the plaintext server-hello (room_salt, server_version) fails
/// fast on the first transport message instead of after the client wastes its
/// Argon2 budget. Both sides MUST pass identical prologue bytes.
pub async fn handshake_initiator<S>(
    psk: &[u8; 32],
    prologue: &[u8],
    framed: &mut FramedStream<S>,
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = initiator(psk, prologue)?;
    let mut buf = vec![0u8; NOISE_BUF];

    let n = hs.write_message(&[], &mut buf)?;
    send_bytes(framed, buf[..n].to_vec()).await?;

    let m1 = recv_bytes(framed).await?;
    let _ = hs.read_message(&m1, &mut buf)?;

    Ok(hs.into_transport_mode()?)
}

pub async fn handshake_responder<S>(
    psk: &[u8; 32],
    prologue: &[u8],
    framed: &mut FramedStream<S>,
) -> Result<TransportState>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = responder(psk, prologue)?;
    let mut buf = vec![0u8; NOISE_BUF];

    let m0 = recv_bytes(framed).await?;
    let _ = hs.read_message(&m0, &mut buf)?;

    let n = hs.write_message(&[], &mut buf)?;
    send_bytes(framed, buf[..n].to_vec()).await?;

    Ok(hs.into_transport_mode()?)
}

pub fn transport_seal(state: &mut TransportState, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; plaintext.len() + 64];
    let n = state.write_message(plaintext, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub fn transport_open(state: &mut TransportState, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; ciphertext.len()];
    let n = state.read_message(ciphertext, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

pub async fn send_encrypted<S, T>(
    framed: &mut FramedStream<S>,
    transport: &mut TransportState,
    value: &T,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize,
{
    let pt = postcard::to_stdvec(value)?;
    let ct = transport_seal(transport, &pt)?;
    send_bytes(framed, ct).await
}

pub async fn recv_encrypted<S, T>(
    framed: &mut FramedStream<S>,
    transport: &mut TransportState,
) -> Result<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: DeserializeOwned,
{
    let bytes = recv_bytes(framed).await?;
    let pt = transport_open(transport, &bytes)?;
    Ok(postcard::from_bytes(&pt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::frame;
    use tokio::io::duplex;

    const PROLOGUE: &[u8] = b"test";

    #[tokio::test]
    async fn handshake_round_trip() {
        let psk = [7u8; 32];
        let (a, b) = duplex(8192);
        let mut server_framed = frame(a);
        let mut client_framed = frame(b);

        let server = tokio::spawn(async move {
            let t = handshake_responder(&[7u8; 32], PROLOGUE, &mut server_framed).await?;
            Ok::<_, crate::error::Error>(t)
        });
        let mut client_t = handshake_initiator(&psk, PROLOGUE, &mut client_framed)
            .await
            .unwrap();
        let mut server_t = server.await.unwrap().unwrap();

        let ct = transport_seal(&mut client_t, b"hi").unwrap();
        let pt = transport_open(&mut server_t, &ct).unwrap();
        assert_eq!(pt, b"hi");
    }

    #[tokio::test]
    async fn wrong_psk_fails() {
        let (a, b) = duplex(8192);
        let mut server_framed = frame(a);
        let mut client_framed = frame(b);

        let server = tokio::spawn(async move {
            handshake_responder(&[1u8; 32], PROLOGUE, &mut server_framed).await
        });
        let client = handshake_initiator(&[2u8; 32], PROLOGUE, &mut client_framed).await;
        let server = server.await.unwrap();
        assert!(client.is_err() || server.is_err());
    }

    #[tokio::test]
    async fn prologue_mismatch_fails() {
        // Both sides have the right PSK but disagree on the prologue (i.e.,
        // an active MITM tampered with the plaintext server-hello). Handshake
        // must fail.
        let (a, b) = duplex(8192);
        let mut server_framed = frame(a);
        let mut client_framed = frame(b);

        let server = tokio::spawn(async move {
            handshake_responder(&[7u8; 32], b"server-prologue", &mut server_framed).await
        });
        let client = handshake_initiator(&[7u8; 32], b"client-prologue", &mut client_framed).await;
        let server = server.await.unwrap();
        assert!(client.is_err() || server.is_err());
    }
}
