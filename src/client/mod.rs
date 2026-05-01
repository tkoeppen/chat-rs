//! Client module.
//!
//! NEVER log fields named `password`, `psk`, `room_key`, or any AEAD nonce/tag.
//! Plaintext message bodies are also forbidden in logs.

use std::net::SocketAddr;

use futures_util::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::noise::{handshake_initiator, recv_encrypted, send_encrypted, transport_open};
use crate::crypto::password::derive_keys;
use crate::crypto::room;
use crate::error::{Error, Result};
use crate::proto::{ClientFrame, MessageAd, PROTOCOL_VERSION, RoomMessage, ServerFrame, now_ms};
use crate::wire::{frame, recv_postcard};

const OUTBOX_DEPTH: usize = 64;

pub async fn run(addr: SocketAddr, username: String, password: Zeroizing<Vec<u8>>) -> Result<()> {
    let sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true).ok();
    let mut framed = frame(sock);

    let hello: ServerFrame = recv_postcard(&mut framed).await?;
    let (room_salt, server_version) = match hello {
        ServerFrame::Hello {
            room_salt,
            server_version,
        } => (room_salt, server_version),
        _ => return Err(Error::Protocol("expected ServerFrame::Hello")),
    };
    if server_version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(server_version));
    }

    let keys = derive_keys(&password, &room_salt)?;
    drop(password); // password is no longer needed; zeroize via Zeroizing::Drop
    let mut transport = handshake_initiator(&keys.psk, &mut framed).await?;
    let room_key = Zeroizing::new(keys.room_key);
    drop(keys); // psk is no longer needed; zeroize via DerivedKeys::Drop

    send_encrypted(
        &mut framed,
        &mut transport,
        &ClientFrame::Hello {
            username: username.clone(),
        },
    )
    .await?;

    let welcome: ServerFrame = recv_encrypted(&mut framed, &mut transport).await?;
    let (user_id, history) = match welcome {
        ServerFrame::Welcome { user_id, history } => (user_id, history),
        ServerFrame::Error { reason } => return Err(Error::Server(reason)),
        _ => return Err(Error::Protocol("expected ServerFrame::Welcome")),
    };

    println!("connected as {username} ({user_id})");
    for msg in &history {
        print_message(&room_key, msg);
    }
    println!("---");

    let (out_tx, mut out_rx) = mpsc::channel::<ClientFrame>(OUTBOX_DEPTH);
    tokio::spawn(stdin_loop(out_tx, user_id, room_key.clone()));

    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                debug!("ctrl-c received; disconnecting");
                return Ok(());
            }
            outgoing = out_rx.recv() => {
                match outgoing {
                    Some(frame_out) => send_encrypted(&mut framed, &mut transport, &frame_out).await?,
                    None => return Ok(()),
                }
            }
            incoming = framed.next() => {
                let bytes = match incoming {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                };
                let pt = transport_open(&mut transport, &bytes)?;
                let msg: ServerFrame = postcard::from_bytes(&pt)?;
                if let Some(err) = handle_server_frame(&room_key, msg) {
                    return Err(err);
                }
            }
        }
    }
}

fn handle_server_frame(room_key: &[u8; 32], msg: ServerFrame) -> Option<Error> {
    match msg {
        ServerFrame::Message(m) => {
            print_message(room_key, &m);
            None
        }
        ServerFrame::Cleared { by } => {
            println!("--- cleared by {by} ---");
            None
        }
        ServerFrame::Error { reason } => Some(Error::Server(reason)),
        ServerFrame::Hello { .. } | ServerFrame::Welcome { .. } => {
            Some(Error::Protocol("unexpected handshake frame after auth"))
        }
    }
}

fn print_message(room_key: &[u8; 32], msg: &RoomMessage) {
    match room::open(room_key, &msg.ciphertext, &msg.ad) {
        Ok(pt) => {
            let text = String::from_utf8_lossy(&pt);
            println!(
                "[{}] {}: {}",
                fmt_ts(msg.ad.timestamp_ms),
                msg.username,
                text
            );
        }
        Err(_) => println!("[?] {}: [decryption failed]", msg.username),
    }
}

fn fmt_ts(ms: u64) -> String {
    let secs = ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

async fn stdin_loop(tx: mpsc::Sender<ClientFrame>, user_id: Uuid, room_key: Zeroizing<[u8; 32]>) {
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "/clear" {
            if tx.send(ClientFrame::Clear).await.is_err() {
                break;
            }
            continue;
        }
        let ad = MessageAd {
            from: user_id,
            timestamp_ms: now_ms(),
        };
        let ct = match room::seal(&room_key, trimmed.as_bytes(), &ad) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "room seal failed");
                continue;
            }
        };
        if tx
            .send(ClientFrame::Message { ad, ciphertext: ct })
            .await
            .is_err()
        {
            debug!("outbox closed; stdin loop ending");
            break;
        }
    }
}
