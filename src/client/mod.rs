//! Client module.
//!
//! NEVER log fields named `password`, `psk`, `room_key`, or any AEAD nonce/tag.
//! Plaintext message bodies are also forbidden in logs.

pub mod ui;

use std::net::SocketAddr;

use crossterm::event::{Event, EventStream};
use futures_util::StreamExt;
use ratatui::Frame;
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::crypto::noise::{
    build_prologue, handshake_initiator, recv_encrypted, send_encrypted, transport_open,
};
use crate::crypto::password::derive_keys;
use crate::error::{Error, Result};
use crate::proto::{ClientFrame, PROTOCOL_VERSION, ServerFrame};
use crate::wire::{FramedStream, frame, recv_postcard, send_postcard};

use ui::{KeyAction, TerminalGuard, UiState};

pub async fn run(
    addr: SocketAddr,
    username: String,
    room: String,
    password: Zeroizing<Vec<u8>>,
) -> Result<()> {
    let sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true).ok();
    let mut framed = frame(sock);

    // Pre-Noise plaintext frame: tell the server which room we want.
    send_postcard(&mut framed, &ClientFrame::RoomSelect { room: room.clone() }).await?;

    let hello: ServerFrame = recv_postcard(&mut framed).await?;
    let (room_salt, server_version) = match hello {
        ServerFrame::Hello {
            room_salt,
            server_version,
        } => (room_salt, server_version),
        ServerFrame::Error { reason } => return Err(Error::Server(reason)),
        _ => return Err(Error::Protocol("expected ServerFrame::Hello")),
    };
    if server_version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(server_version));
    }

    let keys = derive_keys(&password, &room_salt)?;
    drop(password);
    // Prologue binds (room_id, room_salt, server_version): MITM tampering
    // with the plaintext server-hello, version downgrade, or shuffling a
    // client between rooms all fail at handshake M1 verify.
    let prologue = build_prologue(&room, &room_salt, server_version);
    let mut transport = handshake_initiator(&keys.psk, &prologue, &mut framed).await?;
    let room_key = Zeroizing::new(keys.room_key);
    drop(keys);

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

    let mut state = UiState::new(username, user_id, addr, room);
    for m in &history {
        // Seed seen_counters from the replayed history so the next live
        // message from each sender must strictly exceed what we saw here.
        state.try_accept_counter(m.ad.from, m.ad.counter);
        state.push(ui::decrypt_to_display(&room_key, m));
    }

    // RAII guard restores the terminal even if event_loop panics.
    let mut guard = TerminalGuard::enter().map_err(Error::Io)?;
    let mut events = EventStream::new();
    event_loop(
        &mut state,
        &mut guard,
        &mut events,
        &mut framed,
        &mut transport,
        &room_key,
    )
    .await
}

async fn event_loop<S>(
    state: &mut UiState,
    guard: &mut TerminalGuard,
    events: &mut EventStream,
    framed: &mut FramedStream<S>,
    transport: &mut snow::TransportState,
    room_key: &[u8; 32],
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        guard
            .term()
            .draw(|f: &mut Frame| ui::render(f, state))
            .map_err(Error::Io)?;

        tokio::select! {
            biased;
            ev = events.next() => {
                match ev {
                    Some(Ok(Event::Key(k))) => match ui::handle_key(state, k, room_key) {
                        KeyAction::Quit => return Ok(()),
                        KeyAction::Send(frame_out) => {
                            send_encrypted(framed, transport, &frame_out).await?;
                        }
                        KeyAction::None => {}
                    },
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(Error::Io(e)),
                    None => return Ok(()),
                }
            }
            incoming = framed.next() => {
                let bytes = match incoming {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                };
                let pt = transport_open(transport, &bytes)?;
                let msg: ServerFrame = postcard::from_bytes(&pt)?;
                if let Some(err) = handle_server_frame(state, room_key, msg) {
                    return Err(err);
                }
            }
        }
    }
}

fn handle_server_frame(
    state: &mut UiState,
    room_key: &[u8; 32],
    msg: ServerFrame,
) -> Option<Error> {
    match msg {
        ServerFrame::Message(m) => {
            // Reject server-side replay: counter must strictly exceed the
            // last we accepted from this sender (keyed by user_id, which is
            // unique per session).
            if !state.try_accept_counter(m.ad.from, m.ad.counter) {
                state.push_system(format!("dropped replay from {}", m.username));
                return None;
            }
            state.push(ui::decrypt_to_display(room_key, &m));
            None
        }
        ServerFrame::Cleared { by: _, username } => {
            // Wipe local display too, so /clear actually empties the room
            // for every client (sender included). The notice survives so
            // the user sees feedback that the clear happened.
            state.clear_messages();
            state.push_system(format!("cleared by {username}"));
            None
        }
        ServerFrame::Error { reason } => Some(Error::Server(reason)),
        ServerFrame::Hello { .. } | ServerFrame::Welcome { .. } => {
            Some(Error::Protocol("unexpected handshake frame after auth"))
        }
    }
}
