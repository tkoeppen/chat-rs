//! Server module.
//!
//! NEVER log fields named `password`, `psk`, `room_key`, or any AEAD nonce/tag.
//! Plaintext message bodies are also forbidden in logs.

pub mod managers;
pub mod ratelimit;
pub mod rooms;
pub mod stores;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::noise::{build_prologue, handshake_responder, recv_encrypted, send_encrypted};
use crate::crypto::password::derive_keys;
use crate::error::{Error, ErrorKind, Result};
use crate::proto::{
    ClientFrame, MAX_ROOM_ID_LEN, MAX_USERNAME_LEN, PROTOCOL_VERSION, RoomMessage, ServerFrame,
};
use crate::wire::{FramedStream, frame, recv_postcard, send_postcard};

use managers::ConnectionManager;
use ratelimit::RateLimiter;
use rooms::RoomConfig;
use stores::{MessageStore, UserSessionStore};

const SESSION_TIMEOUT: Duration = Duration::from_secs(3600);
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const OUTBOX_DEPTH: usize = 64;
/// Time budget for the unauthenticated handshake phase (RoomSelect + Noise
/// M0/M1 + the first encrypted ClientFrame::Hello). Connections that don't
/// complete in this window are dropped — closes the slow-loris vector.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RATELIMIT_MAX: usize = 60;
const RATELIMIT_WINDOW: Duration = Duration::from_secs(60);

pub type RoomId = String;

/// Per-room server state. One `Arc<RoomState>` per room, shared by every
/// connection in that room.
pub struct RoomState {
    pub room_id: RoomId,
    pub room_salt: [u8; 32],
    /// Noise PSK derived once at startup from the room's password + salt.
    pub psk: Zeroizing<[u8; 32]>,
    pub messages: Mutex<MessageStore>,
    pub sessions: Mutex<UserSessionStore>,
    pub connections: Mutex<ConnectionManager>,
}

/// Top-level server: a map of rooms + a global rate-limiter.
pub struct ServerHub {
    pub rooms: HashMap<RoomId, Arc<RoomState>>,
    pub ratelimit: RateLimiter,
}

impl ServerHub {
    /// Derives every room's PSK at startup. Each room's password is dropped
    /// (zeroized) before this returns; the unauthenticated TCP path never
    /// triggers Argon2.
    pub fn new(configs: Vec<RoomConfig>) -> Result<Arc<Self>> {
        let mut rooms = HashMap::with_capacity(configs.len());
        for cfg in configs {
            let mut salt = [0u8; 32];
            getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
            let pw = Zeroizing::new(cfg.password.into_bytes());
            let keys = derive_keys(&pw, &salt)?;
            let psk = Zeroizing::new(keys.psk);
            // pw + keys (with room_key) drop here — both zeroized.
            rooms.insert(
                cfg.name.clone(),
                Arc::new(RoomState {
                    room_id: cfg.name,
                    room_salt: salt,
                    psk,
                    messages: Mutex::new(MessageStore::new()),
                    sessions: Mutex::new(UserSessionStore::new(SESSION_TIMEOUT)),
                    connections: Mutex::new(ConnectionManager::new()),
                }),
            );
        }
        Ok(Arc::new(Self {
            rooms,
            ratelimit: RateLimiter::new(RATELIMIT_MAX, RATELIMIT_WINDOW),
        }))
    }
}

pub async fn run(addr: SocketAddr, configs: Vec<RoomConfig>) -> Result<()> {
    let hub = ServerHub::new(configs)?;
    let listener = TcpListener::bind(addr).await?;
    info!(rooms = hub.rooms.len(), %addr, "listening");

    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();

    tasks.spawn(sweeper(hub.clone(), shutdown.clone()));

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received; shutting down");
                shutdown.cancel();
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((sock, peer)) => {
                        if !hub.ratelimit.check(peer.ip()) {
                            warn!(%peer, "rate-limited; dropping connection");
                            drop(sock);
                            continue;
                        }
                        let hub = hub.clone();
                        let shutdown = shutdown.clone();
                        tasks.spawn(async move {
                            if let Err(e) = handle_connection(hub, sock, peer, shutdown).await {
                                warn!(%peer, error = %e, "connection error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    drop(listener);
    info!(active = tasks.len(), "draining tasks");
    while tasks.join_next().await.is_some() {}
    info!("shutdown complete");
    Ok(())
}

async fn sweeper(hub: Arc<ServerHub>, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.tick().await; // skip immediate fire
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        hub.ratelimit.cleanup();
        for room in hub.rooms.values() {
            let stale = {
                let s = room.sessions.lock().await;
                s.stale()
            };
            if stale.is_empty() {
                continue;
            }
            let count = stale.len();
            let mut sessions = room.sessions.lock().await;
            let mut conns = room.connections.lock().await;
            for id in stale {
                sessions.remove(&id);
                conns.remove(&id);
            }
            info!(room = %room.room_id, evicted = count, "sweeper evicted stale sessions");
        }
    }
}

async fn handle_connection(
    hub: Arc<ServerHub>,
    sock: TcpStream,
    peer: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let mut framed = frame(sock);

    // Phase 0a: read RoomSelect (plaintext) under the handshake timeout.
    let select: ClientFrame = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        recv_postcard::<_, ClientFrame>(&mut framed),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            warn!(%peer, "client did not send RoomSelect in time");
            return Err(Error::Protocol("room select timeout"));
        }
    };
    let room_name = match select {
        ClientFrame::RoomSelect { room } => room,
        _ => return Err(Error::Protocol("expected RoomSelect")),
    };
    if room_name.is_empty() || room_name.len() > MAX_ROOM_ID_LEN {
        let _ = send_postcard(
            &mut framed,
            &ServerFrame::Error {
                reason: ErrorKind::BadFrame,
            },
        )
        .await;
        return Err(Error::Protocol("invalid room name length"));
    }
    // Look up room. Reply with AuthFailed (not a more specific error) on miss
    // so an attacker can't enumerate room names.
    let room = match hub.rooms.get(&room_name).cloned() {
        Some(r) => r,
        None => {
            let _ = send_postcard(
                &mut framed,
                &ServerFrame::Error {
                    reason: ErrorKind::AuthFailed,
                },
            )
            .await;
            warn!(%peer, room = %room_name, "unknown room");
            return Err(Error::Protocol("unknown room"));
        }
    };

    // Phase 0b: send the room's plaintext server hello.
    send_postcard(
        &mut framed,
        &ServerFrame::Hello {
            room_salt: room.room_salt,
            server_version: PROTOCOL_VERSION,
        },
    )
    .await?;

    // Phase 1: Noise NNpsk0 with prologue = (room_id, room_salt). Wrapped in
    // a timeout to close the slow-loris vector.
    let prologue = build_prologue(&room.room_id, &room.room_salt);
    let mut transport = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_responder(&room.psk, &prologue, &mut framed),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            warn!(%peer, room = %room.room_id, error = %e, "handshake failed");
            return Err(e);
        }
        Err(_) => {
            warn!(%peer, room = %room.room_id, "handshake timed out");
            return Err(Error::Protocol("handshake timeout"));
        }
    };

    // First Noise-encrypted frame from client must be ClientFrame::Hello.
    let first: ClientFrame = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        recv_encrypted(&mut framed, &mut transport),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            warn!(%peer, room = %room.room_id, "client did not send Hello in time");
            return Err(Error::Protocol("hello timeout"));
        }
    };
    let username = match first {
        ClientFrame::Hello { username } => {
            if username.is_empty() || username.len() > MAX_USERNAME_LEN {
                let _ = send_encrypted(
                    &mut framed,
                    &mut transport,
                    &ServerFrame::Error {
                        reason: ErrorKind::BadFrame,
                    },
                )
                .await;
                return Err(Error::Protocol("invalid username length"));
            }
            username
        }
        _ => {
            let _ = send_encrypted(
                &mut framed,
                &mut transport,
                &ServerFrame::Error {
                    reason: ErrorKind::BadFrame,
                },
            )
            .await;
            return Err(Error::Protocol("expected ClientFrame::Hello"));
        }
    };

    let user_id = Uuid::new_v4();
    let (tx, mut rx) = mpsc::channel::<ServerFrame>(OUTBOX_DEPTH);

    {
        let mut sessions = room.sessions.lock().await;
        sessions.insert(user_id, username.clone());
        let mut conns = room.connections.lock().await;
        conns.insert(user_id, tx);
    }
    info!(%peer, room = %room.room_id, %user_id, %username, "connected");

    let history = {
        let m = room.messages.lock().await;
        m.snapshot()
    };
    send_encrypted(
        &mut framed,
        &mut transport,
        &ServerFrame::Welcome { user_id, history },
    )
    .await?;

    let result = pump(
        &room,
        user_id,
        &username,
        &mut framed,
        &mut transport,
        &mut rx,
        &shutdown,
    )
    .await;

    {
        let mut sessions = room.sessions.lock().await;
        sessions.remove(&user_id);
        let mut conns = room.connections.lock().await;
        conns.remove(&user_id);
    }
    info!(%peer, room = %room.room_id, %user_id, %username, "disconnected");
    result
}

async fn pump<S>(
    room: &Arc<RoomState>,
    user_id: Uuid,
    username: &str,
    framed: &mut FramedStream<S>,
    transport: &mut snow::TransportState,
    rx: &mut mpsc::Receiver<ServerFrame>,
    shutdown: &CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return Ok(()),
            outgoing = rx.recv() => {
                match outgoing {
                    Some(frame_out) => send_encrypted(framed, transport, &frame_out).await?,
                    None => return Ok(()),
                }
            }
            incoming = framed.next() => {
                let bytes = match incoming {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => return Err(e.into()),
                    None => return Ok(()),
                };
                let pt = crate::crypto::noise::transport_open(transport, &bytes)?;
                let msg: ClientFrame = postcard::from_bytes(&pt)?;
                handle_client_frame(room, user_id, username, msg).await?;
            }
        }
    }
}

async fn handle_client_frame(
    room: &Arc<RoomState>,
    user_id: Uuid,
    username: &str,
    msg: ClientFrame,
) -> Result<()> {
    {
        let mut sessions = room.sessions.lock().await;
        sessions.touch(user_id);
    }
    match msg {
        ClientFrame::RoomSelect { .. } | ClientFrame::Hello { .. } => {
            Err(Error::Protocol("unexpected handshake frame after auth"))
        }
        ClientFrame::Message { ad, ciphertext } => {
            if ad.from != user_id {
                return Err(Error::Protocol("ad.from does not match session user_id"));
            }
            if ad.username != username {
                return Err(Error::Protocol("ad.username does not match session"));
            }
            {
                let mut sessions = room.sessions.lock().await;
                if !sessions.try_advance_counter(user_id, ad.counter) {
                    return Err(Error::Protocol("ad.counter not strictly increasing"));
                }
            }
            let room_msg = RoomMessage {
                from: user_id,
                username: username.to_string(),
                ad,
                ciphertext,
            };
            {
                let mut m = room.messages.lock().await;
                m.push(room_msg.clone());
            }
            broadcast(room, ServerFrame::Message(room_msg)).await;
            Ok(())
        }
        ClientFrame::Clear => {
            {
                let mut m = room.messages.lock().await;
                m.clear();
            }
            broadcast(
                room,
                ServerFrame::Cleared {
                    by: user_id,
                    username: username.to_string(),
                },
            )
            .await;
            Ok(())
        }
    }
}

/// Broadcast a frame to all connected peers in this room. Uses `try_send` so a
/// slow or stuck peer cannot head-of-line block delivery; full or closed
/// outboxes are evicted.
async fn broadcast(room: &Arc<RoomState>, frame_out: ServerFrame) {
    let snapshot = {
        let conns = room.connections.lock().await;
        conns.snapshot()
    };
    let mut dead = Vec::new();
    for (id, tx) in snapshot {
        match tx.try_send(frame_out.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => dead.push(id),
        }
    }
    if !dead.is_empty() {
        let dead_count = dead.len();
        let mut conns = room.connections.lock().await;
        for id in dead {
            conns.remove(&id);
        }
        debug!(room = %room.room_id, evicted = dead_count, "broadcast evicted slow or dead peers");
    }
}
