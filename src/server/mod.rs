//! Server module.
//!
//! NEVER log fields named `password`, `psk`, `room_key`, or any AEAD nonce/tag.
//! Plaintext message bodies are also forbidden in logs.

pub mod managers;
pub mod ratelimit;
pub mod stores;

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

use crate::crypto::noise::{handshake_responder, recv_encrypted, send_encrypted};
use crate::crypto::password::derive_keys;
use crate::error::{Error, ErrorKind, Result};
use crate::proto::{ClientFrame, MAX_USERNAME_LEN, PROTOCOL_VERSION, RoomMessage, ServerFrame};
use crate::wire::{FramedStream, frame, send_postcard};

use managers::ConnectionManager;
use ratelimit::RateLimiter;
use stores::{MessageStore, UserSessionStore};

const SESSION_TIMEOUT: Duration = Duration::from_secs(3600);
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
const OUTBOX_DEPTH: usize = 64;
/// Time budget for the unauthenticated handshake phase (Noise M0/M1 + the
/// first encrypted ClientFrame::Hello). Connections that don't complete in
/// this window are dropped — closes the slow-loris vector against tasks/FDs.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-IP connection cap inside `RATELIMIT_WINDOW`. Generous enough that a
/// typical user with many tabs/sessions isn't blocked, low enough that a
/// scripted flood from a single source is.
const RATELIMIT_MAX: usize = 60;
const RATELIMIT_WINDOW: Duration = Duration::from_secs(60);

pub struct ServerState {
    pub room_salt: [u8; 32],
    /// Cached at startup. The password is derived once and then dropped, so an
    /// unauthenticated TCP connect cannot trigger Argon2 work.
    pub psk: Zeroizing<[u8; 32]>,
    pub messages: Mutex<MessageStore>,
    pub sessions: Mutex<UserSessionStore>,
    pub connections: Mutex<ConnectionManager>,
    pub ratelimit: RateLimiter,
}

impl ServerState {
    pub fn new(password: &Zeroizing<Vec<u8>>) -> Result<Arc<Self>> {
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
        let keys = derive_keys(password, &salt)?;
        let psk = Zeroizing::new(keys.psk);
        // `keys` (with room_key) drops here — zeroized.
        Ok(Arc::new(Self {
            room_salt: salt,
            psk,
            messages: Mutex::new(MessageStore::new()),
            sessions: Mutex::new(UserSessionStore::new(SESSION_TIMEOUT)),
            connections: Mutex::new(ConnectionManager::new()),
            ratelimit: RateLimiter::new(RATELIMIT_MAX, RATELIMIT_WINDOW),
        }))
    }
}

pub async fn run(addr: SocketAddr, password: Zeroizing<Vec<u8>>) -> Result<()> {
    let state = ServerState::new(&password)?;
    drop(password);
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();

    tasks.spawn(sweeper(state.clone(), shutdown.clone()));

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
                        if !state.ratelimit.check(peer.ip()) {
                            warn!(%peer, "rate-limited; dropping connection");
                            drop(sock);
                            continue;
                        }
                        let state = state.clone();
                        let shutdown = shutdown.clone();
                        tasks.spawn(async move {
                            if let Err(e) = handle_connection(state, sock, peer, shutdown).await {
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

async fn sweeper(state: Arc<ServerState>, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.tick().await; // skip immediate fire
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let stale = {
            let s = state.sessions.lock().await;
            s.stale()
        };
        // Always sweep the rate-limiter so a churn of distinct IPs doesn't
        // grow its HashMap unbounded.
        state.ratelimit.cleanup();
        if stale.is_empty() {
            continue;
        }
        let count = stale.len();
        let mut sessions = state.sessions.lock().await;
        let mut conns = state.connections.lock().await;
        for id in stale {
            sessions.remove(&id);
            conns.remove(&id);
        }
        info!(evicted = count, "sweeper evicted stale sessions");
    }
}

async fn handle_connection(
    state: Arc<ServerState>,
    sock: TcpStream,
    peer: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let mut framed = frame(sock);

    // Phase 0: plaintext server hello.
    send_postcard(
        &mut framed,
        &ServerFrame::Hello {
            room_salt: state.room_salt,
            server_version: PROTOCOL_VERSION,
        },
    )
    .await?;

    // Phase 1: Noise NNpsk0 handshake using the pre-derived psk. The salt is
    // bound into the Noise prologue so MITM tampering with the plaintext
    // server-hello fails immediately on M0 instead of after Argon2 work.
    // Wrapped in a timeout to close the slow-loris vector.
    let mut transport = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_responder(&state.psk, &state.room_salt, &mut framed),
    )
    .await
    {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            warn!(%peer, error = %e, "handshake failed");
            return Err(e);
        }
        Err(_) => {
            warn!(%peer, "handshake timed out");
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
            warn!(%peer, "client did not send Hello in time");
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
        let mut sessions = state.sessions.lock().await;
        sessions.insert(user_id, username.clone());
        let mut conns = state.connections.lock().await;
        conns.insert(user_id, tx);
    }
    info!(%peer, %user_id, %username, "connected");

    let history = {
        let m = state.messages.lock().await;
        m.snapshot()
    };
    send_encrypted(
        &mut framed,
        &mut transport,
        &ServerFrame::Welcome { user_id, history },
    )
    .await?;

    let result = pump(
        &state,
        user_id,
        &username,
        &mut framed,
        &mut transport,
        &mut rx,
        &shutdown,
    )
    .await;

    {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&user_id);
        let mut conns = state.connections.lock().await;
        conns.remove(&user_id);
    }
    info!(%peer, %user_id, %username, "disconnected");
    result
}

async fn pump<S>(
    state: &Arc<ServerState>,
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
                handle_client_frame(state, user_id, username, msg).await?;
            }
        }
    }
}

async fn handle_client_frame(
    state: &Arc<ServerState>,
    user_id: Uuid,
    username: &str,
    msg: ClientFrame,
) -> Result<()> {
    {
        let mut sessions = state.sessions.lock().await;
        sessions.touch(user_id);
    }
    match msg {
        ClientFrame::Hello { .. } => Err(Error::Protocol("duplicate Hello")),
        ClientFrame::Message { ad, ciphertext } => {
            // Validate the bound metadata. ad.from / ad.username are checked
            // here, and ad.counter must strictly increase (replay protection).
            // All three failures are protocol violations → drop the connection.
            if ad.from != user_id {
                return Err(Error::Protocol("ad.from does not match session user_id"));
            }
            if ad.username != username {
                return Err(Error::Protocol("ad.username does not match session"));
            }
            {
                let mut sessions = state.sessions.lock().await;
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
                let mut m = state.messages.lock().await;
                m.push(room_msg.clone());
            }
            broadcast(state, ServerFrame::Message(room_msg)).await;
            Ok(())
        }
        ClientFrame::Clear => {
            {
                let mut m = state.messages.lock().await;
                m.clear();
            }
            broadcast(
                state,
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

/// Broadcast a frame to all connected peers. Uses `try_send` so a slow or stuck
/// peer cannot head-of-line block delivery to everyone else; full or closed
/// outboxes are evicted.
async fn broadcast(state: &Arc<ServerState>, frame_out: ServerFrame) {
    let snapshot = {
        let conns = state.connections.lock().await;
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
        let mut conns = state.connections.lock().await;
        for id in dead {
            conns.remove(&id);
        }
        debug!(evicted = dead_count, "broadcast evicted slow or dead peers");
    }
}
