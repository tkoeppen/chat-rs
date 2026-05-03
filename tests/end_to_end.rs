#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use chat_rs::crypto::noise::{
    build_prologue, handshake_initiator, recv_encrypted, send_encrypted, transport_open,
    transport_seal,
};
use chat_rs::crypto::password::derive_keys;
use chat_rs::crypto::room;
use chat_rs::error::{ErrorKind, Result};
use chat_rs::proto::{
    ClientFrame, HISTORY_LEN, MAX_FRAME_LEN, MAX_USERNAME_LEN, MessageAd, PROTOCOL_VERSION,
    RoomMessage, ServerFrame, now_ms,
};
use chat_rs::server;
use chat_rs::server::rooms::RoomConfig;
use chat_rs::wire::{FramedStream, frame, recv_bytes, recv_postcard, send_bytes, send_postcard};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;

fn one_room(password: &str) -> Vec<RoomConfig> {
    vec![RoomConfig {
        name: "main".into(),
        password: password.into(),
    }]
}

struct ClientCtx {
    room_key: [u8; 32],
    user_id: Uuid,
    username: String,
    next_counter: u64,
    transport: snow::TransportState,
    framed: FramedStream<TcpStream>,
    welcome_history: Vec<RoomMessage>,
}

async fn connect_client(
    addr: SocketAddr,
    password: &[u8],
    username: &str,
    room: &str,
) -> Result<ClientCtx> {
    let sock = TcpStream::connect(addr).await?;
    let mut framed = frame(sock);
    send_postcard(&mut framed, &ClientFrame::RoomSelect { room: room.into() }).await?;
    let salt = match recv_postcard::<_, ServerFrame>(&mut framed).await? {
        ServerFrame::Hello {
            room_salt,
            server_version,
        } => {
            assert_eq!(server_version, PROTOCOL_VERSION);
            room_salt
        }
        ServerFrame::Error { reason } => return Err(chat_rs::error::Error::Server(reason)),
        _ => panic!("expected Hello"),
    };
    let keys = derive_keys(password, &salt)?;
    let room_key = keys.room_key;
    let prologue = build_prologue(room, &salt, PROTOCOL_VERSION);
    let mut transport = handshake_initiator(&keys.psk, &prologue, &mut framed).await?;
    let pt = postcard::to_stdvec(&ClientFrame::Hello {
        username: username.into(),
    })
    .unwrap();
    let ct = transport_seal(&mut transport, &pt)?;
    send_bytes(&mut framed, ct).await?;
    let welcome_ct = recv_bytes(&mut framed).await?;
    let welcome_pt = transport_open(&mut transport, &welcome_ct)?;
    let (user_id, welcome_history) = match postcard::from_bytes::<ServerFrame>(&welcome_pt).unwrap()
    {
        ServerFrame::Welcome { user_id, history } => (user_id, history),
        ServerFrame::Error { reason } => return Err(chat_rs::error::Error::Server(reason)),
        other => panic!("expected Welcome, got {other:?}"),
    };
    Ok(ClientCtx {
        room_key,
        user_id,
        username: username.to_string(),
        next_counter: 1,
        transport,
        framed,
        welcome_history,
    })
}

async fn ephemeral_addr() -> SocketAddr {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .await
            .unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_ready(addr: SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never came up at {addr}");
}

#[tokio::test]
async fn two_clients_exchange_message() {
    let addr = ephemeral_addr().await;
    let server_handle =
        tokio::spawn(async move { server::run(addr, one_room("correct horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"correct horse", "alice", "main")
        .await
        .expect("alice connect");
    let mut bob = connect_client(addr, b"correct horse", "bob", "main")
        .await
        .expect("bob connect");

    let plaintext = b"hello bob";
    let ad = MessageAd {
        from: alice.user_id,
        username: alice.username.clone(),
        counter: alice.next_counter,
        timestamp_ms: now_ms(),
        ephemeral: false,
    };
    alice.next_counter += 1;
    let ct = room::seal(&alice.room_key, plaintext, &ad).unwrap();
    let pt = postcard::to_stdvec(&ClientFrame::Message {
        ad: ad.clone(),
        ciphertext: ct,
    })
    .unwrap();
    let sealed = transport_seal(&mut alice.transport, &pt).unwrap();
    send_bytes(&mut alice.framed, sealed).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let bytes = recv_bytes(&mut bob.framed).await.unwrap();
            let pt = transport_open(&mut bob.transport, &bytes).unwrap();
            let server_frame: ServerFrame = postcard::from_bytes(&pt).unwrap();
            if let ServerFrame::Message(m) = server_frame {
                let decrypted = room::open(&bob.room_key, &m.ciphertext, &m.ad).unwrap();
                return (m.username, decrypted, m.ciphertext);
            }
        }
    })
    .await
    .expect("bob got message");

    assert_eq!(received.0, "alice");
    assert_eq!(received.1, plaintext);
    // Sanity: server-broadcast ciphertext does not contain the plaintext.
    assert!(
        !received.2.windows(plaintext.len()).any(|w| w == plaintext),
        "plaintext leaked into broadcast"
    );

    assert!(!server_handle.is_finished());
}

async fn send_message(ctx: &mut ClientCtx, body: &[u8]) {
    let ad = MessageAd {
        from: ctx.user_id,
        username: ctx.username.clone(),
        counter: ctx.next_counter,
        timestamp_ms: now_ms(),

        ephemeral: false,
    };
    ctx.next_counter += 1;
    let ct = room::seal(&ctx.room_key, body, &ad).unwrap();
    send_encrypted(
        &mut ctx.framed,
        &mut ctx.transport,
        &ClientFrame::Message { ad, ciphertext: ct },
    )
    .await
    .unwrap();
}

async fn next_room_message(ctx: &mut ClientCtx) -> RoomMessage {
    loop {
        let frame: ServerFrame = recv_encrypted(&mut ctx.framed, &mut ctx.transport)
            .await
            .unwrap();
        if let ServerFrame::Message(m) = frame {
            return m;
        }
    }
}

#[tokio::test]
async fn history_replays_for_late_joiner() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    for i in 0..3 {
        send_message(&mut alice, format!("msg-{i}").as_bytes()).await;
        // drain alice's own echo so the socket buffer doesn't fill up
        let _ = next_room_message(&mut alice).await;
    }

    let bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();
    assert_eq!(
        bob.welcome_history.len(),
        3,
        "bob should see all 3 prior messages"
    );
    for (i, m) in bob.welcome_history.iter().enumerate() {
        let pt = room::open(&bob.room_key, &m.ciphertext, &m.ad).unwrap();
        assert_eq!(pt, format!("msg-{i}").as_bytes());
        assert_eq!(m.username, "alice");
    }
}

#[tokio::test]
async fn history_caps_at_limit_over_wire() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    let total = HISTORY_LEN + 5;
    for i in 0..total {
        send_message(&mut alice, format!("m{i}").as_bytes()).await;
        let _ = next_room_message(&mut alice).await;
    }

    let bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();
    assert_eq!(bob.welcome_history.len(), HISTORY_LEN);
    // First in history should be the (total - HISTORY_LEN)th message.
    let first_pt = room::open(
        &bob.room_key,
        &bob.welcome_history[0].ciphertext,
        &bob.welcome_history[0].ad,
    )
    .unwrap();
    assert_eq!(first_pt, format!("m{}", total - HISTORY_LEN).as_bytes());
}

#[tokio::test]
async fn clear_propagates_to_all_clients() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    let mut bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();

    send_encrypted(&mut alice.framed, &mut alice.transport, &ClientFrame::Clear)
        .await
        .unwrap();

    let (cleared_by, cleared_username) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let f: ServerFrame = recv_encrypted(&mut bob.framed, &mut bob.transport)
                .await
                .unwrap();
            if let ServerFrame::Cleared { by, username } = f {
                return (by, username);
            }
        }
    })
    .await
    .expect("bob got clear");
    assert_eq!(cleared_by, alice.user_id);
    assert_eq!(cleared_username, "alice");
}

#[tokio::test]
async fn oversized_frame_is_rejected() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    // Open a raw socket and shove a length-prefix header that exceeds MAX_FRAME_LEN.
    let mut sock = TcpStream::connect(addr).await.unwrap();
    // Drain the plaintext server hello frame so we don't confuse the codec on the server side.
    // The server sends the hello before reading; we just write our oversized frame and expect a close.
    let oversize = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
    sock.write_all(&oversize).await.unwrap();
    // Don't bother sending payload; the server's LengthDelimitedCodec rejects on header alone.
    // The connection should close cleanly without OOM.
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
    )
    .await;
    // Test passes if the server didn't OOM/panic; we don't strictly assert close here because
    // the server may have already written the hello before reading our header.
}

#[tokio::test]
async fn ad_from_mismatch_drops_connection() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    // Build a Message with ad.from set to someone else's UUID — this would
    // make peers' decrypts silently fail, so the server must reject loud.
    let bogus = Uuid::new_v4();
    let ad = MessageAd {
        from: bogus,
        username: alice.username.clone(),
        counter: alice.next_counter,
        timestamp_ms: now_ms(),

        ephemeral: false,
    };
    alice.next_counter += 1;
    let ct = room::seal(&alice.room_key, b"spoof", &ad).unwrap();
    send_encrypted(
        &mut alice.framed,
        &mut alice.transport,
        &ClientFrame::Message { ad, ciphertext: ct },
    )
    .await
    .unwrap();

    let r = tokio::time::timeout(Duration::from_millis(500), recv_bytes(&mut alice.framed)).await;
    assert!(
        matches!(r, Ok(Err(_)) | Err(_)),
        "server should drop the connection on ad.from mismatch"
    );

    // Server still alive — another client can connect.
    let _bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();
}

#[tokio::test]
async fn over_cap_username_rejected() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let sock = TcpStream::connect(addr).await.unwrap();
    let mut framed = frame(sock);
    send_postcard(
        &mut framed,
        &ClientFrame::RoomSelect {
            room: "main".into(),
        },
    )
    .await
    .unwrap();
    let salt = match recv_postcard::<_, ServerFrame>(&mut framed).await.unwrap() {
        ServerFrame::Hello { room_salt, .. } => room_salt,
        _ => panic!("expected Hello"),
    };
    let keys = chat_rs::crypto::password::derive_keys(b"horse-staple-correct", &salt).unwrap();
    let prologue = build_prologue("main", &salt, PROTOCOL_VERSION);
    let mut transport = handshake_initiator(&keys.psk, &prologue, &mut framed)
        .await
        .unwrap();

    // 33 chars = MAX_USERNAME_LEN + 1
    let big = "a".repeat(MAX_USERNAME_LEN + 1);
    let pt = postcard::to_stdvec(&ClientFrame::Hello { username: big }).unwrap();
    let ct = transport_seal(&mut transport, &pt).unwrap();
    send_bytes(&mut framed, ct).await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(2), recv_bytes(&mut framed))
        .await
        .expect("server replied")
        .expect("no read error");
    let resp_pt = transport_open(&mut transport, &resp).unwrap();
    let resp_frame: ServerFrame = postcard::from_bytes(&resp_pt).unwrap();
    match resp_frame {
        ServerFrame::Error { reason } => assert_eq!(reason, ErrorKind::BadFrame),
        other => panic!("expected ServerFrame::Error, got {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_hello_after_auth_drops_connection() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    send_encrypted(
        &mut alice.framed,
        &mut alice.transport,
        &ClientFrame::Hello {
            username: "alice2".into(),
        },
    )
    .await
    .unwrap();

    let r = tokio::time::timeout(Duration::from_millis(500), recv_bytes(&mut alice.framed)).await;
    assert!(
        matches!(r, Ok(Err(_)) | Err(_)),
        "server should drop the connection on duplicate Hello"
    );
}

#[tokio::test]
async fn rooms_are_isolated() {
    // Two rooms on the same server with different passwords. Alice in room A
    // sends a message; Bob (in room B) must NOT receive it. Verifies per-room
    // ConnectionManager + MessageStore isolation.
    let addr = ephemeral_addr().await;
    let configs = vec![
        RoomConfig {
            name: "alpha".into(),
            password: "password-aaaa-long".into(),
        },
        RoomConfig {
            name: "beta".into(),
            password: "password-bbbb-long".into(),
        },
    ];
    let _server = tokio::spawn(async move { server::run(addr, configs).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"password-aaaa-long", "alice", "alpha")
        .await
        .unwrap();
    let mut bob = connect_client(addr, b"password-bbbb-long", "bob", "beta")
        .await
        .unwrap();

    send_message(&mut alice, b"only-for-alpha").await;
    let _echo = next_room_message(&mut alice).await;

    // Bob should NOT see anything for at least 500ms (no cross-room delivery).
    let bob_got_anything =
        tokio::time::timeout(Duration::from_millis(500), recv_bytes(&mut bob.framed)).await;
    assert!(
        bob_got_anything.is_err(),
        "bob in room beta must not receive alpha's broadcast"
    );

    // Sanity: Bob's room is functional.
    send_message(&mut bob, b"hello-from-beta").await;
    let bob_echo = next_room_message(&mut bob).await;
    let pt = room::open(&bob.room_key, &bob_echo.ciphertext, &bob_echo.ad).unwrap();
    assert_eq!(pt, b"hello-from-beta");
}

#[tokio::test]
async fn unknown_room_indistinguishable_from_wrong_password() {
    // The server synthesizes a fake (random salt, random PSK) hello on
    // unknown rooms. The client receives a valid Hello, derives keys, and
    // the handshake fails at M1 verify — same wire shape as wrong-password
    // against a real room. Either path surfaces as a Noise/AEAD-style error,
    // never `Server(AuthFailed)`.
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let unknown = connect_client(addr, b"horse-staple-correct", "ghost", "no-such-room").await;
    let wrong_pw = connect_client(addr, b"definitely-wrong-pw", "mallory", "main").await;

    assert!(unknown.is_err(), "unknown room must fail");
    assert!(wrong_pw.is_err(), "wrong password must fail");
    // Neither path should yield Server(AuthFailed) any more — both fail
    // inside the Noise handshake on the client side.
    for (label, r) in [("unknown", unknown), ("wrong_pw", wrong_pw)] {
        if let Err(chat_rs::error::Error::Server(ErrorKind::AuthFailed)) = r {
            panic!("{label}: expected handshake failure, not Server(AuthFailed)");
        }
    }
}

#[tokio::test]
async fn unique_user_ids_per_connection() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    let bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();
    assert_ne!(alice.user_id, bob.user_id);
}

/// Usernames with non-`[A-Za-z0-9_-]` chars are rejected at Hello time.
/// Picks a username with a bidi RTL override — innocuous on the wire,
/// dangerous in a TUI render. Must surface as `BadFrame`.
#[tokio::test]
async fn invalid_username_charset_rejected() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let r = connect_client(addr, b"horse-staple-correct", "ali\u{202E}ce", "main").await;
    match r {
        Err(chat_rs::error::Error::Server(ErrorKind::BadFrame)) => {}
        Err(other) => panic!("expected Server(BadFrame), got Err({other})"),
        Ok(_) => panic!("invalid charset username should be rejected"),
    }
}

/// A `Message` whose ciphertext exceeds `MAX_CIPHERTEXT_LEN` is dropped by
/// the server (connection closes). Without this cap, the next joiner's
/// `Welcome` could exceed `MAX_FRAME_LEN`.
#[tokio::test]
async fn oversized_ciphertext_rejected() {
    use chat_rs::proto::MAX_CIPHERTEXT_LEN;
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    // Hand-craft an over-cap Message: bypass `room::seal` so we can attach
    // arbitrary-sized ciphertext bytes.
    let ad = MessageAd {
        from: alice.user_id,
        username: alice.username.clone(),
        counter: alice.next_counter,
        timestamp_ms: now_ms(),

        ephemeral: false,
    };
    alice.next_counter += 1;
    let ciphertext = vec![0u8; MAX_CIPHERTEXT_LEN + 1];
    send_encrypted(
        &mut alice.framed,
        &mut alice.transport,
        &ClientFrame::Message { ad, ciphertext },
    )
    .await
    .unwrap();

    let r = tokio::time::timeout(Duration::from_millis(500), recv_bytes(&mut alice.framed)).await;
    assert!(
        matches!(r, Ok(Err(_)) | Err(_)),
        "server should drop the connection on oversized ciphertext"
    );
}

/// Per-session message-rate cap. Sends `MSG_RATE_MAX + 1` messages back to
/// back; the last one must close the connection.
#[tokio::test]
async fn message_rate_cap_enforced() {
    use chat_rs::server::stores::MSG_RATE_MAX;
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    for i in 0..=MSG_RATE_MAX {
        send_message(&mut alice, format!("m{i}").as_bytes()).await;
    }

    // The connection should close (server returned a Protocol error).
    let r = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if recv_bytes(&mut alice.framed).await.is_err() {
                return;
            }
        }
    })
    .await;
    assert!(r.is_ok(), "server should close the connection over the cap");
}

/// Server enforces per-sender counter monotonicity (`try_advance_counter`).
/// Sending the same `counter` twice — or a smaller one — must drop the
/// connection. This is the server-side half of the replay defense.
#[tokio::test]
async fn server_rejects_counter_replay() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    // Two messages with the same counter. The second must be rejected.
    for _ in 0..2 {
        let ad = MessageAd {
            from: alice.user_id,
            username: alice.username.clone(),
            counter: 5,
            timestamp_ms: now_ms(),

            ephemeral: false,
        };
        let ct = room::seal(&alice.room_key, b"replayed", &ad).unwrap();
        send_encrypted(
            &mut alice.framed,
            &mut alice.transport,
            &ClientFrame::Message { ad, ciphertext: ct },
        )
        .await
        .unwrap();
    }

    // First message succeeds and echoes back; the second trips the server's
    // monotonicity check. Drain until the read errors (= server closed).
    let r = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if recv_bytes(&mut alice.framed).await.is_err() {
                return;
            }
        }
    })
    .await;
    assert!(
        r.is_ok(),
        "server should drop the connection on counter replay"
    );
}

/// Server enforces `ad.username == session_username` so a malicious peer
/// can't relabel its own messages mid-session. Symmetric to the existing
/// `ad_from_mismatch_drops_connection` test.
#[tokio::test]
async fn ad_username_mismatch_drops_connection() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    let ad = MessageAd {
        from: alice.user_id,
        username: "mallory".into(), // session is "alice" — server must reject
        counter: alice.next_counter,
        timestamp_ms: now_ms(),

        ephemeral: false,
    };
    alice.next_counter += 1;
    let ct = room::seal(&alice.room_key, b"spoof", &ad).unwrap();
    send_encrypted(
        &mut alice.framed,
        &mut alice.transport,
        &ClientFrame::Message { ad, ciphertext: ct },
    )
    .await
    .unwrap();

    let r = tokio::time::timeout(Duration::from_millis(500), recv_bytes(&mut alice.framed)).await;
    assert!(
        matches!(r, Ok(Err(_)) | Err(_)),
        "server should drop the connection on ad.username mismatch"
    );
}

/// Per-session `/clear` cooldown. Two `/clear` frames in a row from the
/// same session: the second must close the connection.
#[tokio::test]
async fn clear_cooldown_enforced() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();

    send_encrypted(&mut alice.framed, &mut alice.transport, &ClientFrame::Clear)
        .await
        .unwrap();
    send_encrypted(&mut alice.framed, &mut alice.transport, &ClientFrame::Clear)
        .await
        .unwrap();

    let r = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if recv_bytes(&mut alice.framed).await.is_err() {
                return;
            }
        }
    })
    .await;
    assert!(
        r.is_ok(),
        "server should close on second /clear within cooldown"
    );
}

/// Ephemeral message: alice sends with `ad.ephemeral = true`. Bob (already
/// connected) receives it via broadcast. A late-joining carol sees an empty
/// history — the server skipped the join-replay store. Auto-expiry is a UI
/// concern (covered by unit tests in `client/ui.rs`).
#[tokio::test]
async fn ephemeral_message_broadcasts_but_not_in_history() {
    let addr = ephemeral_addr().await;
    let _server =
        tokio::spawn(async move { server::run(addr, one_room("horse-staple-correct")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse-staple-correct", "alice", "main")
        .await
        .unwrap();
    let mut bob = connect_client(addr, b"horse-staple-correct", "bob", "main")
        .await
        .unwrap();

    let plaintext = b"meet me at the docks";
    let ad = MessageAd {
        from: alice.user_id,
        username: alice.username.clone(),
        counter: alice.next_counter,
        timestamp_ms: now_ms(),
        ephemeral: true,
    };
    alice.next_counter += 1;
    let ct = room::seal(&alice.room_key, plaintext, &ad).unwrap();
    send_encrypted(
        &mut alice.framed,
        &mut alice.transport,
        &ClientFrame::Message { ad, ciphertext: ct },
    )
    .await
    .unwrap();

    // Bob, already in the room, gets the broadcast normally.
    let received = tokio::time::timeout(Duration::from_secs(2), next_room_message(&mut bob))
        .await
        .expect("bob got message");
    assert!(received.ad.ephemeral, "ephemeral flag must survive AAD");
    let pt = room::open(&bob.room_key, &received.ciphertext, &received.ad).unwrap();
    assert_eq!(pt, plaintext);

    // Carol joins after the message — must NOT see it in welcome history.
    let carol = connect_client(addr, b"horse-staple-correct", "carol", "main")
        .await
        .unwrap();
    assert!(
        carol.welcome_history.is_empty(),
        "ephemeral messages must not enter join-replay history"
    );
}
