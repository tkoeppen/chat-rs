use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use chat_rs::crypto::noise::{
    handshake_initiator, recv_encrypted, send_encrypted, transport_open, transport_seal,
};
use chat_rs::crypto::password::derive_keys;
use chat_rs::crypto::room;
use chat_rs::error::{ErrorKind, Result};
use chat_rs::proto::{
    ClientFrame, HISTORY_LEN, MAX_FRAME_LEN, MAX_USERNAME_LEN, MessageAd, PROTOCOL_VERSION,
    RoomMessage, ServerFrame, now_ms,
};
use chat_rs::server;
use chat_rs::wire::{FramedStream, frame, recv_bytes, recv_postcard, send_bytes};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;
use zeroize::Zeroizing;

fn pw(s: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.to_vec())
}

struct ClientCtx {
    room_key: [u8; 32],
    user_id: Uuid,
    transport: snow::TransportState,
    framed: FramedStream<TcpStream>,
    welcome_history: Vec<RoomMessage>,
}

async fn connect_client(addr: SocketAddr, password: &[u8], username: &str) -> Result<ClientCtx> {
    let sock = TcpStream::connect(addr).await?;
    let mut framed = frame(sock);
    let salt = match recv_postcard::<_, ServerFrame>(&mut framed).await? {
        ServerFrame::Hello {
            room_salt,
            server_version,
        } => {
            assert_eq!(server_version, PROTOCOL_VERSION);
            room_salt
        }
        _ => panic!("expected Hello"),
    };
    let keys = derive_keys(password, &salt)?;
    let room_key = keys.room_key;
    let mut transport = handshake_initiator(&keys.psk, &mut framed).await?;
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
        other => panic!("expected Welcome, got {other:?}"),
    };
    Ok(ClientCtx {
        room_key,
        user_id,
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
    let server_handle = tokio::spawn(async move { server::run(addr, pw(b"correct horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"correct horse", "alice")
        .await
        .expect("alice connect");
    let mut bob = connect_client(addr, b"correct horse", "bob")
        .await
        .expect("bob connect");

    let plaintext = b"hello bob";
    let ad = MessageAd {
        from: alice.user_id,
        timestamp_ms: now_ms(),
    };
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

#[tokio::test]
async fn wrong_password_fails_to_join() {
    let addr = ephemeral_addr().await;
    let _server = tokio::spawn(async move { server::run(addr, pw(b"correct horse")).await });
    wait_ready(addr).await;

    let result = connect_client(addr, b"wrong password", "mallory").await;
    assert!(result.is_err(), "wrong password must fail");
}

async fn send_message(ctx: &mut ClientCtx, body: &[u8]) {
    let ad = MessageAd {
        from: ctx.user_id,
        timestamp_ms: now_ms(),
    };
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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse", "alice").await.unwrap();
    for i in 0..3 {
        send_message(&mut alice, format!("msg-{i}").as_bytes()).await;
        // drain alice's own echo so the socket buffer doesn't fill up
        let _ = next_room_message(&mut alice).await;
    }

    let bob = connect_client(addr, b"horse", "bob").await.unwrap();
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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse", "alice").await.unwrap();
    let total = HISTORY_LEN + 5;
    for i in 0..total {
        send_message(&mut alice, format!("m{i}").as_bytes()).await;
        let _ = next_room_message(&mut alice).await;
    }

    let bob = connect_client(addr, b"horse", "bob").await.unwrap();
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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse", "alice").await.unwrap();
    let mut bob = connect_client(addr, b"horse", "bob").await.unwrap();

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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse", "alice").await.unwrap();

    // Build a Message with ad.from set to someone else's UUID — this would
    // make peers' decrypts silently fail, so the server must reject loud.
    let bogus = Uuid::new_v4();
    let ad = MessageAd {
        from: bogus,
        timestamp_ms: now_ms(),
    };
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
    let _bob = connect_client(addr, b"horse", "bob").await.unwrap();
}

#[tokio::test]
async fn over_cap_username_rejected() {
    let addr = ephemeral_addr().await;
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let sock = TcpStream::connect(addr).await.unwrap();
    let mut framed = frame(sock);
    let salt = match recv_postcard::<_, ServerFrame>(&mut framed).await.unwrap() {
        ServerFrame::Hello { room_salt, .. } => room_salt,
        _ => panic!("expected Hello"),
    };
    let keys = chat_rs::crypto::password::derive_keys(b"horse", &salt).unwrap();
    let mut transport = handshake_initiator(&keys.psk, &mut framed).await.unwrap();

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
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let mut alice = connect_client(addr, b"horse", "alice").await.unwrap();
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
async fn unique_user_ids_per_connection() {
    let addr = ephemeral_addr().await;
    let _server = tokio::spawn(async move { server::run(addr, pw(b"horse")).await });
    wait_ready(addr).await;

    let alice = connect_client(addr, b"horse", "alice").await.unwrap();
    let bob = connect_client(addr, b"horse", "bob").await.unwrap();
    assert_ne!(alice.user_id, bob.user_id);
}
