# chat-rs — Feature Spec

Encrypted terminal chat in Rust. Single binary; runs as either server or client. Zero persistence, zero plaintext on the wire, zero secrets on disk.

This spec is **not** wire-compatible with the Python `cmd-chat` references. They informed the UX (CLI shape, broadcast semantics, history-on-join) but their crypto stack (SRP + Fernet + JSON) is replaced with a stronger, smaller, modern alternative.

## Goals

- Strongest practical crypto with the fewest moving parts.
- Audited primitives only — no hand-rolled handshakes or AEAD.
- One small binary; minimal dependency tree.
- Forward secrecy per connection. Server never observes plaintext or password-equivalents.

## Non-goals

- Wire compatibility with Python `cmd-chat`.
- Persistent message history.
- User registration, accounts, federation.
- TLS termination in-process (run behind a reverse proxy if needed).
- File transfer, voice, presence beyond connect/disconnect.
- Multi-room routing — one server, one shared room.

## CLI

```
chat-rs serve   <ip> <port> --password <pw>
chat-rs connect <ip> <port> <username> <password>
```

No env-var config. Mirrors the Python CLI for muscle memory.

## Cryptographic design

### Primitives

| Role | Choice | Crate |
|------|--------|-------|
| Password stretching | Argon2id (m=64 MiB, t=3, p=1, len=32) | `argon2` |
| Authenticated key exchange | Noise NNpsk0 — X25519 + ChaCha20-Poly1305 + BLAKE2s | `snow` |
| Room-level AEAD | XChaCha20-Poly1305 (24-byte random nonce) | `chacha20poly1305` |
| Key separation | HKDF-SHA256 (single tiny use, see below) | `hkdf` + `sha2` *(optional — could fold into `snow`'s mix-key API)* |
| Constant-time compare | `subtle` *(transitive, not a direct dep)* | — |
| Zeroization | `zeroize` (derive on key types) | `zeroize` |

### Connection setup

Two phases: one plaintext server-hello frame, then a Noise NNpsk0 handshake.

**Phase 0 — Server hello (plaintext):**

Server sends a single length-prefixed frame: `postcard(ServerFrame::Hello { room_salt, server_version })`. `room_salt` is non-secret (a stretching salt, not a key), so sending it in the clear is fine — and it avoids the chicken-and-egg of needing `room_salt` to derive the PSK *before* the Noise handshake begins.

The server generates `room_salt` once at startup (32 random bytes) and reuses it for the process lifetime. Restarting the server rotates the salt, which forces every client to re-stretch its password.

### Key schedule

Once the client has `room_salt` from the server hello:

```
master   = Argon2id(password, room_salt, m=64 MiB, t=3, p=1, len=32)
psk      = HKDF-SHA256(master, info = b"chat-rs/v1/psk",  len = 32)
room_key = HKDF-SHA256(master, info = b"chat-rs/v1/room", len = 32)
```

`master` is zeroized immediately after expansion. `psk` is consumed by the Noise handshake. `room_key` lives for the connection lifetime in a `Zeroizing<[u8; 32]>`.

### Handshake — Phase 1 — Noise NNpsk0

Pattern: `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`. Two messages:

```
client ─ M0 = e, psk-mix ───────────────────────► server
client ◄─ M1 = e, ee, transport(empty payload) ── server
                                                       // both sides now in transport phase
```

Both sides call `Builder::psk(0, &psk)` before the handshake. After M1, transport keys are ready and either side can send. Properties:

- Mutual authentication via the PSK (anyone without the password fails to derive matching transport keys; the first ciphertext fails its tag check and the connection drops).
- Forward secrecy via ephemeral X25519 on both sides.
- Server identity not pinned — the password *is* the shared secret. (XKpsk3 with a server static key is a future option if cross-server identity becomes useful.)

### Frame format

Outer: `tokio_util::codec::LengthDelimitedCodec`, big-endian u32 length, **max 64 KiB**.

Inner (after Noise transport decrypt): `postcard`-encoded enum.

```rust
enum ClientFrame {
    Hello { username: String },
    Message { ad: MessageAd, ciphertext: Vec<u8> },   // XChaCha20-Poly1305 over room_key
    Clear,
}

enum ServerFrame {
    Hello   { room_salt: [u8; 32], server_version: u16 }, // sent once, plaintext, before Noise
    Welcome { user_id: Uuid, history: Vec<RoomMessage> }, // sent inside Noise transport
    Message(RoomMessage),
    Cleared { by: Uuid },
    Error   { reason: ErrorKind },
}

enum ErrorKind {
    AuthFailed,
    BadFrame,
    RateLimited,
    UnsupportedVersion,
    Internal,
}

struct RoomMessage {
    from: Uuid,
    username: String,
    ad: MessageAd,            // included as additional data in the AEAD seal
    ciphertext: Vec<u8>,      // 24-byte nonce ‖ ct ‖ tag
}

struct MessageAd { from: Uuid, timestamp_ms: u64 }
```

The server **never** decrypts `ciphertext` — it only forwards it and tracks ordering / history. Sender identity (`from`) and timestamp are bound to the ciphertext via AEAD additional data, so a malicious server cannot relabel messages without breaking decryption.

### Room encryption

```
nonce      = XChaCha20-Poly1305 random 24 bytes
plaintext  = UTF-8 message body
ad         = postcard(MessageAd { from, timestamp_ms })
ciphertext = XChaCha20Poly1305::seal(room_key, nonce, plaintext, ad)
```

24-byte nonces make random selection safe (collision probability is negligible until ~2⁴⁸ messages — we will never approach that).

## Connection lifecycle

1. TCP connect.
2. Server sends `ServerFrame::Hello { room_salt, server_version }` (plaintext, length-prefixed).
3. Client stretches password → `master`, splits → `psk` + `room_key`. If `server_version` is incompatible the client closes immediately.
4. Noise NNpsk0 handshake (M0 from client, M1 from server). Wrong PSK → AEAD tag fails on first transport message → both sides close.
5. Client sends `ClientFrame::Hello { username }` (Noise-encrypted).
6. Server replies `ServerFrame::Welcome { user_id, history }` with up to **15** prior `RoomMessage`s for the join replay.
7. Bidirectional message flow until disconnect.
8. Idle sessions evicted after **3600 s** of inactivity; sweeper runs every **300 s**.
9. On disconnect: drop sender, zeroize session keys, evict from `ConnectionManager`.

Argon2 cost is paid once per connect on both sides (~100–500 ms on commodity hardware). This is the deliberate trade-off behind the rate-limiter in §Security invariants.

## Module layout

Single binary, idiomatic split:

```
src/
  main.rs               // entrypoint: clap parse → cli::run
  lib.rs                // re-exports for integration tests
  cli.rs                // clap derive + dispatch
  crypto/
    mod.rs
    password.rs         // Argon2id master + HKDF split
    room.rs             // XChaCha20-Poly1305 wrappers
    noise.rs            // snow handshake helpers
  proto.rs              // postcard frame enums + length-delimited codec
  server/
    mod.rs              // listener + per-connection task
    stores.rs           // MessageStore, UserSessionStore
    managers.rs         // ConnectionManager (mpsc::Sender map)
  client/
    mod.rs              // connect, auth, send/receive loops
    tui.rs              // crossterm + ratatui
  error.rs              // thiserror types incl. ErrorKind
```

## Dependencies (target)

```toml
[dependencies]
tokio        = { version = "1", features = ["full"] }
tokio-util   = { version = "0.7", features = ["codec"] }
clap         = { version = "4", features = ["derive"] }
serde        = { version = "1", features = ["derive"] }
postcard     = { version = "1", features = ["use-std"] }
snow         = "0.10"
argon2       = "0.5"
chacha20poly1305 = "0.10"
hkdf         = "0.12"
sha2         = "0.10"
zeroize      = { version = "1", features = ["derive"] }
thiserror    = "2"
uuid         = { version = "1", features = ["v4", "serde"] }
crossterm    = "0.28"
ratatui      = "0.29"

[dev-dependencies]
proptest     = "1"
```

Removed compared to the previous draft: `srp`, `fernet`, `serde_json`, `subtle` (transitive only), `anyhow` (errors are typed end-to-end).

Possible further trim: swap HKDF-SHA256 → BLAKE2s for the `master → {psk, room_key}` split. `snow` already pulls in `blake2`, so we'd drop `hkdf` + `sha2` (two crates) at the cost of a less-conventional KDF. Defer to Phase 2.

## Security invariants

The Python references skip these; chat-rs enforces them:

- **Zeroize on drop** for `password`, `master`, `psk`, `room_key`, transport keys held by `snow`. Wrap in `zeroize::Zeroizing` or derive `ZeroizeOnDrop`.
- **Bounded reads** via `LengthDelimitedCodec` with `max_frame_length(64 * 1024)`. No unbounded `read_to_end` paths.
- **Constant-time** comparisons handled inside `chacha20poly1305` and `argon2`; no direct `==` on tags or proofs in our code.
- **No `unwrap` / `expect`** on any path reachable from network input. Malformed frames → typed error → connection drop.
- **Logger scrub:** logging config rejects fields named `password`, `master`, `psk`, `room_key`, `auth_tag`. Tracing structured fields make this enforceable.
- **Argon2 cost is non-negotiable** — minimum m=64 MiB, t=3 even on connect path. Rate-limit failed handshakes per source IP to avoid CPU exhaustion.

## Testing

- Unit: `crypto/password.rs`, `crypto/room.rs`, `proto.rs` round-trip, store/manager invariants.
- Integration: spin up a server on a random port, connect two in-process clients, exchange a message, snapshot the bytes the server observes — assert no plaintext appears.
- Negative: wrong-password handshake fails fast and cleanly; oversized frame rejected without OOM; replayed ciphertext rejected (post-MVP — requires a per-room counter or skip-list).
- Property tests: `proto` enums round-trip through `postcard` for arbitrary inputs (`proptest`).

## Open questions

- **Password on the CLI.** `--password <pw>` exposes the password via `ps` / `/proc/<pid>/cmdline`. Inherited from the Python references but at odds with the rest of this design. Options: read from stdin if not provided, accept `CHAT_RS_PASSWORD` env, or interactive prompt. Pick before Phase 1.
- **Replay protection inside the room.** Currently the AEAD `ad` binds sender + timestamp, but a malicious server can re-broadcast an old ciphertext. Mitigation options: per-sender monotonic counter in `ad`, or a sliding-window cache on each client. Decide before Phase 4.
- **Username spoofing.** `username` is in `Welcome` and `ServerFrame::Message` but not sealed under the room key. A malicious server can swap usernames. Fix by including `username` in `MessageAd`.
- **Forward secrecy on the room key.** Currently `room_key` is static for the password. To get forward secrecy we'd need a ratchet (Double Ratchet–lite) — not free; defer unless threat model demands it.
- **Protocol-version negotiation.** Server advertises `server_version`; client doesn't. Fine for v0 (clients just refuse incompatible versions), but consider a `ClientFrame::Hello` field if we ever need server-side gating.
- **KDF swap.** Replace HKDF-SHA256 with BLAKE2s in `crypto::password` to drop `hkdf` + `sha2`. Decide in Phase 2.
