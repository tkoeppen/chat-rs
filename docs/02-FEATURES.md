# chat-rs — Feature Spec

Encrypted terminal chat in Rust. Single binary; runs as either server or client. Zero persistence, zero plaintext on the wire, zero secrets on disk.

This spec is **not** wire-compatible with the Python `cmd-chat` references. They informed the UX (broadcast semantics, history-on-join, `/clear`) but their crypto stack (SRP + Fernet + JSON) is replaced with a stronger, smaller, modern alternative.

For the in-flight checklist, see [`01-TODO.md`](01-TODO.md). This document is the design — what the code *is*. The TODO is what's left to do.

## Goals

- Strongest practical crypto with the fewest moving parts.
- Audited primitives only — no hand-rolled handshakes or AEAD.
- One small binary; minimal direct dependency tree.
- Forward secrecy at the transport layer. Server never observes plaintext or password-equivalents.

## Non-goals

- Persistent message history.
- User registration, accounts, federation.
- TLS termination in-process (run behind a reverse proxy if needed).
- File transfer, voice, presence beyond connect/disconnect.
- Multi-room routing — one server, one shared room.

## CLI

```sh
chat-rs serve   <ip> <port>
chat-rs connect <ip> <port> <username>
```

The password is read from the `CHAT_RS_PASSWORD` environment variable if set, otherwise from an interactive prompt (`rpassword`, no echo). There is **no** `--password` flag — passwords on the command line leak into shell history and `ps`.

## Cryptographic design

### Primitives

| Role | Choice | Crate |
| --- | --- | --- |
| Password stretching | Argon2id (m=64 MiB, t=3, p=1, len=32) | `argon2` |
| Authenticated key exchange | Noise NNpsk0 — X25519 + ChaCha20-Poly1305 + BLAKE2s | `snow` |
| Room-level AEAD | XChaCha20-Poly1305 (24-byte random nonce) | `chacha20poly1305` |
| Master-key splitting (KDF) | Keyed BLAKE2s-256 (`Blake2sMac256`) | `blake2` |
| Constant-time compare | `subtle` *(transitive via AEAD/argon2; not a direct dep)* | — |
| Zeroization | `Zeroizing<T>` + `#[derive(Zeroize, ZeroizeOnDrop)]` | `zeroize` |
| Random | OS RNG via `getrandom::fill` | `getrandom` |

### Connection setup

Two phases: one plaintext server-hello frame, then a Noise NNpsk0 handshake.

**Phase 0 — Server hello (plaintext):**

Server sends a single length-prefixed frame: `postcard(ServerFrame::Hello { room_salt, server_version })`. `room_salt` is non-secret (an Argon2 stretching salt, not a key), so sending it in the clear is fine — and it avoids the chicken-and-egg of needing `room_salt` to derive the PSK *before* the Noise handshake begins.

The server generates `room_salt` once at startup (32 random bytes) and reuses it for the process lifetime. Restarting the server rotates the salt, which forces every client to re-stretch its password.

### Key schedule

Once the client has `room_salt` from the server hello:

```text
master   = Argon2id(password, room_salt, m=64 MiB, t=3, p=1, len=32)
psk      = Blake2sMac256(key=master, msg=b"chat-rs/v1/psk")     // 32 bytes
room_key = Blake2sMac256(key=master, msg=b"chat-rs/v1/room")    // 32 bytes
```

Keyed BLAKE2s-256 is used as a one-shot KDF: distinct labels yield independent 32-byte keys from the same master. `master` is zeroized immediately after expansion (it lives in `Zeroizing<[u8; 32]>`). `psk` is consumed by the Noise handshake. `room_key` lives for the connection lifetime in a `Zeroizing<[u8; 32]>`.

The server precomputes its `psk` once at startup (in `ServerState::new`), drops the password, and stores only the `psk` — so an unauthenticated TCP connect cannot trigger any Argon2 work.

### Handshake — Phase 1 — Noise NNpsk0

Pattern: `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`. Two messages:

```text
client ─ M0 = e, psk-mix ───────────────────────► server
client ◄─ M1 = e, ee, transport(empty payload) ── server
                                                       // both sides now in transport phase
```

Both sides call `Builder::psk(0, &psk)` before the handshake. After M1, transport keys are ready and either side can send. Properties:

- Mutual authentication via the PSK (anyone without the password fails to derive matching transport keys; the first ciphertext fails its tag check and the connection drops).
- Forward secrecy via ephemeral X25519 on both sides (per-connection only; the room-level key is not yet ratcheted — see Open questions).
- Server identity not pinned — the password *is* the shared secret. (XKpsk3 with a server static key is a future option if cross-server identity becomes useful.)

### Frame format

Outer: `tokio_util::codec::LengthDelimitedCodec`, big-endian u32 length, **max 64 KiB**.

Inner (after Noise transport decrypt): `postcard`-encoded enum.

```rust
enum ClientFrame {
    Hello { username: String },                       // username capped at MAX_USERNAME_LEN = 32
    Message { ad: MessageAd, ciphertext: Vec<u8> },   // XChaCha20-Poly1305 over room_key
    Clear,
}

enum ServerFrame {
    Hello   { room_salt: [u8; 32], server_version: u16 }, // sent once, plaintext, before Noise
    Welcome { user_id: Uuid, history: Vec<RoomMessage> }, // sent inside Noise transport
    Message(RoomMessage),
    Cleared { by: Uuid, username: String },
    Error   { reason: ErrorKind },
}

enum ErrorKind { AuthFailed, BadFrame, RateLimited, UnsupportedVersion, Internal }

struct RoomMessage {
    from: Uuid,
    username: String,
    ad: MessageAd,            // included as additional data in the AEAD seal
    ciphertext: Vec<u8>,      // 24-byte nonce ‖ ct ‖ tag
}

struct MessageAd { from: Uuid, timestamp_ms: u64 }
```

The server **never** decrypts `ciphertext` — it only forwards it and tracks ordering / history. Sender identity (`from`) and timestamp are bound to the ciphertext via AEAD additional data, so a malicious server cannot relabel `from` without breaking decryption. The server enforces `ad.from == session user_id` on receive: misbehaving clients are rejected with `Protocol`, not silently overwritten.

### Room encryption

```text
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
5. Client sends `ClientFrame::Hello { username }` (Noise-encrypted). Server validates `1 ≤ len ≤ MAX_USERNAME_LEN`.
6. Server replies `ServerFrame::Welcome { user_id, history }` with up to **15** prior `RoomMessage`s for the join replay.
7. Bidirectional message flow until disconnect. Broadcast uses `try_send` + evict on `Full`/`Closed` so a slow peer cannot head-of-line block delivery.
8. Idle sessions evicted after **3600 s** of inactivity; sweeper runs every **300 s**.
9. On disconnect: drop sender, zeroize session keys, evict from `ConnectionManager`.
10. **Graceful shutdown:** server's accept loop, sweeper, and per-connection `pump` all share a `tokio_util::sync::CancellationToken`. SIGINT cancels the token; the `JoinSet` drains in-flight tasks; once empty, `Arc<ServerState>` refcount hits zero and the cached `psk` zeroizes. Client catches ctrl-c as a key event in raw mode (the TUI swallows the SIGINT) and returns from its event loop, dropping `room_key`.

## Client TUI

The client uses an alt-screen TUI built on `crossterm` 0.29 + `ratatui` 0.30 (`crossterm_0_29` feature pin so there's exactly one crossterm in the tree).

### Layout

```text
Secure Terminal Chat                           ← centered bold-magenta header
 alice · 127.0.0.1:3000  —  enter · /clear …   ← cyan status bar
┌ room ─────────────────────────────────────┐
│ [12:34:56] alice: hello                   │
│ [12:34:58] bob: hi                        │  ← scrolling pane, per-username color
│ ...                                       │
├ message ──────────────────────────────────┤
│ ▌                                         │  ← single-line input box w/ cursor
└───────────────────────────────────────────┘
```

When scrolled back, the room title shows `room (↑ scrolled N — End to return)` so the engaged state is obvious.

### Keys

| Key | Action |
| --- | --- |
| Enter | Send message, or run a slash command |
| Backspace | Delete previous char in input |
| Char | Append to input |
| ↑ / ↓ | Scroll back / forward 1 message |
| PgUp / PgDn | Scroll back / forward nearly a full pane |
| Home / End | Oldest visible / back to live |
| Ctrl-C | Quit cleanly (terminal restored via RAII) |

Slash commands: `/clear` or `/c` wipes room history for everyone (locally too); `/quit` or `/q` exits the client (same as Ctrl-C).

### State

- `messages: VecDeque<DisplayMsg>` capped at **500** entries (oldest evicted; `scroll` position adjusts).
- Per-username color via a small palette + 31-mul hash; system lines (decryption failures, `/clear` notice) styled italic-yellow.
- Auto-scrolls to latest while pinned (`scroll == 0`); when scrolled back, new messages bump `scroll` so the historical view stays anchored.
- `/clear` wipes `state.messages` locally (not just on the server) and resets scroll, so every client sees a fresh empty room with only the cleared-by notice.
- `TerminalGuard` (RAII) enters alt-screen + raw mode on construction and restores on `Drop` — even on panic the terminal is never left scrambled.

## Module layout

```text
src/
  main.rs               // entrypoint: clap parse → cli::run + tracing init
  lib.rs                // re-exports for integration tests
  cli.rs                // clap derive + dispatch + read_password
  proto.rs              // postcard frame enums; PROTOCOL_VERSION; MAX_FRAME_LEN; MAX_USERNAME_LEN; HISTORY_LEN
  wire.rs               // LengthDelimitedCodec + send_postcard / recv_postcard helpers
  error.rs              // thiserror Error + ErrorKind
  crypto/
    mod.rs
    password.rs         // Argon2id master + keyed BLAKE2s split into psk + room_key
    room.rs             // XChaCha20-Poly1305 wrappers (seal/open)
    noise.rs            // snow Noise NNpsk0 handshake + transport helpers
  server/
    mod.rs              // listener, handle_connection, pump, broadcast, sweeper, shutdown
    stores.rs           // MessageStore (ring buffer), UserSessionStore (idle eviction)
    managers.rs         // ConnectionManager (mpsc::Sender map per session)
  client/
    mod.rs              // connect, handshake, event_loop orchestration
    ui.rs               // ratatui TUI: UiState, render, handle_key, TerminalGuard
tests/
  end_to_end.rs         // 7 integration tests (handshake, history, /clear, oversized, …)
```

## Dependencies

See `Cargo.toml` for the canonical list; each direct dep has a one-line purpose comment. Summary:

```text
Async/transport:   tokio (trimmed features), tokio-util (codec + sync),
                   futures-util (sink+std)
CLI / I/O:         clap (derive), rpassword
Wire / serde:      serde (derive), postcard (use-std, default-features=false)
Crypto:            snow, argon2, chacha20poly1305, blake2, zeroize, getrandom
Errors:            thiserror
Identifiers:       uuid (v4 + serde)
Logging:           tracing, tracing-subscriber (env-filter + fmt + ansi)
TUI:               crossterm (event-stream), ratatui (default-features=false,
                   crossterm_0_29 + layout-cache + underline-color)
Dev:               none
```

Removed compared to the original draft: `srp`, `fernet`, `serde_json`, `subtle` (transitive only), `anyhow`, `hkdf`, `sha2`, `bytes` (re-exported by `tokio_util`), `proptest`, `rand`.

Supply-chain hygiene: `deny.toml` runs `cargo deny check` over licenses, advisories, bans (wildcards forbidden, multi-versions warn), and sources (only crates.io trusted).

## Security invariants

The Python references skip these; chat-rs enforces them:

- **Zeroize on drop** for `password`, `master`, `psk`, `room_key`, transport keys held by `snow`. All key types are `Zeroizing<T>` or derive `ZeroizeOnDrop`.
- **Bounded reads** via `LengthDelimitedCodec` with `max_frame_length(64 * 1024)`. No unbounded `read_to_end` paths.
- **Constant-time** comparisons handled inside `chacha20poly1305`, `blake2`, and `argon2`; no direct `==` on tags or proofs in our code.
- **No `unwrap` / `expect`** on any path reachable from network input. The single `expect` in non-test code is `crypto/noise.rs::params()` parsing the static Noise pattern string — to be folded into a `LazyLock` (see TODO Phase 4).
- **Logger scrub** is *discipline-only* today: module-level doc comments in `server/mod.rs` and `client/mod.rs` list forbidden field names (`password`, `psk`, `room_key`, AEAD nonces/tags). A structured-logger filter would make this enforceable.
- **Argon2 cost on the server is paid once at startup**, not per connect — `ServerState` caches the derived `psk` and drops the password before listening. Closes the otherwise-trivial 64 MiB-per-connect DoS.
- **Per-message AEAD AAD** binds `(from, timestamp_ms)` so a malicious server can't relabel sender or rewind timestamps. The server additionally rejects `ClientFrame::Message` with `ad.from != session user_id` to fail loud rather than make peers' decrypts silently fail.

## Testing

- Unit (in-tree): `crypto/password.rs` (4), `crypto/room.rs` (4), `crypto/noise.rs` (2), `server/stores.rs` (1) — round-trip seal/open, wrong-password rejects, AD tampering rejects, truncated ciphertext rejects, wrong-PSK handshake fails, history ring-buffer cap.
- Integration (`tests/end_to_end.rs`): two-client message exchange (asserts plaintext does not appear in broadcast bytes), wrong-password failure, history replay for late joiner, history cap over wire, `/clear` propagation, oversized-frame rejection without OOM, unique `user_id` per connection.
- Pre-commit gate: `build.sh` runs `cargo fmt → cargo clippy --all-targets -- -D warnings → cargo test`.
- Supply chain: `cargo deny check` (licenses + advisories + bans + sources).

Outstanding test gaps tracked in TODO Phase 4: sweeper-driven idle eviction, slow-peer broadcast (HOL), `ad.from` rejection, over-cap username rejection, duplicate `Hello` rejection.

## Open questions

Tracked in detail in [`01-TODO.md`](01-TODO.md) Phase 5. Headlines:

- **Replay protection inside the room** — per-sender monotonic counter in `MessageAd`, or sliding-window cache on the client.
- **Bind `username` into `MessageAd`** — close the relabeling gap (`from` Uuid is bound; display name is not).
- **Forward secrecy on the room key** — currently fixed for the room's lifetime. Tentative direction: server-driven salt rotation (Phase 5 has the full options table and reasoning).
- **Protocol-version negotiation** — server advertises; client doesn't. Add a `ClientFrame::Hello` field if server-side gating ever matters.
- **Rate-limit failed Noise handshakes** — per source IP. Defense-in-depth now that the per-connect Argon2 cost is gone.
