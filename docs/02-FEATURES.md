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

## CLI

```sh
chat-rs serve     # reads CHAT_RS_BIND, CHAT_RS_ROOMS
chat-rs connect   # reads CHAT_RS_SERVER, CHAT_RS_USERNAME, CHAT_RS_ROOM, CHAT_RS_PASSWORD
```

All configuration is read from environment variables. A `.env` file in the working directory is auto-loaded at startup via `dotenvy`; process env wins over `.env`, so an inline override of `CHAT_RS_PASSWORD` beats a placeholder in the file. See `.env.example` in the repo root for the full set.

`CHAT_RS_BIND` and `CHAT_RS_SERVER` are `ip:port` strings (parsed by `SocketAddr::parse`). `CHAT_RS_ROOMS` is a multi-line value with one `name = password` per line, `[A-Za-z0-9_-]{1,32}` names, ≥ 8-char passwords, `#` comments. The client picks one room at connect time via `CHAT_RS_ROOM`. The password is read from `CHAT_RS_PASSWORD` if set, otherwise from an interactive prompt (`rpassword`, no echo). There are **no** positional or `--flag` config arguments — passwords on the command line leak into shell history and `ps`, and concentrating all config in one mechanism removes a class of "where does this come from" surprises.

## Cryptographic design

### Primitives

| Role | Choice | Crate |
| --- | --- | --- |
| Password stretching | Argon2id (m=64 MiB, t=4, p=1, len=32) | `argon2` |
| Authenticated key exchange | Noise NNpsk0 — X25519 + ChaCha20-Poly1305 + BLAKE2s | `snow` |
| Room-level AEAD | XChaCha20-Poly1305 (24-byte random nonce) | `chacha20poly1305` |
| Master-key splitting (KDF) | Keyed BLAKE2s-256 (`Blake2sMac256`) | `blake2` |
| Constant-time compare | `subtle` *(transitive via AEAD/argon2; not a direct dep)* | — |
| Zeroization | `Zeroizing<T>` + `#[derive(Zeroize, ZeroizeOnDrop)]` | `zeroize` |
| Random | OS RNG via `getrandom::fill` | `getrandom` |

### Connection setup

Three phases: a plaintext room-select frame from the client, a plaintext server-hello with that room's salt, then a Noise NNpsk0 handshake bound to `(room_id, room_salt)`.

**Phase 0a — Room select (plaintext, client → server):**

`postcard(ClientFrame::RoomSelect { room: String })`. The room name is plaintext (server can't pick a PSK otherwise; room *names* are not secrets, passwords are). The server validates the name against `MAX_ROOM_ID_LEN`, looks up the room, and either:

- on hit: replies with that room's `ServerFrame::Hello { room_salt, server_version }`;
- on miss: synthesizes a junk `RoomState` (fresh random salt, fresh random PSK) and replies with that room's hello, then proceeds through `handshake_responder` exactly as for a real room. The handshake fails on the client's M1 verify — same wire shape as a wrong-password connect against a real room. An external observer cannot tell "no such room" from "wrong password," so room names are not enumerable.

**Phase 0b — Server hello (plaintext, server → client):**

`postcard(ServerFrame::Hello { room_salt, server_version })`. `room_salt` is non-secret (an Argon2 stretching salt, not a key). The server generates one salt per room at startup (32 random bytes) and reuses it for the process lifetime; restarting the server rotates every room's salt.

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
    RoomSelect { room: String },                      // pre-Noise plaintext, capped at MAX_ROOM_ID_LEN = 32
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

struct MessageAd { from: Uuid, username: String, counter: u64, timestamp_ms: u64 }
```

The server **never** decrypts `ciphertext` — it only forwards it and tracks ordering / history. The AEAD AAD binds:

- `from`: sender's UUID. Server enforces `ad.from == session user_id` on receive.
- `username`: sender's display name. Server enforces `ad.username == session username` so a malicious server can't relabel messages without breaking decryption everywhere.
- `counter`: per-sender monotonic. Server tracks `last_counter` per session and rejects non-increasing values; clients also track per-`(user_id)` to reject any replay the server might inject.
- `timestamp_ms`: client wall-clock at send. Bound to detect tamper but not authoritatively validated.

All three of (from / username / counter) failing → `Protocol` error → connection dropped.

### Room encryption

```text
nonce      = XChaCha20-Poly1305 random 24 bytes
plaintext  = UTF-8 message body
ad         = postcard(MessageAd { from, username, counter, timestamp_ms })
ciphertext = XChaCha20Poly1305::seal(room_key, nonce, plaintext, ad)
```

24-byte nonces make random selection safe (collision probability is negligible until ~2⁴⁸ messages — we will never approach that).

## Connection lifecycle

1. TCP connect.
2. Client sends `ClientFrame::RoomSelect { room }` (plaintext, length-prefixed). Server validates the name and looks it up; on miss it replies `ServerFrame::Error { reason: AuthFailed }` and closes.
3. Server sends `ServerFrame::Hello { room_salt, server_version }` for that room (plaintext).
4. Client stretches password → `master`, splits → `psk` + `room_key`. If `server_version` is incompatible the client closes immediately.
5. Noise NNpsk0 handshake (M0 from client, M1 from server) with prologue = `len(room_id) || room_id || room_salt`. Wrong PSK → AEAD tag fails on first transport message → both sides close.
6. Client sends `ClientFrame::Hello { username }` (Noise-encrypted). Server validates `1 ≤ len ≤ MAX_USERNAME_LEN`.
7. Server replies `ServerFrame::Welcome { user_id, history }` with up to **15** prior `RoomMessage`s for the join replay (per-room).
8. Bidirectional message flow until disconnect. Broadcast (per-room) uses `try_send` + evict on `Full`/`Closed` so a slow peer cannot head-of-line block delivery.
9. Idle sessions evicted after **3600 s** of inactivity; sweeper runs every **300 s** and iterates every room.
10. On disconnect: drop sender, zeroize session keys, evict from the room's `ConnectionManager`.
11. **Graceful shutdown:** server's accept loop, sweeper, and per-connection `pump` all share a `tokio_util::sync::CancellationToken`. SIGINT cancels the token; the `JoinSet` drains in-flight tasks; once empty, every `Arc<RoomState>` refcount hits zero and each cached `psk` zeroizes. Client catches ctrl-c as a key event in raw mode (the TUI swallows the SIGINT) and returns from its event loop, dropping `room_key`.

## Client TUI

The client uses an alt-screen TUI built on `crossterm` 0.29 + `ratatui` 0.30 (`crossterm_0_29` feature pin so there's exactly one crossterm in the tree).

### Layout

```text
Secure Terminal Chat                              ← centered bold-magenta header
 alice · 127.0.0.1:3000  —  enter · /(c)lear …   ← cyan status bar
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
  cli.rs                // clap subcommand dispatch + CHAT_RS_* env lookups + read_password
  proto.rs              // postcard frame enums; PROTOCOL_VERSION; MAX_FRAME_LEN; MAX_USERNAME_LEN; HISTORY_LEN
  wire.rs               // LengthDelimitedCodec + send_postcard / recv_postcard helpers
  error.rs              // thiserror Error + ErrorKind
  crypto/
    mod.rs
    password.rs         // Argon2id master + keyed BLAKE2s split into psk + room_key
    room.rs             // XChaCha20-Poly1305 wrappers (seal/open)
    noise.rs            // snow Noise NNpsk0 handshake + transport helpers
  server/
    mod.rs              // ServerHub + per-RoomState; listener, handle_connection, pump, broadcast, sweeper, shutdown
    rooms.rs            // RoomConfig + parser for the CHAT_RS_ROOMS env var
    stores.rs           // MessageStore (ring buffer), UserSessionStore (idle eviction + per-session counter)
    managers.rs         // ConnectionManager (mpsc::Sender map per session)
    ratelimit.rs        // per-source-IP sliding-window connection cap
  client/
    mod.rs              // connect, handshake, event_loop orchestration
    ui.rs               // ratatui TUI: UiState, render, handle_key, TerminalGuard
tests/
  end_to_end.rs         // 12 integration tests (handshake, history, /clear, oversized, ad.from, username cap, dup Hello, room isolation, unknown room, …)
```

## Dependencies

See `Cargo.toml` for the canonical list; each direct dep has a one-line purpose comment. Summary:

```text
Async/transport:   tokio (trimmed features), tokio-util (codec + sync),
                   futures-util (sink+std)
CLI / I/O:         clap (derive), rpassword, dotenvy (.env loader)
Wire / serde:      serde (derive), postcard (use-std, default-features=false)
Crypto:            snow, argon2, chacha20poly1305, blake2, zeroize, getrandom
Errors:            thiserror
Identifiers:       uuid (v4 + serde)
Logging:           tracing, tracing-subscriber (env-filter + fmt + ansi + registry)
Unix-only:         libc (for setrlimit on RLIMIT_CORE at startup)
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
- **Logger scrub is enforced**: a `FieldScrub` `tracing_subscriber::Filter` in `main.rs` drops any event whose metadata declares a field named `password`, `psk`, `room_key`, `master`, `nonce`, `tag`, or `auth_tag`. A misplaced `info!(?password, …)` becomes a silent no-op rather than a leak.
- **Argon2 cost on the server is paid once at startup**, not per connect — `ServerState` caches the derived `psk` and drops the password before listening.
- **Handshake timeout (5 s)** on the unauthenticated phase (Noise M0/M1 + first encrypted Hello). Closes the slow-loris vector against tasks/FDs.
- **Per-source-IP rate limit (60 connects / 60 s)** sliding window. Drops the socket without spawning a task. Sweeper periodically prunes the IP table.
- **Global concurrent-connection cap (4096)** via `AtomicUsize` + RAII guard on `ServerHub`. Bounds FD + outbox memory under a flood that defeats the per-IP limit (botnet, IPv6 /64).
- **Per-session message-rate cap (30 / 10 s)** and **`/clear` cooldown (30 s)** in `UserSessionStore`. An authenticated client can no longer flood the broadcast path or wipe history at will.
- **Per-message ciphertext cap (`MAX_CIPHERTEXT_LEN = 4096`)** so the worst-case `ServerFrame::Welcome { history }` (15 messages) fits inside `MAX_FRAME_LEN`. Without this, a busy room could lock new joiners out.
- **Username charset:** ASCII `[A-Za-z0-9_-]{1,32}` enforced server-side. Blocks bidi/zero-width/control-char spoofing in the TUI.
- **Salt + version bound into Noise prologue** (`(room_id, room_salt, server_version)`). MITM tampering with the plaintext server-hello — including version downgrade — fails on M0/M1 instead of after Argon2 work.
- **Minimum password length: 12 chars** enforced in `cli::read_password` (env and prompt paths) and in `server::rooms::parse`. Counters offline brute-force against captured `room_salt`.
- **Core dumps disabled** at startup via `setrlimit(RLIMIT_CORE, 0)` (Unix). A crash can't write key material to disk.
- **Per-message AEAD AAD** binds `(from, username, counter, timestamp_ms)` so a malicious server can't relabel sender, change usernames, or replay messages without breaking decryption. Server enforces all three; clients enforce counter monotonicity client-side.
- **Unknown-room indistinguishability:** server synthesizes a junk salt + junk PSK and runs the full handshake on a miss, so an unauthenticated probe can't enumerate room names by response shape.

## Testing

**30 unit + 17 integration = 47 tests.**

- Unit (in-tree):
  - `crypto/password.rs` (4) — KDF determinism, password sensitivity, salt sensitivity, label separation.
  - `crypto/room.rs` (4) — round-trip seal/open, wrong key, AD tampering, truncated ciphertext.
  - `crypto/noise.rs` (3) — handshake round-trip, wrong PSK fails, prologue mismatch fails.
  - `server/stores.rs` (1) — history ring-buffer cap.
  - `server/ratelimit.rs` (3) — below-limit allowed, distinct IPs independent, cleanup drops empty.
  - `server/rooms.rs` (5) — parses two rooms with comments, rejects short password, rejects invalid name, rejects duplicate room, rejects empty config.
  - `proto.rs` (2) — postcard round-trip for every variant of `ClientFrame` and `ServerFrame`.
  - `client/ui.rs` (8) — pinned-push keeps scroll 0, scrolled-push anchors view, `clear_messages` resets scroll, `HISTORY_CAP` evicts oldest, scroll clamps to max, `/q`+`/quit` exit, `/c`+`/clear` send Clear, `try_accept_counter` rejects per-sender replay.
- Integration (`tests/end_to_end.rs`, 17): two-client message exchange (asserts plaintext does not appear in broadcast bytes), history replay for late joiner, history cap over wire, `/clear` propagation (incl. `Cleared.username`), oversized-frame rejection without OOM, unique `user_id` per connection, `ad.from` mismatch drops connection, **`ad.username` mismatch drops connection** (server-side relabel defense), **server rejects counter replay** (per-session monotonicity), over-cap username rejected with `BadFrame`, **invalid-charset username rejected** (bidi-override `\u{202E}`), duplicate `Hello` after auth drops connection, **rooms are isolated** (alice in alpha doesn't see bob's beta traffic), **unknown room indistinguishable from wrong password** (M-1 fake-hello — also covers wrong-password rejection), **oversized ciphertext rejected** (L-3), **message-rate cap enforced** (M-4), **`/clear` cooldown enforced** (L-2).
- Pre-commit gate: `build.sh` runs `cargo fmt → cargo clippy --all-targets -- -D warnings → cargo test`.
- Supply chain: `cargo deny check` (licenses + advisories + bans + sources).

Outstanding test gaps (TODO Phase 4): sweeper-driven idle eviction, slow-peer broadcast (HOL), graceful-shutdown drain — all three need small refactors to expose injection hooks.

## Open questions

Tracked in detail in [`01-TODO.md`](01-TODO.md) Phase 5. Headlines:

- **Forward secrecy on the room key** — currently fixed for the room's lifetime. Tentative direction: server-driven salt rotation (Phase 5 has the full options table and reasoning).
- **Protocol-version negotiation** — server advertises; client doesn't. Add a `ClientFrame::Hello` field if server-side gating ever matters.
- **Sender-keys ratchet** — beyond v0; would give post-compromise security at significant complexity cost.
