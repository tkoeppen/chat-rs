# chat-rs — TODO

A Rust-based command-line chat tool. Modern crypto stack;
**Read first:**

- [`02-FEATURES.md`](02-FEATURES.md) — feature spec, crypto design, dependency budget.
- [`03-review-python-chat.md`](03-review-python-chat.md) — comparison of the two Python references (kept for UX/architecture context only — their crypto is replaced).

Reference implementations (UX/CLI parity only):

1. `/Users/tk/src/dl/others/cmd-chat/cmd-chat` (Project A — Sanic/HTTP/WebSocket)
2. `/Users/tk/src/dl/others/cmd-chat/2/cmd-chat` (Project B — raw asyncio TCP)

## Crypto stack — at-a-glance

| Layer | Choice | Crate |
|------|--------|-------|
| Password stretching | Argon2id (m=64 MiB, t=3, p=1) | `argon2` |
| Authenticated KEX | Noise NNpsk0 (X25519 + ChaCha20-Poly1305 + BLAKE2s) | `snow` |
| Room AEAD | XChaCha20-Poly1305 (24-byte random nonce) | `chacha20poly1305` |
| Frame codec | `postcard` (binary serde) | `postcard` |
| Framing | `LengthDelimitedCodec`, 64 KiB cap | `tokio-util` |

Dropped vs the cmd-chat-derived design: `srp`, `fernet`, `serde_json`, `subtle` (direct), `anyhow`.

## Phase 0 — Bootstrap

- [x] `cargo init` with edition 2024 (uses `src/main.rs` + `src/lib.rs`, *not* `src/bin/`)
- [x] Core deps: `tokio`, `tokio-util`, `futures-util`, `bytes`, `clap`, `serde`, `postcard`, `thiserror`, `uuid`
- [x] Crypto deps: `snow`, `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`, `rand`
- [x] Password input: `rpassword` (interactive prompt) + `CHAT_RS_PASSWORD` env
- [ ] TUI deps: `crossterm`, `ratatui` *(deferred — v0 uses plain stdin/stdout)*
- [x] Dev deps: `proptest`
- [x] `cargo fmt` + `cargo clippy -- -D warnings` clean baseline

## Phase 1 — CLI + transport skeleton

- [x] `serve <ip> <port>` subcommand — `CHAT_RS_PASSWORD` env, fall back to interactive prompt via `rpassword` (the `--password` flag was dropped)
- [x] `connect <ip> <port> <username>` subcommand — same password-source rules
- [x] TCP listener + per-connection `tokio` task
- [x] `LengthDelimitedCodec` with `max_frame_length(65536)`
- [x] Plaintext `ServerFrame::Hello { room_salt, server_version }` as the very first frame on every connection (server generates `room_salt` once at startup)

## Phase 2 — Crypto core

- [x] `crypto::password` — Argon2id over `(password, room_salt)` → `master`; HKDF split into `psk` + `room_key`
- [x] `crypto::noise` — Noise NNpsk0 handshake helpers (`snow` initiator + responder; both call `Builder::psk(0, &psk)` before starting)
- [x] `crypto::room` — XChaCha20-Poly1305 seal/open helpers; AD = postcard(`MessageAd`)
- [x] `Zeroizing` wrappers / `ZeroizeOnDrop` derives on `master`, `psk`, `room_key`
- [x] `error::ErrorKind` enum (`AuthFailed`, `BadFrame`, `RateLimited`, `UnsupportedVersion`, `Internal`)
- [x] Unit tests: round-trip seal/open, wrong-password rejects, AD tampering rejects (4 room + 4 password + 2 noise tests)
- [ ] Decide: keep `hkdf` + `sha2`, or swap KDF to BLAKE2s (already pulled in by `snow`) and drop both crates

## Phase 3 — Protocol + chat

- [x] `proto.rs` — `ClientFrame` / `ServerFrame` / `RoomMessage` / `ErrorKind` enums (postcard)
- [x] Phase 0 plaintext server hello gates Noise NNpsk0
- [x] `ClientFrame::Hello { username }` after Noise handshake
- [x] `ServerFrame::Welcome { user_id, history }` with last 15 ciphertexts replayed
- [x] Broadcast: server forwards `RoomMessage` to all connected clients (including sender for echo confirmation)
- [x] `Clear` command (sent as `/clear` from the client REPL) broadcasts `Cleared { by }`

## Phase 4 — Polish & safety

- [x] Stale-session cleanup task (3600 s timeout, 300 s sweep interval)
- [ ] Graceful shutdown (Ctrl-C drains, zeroizes keys, closes sockets) — currently the process exits abruptly; Tokio drops are clean but no explicit drain
- [x] `tracing` + `tracing-subscriber` with `RUST_LOG`/`EnvFilter` (default `chat_rs=info,warn`); discipline-only field scrub via module-level doc comments listing forbidden field names — no structured logger filter yet
- [x] Cache Noise psk in `ServerState::new` and drop the password before listening — closes the per-connect 64 MiB Argon2 DoS
- [x] Reject `ClientFrame::Message` with `ad.from != session user_id` — prevents AAD-mismatch DoS where peers' decrypts silently fail
- [x] Cap `Hello.username` at `MAX_USERNAME_LEN = 32`
- [x] Broadcast uses `try_send` + evict on `Full`/`Closed` — slow peer can no longer head-of-line block delivery
- [ ] Rate-limit failed Noise handshakes per source IP — defense-in-depth; per-connect Argon2 cost is no longer the issue (psk is cached)
- [x] Integration test: two clients exchange a message; assert plaintext does not leak into broadcast bytes
- [x] Integration test: wrong password fails to join
- [x] Integration test: history replay for late joiner (3 messages + capped at 15)
- [x] Integration test: `/clear` propagates to all clients
- [x] Integration test: oversized frame rejected without OOM
- [x] Integration test: unique `user_id` per connection

## Phase 5 — Open questions to resolve before 1.0

- [x] Password input source (stdin / env / interactive prompt) — `CHAT_RS_PASSWORD` env, falling back to interactive `rpassword` prompt; no `--password` flag
- [ ] Replay protection inside the room — per-sender monotonic counter in `MessageAd`, or sliding-window cache on the client
- [ ] Bind `username` into `MessageAd` so a malicious server can't relabel messages
- [ ] Decide whether room-key forward secrecy (ratchet) is in scope for 1.0 or deferred
- [ ] KDF swap (HKDF-SHA256 → BLAKE2s) to drop `hkdf` + `sha2`
- [ ] Protocol-version negotiation — add a client version field if server-side gating ever matters

## Improvements applied vs initial draft (rationale)

- **SRP-6a → Noise NNpsk0.** SRP is hard to use safely and ties us to a niche crate; Noise via `snow` gives mutual auth + forward secrecy from a well-audited toolkit with a tiny API surface.
- **Raw HKDF over password → Argon2id.** Argon2id forces attackers to spend memory + time per guess; raw HKDF over a low-entropy password is essentially free to brute-force.
- **Fernet (AES-128-CBC + HMAC-SHA256) → XChaCha20-Poly1305.** Modern AEAD, no padding-oracle surface, smaller code, faster on commodity hardware, 24-byte nonce so random selection is safe.
- **JSON over `\n` → postcard over length-prefix.** Drops `serde_json` entirely, removes JSON-escaping foot-guns, gives bounded reads by construction.
- **Drop `subtle` (direct) + `anyhow`.** `subtle` is transitively pulled in by AEAD/argon2 anyway; `anyhow` is unnecessary if errors are typed end-to-end with `thiserror`.
