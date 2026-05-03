# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0,
**minor bumps may be wire-breaking** — protocol changes are called out
explicitly.

## [Unreleased] — 0.2.0

### Added

- **Ephemeral messages.** New `/secret <msg>` (alias `/s`) sends a message
  that:
  - renders as a fixed-width mask (`*******`) on every receiver's TUI,
  - shows a per-message countdown next to the sender name (`bob (29):`),
  - auto-deletes from every client's view after 30 s,
  - is excluded from the server's join-replay history (late joiners never
    see it).

  Press **Ctrl-R** to briefly reveal currently-masked messages (3 s window).
- New `MessageAd.ephemeral: bool` field; AAD-bound, so the server can act on
  it (skip history) without being able to flip it.
- Constants `EPHEMERAL_TTL_MS` / `EPHEMERAL_REVEAL_MS` / `EPHEMERAL_MASK` in
  `proto.rs` for cross-module reuse.
- 500 ms tick in the client event loop drives auto-expiry + countdown
  refresh.
- 3 new tests: `ephemeral_message_broadcasts_but_not_in_history` (e2e),
  `tick_expire_drops_aged_ephemerals_only`, `reveal_then_remask_after_window`,
  `ephemeral_countdown_rounds_up` (unit).

### Changed (BREAKING)

- **Wire-incompatible.** `PROTOCOL_VERSION` bumped 1 → 2; `MessageAd` gained
  `ephemeral`. Postcard is positional — old/new builds cannot interoperate.
  The Noise prologue binds version, so the handshake fails fast on
  mismatched peers.

---

## [0.1.0] — 2026-05-03

First public release.

### Added

- **Encrypted terminal chat in a single binary**, server or client mode
  (`chat-rs serve` / `chat-rs connect`).
- **Crypto stack:** Argon2id (m=64 MiB, t=4) over `(password, room_salt)` →
  master, split via keyed BLAKE2s into Noise PSK + room AEAD key. Noise
  NNpsk0 (X25519 + ChaCha20-Poly1305 + BLAKE2s) for the handshake;
  XChaCha20-Poly1305 (24-byte random nonce) for room messages with AAD-bound
  `(from, username, counter, timestamp_ms)`.
- **Multi-room server** (closed model). `CHAT_RS_ROOMS` env var lists
  `name = password` rooms; each gets its own salt + cached PSK at startup.
  Pre-Noise `RoomSelect` frame; prologue binds `(room_id, room_salt,
  server_version)` to prevent MITM tampering and version downgrade.
- **Env-var-only CLI** with `dotenvy` auto-loading `.env` from cwd.
  No positional args, no password on command line.
- **Ratatui TUI client.** Header, status bar, scrolling message pane,
  single-line input. Per-username color, `/clear` / `/quit` slash commands,
  `↑↓ / PgUp PgDn / Home End` scrollback, RAII guard restores the terminal
  on panic.
- **GitHub Actions** for CI (Ubuntu runs `build.sh`; macOS + Windows run
  `cargo test`), security (`cargo-deny` weekly + on lock change),
  release (tag push → cross-built archives for `aarch64-apple-darwin`,
  `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`).
- **Dependabot** for cargo + github-actions dependencies (weekly).
- **`build.sh` pre-commit gate**: `cargo fmt --check`,
  `cargo clippy --all-targets -- -D warnings -D clippy::missing_panics_doc
  -D clippy::unwrap_used -D clippy::expect_used`, `cargo test`.

### Security

- **Pen-test hardening pass** closing 10 findings (M1–M4 + L1–L6):
  - **M-1** Fake-hello + handshake on unknown room — wire shape
    indistinguishable from wrong-password, blocking room-name enumeration.
  - **M-2** 12-char password floor + Argon2 `t=4` — raises offline
    brute-force cost against the publicly-fetchable salt.
  - **M-3** Global concurrent-connection cap (4096) via `AtomicUsize` + RAII
    guard.
  - **M-4** Per-session message-rate cap (30 / 10 s).
  - **L-1** Username charset enforced server-side (`[A-Za-z0-9_-]{1,32}`)
    — blocks bidi/zero-width spoofing in the TUI.
  - **L-2** `/clear` cooldown (30 s per session).
  - **L-3** Per-message ciphertext cap (`MAX_CIPHERTEXT_LEN = 4096`) so
    `Welcome` history can't blow past `MAX_FRAME_LEN`.
  - **L-4** Rate-limiter mutex fail-closed instead of panic on poison.
  - **L-5** Noise prologue binds `server_version` (downgrade defence).
  - **L-6** README documents the `.env`-from-cwd risk.
- **Replay defence:** per-sender monotonic `counter` in `MessageAd`,
  enforced server-side and on every receiving client.
- **Username relabel defence:** `ad.username` AAD-bound; server enforces
  `ad.username == session_username`.
- **Logger field-scrub.** `tracing` filter drops any event whose metadata
  declares `password`, `psk`, `room_key`, `master`, `nonce`, `tag`, or
  `auth_tag` — turns the no-log-secrets rule into a runtime guarantee.
- **Zeroize-on-drop** for password material and derived keys
  (`Zeroizing<T>` / `#[derive(Zeroize, ZeroizeOnDrop)]`).
- **Core-dump suppression** via `setrlimit(RLIMIT_CORE, 0)` at startup
  (Unix-only; Windows takes a no-op).
- **5-second handshake timeout** (Noise M0/M1 + first encrypted Hello)
  closes the slow-loris vector.
- **Per-source-IP rate limit** (60 connects / 60 s) on accept.
- **64 KiB frame cap** via `LengthDelimitedCodec` — no unbounded reads.
- **No `unwrap()` / `expect()` in non-test code**, lint-enforced. The single
  documented exception is a static infallible Noise-pattern parse, narrowly
  `#[allow]`-ed.

[Unreleased]: https://github.com/tkoeppen/chat-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tkoeppen/chat-rs/releases/tag/v0.1.0
