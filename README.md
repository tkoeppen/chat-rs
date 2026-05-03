# chat-rs

[![CI](https://github.com/tkoeppen/chat-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/tkoeppen/chat-rs/actions/workflows/ci.yml)
[![Security](https://github.com/tkoeppen/chat-rs/actions/workflows/security.yml/badge.svg)](https://github.com/tkoeppen/chat-rs/actions/workflows/security.yml)

Encrypted terminal chat in Rust. No persistence, no logs — keys live in RAM only.

A Rust port of [cmd-chat](https://github.com/diorwave/cmd-chat) (Python). One binary acts as both server and client; messages are end-to-end encrypted and the server only ever sees ciphertext.

## Status

Early development. The wire protocol is not yet stable.

## Design

- **Password stretching:** Argon2id (m=64 MiB, t=4, p=1) over `(password, room_salt)`, split via keyed BLAKE2s into a Noise PSK and a room AEAD key. Minimum password length: 12 chars (anyone who can connect can request a room's salt and start an offline guess; Argon2 cost + length floor make it impractical).
- **Multi-room:** server hosts a configured set of rooms (`CHAT_RS_ROOMS` env var, multi-line `name = password`). Each room has its own password, salt, and PSK derived once at startup; broadcast and history are strictly per-room.
- **Authenticated key exchange:** Noise NNpsk0 (X25519 + ChaCha20-Poly1305 + BLAKE2s) using the derived PSK — gives mutual auth and forward secrecy from a small, well-audited pattern. The Noise prologue binds `(room_id, room_salt)`, so MITM tampering with the plaintext server-hello — or shuffling a client between rooms — fails on M0.
- **Transport:** raw TCP with `LengthDelimitedCodec` framing (64 KiB cap), `postcard` for binary serde.
- **Message encryption:** XChaCha20-Poly1305 with a fresh 24-byte random nonce per message; `MessageAd { from, username, counter, timestamp_ms }` is bound in as AAD. The bound `username` blocks server-side relabeling; the per-sender monotonic `counter` blocks replay (server enforces; clients also reject).
- **DoS hardening:** server caches the Noise PSK at startup (no per-connect Argon2 work), 5-second handshake timeout (slow-loris), per-source-IP connection rate limit (60/minute), global concurrent-connection cap (4096), per-session message rate (30/10s) and `/clear` cooldown (30s), 64 KiB frame cap, 4 KiB per-message ciphertext cap, broadcast uses `try_send` + evict so a slow peer can't head-of-line block delivery. Unknown rooms are answered with a synthesized fake hello + junk PSK so an unauthenticated probe can't enumerate room names.
- **No disk writes:** keys, messages, and history exist only in process memory; password material is zeroized on drop and never leaves the client. Core dumps are disabled at startup so a crash can't write key material to disk. Logger drops events whose metadata declares a forbidden field name (`password`, `psk`, `room_key`, `nonce`, …).

## Build

```sh
cargo build --release
# optional — put `chat-rs` on your PATH:
cargo install --path .
```

If you skip `cargo install`, every `chat-rs …` invocation in the snippets below can be replaced with `cargo run --release -- …`. The two are equivalent; the **Usage** section uses `chat-rs` for brevity, and the **Try it locally** walkthrough uses `cargo run` so it works straight from a fresh checkout.

## Usage

All configuration is read from environment variables. A `.env` file in the current working directory is auto-loaded at startup; copy [`.env.example`](.env.example) to `.env` to get going. Process env overrides `.env`, so a real `CHAT_RS_PASSWORD` set inline beats a placeholder in the file.

| Variable | Used by | Meaning |
| --- | --- | --- |
| `CHAT_RS_BIND` | `serve` | `ip:port` to bind, e.g. `0.0.0.0:3000` |
| `CHAT_RS_ROOMS` | `serve` | Multi-line `name = password` per line; `[A-Za-z0-9_-]{1,32}` names, passwords ≥ 8 chars, `#` for comments |
| `CHAT_RS_SERVER` | `connect` | Server `ip:port` |
| `CHAT_RS_USERNAME` | `connect` | Display name shown to other clients |
| `CHAT_RS_ROOM` | `connect` | Room to join (must be configured on the server) |
| `CHAT_RS_PASSWORD` | `connect` | Room password, ≥ 12 chars. If unset, the client falls back to an interactive no-echo prompt |

Run the server:

```sh
chat-rs serve
```

Run a client:

```sh
chat-rs connect
```

There are no positional or `--flag` config arguments — passwords on the command line leak into shell history and `ps`, and once one secret has to live in env the rest are easier to keep there too.

Inside the client TUI, `/clear` (or `/c`) wipes the room history for everyone (locally too), `/quit` (or `/q`) — or **Ctrl-C** — exits cleanly.

### Operational notes

- **Don't run from an untrusted cwd.** `chat-rs` auto-loads `.env` from the working directory; a hostile `.env` there will dictate the bind address, the room set, and the password. Run from a directory you own.
- **Salt is observable.** The room salt is sent in the plaintext server-hello — anyone who can connect can request it. Argon2id (m=64 MiB, t=4) and the 12-char password floor make offline brute-force expensive but not impossible; pick passwords accordingly. Use `pwgen -s 16` or similar.

## Try it locally

One server + three clients across two rooms on `127.0.0.1` — alice and bob chat in `main`, carol is alone in `lounge` and won't see anything they say. Run every terminal from the repo root: `cargo run` reuses the same build, and `.env` is auto-loaded from cwd.

[`.env.example`](.env.example) ships as a runnable local setup (server on `127.0.0.1:3000`, two rooms, alice as the default client). Server and client vars don't overlap, so one shared `.env` covers both roles; per-client tweaks ride on the command line, where process env beats `.env`.

```sh
cp .env.example .env
```

**Terminal 1 — server:** `cargo run --release -- serve`
**Terminal 2 — alice in `main`:** `cargo run --release -- connect`
**Terminal 3 — bob in `main`:** `CHAT_RS_USERNAME=bob cargo run --release -- connect`
**Terminal 4 (optional) — carol in `lounge`:** `CHAT_RS_USERNAME=carol CHAT_RS_ROOM=lounge CHAT_RS_PASSWORD=lounge-pw cargo run --release -- connect`

> Already ran `cargo install --path .`? Use `chat-rs serve` / `chat-rs connect` instead — the rest is identical.

Each client opens a small TUI (alt-screen, raw mode): centered **Secure Terminal Chat** header, cyan status bar showing `username · #room · addr`, scrolling room pane, single-line input box. Anything alice or bob types in `main` is invisible to carol in `lounge`, and vice versa — broadcast and history are strictly per-room.

| Key | Action |
| --- | --- |
| Enter | Send the current line, or run a slash command |
| ↑ / ↓ | Scroll the room pane 1 line |
| PgUp / PgDn | Scroll nearly a full pane |
| Home / End | Oldest visible / back to live |
| Ctrl-C | Quit cleanly (terminal restored via RAII guard) |
| Ctrl-R | Briefly reveal masked ephemeral messages (3 s) |

| Slash command | Action |
| --- | --- |
| `/clear` or `/c` | Wipe room history for everyone (locally too) |
| `/quit` or `/q` | Exit cleanly (same as Ctrl-C) |
| `/secret <msg>` or `/s <msg>` | Send an ephemeral message: shown as `*******` on every client, never enters the join-replay history, auto-deleted after 30 s. Press **Ctrl-R** to briefly reveal currently-masked messages (3 s). |

Type a line in alice's window and hit **enter** — bob sees it as `[hh:mm:ss] alice: <message>` with usernames colored. The last 15 messages are replayed to anyone who joins later. Send `/clear` from either client to wipe the room history for everyone — the post-clear screen is a single `cleared by alice` notice.

## License

See [LICENSE.txt](LICENSE.txt).
