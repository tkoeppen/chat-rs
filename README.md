# chat-rs

Encrypted terminal chat in Rust. No persistence, no logs — keys live in RAM only.

A Rust port of [cmd-chat](https://github.com/diorwave/cmd-chat) (Python). One binary acts as both server and client; messages are end-to-end encrypted and the server only ever sees ciphertext.

## Status

Early development. The wire protocol is not yet stable.

## Design

- **Password stretching:** Argon2id (m=64 MiB, t=3, p=1) over `(password, room_salt)`, split via keyed BLAKE2s into a Noise PSK and a room AEAD key.
- **Authenticated key exchange:** Noise NNpsk0 (X25519 + ChaCha20-Poly1305 + BLAKE2s) using the derived PSK — gives mutual auth and forward secrecy from a small, well-audited pattern.
- **Transport:** raw TCP with `LengthDelimitedCodec` framing (64 KiB cap), `postcard` for binary serde.
- **Message encryption:** XChaCha20-Poly1305 with a fresh 24-byte random nonce per message; `MessageAd { from, timestamp_ms }` is bound in as AAD.
- **No disk writes:** keys, messages, and history exist only in process memory; password material is zeroized on drop and never leaves the client.

## Build

```sh
cargo build --release
# optional — put `chat-rs` on your PATH:
cargo install --path .
```

If you skip `cargo install`, every `chat-rs …` invocation in the snippets below can be replaced with `cargo run --release -- …`. The two are equivalent; the rest of this README uses `chat-rs` for brevity.

## Usage

The password is read from the `CHAT_RS_PASSWORD` environment variable if set, otherwise from an interactive prompt. There is no `--password` flag — passwords on the command line leak into shell history and `ps`.

Start a server:

```sh
chat-rs serve 0.0.0.0 3000
```

Connect a client:

```sh
chat-rs connect SERVER_IP 3000 username
```

Inside the client TUI, `/clear` wipes the room history for everyone (locally too), and **Ctrl-C** quits cleanly.

## Try it locally

One server + two clients, each in its own terminal, talking on `127.0.0.1`. The `CHAT_RS_PASSWORD` export is used here to skip three interactive prompts; for real use, just run the commands without it and type the password when asked.

> If you haven't run `cargo install --path .`, substitute `cargo run --release --` for `chat-rs` in each snippet — the rest is identical.

**Terminal 1 — server:**

```sh
export CHAT_RS_PASSWORD=hunter2
chat-rs serve 127.0.0.1 3000
```

**Terminal 2 — alice:**

```sh
export CHAT_RS_PASSWORD=hunter2
chat-rs connect 127.0.0.1 3000 alice
```

**Terminal 3 — bob:**

```sh
export CHAT_RS_PASSWORD=hunter2
chat-rs connect 127.0.0.1 3000 bob
```

Each client opens a small TUI (alt-screen, raw mode): centered **Secure Terminal Chat** header, cyan status bar, scrolling room pane, single-line input box.

| Key | Action |
| --- | --- |
| Enter | Send the current line (or `/clear`) |
| ↑ / ↓ | Scroll the room pane 1 line |
| PgUp / PgDn | Scroll nearly a full pane |
| Home / End | Oldest visible / back to live |
| Ctrl-C | Quit cleanly (terminal restored via RAII guard) |

Type a line in alice's window and hit **enter** — bob sees it as `[hh:mm:ss] alice: <message>` with usernames colored. The last 15 messages are replayed to anyone who joins later. Send `/clear` from either client to wipe the room history for everyone — the post-clear screen is a single `cleared by alice` notice.

## License

See [LICENSE.txt](LICENSE.txt).
