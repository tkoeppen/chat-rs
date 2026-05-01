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

## Usage

The password is read from the `CHAT_RS_PASSWORD` environment variable if set, otherwise from an interactive prompt. There is no `--password` flag — passwords on the command line leak into shell history.

Start a server:

```sh
chat-rs serve 0.0.0.0 3000
```

Connect a client:

```sh
chat-rs connect SERVER_IP 3000 username
```

Inside the client REPL, `/clear` wipes the room history for everyone.

## Try it locally

One server + two clients, each in its own terminal, talking on `127.0.0.1`. The `CHAT_RS_PASSWORD` export is used here to skip three interactive prompts; for real use, just run the commands without it and type the password when asked.

**Terminal 1 — server:**

```sh
export CHAT_RS_PASSWORD=hunter2
cargo run --release -- serve 127.0.0.1 3000
```

**Terminal 2 — alice:**

```sh
export CHAT_RS_PASSWORD=hunter2
cargo run --release -- connect 127.0.0.1 3000 alice
```

**Terminal 3 — bob:**

```sh
export CHAT_RS_PASSWORD=hunter2
cargo run --release -- connect 127.0.0.1 3000 bob
```

Type a line in alice's window — bob sees it as `[hh:mm:ss] alice: <message>` and vice-versa. The last 15 messages are replayed to anyone who joins later. Send `/clear` from either client to wipe the room history for everyone. Ctrl-D (EOF) on a client disconnects it cleanly.

## Build

```sh
cargo build --release
```

## License

See [LICENSE.txt](LICENSE.txt).
