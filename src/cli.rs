use std::env;
use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::server::rooms;

#[derive(Debug, Parser)]
#[command(
    name = "chat-rs",
    about = "Encrypted terminal chat. No persistence, no logs.",
    long_about = "Encrypted terminal chat. No persistence, no logs.\n\
                  \n\
                  All configuration is read from environment variables. A `.env` file in the\n\
                  current working directory is auto-loaded at startup; see `.env.example` for\n\
                  the full set of variables for each subcommand."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run as the server. Reads CHAT_RS_BIND and CHAT_RS_ROOMS from env.
    Serve,
    /// Connect to a server as a client. Reads CHAT_RS_SERVER, CHAT_RS_USERNAME,
    /// CHAT_RS_ROOM, and CHAT_RS_PASSWORD from env.
    Connect,
}

const PASSWORD_ENV: &str = "CHAT_RS_PASSWORD";
const BIND_ENV: &str = "CHAT_RS_BIND";
const ROOMS_ENV: &str = "CHAT_RS_ROOMS";
const SERVER_ENV: &str = "CHAT_RS_SERVER";
const USERNAME_ENV: &str = "CHAT_RS_USERNAME";
const ROOM_ENV: &str = "CHAT_RS_ROOM";
/// Floor on password length. 12 chars stops trivial dictionary brute-force
/// against the captured `room_salt` even with a single GPU. Mirrored in
/// `server/rooms.rs::MIN_PW_LEN`.
const MIN_PW_LEN: usize = 12;

fn require_env(key: &'static str) -> Result<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(Error::MissingEnv(key)),
    }
}

fn read_addr(key: &'static str) -> Result<SocketAddr> {
    let raw = require_env(key)?;
    raw.parse::<SocketAddr>()
        .map_err(|_| Error::Protocol("env var must be ip:port"))
}

fn read_password(role: &str) -> Result<Zeroizing<Vec<u8>>> {
    let raw: Zeroizing<Vec<u8>> = if let Ok(env) = env::var(PASSWORD_ENV)
        && !env.is_empty()
    {
        let z = Zeroizing::new(env);
        Zeroizing::new(z.as_bytes().to_vec())
    } else {
        let prompt = format!("{role} password (min {MIN_PW_LEN} chars): ");
        // Read into a Zeroizing<String> so the original buffer is wiped on drop.
        let pw = Zeroizing::new(rpassword::prompt_password(prompt).map_err(Error::Io)?);
        Zeroizing::new(pw.as_bytes().to_vec())
    };
    if raw.len() < MIN_PW_LEN {
        return Err(Error::Protocol("password too short"));
    }
    Ok(raw)
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve => {
            let addr = read_addr(BIND_ENV)?;
            let rooms_text = require_env(ROOMS_ENV)?;
            let configs = rooms::parse(&rooms_text)?;
            crate::server::run(addr, configs).await
        }
        Command::Connect => {
            let addr = read_addr(SERVER_ENV)?;
            let username = require_env(USERNAME_ENV)?;
            let room = require_env(ROOM_ENV)?;
            rooms::validate_name(&room)?;
            let pw = read_password("connect")?;
            crate::client::run(addr, username, room, pw).await
        }
    }
}
