use std::net::{IpAddr, SocketAddr};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::error::Result;

#[derive(Debug, Parser)]
#[command(
    name = "chat-rs",
    about = "Encrypted terminal chat. No persistence, no logs."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run as the server.
    Serve {
        /// IP address to bind.
        ip: IpAddr,
        /// TCP port to bind.
        port: u16,
    },
    /// Connect to a server as a client.
    Connect {
        /// Server IP address.
        ip: IpAddr,
        /// Server TCP port.
        port: u16,
        /// Display name.
        username: String,
    },
}

const PASSWORD_ENV: &str = "CHAT_RS_PASSWORD";
const MIN_PW_LEN: usize = 8;

fn read_password(role: &str) -> Result<Zeroizing<Vec<u8>>> {
    let raw: Zeroizing<Vec<u8>> = if let Ok(env) = std::env::var(PASSWORD_ENV)
        && !env.is_empty()
    {
        let z = Zeroizing::new(env);
        Zeroizing::new(z.as_bytes().to_vec())
    } else {
        let prompt = format!("{role} password (min {MIN_PW_LEN} chars): ");
        // Read into a Zeroizing<String> so the original buffer is wiped on drop.
        let pw =
            Zeroizing::new(rpassword::prompt_password(prompt).map_err(crate::error::Error::Io)?);
        Zeroizing::new(pw.as_bytes().to_vec())
    };
    if raw.len() < MIN_PW_LEN {
        return Err(crate::error::Error::Protocol("password too short"));
    }
    Ok(raw)
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { ip, port } => {
            let pw = read_password("serve")?;
            let addr = SocketAddr::new(ip, port);
            crate::server::run(addr, pw).await
        }
        Command::Connect { ip, port, username } => {
            let pw = read_password("connect")?;
            let addr = SocketAddr::new(ip, port);
            crate::client::run(addr, username, pw).await
        }
    }
}
