use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

use chat_rs::cli::{Cli, run};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");
            std::process::ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("chat_rs=info,warn"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
