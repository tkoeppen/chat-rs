use clap::Parser;
use tracing::{Metadata, Subscriber};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use chat_rs::cli::{Cli, run};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    disable_core_dumps();
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

/// Set RLIMIT_CORE to 0 so a crash can't write a core file containing the
/// cached PSK or per-connection room key. No-op on non-Unix.
fn disable_core_dumps() {
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

fn init_tracing() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("chat_rs=info,warn"));
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(FieldScrub);
    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .try_init();
}

/// Drops any tracing event whose metadata declares a forbidden field name —
/// turns the previous discipline-only doc-comment denylist into an enforced
/// filter. A misplaced `info!(?password, …)` becomes a silent no-op instead
/// of leaking secrets.
struct FieldScrub;

const FORBIDDEN_FIELDS: &[&str] = &[
    "password", "psk", "room_key", "master", "nonce", "tag", "auth_tag",
];

impl<S: Subscriber> Filter<S> for FieldScrub {
    fn enabled(&self, meta: &Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        !meta
            .fields()
            .iter()
            .any(|f| FORBIDDEN_FIELDS.contains(&f.name()))
    }
}
