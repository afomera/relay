//! `relay` — the CLI entry point. See `SPEC.md` §10 for the full command
//! surface planned. The v0.x CLI only exposes the commands that are fully
//! implemented end-to-end (auth + http + tcp). Management commands
//! (tunnels/domains/reservations) and tls-passthrough land once they're
//! shippable — until then they live in the dashboard or the spec.

mod commands;

use relay_cli::config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "relay", version, about = "Expose local services through a relayd server.")]
struct Cli {
    /// Override the relay server (host:port UDP). Defaults to config or localhost:7443.
    #[arg(long, global = true, env = "RELAY_SERVER")]
    server: Option<String>,

    /// Skip TLS certificate verification. Dev only.
    #[arg(long, global = true, env = "RELAY_INSECURE")]
    insecure: bool,

    /// PEM-encoded CA (or self-signed cert) to trust for the relay server.
    #[arg(long, global = true, env = "RELAY_CAFILE")]
    cafile: Option<String>,

    /// Auth token override. Normally loaded from ~/.config/relay/config.toml.
    #[arg(long, global = true, env = "RELAY_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage CLI authentication with a relay server.
    #[command(subcommand)]
    Auth(AuthCmd),

    /// Open an HTTP tunnel to a local port.
    Http {
        port: u16,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        /// Disable request inspection (default: on).
        #[arg(long)]
        no_inspect: bool,
        /// Exit on the first disconnect instead of reconnecting with backoff.
        #[arg(long)]
        no_reconnect: bool,
    },

    /// Open a raw TCP tunnel to a local port.
    Tcp { port: u16 },
}

#[derive(Subcommand)]
enum AuthCmd {
    Login {
        #[arg(long)]
        token: String,
    },
    Logout,
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let cfg = config::load()?;
    let runtime = commands::RuntimeCtx {
        server: cli.server.or(cfg.server.clone()).unwrap_or_else(|| "localhost:7443".into()),
        token: cli.token.or(cfg.token.clone()).unwrap_or_default(),
        insecure: cli.insecure,
        cafile: cli.cafile,
    };

    match cli.command {
        Command::Auth(sub) => commands::auth::run(sub, cfg).await,
        Command::Http { port, hostname, domain, no_inspect, no_reconnect } => {
            commands::http::run(runtime, port, hostname, domain, !no_inspect, !no_reconnect).await
        }
        Command::Tcp { port } => commands::tcp::run(runtime, port).await,
    }
}
