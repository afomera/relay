//! `relay` — the CLI entry point. See `SPEC.md` §10 for the full command
//! surface planned. The v0.x CLI only exposes the commands that are fully
//! implemented end-to-end (auth + http + tcp). Management commands
//! (tunnels/domains/reservations) and tls-passthrough land once they're
//! shippable — until then they live in the dashboard or the spec.

mod commands;

use relay_cli::config;

use clap::{Parser, Subcommand};

/// The default server address, baked in at compile time.
///
/// - Hosted builds: set `RELAY_DEFAULT_SERVER=tunnel.sharedwithrelay.com:443`
///   (or whatever your edge lives at) in the release workflow to ship a CLI
///   that needs zero config out of the box.
/// - Fork / self-host builds: set your own value.
/// - Dev builds: the fallback is `localhost:7443`, matching `relayd --dev`.
pub(crate) const DEFAULT_SERVER: &str = match option_env!("RELAY_DEFAULT_SERVER") {
    Some(s) => s,
    None => "localhost:7443",
};

#[derive(Parser)]
#[command(name = "relay", version, about = "Expose local services through a relayd server.")]
struct Cli {
    /// Override the relay server (host:port UDP). Precedence:
    ///   1. --server flag
    ///   2. RELAY_SERVER env
    ///   3. `server` from ~/.config/relay/config.toml
    ///   4. compile-time default (see DEFAULT_SERVER)
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
        /// Require visitors to enter this password before the tunnel proxies
        /// their request. The edge shows a login page on first visit and sets
        /// a signed cookie on success. Ephemeral — clears when the tunnel
        /// disconnects; reconnect must pass `--password` again.
        #[arg(long)]
        password: Option<String>,
    },

    /// Share a puma-dev-style local domain through a tunnel.
    ///
    /// The CLI dials `127.0.0.1:<port>` (port 80 by default, i.e. the puma-dev
    /// front door) and writes `Host: <local_host>` on each outbound request so
    /// the local reverse-proxy can route by name. Use this when your app
    /// listens on a hostname like `admin.sample.test` rather than a raw port.
    Share {
        /// Local Host header value (e.g. `admin.sample.test`).
        local_host: String,
        /// Local port to dial. Defaults to 80 (the puma-dev default).
        #[arg(long, default_value_t = 80)]
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
        /// Require visitors to enter this password before the tunnel proxies
        /// their request. See `relay http --help` for semantics.
        #[arg(long)]
        password: Option<String>,
    },

    /// Open a raw TCP tunnel to a local port.
    Tcp { port: u16 },
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Sign in to a relay server.
    ///
    /// Default: opens the dashboard in your browser, creates a token after
    /// you confirm, and saves it locally. Pass `--token` to skip the browser
    /// and paste a pre-minted PAT (useful for CI / headless machines).
    Login {
        /// Paste a pre-existing PAT instead of doing the browser dance.
        #[arg(long)]
        token: Option<String>,
        /// Relay server this token belongs to (host:port UDP). Pass this
        /// when pointing at a self-hosted relay; omit it to keep whatever
        /// server is already in the config (or fall back to the built-in
        /// default).
        #[arg(long)]
        server: Option<String>,
        /// Skip auto-opening the browser; print the URL instead.
        #[arg(long)]
        no_browser: bool,
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
    let raw_server =
        cli.server.or(cfg.server.clone()).unwrap_or_else(|| DEFAULT_SERVER.to_string());
    let runtime = commands::RuntimeCtx {
        server: relay_cli::normalize_server(&raw_server),
        token: cli.token.or(cfg.token.clone()).unwrap_or_default(),
        insecure: cli.insecure,
        cafile: cli.cafile,
    };

    match cli.command {
        Command::Auth(sub) => commands::auth::run(sub, cfg).await,
        Command::Http { port, hostname, domain, no_inspect, no_reconnect, password } => {
            commands::http::run(
                runtime,
                relay_cli::client::LocalTarget::port(port),
                hostname,
                domain,
                !no_inspect,
                !no_reconnect,
                password,
            )
            .await
        }
        Command::Share {
            local_host,
            port,
            hostname,
            domain,
            no_inspect,
            no_reconnect,
            password,
        } => {
            validate_share_local_host(&local_host)?;
            warn_on_share_wildcard_mismatch(&local_host, hostname.as_deref(), domain.as_deref());
            commands::http::run(
                runtime,
                relay_cli::client::LocalTarget::with_host(port, local_host),
                hostname,
                domain,
                !no_inspect,
                !no_reconnect,
                password,
            )
            .await
        }
        Command::Tcp { port } => commands::tcp::run(runtime, port).await,
    }
}

/// The `share` local-host pattern supports a single wildcard `*` in the
/// leading label (e.g. `*.sample.test`). Reject anything fancier so we fail
/// with a clear message before opening a QUIC connection.
fn validate_share_local_host(local_host: &str) -> anyhow::Result<()> {
    let stars = local_host.matches('*').count();
    if stars == 0 {
        return Ok(());
    }
    if stars > 1 {
        anyhow::bail!(
            "--local-host supports at most one '*' (got {stars}): {local_host}\n\
             example: `relay share '*.sample.test'`"
        );
    }
    // Exactly one star: must be the full leading label (`*.…`), nothing else.
    if !local_host.starts_with("*.") {
        anyhow::bail!(
            "wildcard '*' must be the leading label, not a partial one: {local_host}\n\
             example: `relay share '*.sample.test'`"
        );
    }
    Ok(())
}

fn warn_on_share_wildcard_mismatch(local_host: &str, hostname: Option<&str>, domain: Option<&str>) {
    if !local_host.contains('*') {
        return;
    }
    let public_is_wild =
        hostname.is_some_and(|h| h.contains('*')) || domain.is_some_and(|d| d.contains('*'));
    if !public_is_wild {
        eprintln!(
            "note: local host `{local_host}` is wildcarded but the public tunnel isn't —\n\
             every request will substitute the same leading label. Register a wildcard\n\
             public tunnel (e.g. `--hostname '*.acme' --domain sharedwithrelay.com`) to\n\
             route per-subdomain."
        );
    }
}
