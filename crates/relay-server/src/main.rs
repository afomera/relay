//! `relayd` — the relay server binary.
//!
//! Two boot modes:
//!   * `--dev`: zero-config local run with in-memory SQLite, allow-all auth,
//!     no control plane. Useful for `cargo run` and integration tests.
//!   * `--config <path>`: load a TOML config, run DB migrations, start the
//!     control plane and the edge with DB-backed auth + reservations.

use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use clap::Parser;
use rand::RngCore;
use relay_acme::{
    CertResolver, CertStore, DbCertStore, Http01Pending, RenewalWorker, issue::IssueOptions,
};
use relay_control::config::GithubOauthConfig;
use relay_control::{
    AppState, CertIssuerCtx, ControlConfig, DbAuthProvider, DbCaptureSink, DbReservationStore,
    DbTunnelRecorder, EventBus,
};
use relay_db::Db;
use relay_dns::DnsProvider;
use relay_dns::cloudflare::CloudflareProvider;
use relay_edge::{EdgeConfig, generate_dev_cert, start as start_edge};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "relayd", version, about = "The relay tunneling server.")]
struct Args {
    /// Path to TOML config (ignored when --dev is set).
    #[arg(long, env = "RELAYD_CONFIG")]
    config: Option<String>,

    /// Run in development mode: self-signed certs, allow-all auth, no dashboard.
    #[arg(long)]
    dev: bool,

    /// Base domain override (dev only). Default uses `.localhost` because
    /// browsers resolve `*.localhost` to loopback automatically and it doesn't
    /// collide with tools like puma-dev that grab `.test`.
    #[arg(long, default_value = "relay.localhost")]
    base_domain: String,

    /// QUIC listener (dev only).
    #[arg(long, default_value = "127.0.0.1:7443")]
    bind_quic: SocketAddr,

    /// HTTP ingress listener (dev only).
    #[arg(long, default_value = "127.0.0.1:7080")]
    bind_http: SocketAddr,

    /// Dashboard / control-plane bind (dev only).
    #[arg(long, default_value = "127.0.0.1:7090")]
    bind_admin: SocketAddr,

    /// SQLite path for dev mode.
    #[arg(long, default_value = "./relay-dev.db")]
    dev_db: String,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    server: ServerSection,
    domains: DomainsSection,
    db: DbSection,
    #[serde(default)]
    github_oauth: Option<GithubSection>,
    security: SecuritySection,
    #[serde(default)]
    dns: Option<DnsSection>,
    #[serde(default)]
    acme: Option<AcmeSection>,
}

#[derive(Debug, Deserialize)]
struct AcmeSection {
    /// Default: Let's Encrypt staging. Flip to the prod URL once verified.
    #[serde(default = "default_acme_directory")]
    directory: String,
    contact_email: String,
    /// Zone Relay controls for ACME DNS-01 delegation, e.g.
    /// `acme-delegate.withrelay.dev`. The configured [dns] provider must
    /// have write scope on this zone. When unset, users can still add
    /// apex-only (HTTP-01) custom domains, but wildcard custom domains are
    /// disabled in the dashboard.
    #[serde(default)]
    delegation_zone: Option<String>,
}
fn default_acme_directory() -> String {
    "https://acme-staging-v02.api.letsencrypt.org/directory".into()
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    bind_http: SocketAddr,
    bind_https: Option<SocketAddr>,
    bind_quic: SocketAddr,
    bind_admin: SocketAddr,
    public_url: String,
    #[serde(default = "default_scheme")]
    tunnel_scheme: String,
    /// If set, the edge serves the dashboard on this hostname via the same
    /// :80/:443 listeners (instead of only on the loopback `bind_admin`).
    /// Certificate for it is issued on boot via ACME HTTP-01.
    #[serde(default)]
    admin_hostname: Option<String>,
}
fn default_scheme() -> String {
    "https".into()
}

#[derive(Debug, Deserialize)]
struct DomainsSection {
    base: String,
    #[serde(default)]
    temporary: Option<String>,
    /// Marketing site shown when a visitor hits the apex of `base` with no
    /// subdomain. Optional — leave unset for self-hosted deploys that don't
    /// have a separate marketing domain.
    #[serde(default)]
    marketing_url: Option<String>,
}

/// `[db]` config. Exactly one of `url` / `url_env` must be set; the latter
/// matches the pattern used for `data_key_env`, `client_secret_env` et al and
/// is the ergonomic choice for managed-Postgres deploys that expose a
/// `DATABASE_URL`-style env var.
#[derive(Debug, Deserialize)]
struct DbSection {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    url_env: Option<String>,
    /// Optional pool-size override. Defaults: SQLite = 10, Postgres = 20.
    #[serde(default)]
    max_connections: Option<u32>,
    /// Optional per-acquire timeout in seconds. Default: 5s.
    #[serde(default)]
    acquire_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GithubSection {
    client_id: String,
    client_secret_env: String,
    /// Optional GitHub org allowlist. When set, sign-in is restricted to
    /// users who are members of at least one of these orgs (case-insensitive).
    /// Self-hosters lock the dashboard to their company's org by adding
    /// `allowed_orgs = ["mycompany"]`.
    #[serde(default)]
    allowed_orgs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SecuritySection {
    data_key_env: String,
}

#[derive(Debug, Deserialize)]
struct DnsSection {
    provider: String,
    #[serde(default)]
    cloudflare: Option<CloudflareSection>,
}

#[derive(Debug, Deserialize)]
struct CloudflareSection {
    api_token_env: String,
    zone_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    if args.dev {
        run_dev(args).await
    } else {
        let cfg_path =
            args.config.ok_or_else(|| anyhow::anyhow!("--config PATH or --dev is required"))?;
        run_from_config(&cfg_path).await
    }
}

async fn run_dev(args: Args) -> anyhow::Result<()> {
    let temporary = format!("temporary.{}", args.base_domain);
    let sans =
        vec![args.base_domain.clone(), format!("*.{}", args.base_domain), format!("*.{temporary}")];
    let (cert, key) = generate_dev_cert(&sans)?;

    // Open SQLite, run migrations.
    let db_url = if args.dev_db.contains("://") {
        args.dev_db.clone()
    } else {
        format!("sqlite://{}", args.dev_db)
    };
    let db = Db::connect_url(&db_url).await?;
    db.migrate().await?;
    let stale = relay_db::mark_all_tunnels_disconnected(&db).await?;
    tracing::info!(url = %redact_db_url(&db_url), stale_swept = stale, "dev database ready");

    // Random data key per process — fine for dev because we re-encrypt nothing
    // important across restarts (no real certs in dev).
    let data_key_b64 = random_data_key_b64();

    let control_cfg = ControlConfig {
        bind_admin: args.bind_admin,
        base_domain: args.base_domain.clone(),
        public_url: format!("http://{}", args.bind_admin),
        tunnel_scheme: "http".into(),
        tunnel_public_port: Some(args.bind_http.port()),
        github: None,
        data_key_b64,
        dev_mode: true,
        acme_delegation_zone: None,
    };
    let events = EventBus::new();
    let http01 = Arc::new(Http01Pending::new());
    let control_state = AppState::new(control_cfg, db.clone(), events.clone(), None);
    let control_task = tokio::spawn(async move {
        let bind = control_state.config.bind_admin;
        let app = relay_control::build_router(control_state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(addr = %bind, "dev dashboard at http://{bind}");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    });

    // Edge wired to the same DB so dashboard sees real tunnels + tokens.
    let bind_http = args.bind_http;
    let auth = Arc::new(DbAuthProvider { db: db.clone() });
    let reservations = Arc::new(DbReservationStore {
        db: db.clone(),
        base_domain: args.base_domain.clone(),
        temporary_label: "temporary".into(),
    });
    let recorder = Arc::new(DbTunnelRecorder { db: db.clone(), events: events.clone() });
    let capture = Arc::new(DbCaptureSink { db: db.clone(), events: events.clone() });
    let edge_cfg = EdgeConfig {
        bind_quic: args.bind_quic,
        bind_http,
        bind_https: None,
        base_domain: args.base_domain.clone(),
        temporary_domain: temporary,
        marketing_url: None,
        public_url_scheme: "http".into(),
        public_port: Some(bind_http.port()),
        tls_cert: cert,
        tls_key: key,
        tls_resolver: None,
        auth,
        reservations,
        recorder,
        capture,
        http01,
        admin_hostname: None,
        admin_router: None,
        tcp_port_range: 29000..=29999,
        cookie_key: axum_extra::extract::cookie::Key::generate(),
    };
    let edge_task = tokio::spawn(async move { start_edge(edge_cfg).await });

    eprintln!();
    eprintln!("─────────────────────────────────────────────");
    eprintln!("  relayd dev mode");
    eprintln!("  dashboard:  http://{}", args.bind_admin);
    eprintln!("  http:       http://{}", args.bind_http);
    eprintln!("  quic:       udp://{}", args.bind_quic);
    eprintln!("  base:       {}", args.base_domain);
    eprintln!("─────────────────────────────────────────────");
    eprintln!();

    tokio::select! {
        res = control_task => { res??; }
        res = edge_task    => { res??; }
    }
    Ok(())
}

async fn run_from_config(path: &str) -> anyhow::Result<()> {
    let file = fs::read_to_string(path)?;
    let cfg: FileConfig = toml::from_str(&file)?;

    let data_key = std::env::var(&cfg.security.data_key_env).map_err(|_| {
        anyhow::anyhow!("RELAY_DATA_KEY env var `{}` not set", cfg.security.data_key_env)
    })?;

    // Validate the data key decodes to at least 32 bytes; fail fast with a
    // clear message rather than later inside AppState::new.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&data_key)
        .map_err(|e| anyhow::anyhow!("{} is not base64: {e}", cfg.security.data_key_env))?;
    if decoded.len() < 32 {
        anyhow::bail!(
            "{} must decode to >= 32 bytes (got {})",
            cfg.security.data_key_env,
            decoded.len()
        );
    }

    let db_url = resolve_db_url(&cfg.db)?;
    let db_opts = relay_db::DbOpenOpts {
        url: &db_url,
        max_connections: cfg.db.max_connections,
        acquire_timeout: cfg.db.acquire_timeout_secs.map(std::time::Duration::from_secs),
    };
    let db = Db::connect(&db_opts).await?;
    db.migrate().await?;
    let stale = relay_db::mark_all_tunnels_disconnected(&db).await?;
    tracing::info!(url = %redact_db_url(&db_url), stale_swept = stale, "db ready");

    // ---- Control plane ----
    let github = match cfg.github_oauth {
        Some(g) => {
            let secret = std::env::var(&g.client_secret_env).map_err(|_| {
                anyhow::anyhow!("github oauth client_secret env `{}` not set", g.client_secret_env)
            })?;
            let mut cfg_oauth = GithubOauthConfig::new(g.client_id, secret);
            cfg_oauth.allowed_orgs = g.allowed_orgs;
            if !cfg_oauth.allowed_orgs.is_empty() {
                tracing::info!(
                    orgs = ?cfg_oauth.allowed_orgs,
                    "github oauth: restricting sign-in to allowed orgs"
                );
            }
            Some(cfg_oauth)
        }
        None => None,
    };
    let temporary =
        cfg.domains.temporary.unwrap_or_else(|| format!("temporary.{}", cfg.domains.base));
    let control_cfg = ControlConfig {
        bind_admin: cfg.server.bind_admin,
        base_domain: cfg.domains.base.clone(),
        public_url: cfg.server.public_url.clone(),
        tunnel_scheme: cfg.server.tunnel_scheme.clone(),
        tunnel_public_port: None,
        github,
        data_key_b64: data_key.clone(),
        dev_mode: false,
        acme_delegation_zone: cfg.acme.as_ref().and_then(|a| a.delegation_zone.clone()),
    };

    // Shared ACME HTTP-01 pending store — edge serves challenges from here,
    // the cert issuer populates it during issuance.
    let events = EventBus::new();
    let http01 = Arc::new(Http01Pending::new());

    // ---- TLS: cert store, resolver, ACME renewal ----
    // The self-signed cert below is the *fallback* the resolver uses until the
    // ACME-issued wildcard lands in the store. Browsers will get a cert warning
    // during the ~30-second first-issue window; after that the real cert wins.
    let sans =
        vec![cfg.domains.base.clone(), format!("*.{}", cfg.domains.base), format!("*.{temporary}")];
    let (cert, key) = generate_dev_cert(&sans)?;

    let data_key_bytes = relay_acme::encrypt::decode_data_key(&data_key)
        .map_err(|e| anyhow::anyhow!("decode data key: {e}"))?;
    let cert_store = Arc::new(DbCertStore::new(db.clone(), data_key_bytes));
    if let Err(e) = cert_store.refresh().await {
        tracing::warn!(?e, "initial cert-store refresh failed");
    }

    let fallback = {
        let provider = rustls::crypto::ring::default_provider();
        let signing = provider
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|e| anyhow::anyhow!("load fallback key: {e}"))?;
        Arc::new(rustls::sign::CertifiedKey::new(vec![cert.clone()], signing))
    };
    let tls_resolver: Option<Arc<dyn rustls::server::ResolvesServerCert>> =
        Some(Arc::new(CertResolver { store: cert_store.clone(), fallback }));

    // Build the DNS provider once and share it between the cert issuer (for
    // wildcard custom-domain DNS-01) and the renewal worker (for the base
    // apex wildcard + any wildcard custom domains).
    let dns_provider = build_dns_provider(cfg.dns.as_ref())?;

    // Build the cert issuer for custom domains. Needs the ACME
    // directory + contact from `[acme]`; absent that, dashboard verify marks
    // domains verified but doesn't issue certs. The optional DNS provider +
    // delegation_zone gate wildcard custom-domain issuance.
    let cert_issuer = cfg.acme.as_ref().map(|acme_cfg| {
        Arc::new(CertIssuerCtx {
            db: db.clone(),
            http01: http01.clone(),
            store: cert_store.clone(),
            acme_directory: acme_cfg.directory.clone(),
            contact_email: acme_cfg.contact_email.clone(),
            data_key_b64: data_key.clone(),
            dns: dns_provider.clone(),
            delegation_zone: acme_cfg.delegation_zone.clone(),
        })
    });

    // Spawn control plane now that we have the cert issuer.
    let control_state = AppState::new(control_cfg, db.clone(), events.clone(), cert_issuer.clone());
    let admin_router = relay_control::build_router(control_state.clone());
    let control_task = tokio::spawn(async move {
        let bind = control_state.config.bind_admin;
        let app = relay_control::build_router(control_state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(addr = %bind, "control plane listening on loopback");
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    });

    // If admin_hostname is configured, kick off an HTTP-01 cert for it so
    // browsers reach the dashboard over a trusted cert on :443.
    if let (Some(host), Some(issuer)) = (cfg.server.admin_hostname.as_ref(), cert_issuer.as_ref()) {
        let host = host.clone();
        let issuer = issuer.clone();
        tokio::spawn(async move {
            if let Err(e) = issuer.ensure_cert(&host, None).await {
                tracing::warn!(%host, ?e, "admin hostname cert issuance failed");
            }
        });
    }

    if let Some(acme_cfg) = cfg.acme.as_ref() {
        if let Some(dns) = dns_provider.clone() {
            let opts = IssueOptions {
                acme_directory: acme_cfg.directory.clone(),
                contact_email: acme_cfg.contact_email.clone(),
                base_domain: cfg.domains.base.clone(),
                temporary_label: temporary
                    .strip_suffix(&format!(".{}", cfg.domains.base))
                    .map(|s| s.to_string()),
            };
            let worker = RenewalWorker {
                db: db.clone(),
                dns,
                opts,
                data_key_b64: data_key.clone(),
                store: cert_store.clone(),
                delegation_zone: acme_cfg.delegation_zone.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = worker.run().await {
                    tracing::error!(?e, "renewal worker exited");
                }
            });
        } else {
            tracing::warn!("[acme] configured but no [dns] provider — no wildcard will be issued");
        }
    } else {
        tracing::info!("[acme] not configured — HTTPS will use the self-signed fallback");
    }
    let auth = Arc::new(DbAuthProvider { db: db.clone() });
    let reservations = Arc::new(DbReservationStore {
        db: db.clone(),
        base_domain: cfg.domains.base.clone(),
        temporary_label: temporary
            .strip_suffix(&format!(".{}", cfg.domains.base))
            .unwrap_or("temporary")
            .to_string(),
    });
    let edge_cfg = EdgeConfig {
        bind_quic: cfg.server.bind_quic,
        bind_http: cfg.server.bind_http,
        bind_https: cfg.server.bind_https,
        base_domain: cfg.domains.base,
        temporary_domain: temporary,
        marketing_url: cfg.domains.marketing_url,
        public_url_scheme: cfg.server.tunnel_scheme.clone(),
        public_port: None,
        tls_cert: cert.clone(),
        tls_key: key.clone_key(),
        tls_resolver: tls_resolver.clone(),
        auth,
        reservations,
        recorder: Arc::new(DbTunnelRecorder { db: db.clone(), events: events.clone() }),
        capture: Arc::new(DbCaptureSink { db: db.clone(), events }),
        http01,
        admin_hostname: cfg.server.admin_hostname.clone(),
        admin_router: Some(admin_router),
        tcp_port_range: 29000..=29999,
        cookie_key: axum_extra::extract::cookie::Key::generate(),
    };

    let edge_task = tokio::spawn(async move { start_edge(edge_cfg).await });

    tokio::select! {
        res = control_task => {
            tracing::error!(?res, "control plane task exited");
            res??;
        }
        res = edge_task => {
            tracing::error!(?res, "edge task exited");
            res??;
        }
    }
    Ok(())
}

fn random_data_key_b64() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Strip the password out of a DB URL before it's written to logs. Keeps the
/// scheme, user, host, path, and query params intact so the log line remains
/// useful for debugging; only the `:password` in the userinfo and any
/// `password=` query param get replaced with `***`.
///
/// `postgres://u:secret@host/db?sslmode=require`
///   → `postgres://u:***@host/db?sslmode=require`
/// `sqlite:///var/lib/relay/relay.db` — passed through unchanged.
fn redact_db_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len());

    // Split on the first `?` so the userinfo redaction doesn't touch the query.
    let (base, query) = match url.find('?') {
        Some(i) => (&url[..i], Some(&url[i + 1..])),
        None => (url, None),
    };

    // Userinfo: between `://` and the first `@` in the base.
    if let Some(scheme_end) = base.find("://") {
        let rest_start = scheme_end + 3;
        if let Some(at_offset) = base[rest_start..].find('@') {
            let at = rest_start + at_offset;
            let userinfo = &base[rest_start..at];
            if let Some(colon_offset) = userinfo.find(':') {
                let pwd_start = rest_start + colon_offset + 1;
                out.push_str(&base[..pwd_start]);
                out.push_str("***");
                out.push_str(&base[at..]);
            } else {
                out.push_str(base);
            }
        } else {
            out.push_str(base);
        }
    } else {
        out.push_str(base);
    }

    // Query: rewrite any `password=…` param without touching the others. libpq
    // accepts this form, so managed-service URLs occasionally use it.
    if let Some(q) = query {
        out.push('?');
        let mut first = true;
        for pair in q.split('&') {
            if !first {
                out.push('&');
            }
            first = false;
            if let Some(eq) = pair.find('=') {
                let (k, _v) = (&pair[..eq], &pair[eq + 1..]);
                if k.eq_ignore_ascii_case("password") {
                    out.push_str(k);
                    out.push_str("=***");
                    continue;
                }
            }
            out.push_str(pair);
        }
    }

    out
}

/// `url_env` takes precedence when set — self-hosters on PaaS platforms
/// (PlanetScale, Neon, Fly, Railway) inject the URL via env rather than
/// committing it to `relayd.toml`. A literal `url` is the fallback.
fn resolve_db_url(db: &DbSection) -> anyhow::Result<String> {
    if let Some(env_name) = db.url_env.as_deref() {
        let raw = std::env::var(env_name).map_err(|_| {
            anyhow::anyhow!("db.url_env `{env_name}` is not set in the environment")
        })?;
        if raw.is_empty() {
            anyhow::bail!("db.url_env `{env_name}` is empty");
        }
        return Ok(raw);
    }
    if let Some(url) = db.url.as_deref() {
        if url.is_empty() {
            anyhow::bail!("db.url is empty — set `url` or `url_env` in the [db] section");
        }
        return Ok(url.to_string());
    }
    anyhow::bail!("[db] section needs either `url` or `url_env`");
}

fn build_dns_provider(dns: Option<&DnsSection>) -> anyhow::Result<Option<Arc<dyn DnsProvider>>> {
    let Some(dns) = dns else { return Ok(None) };
    match dns.provider.as_str() {
        "cloudflare" => {
            let cf = dns.cloudflare.as_ref().ok_or_else(|| {
                anyhow::anyhow!("[dns.cloudflare] section required when provider=cloudflare")
            })?;
            let token = std::env::var(&cf.api_token_env).map_err(|_| {
                anyhow::anyhow!("cloudflare api token env `{}` not set", cf.api_token_env)
            })?;
            Ok(Some(Arc::new(CloudflareProvider::new(token, cf.zone_id.clone()))))
        }
        "route53" | "rfc2136" => {
            tracing::warn!(provider = %dns.provider, "DNS provider stubbed — no cert issuance");
            Ok(None)
        }
        other => anyhow::bail!("unknown dns provider `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::redact_db_url;

    #[test]
    fn redacts_password_in_userinfo() {
        assert_eq!(
            redact_db_url("postgres://u:hunter2@h.example/db"),
            "postgres://u:***@h.example/db",
        );
        assert_eq!(
            redact_db_url("postgresql://u:hunter2@h.example:5432/db?sslmode=require"),
            "postgresql://u:***@h.example:5432/db?sslmode=require",
        );
    }

    #[test]
    fn leaves_url_without_password_alone() {
        assert_eq!(redact_db_url("postgres://u@h/db"), "postgres://u@h/db");
        assert_eq!(redact_db_url("postgres://h/db"), "postgres://h/db");
        assert_eq!(
            redact_db_url("sqlite:///var/lib/relay/relay.db"),
            "sqlite:///var/lib/relay/relay.db",
        );
        assert_eq!(redact_db_url("sqlite::memory:"), "sqlite::memory:");
    }

    #[test]
    fn redacts_password_in_query_param() {
        assert_eq!(
            redact_db_url("postgres://h/db?password=hunter2&sslmode=require"),
            "postgres://h/db?password=***&sslmode=require",
        );
        // Mixed: password in both userinfo and query. Both get masked.
        assert_eq!(
            redact_db_url("postgres://u:hunter2@h/db?password=other&x=1"),
            "postgres://u:***@h/db?password=***&x=1",
        );
    }

    #[test]
    fn preserves_other_query_params() {
        assert_eq!(
            redact_db_url("postgres://u:p@h/db?sslmode=verify-full&application_name=relay"),
            "postgres://u:***@h/db?sslmode=verify-full&application_name=relay",
        );
    }
}
