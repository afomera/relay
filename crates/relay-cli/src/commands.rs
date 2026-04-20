//! Command handlers.

use relay_cli::config::Config;

pub struct RuntimeCtx {
    pub server: String,
    pub token: String,
    pub insecure: bool,
    pub cafile: Option<String>,
}

pub mod auth {
    use super::*;
    use crate::{AuthCmd, DEFAULT_SERVER};
    use relay_cli::config;

    pub async fn run(cmd: AuthCmd, mut cfg: Config) -> anyhow::Result<()> {
        match cmd {
            AuthCmd::Login { token: Some(tok), server, no_browser: _ } => {
                save_token(&mut cfg, tok, server)?;
            }
            AuthCmd::Login { token: None, server, no_browser } => {
                if let Some(s) = server.clone() {
                    cfg.server = Some(s);
                }
                let server_host = cfg.server.as_deref().unwrap_or(DEFAULT_SERVER).to_string();
                let dashboard = relay_cli::dashboard_url_from(&server_host);
                let tok =
                    crate::commands::auth_web::run_browser_flow(&dashboard, no_browser).await?;
                save_token(&mut cfg, tok, server)?;
            }
            AuthCmd::Logout => {
                cfg.token = None;
                // Keep `server` on disk — it's not a secret and most users
                // re-login against the same server.
                config::save(&cfg)?;
                println!("token removed");
            }
            AuthCmd::Status => {
                let server = cfg.server.as_deref().unwrap_or(DEFAULT_SERVER);
                let source =
                    if cfg.server.is_some() { "from config" } else { "compiled-in default" };
                if cfg.token.is_some() {
                    println!("logged in");
                    println!("server: {server} ({source})");
                } else {
                    println!("no token configured");
                    println!("server: {server} ({source})");
                }
            }
        }
        Ok(())
    }

    fn save_token(cfg: &mut Config, token: String, server: Option<String>) -> anyhow::Result<()> {
        cfg.token = Some(token);
        if let Some(s) = server {
            cfg.server = Some(s);
        }
        config::save(cfg)?;
        let path = config::path()?;
        let active_server = cfg.server.as_deref().unwrap_or(DEFAULT_SERVER);
        println!("saved token to {}", path.display());
        println!("server: {active_server}");
        Ok(())
    }
}

pub mod auth_web {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use anyhow::Context;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, oneshot};

    type CallbackTx = Arc<Mutex<Option<oneshot::Sender<Result<String, String>>>>>;

    // Shared <head> for both SUCCESS/ERROR pages. `color-scheme: light dark`
    // swaps UA chrome (scrollbars/selection), the media query swaps our own
    // palette. No JS; no flash on load.
    const PAGE_HEAD: &str = r#"<meta charset="utf-8"><meta name="color-scheme" content="light dark">
<style>:root{--fg:#222;--bg:#fff;--muted:#666}
@media (prefers-color-scheme: dark){:root{--fg:#e6e6e6;--bg:#111;--muted:#888}}
html,body{background:var(--bg);color:var(--fg)}
body{font-family:system-ui;max-width:32rem;margin:5rem auto;padding:0 1rem}
h1{font-size:1.4rem}
.sub{color:var(--muted)}</style>"#;

    fn page(title: &str, heading: &str, body: &str) -> String {
        format!(
            "<!doctype html><html><head><title>{title}</title>{PAGE_HEAD}</head>\
             <body><h1>{heading}</h1><p class=\"sub\">{body}</p></body></html>"
        )
    }

    /// Run the browser-based PAT handshake end-to-end. Returns the new token.
    ///
    /// Flow: bind a loopback TCP listener, open the browser to
    /// `<dashboard>/cli/authorize?callback=http://127.0.0.1:PORT/cb&state=RAND`,
    /// wait for the dashboard to hit the callback, verify the state, capture
    /// the token. 5-minute overall timeout.
    pub async fn run_browser_flow(dashboard: &str, no_browser: bool) -> anyhow::Result<String> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .context("bind loopback listener")?;
        let port = listener.local_addr()?.port();
        let state_nonce = random_state();

        let (tx, rx) = oneshot::channel::<Result<String, String>>();
        let tx = Arc::new(Mutex::new(Some(tx)));
        let expected_state = state_nonce.clone();

        let server_task = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let tx = tx.clone();
                let expected = expected_state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(tcp);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let tx = tx.clone();
                        let expected = expected.clone();
                        async move { handle_callback(req, expected, tx).await }
                    });
                    let _ =
                        hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        let url = format!(
            "{dashboard}/cli/authorize?callback=http%3A%2F%2F127.0.0.1%3A{port}%2Fcb&state={state}",
            state = state_nonce,
        );
        if no_browser {
            println!("open this URL to sign in: {url}");
        } else {
            println!("opening {dashboard} in your browser — approve the CLI to finish sign-in");
            if let Err(e) = webbrowser::open(&url) {
                println!("couldn't auto-open a browser ({e}); open this URL manually:\n  {url}");
            }
        }

        let timeout = tokio::time::Duration::from_secs(300);
        let token = tokio::time::timeout(timeout, rx)
            .await
            .context("timed out waiting for browser callback (5 min)")?
            .context("callback listener dropped")?
            .map_err(anyhow::Error::msg)?;
        server_task.abort();
        Ok(token)
    }

    async fn handle_callback(
        req: Request<Incoming>,
        expected_state: String,
        tx: CallbackTx,
    ) -> Result<Response<String>, std::convert::Infallible> {
        let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        if !path_and_query.starts_with("/cb") {
            return Ok(not_found());
        }
        let query = req.uri().query().unwrap_or_default();
        let mut token = None;
        let mut got_state = None;
        let mut error = None;
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            match k.as_ref() {
                "token" => token = Some(v.into_owned()),
                "state" => got_state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }
        let state_ok = got_state.as_deref() == Some(expected_state.as_str());
        let result: Result<String, String> = if !state_ok {
            Err("state mismatch".to_string())
        } else {
            match (token, error.as_deref()) {
                (Some(t), _) => Ok(t),
                (None, Some("cancelled")) => Err("cancelled in browser".to_string()),
                (None, Some(e)) => Err(format!("auth error: {e}")),
                _ => Err("callback missing token or state".to_string()),
            }
        };
        let mut slot = tx.lock().await;
        if let Some(tx) = slot.take() {
            let _ = tx.send(result.clone());
        }
        let (status, body) = match &result {
            Ok(_) => (
                StatusCode::OK,
                page(
                    "authorized",
                    "authorized ✓",
                    "Token delivered to the CLI — you can close this tab.",
                ),
            ),
            Err(msg) if msg == "cancelled in browser" => (
                StatusCode::OK,
                page(
                    "cancelled",
                    "cancelled",
                    "The CLI is no longer waiting — you can close this tab.",
                ),
            ),
            Err(_) => (
                StatusCode::BAD_REQUEST,
                page(
                    "auth error",
                    "authorization failed",
                    "The CLI didn't accept the callback. Close this tab and retry.",
                ),
            ),
        };
        Ok(Response::builder()
            .status(status)
            .header("content-type", "text/html; charset=utf-8")
            .body(body)
            .expect("static response"))
    }

    fn not_found() -> Response<String> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("not found".to_string())
            .expect("static response")
    }

    fn random_state() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..32).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
    }
}

pub mod http {
    use std::sync::Arc;
    use std::time::Duration;

    use relay_proto::{ClientMsg, PROTOCOL_VERSION, RegisterTunnel, ServerMsg, TunnelKind};
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::UnboundedSender;
    use uuid::Uuid;

    use super::RuntimeCtx;
    use relay_cli::client::LocalTarget;
    use relay_cli::ui::{self, ReqEvent};
    use relay_cli::{client, tls};

    /// Outcome of a single connect-register-run cycle.
    enum Outcome {
        /// Server hard-rejected (bad auth, hostname not allowed, etc). Don't retry.
        Fatal(anyhow::Error),
        /// Connection dropped — retry with backoff.
        Disconnected,
        /// User pressed Ctrl-C — exit cleanly.
        CtrlC,
    }

    pub async fn run(
        ctx: RuntimeCtx,
        target: LocalTarget,
        hostname: Option<String>,
        domain: Option<String>,
        inspect: bool,
        reconnect: bool,
        password: Option<String>,
    ) -> anyhow::Result<()> {
        // Fail fast with a useful message before we burn cycles on a QUIC
        // handshake that would just be rejected by the server anyway.
        if ctx.token.is_empty() {
            anyhow::bail!("not signed in — run `relay auth login` (or pass --token)");
        }
        // Combine the two flags so `--hostname andrea --domain mycompany.com`
        // registers as `andrea.mycompany.com`. Historically `--domain`
        // silently shadowed `--hostname`; the new behavior matches the way
        // `sharedwithrelay.com` (and most tunnel services) treat a base
        // domain + sub-label. The server still validates that the resulting
        // FQDN is authorized for the org (apex, wildcard subdomain, or
        // reservation) and rejects unknown combinations.
        let mut desired = match (hostname, domain) {
            (Some(h), Some(d)) => Some(format!("{h}.{d}")),
            (None, Some(d)) => Some(d),
            (Some(h), None) => Some(h),
            (None, None) => None,
        };
        let mut backoff = Duration::from_millis(500);

        // One printer task for the whole CLI lifetime — reconnects reuse it so
        // streaming rows continue past a session drop.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ReqEvent>();
        ui::spawn_request_printer(rx);

        loop {
            match session(
                &ctx,
                target.clone(),
                desired.clone(),
                inspect,
                password.clone(),
                tx.clone(),
            )
            .await
            {
                Ok((Outcome::Fatal(e), _)) => return Err(e),
                Ok((Outcome::CtrlC, _)) => return Ok(()),
                Ok((Outcome::Disconnected, assigned)) => {
                    if !reconnect {
                        eprintln!("connection lost; --no-reconnect set, exiting");
                        return Ok(());
                    }
                    // Pin to whatever hostname the server gave us so reconnect
                    // restores the same URL (relevant for temporarys — explicit
                    // hostnames are already pinned).
                    if desired.is_none() {
                        desired = assigned;
                    }
                    eprintln!("connection lost; reconnecting in {}s…", backoff.as_secs().max(1));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
                Err(e) => {
                    if !reconnect {
                        return Err(e);
                    }
                    eprintln!("connect failed: {e}; retrying in {}s…", backoff.as_secs().max(1));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    async fn session(
        ctx: &RuntimeCtx,
        target: LocalTarget,
        desired: Option<String>,
        inspect: bool,
        password: Option<String>,
        events: UnboundedSender<ReqEvent>,
    ) -> anyhow::Result<(Outcome, Option<String>)> {
        let server_name = ctx.server.split(':').next().unwrap_or("localhost").to_string();

        let server_addr = ctx.server.to_socket_addrs_first()?;
        let client_cfg = tls::build_client_config(ctx.insecure, ctx.cafile.as_deref())?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*client_cfg).clone())?;
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(quic_client));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        quic_cfg.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<std::net::SocketAddr>()?)?;
        endpoint.set_default_client_config(quic_cfg);

        let conn = endpoint.connect(server_addr, &server_name)?.await?;
        tracing::info!(server = %server_addr, "connected to relay server");

        let (mut send, mut recv) = conn.open_bi().await?;

        relay_proto::write_frame(
            &mut send,
            &ClientMsg::Hello(relay_proto::ClientHello {
                protocol_version: PROTOCOL_VERSION,
                auth_token: ctx.token.clone(),
                client_version: env!("CARGO_PKG_VERSION").into(),
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
            }),
        )
        .await?;
        match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await? {
            ServerMsg::Hello(h) => {
                tracing::debug!(account = ?h.account_id, features = ?h.features, "server hello");
            }
            ServerMsg::Rejected(r) => {
                return Ok((Outcome::Fatal(anyhow::anyhow!("rejected: {}", r.reason)), None));
            }
            other => {
                return Ok((
                    Outcome::Fatal(anyhow::anyhow!("unexpected server reply {other:?}")),
                    None,
                ));
            }
        }

        let req_id = Uuid::new_v4();
        relay_proto::write_frame(
            &mut send,
            &ClientMsg::Register(RegisterTunnel {
                req_id,
                kind: TunnelKind::Http,
                hostname: desired.clone(),
                labels: vec![],
                inspect,
                password: password.clone(),
            }),
        )
        .await?;
        let public_url = match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await? {
            ServerMsg::Registered(r) if r.req_id == req_id => r.public_url,
            ServerMsg::Rejected(r) if r.req_id == req_id => {
                // Hostname conflicts on reconnect can be transient (the prior
                // session is still being torn down). For explicit hostnames the
                // user set, retry; for temporarys, treat as fatal because
                // re-rolling silently would surprise the user.
                let msg = format!("tunnel rejected: {}", r.reason);
                return if desired.is_some() {
                    Ok((Outcome::Disconnected, desired))
                } else {
                    Ok((Outcome::Fatal(anyhow::anyhow!(msg)), None))
                };
            }
            other => {
                return Ok((
                    Outcome::Fatal(anyhow::anyhow!("unexpected reply during register: {other:?}")),
                    None,
                ));
            }
        };

        let assigned_hostname = strip_url(&public_url);

        let dashboard = relay_cli::dashboard_url_from(&ctx.server);
        let local_display = match &target.host_header {
            Some(h) => format!("http://{h} (via 127.0.0.1:{})", target.port),
            None => format!("http://127.0.0.1:{}", target.port),
        };
        ui::print_http_banner(&dashboard, &public_url, &local_display, inspect, password.is_some());

        let send = Arc::new(Mutex::new(send));
        let send_for_pump = send.clone();
        tokio::spawn(async move {
            loop {
                match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await {
                    Ok(ServerMsg::Ping { seq }) => {
                        let mut s = send_for_pump.lock().await;
                        if relay_proto::write_frame(&mut *s, &ClientMsg::Pong { seq })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let proxy_conn = conn.clone();
        let outcome = tokio::select! {
            _ = client::accept_and_proxy(proxy_conn, target.clone(), Some(events)) => Outcome::Disconnected,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nshutting down…");
                conn.close(0u32.into(), b"cli ctrl-c");
                endpoint.wait_idle().await;
                Outcome::CtrlC
            }
            // Surface the underlying close reason if the connection drops out
            // from under accept_and_proxy (e.g. server-initiated close).
            _ = wait_closed(&conn) => Outcome::Disconnected,
        };
        Ok((outcome, Some(assigned_hostname)))
    }

    async fn wait_closed(conn: &quinn::Connection) {
        let _ = conn.closed().await;
    }

    fn strip_url(url: &str) -> String {
        url.trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or(url)
            .to_string()
    }

    /// Resolve `host:port` and pick the first IPv4 address (we bind a v4 QUIC
    /// endpoint locally, so a v6-first resolution like macOS's `[::1]` would
    /// otherwise fail with "invalid remote address").
    pub(super) trait FirstAddr {
        fn to_socket_addrs_first(&self) -> anyhow::Result<std::net::SocketAddr>;
    }
    impl FirstAddr for String {
        fn to_socket_addrs_first(&self) -> anyhow::Result<std::net::SocketAddr> {
            use std::net::ToSocketAddrs;
            let addrs: Vec<_> = self.as_str().to_socket_addrs()?.collect();
            addrs
                .iter()
                .find(|a| a.is_ipv4())
                .copied()
                .or_else(|| addrs.first().copied())
                .ok_or_else(|| anyhow::anyhow!("could not resolve {self}"))
        }
    }
}

pub mod tcp {
    use std::sync::Arc;

    use relay_proto::{ClientMsg, PROTOCOL_VERSION, RegisterTunnel, ServerMsg, TunnelKind};
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::RuntimeCtx;
    use super::http::FirstAddr;
    use relay_cli::client::LocalTarget;
    use relay_cli::{client, tls, ui};

    pub async fn run(ctx: RuntimeCtx, port: u16) -> anyhow::Result<()> {
        if ctx.token.is_empty() {
            anyhow::bail!("not signed in — run `relay auth login` (or pass --token)");
        }
        let server_name = ctx.server.split(':').next().unwrap_or("localhost").to_string();
        let server_addr = ctx.server.to_socket_addrs_first()?;
        let client_cfg = tls::build_client_config(ctx.insecure, ctx.cafile.as_deref())?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*client_cfg).clone())?;
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(quic_client));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        quic_cfg.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<std::net::SocketAddr>()?)?;
        endpoint.set_default_client_config(quic_cfg);
        let conn = endpoint.connect(server_addr, &server_name)?.await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        relay_proto::write_frame(
            &mut send,
            &ClientMsg::Hello(relay_proto::ClientHello {
                protocol_version: PROTOCOL_VERSION,
                auth_token: ctx.token.clone(),
                client_version: env!("CARGO_PKG_VERSION").into(),
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
            }),
        )
        .await?;
        match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await? {
            ServerMsg::Hello(_) => {}
            ServerMsg::Rejected(r) => anyhow::bail!("rejected: {}", r.reason),
            other => anyhow::bail!("unexpected server reply {other:?}"),
        }

        let req_id = Uuid::new_v4();
        relay_proto::write_frame(
            &mut send,
            &ClientMsg::Register(RegisterTunnel {
                req_id,
                kind: TunnelKind::Tcp,
                hostname: None,
                labels: vec![],
                inspect: false,
                password: None,
            }),
        )
        .await?;
        let public_url = match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await? {
            ServerMsg::Registered(r) => r.public_url,
            ServerMsg::Rejected(r) => anyhow::bail!("tunnel rejected: {}", r.reason),
            other => anyhow::bail!("unexpected reply {other:?}"),
        };

        let dashboard = relay_cli::dashboard_url_from(&ctx.server);
        ui::print_tcp_banner(&dashboard, &public_url, port);

        let send = Arc::new(Mutex::new(send));
        let send_for_pump = send.clone();
        tokio::spawn(async move {
            loop {
                match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await {
                    Ok(ServerMsg::Ping { seq }) => {
                        let mut s = send_for_pump.lock().await;
                        if relay_proto::write_frame(&mut *s, &ClientMsg::Pong { seq })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let proxy_conn = conn.clone();
        tokio::select! {
            res = client::accept_and_proxy(proxy_conn, LocalTarget::port(port), None) => res,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nshutting down…");
                conn.close(0u32.into(), b"cli ctrl-c");
                endpoint.wait_idle().await;
                Ok(())
            }
        }
    }
}
