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
            AuthCmd::Login { token, server } => {
                cfg.token = Some(token);
                if let Some(s) = server {
                    cfg.server = Some(s);
                }
                config::save(&cfg)?;
                let path = config::path()?;
                let active_server = cfg.server.as_deref().unwrap_or(DEFAULT_SERVER);
                println!("saved token to {}", path.display());
                println!("server: {active_server}");
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
}

pub mod http {
    use std::sync::Arc;
    use std::time::Duration;

    use relay_proto::{ClientMsg, PROTOCOL_VERSION, RegisterTunnel, ServerMsg, TunnelKind};
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::RuntimeCtx;
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
        port: u16,
        hostname: Option<String>,
        domain: Option<String>,
        inspect: bool,
        reconnect: bool,
    ) -> anyhow::Result<()> {
        // --domain shadows --hostname when both set.
        let mut desired = domain.or(hostname);
        let mut backoff = Duration::from_millis(500);

        loop {
            match session(&ctx, port, desired.clone(), inspect).await {
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
        port: u16,
        desired: Option<String>,
        inspect: bool,
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

        println!("─────────────────────────────────────────────");
        println!("  relay tunnel established");
        println!("  → {public_url}  →  http://127.0.0.1:{port}");
        if inspect {
            println!("  inspection: on");
        }
        println!("─────────────────────────────────────────────");

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
            _ = client::accept_and_proxy(proxy_conn, port) => Outcome::Disconnected,
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
    use relay_cli::{client, tls};

    pub async fn run(ctx: RuntimeCtx, port: u16) -> anyhow::Result<()> {
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
            }),
        )
        .await?;
        let public_url = match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await? {
            ServerMsg::Registered(r) => r.public_url,
            ServerMsg::Rejected(r) => anyhow::bail!("tunnel rejected: {}", r.reason),
            other => anyhow::bail!("unexpected reply {other:?}"),
        };

        println!("─────────────────────────────────────────────");
        println!("  relay tcp tunnel established");
        println!("  → {public_url}  →  127.0.0.1:{port}");
        println!("─────────────────────────────────────────────");

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
            res = client::accept_and_proxy(proxy_conn, port) => res,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nshutting down…");
                conn.close(0u32.into(), b"cli ctrl-c");
                endpoint.wait_idle().await;
                Ok(())
            }
        }
    }
}
