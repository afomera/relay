//! QUIC listener + per-connection control-stream handler.

use std::sync::Arc;
use std::time::Duration;

use relay_proto::{
    ALPN, ClientMsg, Feature, PROTOCOL_VERSION, ServerHello, ServerMsg, TunnelKind,
    TunnelRegistered, TunnelRejected,
};
use uuid::Uuid;

use crate::auth::Principal;
use crate::config::EdgeConfig;
use crate::hostnames;
use crate::registry::{TunnelHandle, TunnelRegistry};
use crate::tcp::TcpPortPool;

pub async fn run(cfg: Arc<EdgeConfig>, reg: Arc<TunnelRegistry>) -> anyhow::Result<()> {
    let server_config = build_server_config(&cfg)?;
    let endpoint = quinn::Endpoint::server(server_config, cfg.bind_quic)?;
    let pool = Arc::new(TcpPortPool::new());
    tracing::info!(addr = %cfg.bind_quic, "edge QUIC listener bound");

    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        let reg = reg.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn, cfg, reg, pool).await {
                        tracing::warn!(?e, "quic connection ended with error");
                    }
                }
                Err(e) => tracing::warn!(?e, "failed to accept quic connection"),
            }
        });
    }
    Ok(())
}

fn build_server_config(cfg: &EdgeConfig) -> anyhow::Result<quinn::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cfg.tls_cert.clone()], cfg.tls_key.clone_key())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    sc.transport_config(Arc::new(transport));
    Ok(sc)
}

async fn handle_connection(
    conn: quinn::Connection,
    cfg: Arc<EdgeConfig>,
    reg: Arc<TunnelRegistry>,
    pool: Arc<TcpPortPool>,
) -> anyhow::Result<()> {
    tracing::info!(remote = %conn.remote_address(), "quic connection accepted");
    // The CLI opens the control stream first.
    let (mut send, mut recv) = conn.accept_bi().await?;

    // Hello handshake.
    let hello = match relay_proto::read_frame::<_, ClientMsg>(&mut recv).await? {
        ClientMsg::Hello(h) => h,
        other => anyhow::bail!("expected ClientHello, got {other:?}"),
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        anyhow::bail!("protocol version mismatch: client {}", hello.protocol_version);
    }
    let principal = cfg.auth.authenticate(&hello.auth_token).await?;
    relay_proto::write_frame(
        &mut send,
        &ServerMsg::Hello(ServerHello {
            protocol_version: PROTOCOL_VERSION,
            account_id: principal.org_id,
            features: vec![
                Feature::Inspection,
                Feature::TcpTunnels,
                Feature::TlsPassthrough,
                Feature::CustomDomains,
            ],
        }),
    )
    .await?;

    // Track hostnames registered on this connection for cleanup.
    let mut bound: Vec<String> = Vec::new();
    // Cancellation handles per TCP listener spawned for this connection.
    let mut tcp_listeners: Vec<(u16, tokio::sync::oneshot::Sender<()>)> = Vec::new();
    let result = control_loop(
        &conn,
        &mut send,
        &mut recv,
        &cfg,
        &reg,
        &principal,
        &mut bound,
        &pool,
        &mut tcp_listeners,
    )
    .await;

    for hostname in &bound {
        if let Some(h) = reg.lookup_exact(hostname) {
            let _ = cfg.recorder.record_disconnected(h.tunnel_id).await;
        }
        reg.remove(hostname);
    }
    for (port, cancel) in tcp_listeners.drain(..) {
        let _ = cancel.send(());
        pool.release(port);
    }
    tracing::info!(remote = %conn.remote_address(), removed = bound.len(), "quic connection closed");
    result
}

#[allow(clippy::too_many_arguments)]
async fn control_loop(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    cfg: &Arc<EdgeConfig>,
    reg: &TunnelRegistry,
    principal: &Principal,
    bound: &mut Vec<String>,
    pool: &Arc<TcpPortPool>,
    tcp_listeners: &mut Vec<(u16, tokio::sync::oneshot::Sender<()>)>,
) -> anyhow::Result<()> {
    loop {
        let msg = match relay_proto::read_frame::<_, ClientMsg>(recv).await {
            Ok(m) => m,
            Err(relay_proto::ProtoError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        match msg {
            ClientMsg::Hello(_) => anyhow::bail!("unexpected second Hello"),
            ClientMsg::Register(req) => {
                handle_register(conn, send, cfg, reg, principal, req, bound, pool, tcp_listeners)
                    .await?;
            }
            ClientMsg::Unregister { tunnel_id } => {
                // Find and drop by tunnel_id. O(n) — fine, n is small per connection.
                if let Some(idx) = bound.iter().position(|h| {
                    reg.lookup_exact(h).map(|x| x.tunnel_id == tunnel_id).unwrap_or(false)
                }) {
                    let hostname = bound.remove(idx);
                    reg.remove(&hostname);
                }
            }
            ClientMsg::Ping { seq } => {
                relay_proto::write_frame(send, &ServerMsg::Pong { seq }).await?;
            }
            ClientMsg::Pong { .. } => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_register(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    cfg: &Arc<EdgeConfig>,
    reg: &TunnelRegistry,
    principal: &Principal,
    req: relay_proto::RegisterTunnel,
    bound: &mut Vec<String>,
    pool: &Arc<TcpPortPool>,
    tcp_listeners: &mut Vec<(u16, tokio::sync::oneshot::Sender<()>)>,
) -> anyhow::Result<()> {
    match req.kind {
        TunnelKind::Http => {}
        TunnelKind::Tcp => {
            return handle_tcp_register(conn, send, cfg, reg, principal, req, pool, tcp_listeners)
                .await;
        }
        TunnelKind::TlsPassthrough => {
            reject(send, req.req_id, "tls-passthrough lands in a future release".into()).await?;
            return Ok(());
        }
    }

    let hostname = match req.hostname.clone() {
        Some(h) => h.to_ascii_lowercase(),
        None => hostnames::generate_full(&cfg.temporary_domain).to_ascii_lowercase(),
    };

    if let Err(e) = cfg.reservations.check_hostname(principal, &hostname).await {
        reject(send, req.req_id, e.to_string()).await?;
        return Ok(());
    }

    // Persist first so we can use the canonical tunnel_id (reusing an existing
    // row when the CLI is reconnecting to the same hostname).
    let tunnel_id = match cfg
        .recorder
        .record_active(crate::auth::TunnelEvent {
            org_id: principal.org_id,
            kind: req.kind,
            hostname: hostname.clone(),
            labels: req.labels.clone(),
            inspect: req.inspect,
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(?e, "recorder failed; generating fallback id");
            Uuid::new_v4()
        }
    };

    let handle = TunnelHandle {
        tunnel_id,
        org_id: principal.org_id,
        kind: req.kind,
        hostname: hostname.clone(),
        conn: conn.clone(),
        inspect: req.inspect,
        tcp_port: None,
    };

    if reg.insert(handle).is_err() {
        reject(send, req.req_id, format!("hostname `{hostname}` is already in use")).await?;
        return Ok(());
    }
    bound.push(hostname.clone());

    let public_url = match cfg.public_port {
        Some(p) => format!("{}://{}:{}", cfg.public_url_scheme, hostname, p),
        None => format!("{}://{}", cfg.public_url_scheme, hostname),
    };
    tracing::info!(%hostname, %public_url, ?tunnel_id, "tunnel registered");

    relay_proto::write_frame(
        send,
        &ServerMsg::Registered(TunnelRegistered { req_id: req.req_id, tunnel_id, public_url }),
    )
    .await?;
    Ok(())
}

async fn reject(send: &mut quinn::SendStream, req_id: Uuid, reason: String) -> anyhow::Result<()> {
    relay_proto::write_frame(send, &ServerMsg::Rejected(TunnelRejected { req_id, reason })).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_register(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    cfg: &Arc<EdgeConfig>,
    reg: &TunnelRegistry,
    principal: &Principal,
    req: relay_proto::RegisterTunnel,
    pool: &Arc<TcpPortPool>,
    tcp_listeners: &mut Vec<(u16, tokio::sync::oneshot::Sender<()>)>,
) -> anyhow::Result<()> {
    let Some(port) = pool.allocate(&cfg.tcp_port_range) else {
        reject(send, req.req_id, "no TCP ports available in the pool".into()).await?;
        return Ok(());
    };

    let hostname = format!("tcp://{}:{port}", cfg.base_domain);
    let tunnel_id = match cfg
        .recorder
        .record_active(crate::auth::TunnelEvent {
            org_id: principal.org_id,
            kind: req.kind,
            hostname: hostname.clone(),
            labels: req.labels.clone(),
            inspect: false,
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(?e, "recorder failed; generating fallback id");
            Uuid::new_v4()
        }
    };

    let handle = TunnelHandle {
        tunnel_id,
        org_id: principal.org_id,
        kind: req.kind,
        hostname: hostname.clone(),
        conn: conn.clone(),
        inspect: false,
        tcp_port: Some(port),
    };
    if reg.insert(handle).is_err() {
        pool.release(port);
        reject(send, req.req_id, format!("internal collision on tcp port {port}")).await?;
        return Ok(());
    }

    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    tcp_listeners.push((port, cancel_tx));
    let cfg_cl = cfg.clone();
    let conn_cl = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::tcp::run_listener(cfg_cl, tunnel_id, conn_cl, port, cancel_rx).await
        {
            tracing::warn!(?e, port, "tcp listener exited");
        }
    });

    relay_proto::write_frame(
        send,
        &ServerMsg::Registered(TunnelRegistered {
            req_id: req.req_id,
            tunnel_id,
            public_url: hostname,
        }),
    )
    .await?;
    Ok(())
}
