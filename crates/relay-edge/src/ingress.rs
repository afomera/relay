//! Public HTTP ingress for tunneled traffic.
//!
//! Routes incoming requests by Host header to an active QUIC tunnel, opens a
//! fresh bidi stream per request, sends `StreamOpen::Http(header)`, streams
//! the request body, reads back an `HttpResponseHeader` + body.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use futures::StreamExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use relay_proto::{HttpRequestHeader, HttpResponseHeader, StreamOpen};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::Service;
use uuid::Uuid;

use crate::config::EdgeConfig;
use crate::registry::TunnelRegistry;

/// Per-direction body cap for the inspector. See SPEC.md §9 / DECISIONS.md D12.
const INSPECT_BODY_CAP: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) reg: Arc<TunnelRegistry>,
    pub(crate) cfg: Arc<EdgeConfig>,
}

pub async fn run(cfg: Arc<EdgeConfig>, reg: Arc<TunnelRegistry>) -> anyhow::Result<()> {
    let state = AppState { reg, cfg: cfg.clone() };
    let app = axum::Router::new().fallback(handle).with_state(state);
    let make_svc = app.into_make_service_with_connect_info::<SocketAddr>();
    let listener = TcpListener::bind(cfg.bind_http).await?;
    tracing::info!(addr = %cfg.bind_http, "edge HTTP ingress bound");

    // `axum::serve` uses `serve_connection` (no upgrades). We need
    // `serve_connection_with_upgrades` so HTTP/1.1 WebSocket upgrades work
    // over the plain HTTP listener too — same pattern as ingress_https.rs.
    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(?e, "tcp accept");
                continue;
            }
        };
        let mut make_svc = make_svc.clone();
        tokio::spawn(async move {
            let info = HttpConnectInfo(remote);
            let tower_service = match make_svc.call(info).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let hyper_service = hyper::service::service_fn(move |req| {
                let mut s = tower_service.clone();
                async move { s.call(req).await }
            });
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(tcp), hyper_service)
                .await
            {
                tracing::debug!(?e, %remote, "connection ended");
            }
        });
    }
}

/// Adapter so `axum::extract::ConnectInfo<SocketAddr>` is populated from our
/// manual accept loop — axum normally fills this via `axum::serve`.
#[derive(Clone)]
struct HttpConnectInfo(SocketAddr);

impl Connected<HttpConnectInfo> for SocketAddr {
    fn connect_info(target: HttpConnectInfo) -> Self {
        target.0
    }
}

pub(crate) async fn handle(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    match handle_inner(state, remote, req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(?e, "ingress error");
            error_page(StatusCode::BAD_GATEWAY, &format!("relay error: {e}"))
        }
    }
}

async fn handle_inner(
    state: AppState,
    remote: SocketAddr,
    req: Request<Body>,
) -> anyhow::Result<Response<Body>> {
    // HTTP/1.1 puts the host in the `Host` header. HTTP/2 puts it in the
    // `:authority` pseudo-header, which hyper exposes via `req.uri().host()`.
    // Fall back to the URI authority so h2 clients aren't rejected as
    // "missing host header".
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()))
        .map(|h| h.to_ascii_lowercase())
        .unwrap_or_default();

    // ACME HTTP-01 challenge responder. Must come before tunnel lookup so a
    // custom domain that isn't routed yet can still be validated.
    if let Some(token) = req.uri().path().strip_prefix("/.well-known/acme-challenge/") {
        if let Some(auth) = state.cfg.http01.get(token) {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Body::from(auth))
                .expect("http-01 response"));
        }
        return Ok(error_page(StatusCode::NOT_FOUND, "unknown ACME challenge"));
    }

    if host.is_empty() {
        return Ok(error_page(StatusCode::BAD_REQUEST, "missing host header"));
    }

    // Dashboard: if the request is for the configured admin hostname, hand
    // it to the control-plane router. Same process, no internal HTTP hop.
    if let (Some(admin_host), Some(router)) = (&state.cfg.admin_hostname, &state.cfg.admin_router) {
        if host.eq_ignore_ascii_case(admin_host) {
            use tower::ServiceExt;
            let svc = router.clone();
            return Ok(svc.oneshot(req).await.unwrap_or_else(|e| {
                tracing::warn!(?e, "admin router errored");
                error_page(StatusCode::INTERNAL_SERVER_ERROR, "dashboard unavailable")
            }));
        }
    }

    let Some(handle) = state.reg.lookup_for_request(&host) else {
        return Ok(error_page(
            StatusCode::NOT_FOUND,
            &format!("no active tunnel bound to `{host}`"),
        ));
    };

    // WebSocket / HTTP Upgrade detection. Only HTTP/1.1 supports classical
    // upgrades; h2 would need RFC 8441 extended CONNECT, which we don't
    // implement (yet). Browsers default to h1 for WS handshakes anyway.
    let is_upgrade =
        req.version() == http::Version::HTTP_11 && is_ws_upgrade_request(req.headers());

    let (mut send, mut recv) = handle.conn.open_bi().await?;

    let request_id = Uuid::new_v4();
    let started_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let started_instant = std::time::Instant::now();
    let method_str = req.method().to_string();
    let path_str =
        req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".to_string());
    let req_headers = collect_headers(req.headers());
    let client_ip = resolve_client_ip(remote, req.headers());

    let header = HttpRequestHeader {
        tunnel_id: handle.tunnel_id,
        request_id,
        method: method_str.clone(),
        path: path_str.clone(),
        headers: req_headers.clone(),
        remote_ip: client_ip.clone(),
        tls: false,
    };
    relay_proto::write_frame(&mut send, &StreamOpen::Http(header)).await?;

    if is_upgrade {
        return upgrade_path(req, send, recv).await;
    }

    // Two paths: inspected (buffer + capture) and streaming (existing).
    if handle.inspect {
        return inspected_path(
            state,
            handle,
            send,
            recv,
            req,
            request_id,
            started_at,
            started_instant,
            method_str,
            path_str,
            req_headers,
            client_ip,
        )
        .await;
    }

    // ---- streaming path (no capture) ----
    let body = req.into_body();
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(b) => {
                    if send.write_all(&b).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = send.finish();
    });

    let resp_hdr: HttpResponseHeader = relay_proto::read_frame(&mut recv).await?;
    let mut builder = Response::builder().status(resp_hdr.status);
    for (k, v) in &resp_hdr.headers {
        if is_ingress_hop_by_hop(k) {
            continue;
        }
        let Ok(name) = HeaderName::try_from(k.as_str()) else { continue };
        let Ok(value) = HeaderValue::try_from(v.as_str()) else { continue };
        builder = builder.header(name, value);
    }
    let body_stream = tokio_util::io::ReaderStream::new(recv);
    let resp = builder.body(Body::from_stream(body_stream))?;
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
async fn inspected_path(
    state: AppState,
    handle: crate::registry::TunnelHandle,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    req: Request<Body>,
    request_id: Uuid,
    started_at: i64,
    started_instant: std::time::Instant,
    method_str: String,
    path_str: String,
    req_headers: Vec<(String, String)>,
    client_ip: String,
) -> anyhow::Result<Response<Body>> {
    // Buffer request body up to the cap, forwarding chunks as we go.
    let mut req_capture = Vec::new();
    let mut req_truncated = false;
    let mut body = req.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let bytes = chunk?;
        send.write_all(&bytes).await?;
        capture_into(&mut req_capture, &bytes, &mut req_truncated, INSPECT_BODY_CAP);
    }
    let _ = send.finish();

    // Read response header.
    let resp_hdr: HttpResponseHeader = relay_proto::read_frame(&mut recv).await?;
    let status = resp_hdr.status;
    let resp_headers = resp_hdr.headers.clone();

    // Buffer response body. (We hold the full body in memory; the inspector
    // user opted into this. Hard cap at 16 MiB to protect the edge from a
    // misbehaving upstream.)
    const HARD_CAP: usize = 16 * 1024 * 1024;
    let mut full_body = Vec::new();
    let mut resp_capture = Vec::new();
    let mut resp_truncated = false;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match recv.read(&mut buf).await? {
            None => break,
            Some(0) => break,
            Some(n) => {
                if full_body.len() + n > HARD_CAP {
                    return Ok(error_page(
                        StatusCode::BAD_GATEWAY,
                        "response body exceeded inspector hard cap (16 MiB)",
                    ));
                }
                full_body.extend_from_slice(&buf[..n]);
                capture_into(&mut resp_capture, &buf[..n], &mut resp_truncated, INSPECT_BODY_CAP);
            }
        }
    }

    let completed_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let duration_ms = started_instant.elapsed().as_millis() as u64;

    // Persist capture in the background — never block the response on it.
    let sink = state.cfg.capture.clone();
    let capture = crate::auth::HttpCapture {
        tunnel_id: handle.tunnel_id,
        org_id: handle.org_id,
        request_id,
        started_at_unix: started_at,
        completed_at_unix: completed_at,
        method: method_str,
        path: path_str,
        status,
        duration_ms,
        req_headers,
        req_body: req_capture,
        resp_headers: resp_headers.clone(),
        resp_body: resp_capture,
        truncated: req_truncated || resp_truncated,
        client_ip,
    };
    tokio::spawn(async move {
        if let Err(e) = sink.record(capture).await {
            tracing::warn!(?e, "capture sink record failed");
        }
    });

    // Build the response.
    let mut builder = Response::builder().status(status);
    for (k, v) in &resp_headers {
        if is_ingress_hop_by_hop(k) {
            continue;
        }
        let Ok(name) = HeaderName::try_from(k.as_str()) else { continue };
        let Ok(value) = HeaderValue::try_from(v.as_str()) else { continue };
        builder = builder.header(name, value);
    }
    Ok(builder.body(Body::from(full_body))?)
}

fn capture_into(buf: &mut Vec<u8>, chunk: &[u8], truncated: &mut bool, cap: usize) {
    if *truncated {
        return;
    }
    let remaining = cap.saturating_sub(buf.len());
    let take = remaining.min(chunk.len());
    buf.extend_from_slice(&chunk[..take]);
    if take < chunk.len() {
        *truncated = true;
    }
}

/// Prefer forwarded-client headers over the TCP peer so captures show the real
/// client when the edge is behind a proxy (Cloudflare, ALB, etc.). Today we
/// run Cloudflare DNS-only, so these headers won't be present and we fall
/// through to the peer IP — but this future-proofs an orange-cloud flip.
fn resolve_client_ip(remote: SocketAddr, headers: &HeaderMap) -> String {
    if let Some(ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()).map(str::trim) {
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next().map(str::trim) {
            if !first.is_empty() {
                return first.to_string();
            }
        }
    }
    remote.ip().to_string()
}

fn collect_headers(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
        .collect()
}

/// Hop-by-hop headers that we strip when delivering the response. We don't
/// strip on the request side since the CLI reconstitutes a fresh HTTP/1.1
/// request to the local service anyway.
fn is_ingress_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
    )
}

/// Same as `is_ingress_hop_by_hop` but preserves `connection` and `upgrade` —
/// both are required on a 101 Switching Protocols response for the handshake
/// to be valid.
fn is_101_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "keep-alive"
            | "transfer-encoding"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
    )
}

fn is_ws_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_has_upgrade = headers.get_all(http::header::CONNECTION).iter().any(|v| {
        v.to_str()
            .ok()
            .is_some_and(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
    });
    let upgrade_is_websocket = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("websocket"));
    connection_has_upgrade && upgrade_is_websocket
}

/// Handles a WebSocket / HTTP/1.1 upgrade. Extracts `OnUpgrade` from the
/// request (so we can take over the raw socket after the 101 is flushed),
/// reads the local service's response header via QUIC, and — on 101 —
/// spawns a bidirectional byte-copy task between the upgraded IO and the
/// QUIC stream. On any non-101 status we fall through and stream the
/// response normally.
async fn upgrade_path(
    mut req: Request<Body>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> anyhow::Result<Response<Body>> {
    let on_upgrade = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();

    // Upgrade requests don't carry a body that's delivered via hyper's Body
    // stream — post-101 bytes come through the Upgraded IO. So we do NOT
    // spawn the usual body-forwarding task; that would finish the send
    // stream prematurely and close the client→server half of the channel.
    let resp_hdr: HttpResponseHeader = relay_proto::read_frame(&mut recv).await?;

    if resp_hdr.status != 101 {
        // Local service didn't switch protocols (e.g. 400/401). Drop the
        // upgrade future and stream the response body as normal.
        let _ = send.finish();
        let mut builder = Response::builder().status(resp_hdr.status);
        for (k, v) in &resp_hdr.headers {
            if is_ingress_hop_by_hop(k) {
                continue;
            }
            let Ok(name) = HeaderName::try_from(k.as_str()) else { continue };
            let Ok(value) = HeaderValue::try_from(v.as_str()) else { continue };
            builder = builder.header(name, value);
        }
        let body_stream = tokio_util::io::ReaderStream::new(recv);
        return Ok(builder.body(Body::from_stream(body_stream))?);
    }

    let Some(on_upgrade) = on_upgrade else {
        return Ok(error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection does not support upgrade",
        ));
    };

    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in &resp_hdr.headers {
        if is_101_hop_by_hop(k) {
            continue;
        }
        let Ok(name) = HeaderName::try_from(k.as_str()) else { continue };
        let Ok(value) = HeaderValue::try_from(v.as_str()) else { continue };
        builder = builder.header(name, value);
    }
    let resp = builder.body(Body::empty())?;

    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!(?e, "upgrade future failed");
                return;
            }
        };
        let upgraded = TokioIo::new(upgraded);
        let (mut u_read, mut u_write) = tokio::io::split(upgraded);
        let upgraded_to_quic = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match u_read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = send.finish();
                        break;
                    }
                    Ok(n) => {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        };
        let quic_to_upgraded = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) => {
                        // QUIC EOF — propagate half-close to the client by
                        // shutting down the write side of the upgraded IO.
                        // Without this, the browser's read side waits forever.
                        let _ = u_write.shutdown().await;
                        break;
                    }
                    Ok(Some(n)) => {
                        if u_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        };
        tokio::join!(upgraded_to_quic, quic_to_upgraded);
    });

    Ok(resp)
}

fn error_page(status: StatusCode, msg: &str) -> Response<Body> {
    // `color-scheme: light dark` flips UA defaults (form controls, scrollbars)
    // per the user's OS preference; the prefers-color-scheme block swaps our
    // own palette so nobody gets flash-banged at 2am.
    let html = format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>relay</title>
<meta name="color-scheme" content="light dark">
<style>:root{{--fg:#222;--bg:#fff;--code-bg:#f3f3f3;--muted:#666}}
@media (prefers-color-scheme: dark){{:root{{--fg:#e6e6e6;--bg:#111;--code-bg:#1e1e1e;--muted:#888}}}}
html,body{{background:var(--bg);color:var(--fg)}}
body{{font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem}}
h1{{font-size:1.4rem}}
code{{background:var(--code-bg);padding:.15em .3em;border-radius:3px}}
.sub{{color:var(--muted)}}</style></head>
<body><h1>relay — {}</h1><p><code>{}</code></p>
<p class="sub">Tunnel not found, offline, or the request was malformed.</p></body></html>"#,
        status.as_u16(),
        html_escape(msg),
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .expect("static error page")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
