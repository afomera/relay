//! Public HTTP ingress for tunneled traffic.
//!
//! Routes incoming requests by Host header to an active QUIC tunnel, opens a
//! fresh bidi stream per request, sends `StreamOpen::Http(header)`, streams
//! the request body, reads back an `HttpResponseHeader` + body.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use futures::StreamExt;
use relay_proto::{HttpRequestHeader, HttpResponseHeader, StreamOpen};
use tokio::net::TcpListener;
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
    let listener = TcpListener::bind(cfg.bind_http).await?;
    tracing::info!(addr = %cfg.bind_http, "edge HTTP ingress bound");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
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

    let (mut send, mut recv) = handle.conn.open_bi().await?;

    let request_id = Uuid::new_v4();
    let started_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let started_instant = std::time::Instant::now();
    let method_str = req.method().to_string();
    let path_str =
        req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_else(|| "/".to_string());
    let req_headers = collect_headers(req.headers());

    let header = HttpRequestHeader {
        tunnel_id: handle.tunnel_id,
        request_id,
        method: method_str.clone(),
        path: path_str.clone(),
        headers: req_headers.clone(),
        remote_ip: remote.ip().to_string(),
        tls: false,
    };
    relay_proto::write_frame(&mut send, &StreamOpen::Http(header)).await?;

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
