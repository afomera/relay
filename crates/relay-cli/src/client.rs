//! QUIC client: accept per-request streams from the server and proxy them to
//! a local service.

use crate::ui::ReqEvent;
use futures::StreamExt;
use relay_proto::{HttpRequestHeader, HttpResponseHeader, StreamOpen, TcpConnectHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;

/// Where the CLI sends incoming tunnel traffic on this machine.
///
/// `addr` defaults to `127.0.0.1`. Override via `--local-addr` for setups
/// that bind only to `::1`, a non-loopback interface, or want OS-level v4/v6
/// fallback via `localhost`.
///
/// `host_header` is for puma-dev-style local setups that route by Host name
/// (e.g. `admin.sample.test` → a Rails app on some ephemeral port). When set,
/// we still dial `<addr>:port` but write `Host: <host_header>` on the
/// outbound request so the local reverse-proxy can route it.
///
/// `host_header` may contain a single `*` in the leading label — that's a
/// wildcard pattern. At request time, `*` is replaced with the leading label
/// of the incoming request's Host, so a wildcard public tunnel like
/// `*.acme.sharedwithrelay.com` paired with `*.sample.test` forwards
/// `foo.acme.sharedwithrelay.com` → local `Host: foo.sample.test`.
#[derive(Clone, Debug)]
pub struct LocalTarget {
    pub addr: String,
    pub port: u16,
    pub host_header: Option<String>,
}

impl LocalTarget {
    pub fn port(port: u16) -> Self {
        Self { addr: "127.0.0.1".into(), port, host_header: None }
    }

    pub fn with_host(port: u16, host_header: String) -> Self {
        Self { addr: "127.0.0.1".into(), port, host_header: Some(host_header) }
    }

    /// Override the dial address (default `127.0.0.1`). Returns self for
    /// fluent construction.
    pub fn with_addr(mut self, addr: String) -> Self {
        self.addr = addr;
        self
    }
}

/// Resolve `host_header` against the incoming request's Host value. Returns
/// the string we should write for `Host:` on the outbound request.
///
/// - No `*` → return `pattern` verbatim.
/// - Contains `*` → replace the `*` with the leading label of `incoming_host`
///   (port stripped, lowercased). If the incoming Host has no label (empty or
///   looks like an IP), the `*` is replaced with an empty string — puma-dev
///   will 404 and that's the right signal.
pub(crate) fn resolve_host_header(pattern: &str, incoming_host: &str) -> String {
    if !pattern.contains('*') {
        return pattern.to_string();
    }
    let host_only = incoming_host.split(':').next().unwrap_or(incoming_host).to_ascii_lowercase();
    let leading = host_only.split('.').next().unwrap_or("");
    pattern.replacen('*', leading, 1)
}

fn incoming_host_value(hdr: &HttpRequestHeader) -> &str {
    hdr.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

pub async fn accept_and_proxy(
    conn: quinn::Connection,
    target: LocalTarget,
    events: Option<UnboundedSender<ReqEvent>>,
) -> anyhow::Result<()> {
    let http_client =
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::TimedOut) => return Ok(()),
            Err(e) => {
                tracing::warn!(e = %format!("{e:#}"), "accept_bi failed");
                return Err(e.into());
            }
        };
        let client = http_client.clone();
        let ev = events.clone();
        let tgt = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, tgt, client, ev).await {
                tracing::warn!(e = %format!("{e:#}"), "stream proxy failed");
            }
        });
    }
}

async fn handle_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    target: LocalTarget,
    http_client: reqwest::Client,
    events: Option<UnboundedSender<ReqEvent>>,
) -> anyhow::Result<()> {
    let open: StreamOpen = relay_proto::read_frame(&mut recv).await?;
    match open {
        StreamOpen::Http(hdr) if is_ws_upgrade_request(&hdr) => {
            proxy_http_upgrade(send, recv, hdr, &target).await
        }
        StreamOpen::Http(hdr) => proxy_http(send, recv, hdr, &target, http_client, events).await,
        StreamOpen::Tcp(hdr) => proxy_tcp(send, recv, hdr, &target).await,
    }
}

fn is_ws_upgrade_request(hdr: &HttpRequestHeader) -> bool {
    let mut has_upgrade_token = false;
    let mut upgrade_is_websocket = false;
    for (k, v) in &hdr.headers {
        match k.to_ascii_lowercase().as_str() {
            "connection" if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")) => {
                has_upgrade_token = true;
            }
            "upgrade" if v.eq_ignore_ascii_case("websocket") => {
                upgrade_is_websocket = true;
            }
            _ => {}
        }
    }
    has_upgrade_token && upgrade_is_websocket
}

async fn proxy_tcp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    hdr: TcpConnectHeader,
    target: &LocalTarget,
) -> anyhow::Result<()> {
    tracing::debug!(connection_id = ?hdr.connection_id, "tcp connection from edge");
    let mut tcp = match TcpStream::connect((target.addr.as_str(), target.port)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(e = %format!("{e:#}"), "failed to reach local tcp service");
            let _ = send.finish();
            return Ok(());
        }
    };
    let (mut tcp_r, mut tcp_w) = tcp.split();
    let quic_to_tcp = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    };
    let tcp_to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
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
    tokio::join!(quic_to_tcp, tcp_to_quic);
    Ok(())
}

async fn proxy_http(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    hdr: HttpRequestHeader,
    target: &LocalTarget,
    http_client: reqwest::Client,
    events: Option<UnboundedSender<ReqEvent>>,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let method_str = hdr.method.clone();
    let path_str = hdr.path.clone();

    let url = format!("http://{}:{}{}", target.addr, target.port, hdr.path);
    let method = reqwest::Method::from_bytes(hdr.method.as_bytes())?;
    let mut req = http_client.request(method, &url);

    for (k, v) in &hdr.headers {
        // Drop headers that reqwest handles for us to avoid duplication.
        let lower = k.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "content-length" | "connection") {
            continue;
        }
        req = req.header(k, v);
    }
    if let Some(pattern) = &target.host_header {
        // Override the Host header so puma-dev (or another Host-based router)
        // sees the name the user mapped, not `127.0.0.1:port`. Patterns with
        // `*` get the leading label substituted from the incoming Host so
        // wildcard tunnels route 1:1 per-subdomain.
        let host = resolve_host_header(pattern, incoming_host_value(&hdr));
        req = req.header("Host", host);
    }

    let body_stream = tokio_util::io::ReaderStream::new(recv);
    let body = reqwest::Body::wrap_stream(body_stream);
    req = req.body(body);

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let header = HttpResponseHeader {
                request_id: hdr.request_id,
                status: 502,
                headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            };
            relay_proto::write_frame(&mut send, &header).await?;
            send.write_all(
                format!(
                    "relay cli could not reach local service on {}:{}: {e}",
                    target.addr, target.port
                )
                .as_bytes(),
            )
            .await?;
            let _ = send.finish();
            emit_event(&events, method_str, path_str, 502, started.elapsed().as_millis() as u64);
            return Ok(());
        }
    };

    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
        .collect();

    relay_proto::write_frame(
        &mut send,
        &HttpResponseHeader { request_id: hdr.request_id, status, headers },
    )
    .await?;

    // Emit once headers are known — body may stream indefinitely (SSE, long
    // polls), and time-to-first-byte is what the developer actually wants to
    // see in the live table.
    emit_event(&events, method_str, path_str, status, started.elapsed().as_millis() as u64);

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        send.write_all(&bytes).await?;
    }
    let _ = send.finish();
    Ok(())
}

fn emit_event(
    events: &Option<UnboundedSender<ReqEvent>>,
    method: String,
    path: String,
    status: u16,
    duration_ms: u64,
) {
    if let Some(tx) = events {
        let _ = tx.send(ReqEvent { method, path, status, duration_ms });
    }
}

/// Proxies an HTTP upgrade (e.g. WebSocket) to the local service. We hand-roll
/// an HTTP/1.1 request over a raw TCP socket because `reqwest` can't surface
/// the upgraded byte stream. After reading the response status line + headers,
/// we forward them to the edge and then bidirectionally copy bytes — the same
/// pattern `proxy_tcp` uses.
async fn proxy_http_upgrade(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    hdr: HttpRequestHeader,
    target: &LocalTarget,
) -> anyhow::Result<()> {
    let mut tcp = match TcpStream::connect((target.addr.as_str(), target.port)).await {
        Ok(t) => t,
        Err(e) => {
            let header = HttpResponseHeader {
                request_id: hdr.request_id,
                status: 502,
                headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            };
            relay_proto::write_frame(&mut send, &header).await?;
            send.write_all(
                format!(
                    "relay cli could not reach local service on {}:{}: {e}",
                    target.addr, target.port
                )
                .as_bytes(),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
    };

    // Host value to write to the local socket. With `share` the user wants a
    // specific name (puma-dev routing), possibly with `*` substitution from
    // the incoming Host. Otherwise the tunneled Host wouldn't match the local
    // dev server's expectations, so fall back to the dial target.
    let host_line = match &target.host_header {
        Some(pattern) => resolve_host_header(pattern, incoming_host_value(&hdr)),
        None => format!("{}:{}", target.addr, target.port),
    };

    let mut req_bytes = Vec::with_capacity(512);
    req_bytes.extend_from_slice(hdr.method.as_bytes());
    req_bytes.push(b' ');
    req_bytes.extend_from_slice(hdr.path.as_bytes());
    req_bytes.extend_from_slice(b" HTTP/1.1\r\n");
    let mut host_written = false;
    for (k, v) in &hdr.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "host" {
            req_bytes.extend_from_slice(b"Host: ");
            req_bytes.extend_from_slice(host_line.as_bytes());
            req_bytes.extend_from_slice(b"\r\n");
            host_written = true;
            continue;
        }
        req_bytes.extend_from_slice(k.as_bytes());
        req_bytes.extend_from_slice(b": ");
        req_bytes.extend_from_slice(v.as_bytes());
        req_bytes.extend_from_slice(b"\r\n");
    }
    if !host_written {
        req_bytes.extend_from_slice(b"Host: ");
        req_bytes.extend_from_slice(host_line.as_bytes());
        req_bytes.extend_from_slice(b"\r\n");
    }
    req_bytes.extend_from_slice(b"\r\n");
    tcp.write_all(&req_bytes).await?;

    // Read response headers into a buffer until we see \r\n\r\n. Any bytes
    // past the header terminator are the start of the response body (or the
    // first post-upgrade frame) and must be forwarded as-is.
    let mut buf = Vec::with_capacity(4096);
    let header_end: usize;
    let (status, headers) = loop {
        let mut tmp = [0u8; 4096];
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("local service closed before sending upgrade response");
        }
        buf.extend_from_slice(&tmp[..n]);
        let mut header_slots = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut header_slots);
        match parsed.parse(&buf)? {
            httparse::Status::Partial => {
                if buf.len() > 64 * 1024 {
                    anyhow::bail!("local service response headers exceeded 64 KiB");
                }
                continue;
            }
            httparse::Status::Complete(end) => {
                header_end = end;
                let status = parsed.code.unwrap_or(502);
                let headers: Vec<(String, String)> = parsed
                    .headers
                    .iter()
                    .map(|h| {
                        let v = std::str::from_utf8(h.value).unwrap_or("").to_string();
                        (h.name.to_string(), v)
                    })
                    .collect();
                break (status, headers);
            }
        }
    };

    relay_proto::write_frame(
        &mut send,
        &HttpResponseHeader { request_id: hdr.request_id, status, headers },
    )
    .await?;

    // Flush any bytes already read past the header terminator into QUIC send.
    if header_end < buf.len() {
        send.write_all(&buf[header_end..]).await?;
    }

    let (mut tcp_r, mut tcp_w) = tcp.split();
    let quic_to_tcp = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => {
                    // QUIC EOF — half-close the local TCP write side so
                    // the local server sees EOF and can finish gracefully.
                    let _ = tcp_w.shutdown().await;
                    break;
                }
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    let tcp_to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
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
    tokio::join!(quic_to_tcp, tcp_to_quic);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_host_header;

    #[test]
    fn literal_host_passthrough() {
        assert_eq!(
            resolve_host_header("admin.sample.test", "anything.else.com"),
            "admin.sample.test"
        );
    }

    #[test]
    fn wildcard_substitutes_leading_label() {
        assert_eq!(
            resolve_host_header("*.sample.test", "foo.acme.sharedwithrelay.com"),
            "foo.sample.test"
        );
    }

    #[test]
    fn wildcard_strips_port_from_incoming() {
        assert_eq!(
            resolve_host_header("*.sample.test", "tenant1.edge.example.com:8443"),
            "tenant1.sample.test"
        );
    }

    #[test]
    fn wildcard_lowercases_incoming_label() {
        assert_eq!(
            resolve_host_header("*.sample.test", "MixedCase.example.com"),
            "mixedcase.sample.test"
        );
    }

    #[test]
    fn wildcard_empty_incoming_substitutes_empty() {
        assert_eq!(resolve_host_header("*.sample.test", ""), ".sample.test");
    }
}
