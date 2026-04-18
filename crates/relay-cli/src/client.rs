//! QUIC client: accept per-request streams from the server and proxy them to
//! a local service.

use futures::StreamExt;
use relay_proto::{HttpRequestHeader, HttpResponseHeader, StreamOpen, TcpConnectHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn accept_and_proxy(conn: quinn::Connection, local_port: u16) -> anyhow::Result<()> {
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
                tracing::warn!(?e, "accept_bi failed");
                return Err(e.into());
            }
        };
        let client = http_client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, local_port, client).await {
                tracing::warn!(?e, "stream proxy failed");
            }
        });
    }
}

async fn handle_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local_port: u16,
    http_client: reqwest::Client,
) -> anyhow::Result<()> {
    let open: StreamOpen = relay_proto::read_frame(&mut recv).await?;
    match open {
        StreamOpen::Http(hdr) if is_ws_upgrade_request(&hdr) => {
            proxy_http_upgrade(send, recv, hdr, local_port).await
        }
        StreamOpen::Http(hdr) => proxy_http(send, recv, hdr, local_port, http_client).await,
        StreamOpen::Tcp(hdr) => proxy_tcp(send, recv, hdr, local_port).await,
    }
}

fn is_ws_upgrade_request(hdr: &HttpRequestHeader) -> bool {
    let mut has_upgrade_token = false;
    let mut upgrade_is_websocket = false;
    for (k, v) in &hdr.headers {
        match k.to_ascii_lowercase().as_str() {
            "connection"
                if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")) =>
            {
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
    local_port: u16,
) -> anyhow::Result<()> {
    tracing::debug!(connection_id = ?hdr.connection_id, "tcp connection from edge");
    let mut tcp = match TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(?e, "failed to reach local tcp service");
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
    local_port: u16,
    http_client: reqwest::Client,
) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{local_port}{}", hdr.path);
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
                format!("relay cli could not reach local service on :{local_port}: {e}").as_bytes(),
            )
            .await?;
            let _ = send.finish();
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

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        send.write_all(&bytes).await?;
    }
    let _ = send.finish();
    Ok(())
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
    local_port: u16,
) -> anyhow::Result<()> {
    let mut tcp = match TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(t) => t,
        Err(e) => {
            let header = HttpResponseHeader {
                request_id: hdr.request_id,
                status: 502,
                headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            };
            relay_proto::write_frame(&mut send, &header).await?;
            send.write_all(
                format!("relay cli could not reach local service on :{local_port}: {e}").as_bytes(),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
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
            // The tunneled Host (e.g. andrea.sharedwithrelay.com) wouldn't
            // match the local dev server's expectations; rewrite to loopback.
            req_bytes.extend_from_slice(b"Host: 127.0.0.1:");
            req_bytes.extend_from_slice(local_port.to_string().as_bytes());
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
        req_bytes.extend_from_slice(b"Host: 127.0.0.1:");
        req_bytes.extend_from_slice(local_port.to_string().as_bytes());
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
