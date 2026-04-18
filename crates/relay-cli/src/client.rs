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
        StreamOpen::Http(hdr) => proxy_http(send, recv, hdr, local_port, http_client).await,
        StreamOpen::Tcp(hdr) => proxy_tcp(send, recv, hdr, local_port).await,
    }
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
