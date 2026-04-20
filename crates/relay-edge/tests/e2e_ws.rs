//! End-to-end WebSocket test: boot the edge, register a tunnel, start a
//! tokio-tungstenite echo server as the local service, connect a WS client
//! through the public HTTP ingress, and assert frames round-trip.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use relay_acme::Http01Pending;
use relay_edge::{
    AllowAllAuth, AllowAllReservations, EdgeConfig, NoopCaptureSink, NoopRecorder,
    generate_dev_cert, start,
};
use relay_proto::{
    ClientHello, ClientMsg, PROTOCOL_VERSION, RegisterTunnel, ServerMsg, TunnelKind,
};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;
use uuid::Uuid;

async fn free_tcp_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
    use std::net::UdpSocket;
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

/// Accept WebSocket connections on the given port and echo text/binary frames
/// back, closing on a Close frame. Mirrors what Vite/Phoenix/etc. would do.
async fn start_ws_echo_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let ws = match tokio_tungstenite::accept_async(tcp).await {
                    Ok(w) => w,
                    Err(e) => {
                        eprintln!("ws accept failed: {e}");
                        return;
                    }
                };
                let (mut tx, mut rx) = ws.split();
                while let Some(msg) = rx.next().await {
                    let msg = match msg {
                        Ok(m) => m,
                        Err(_) => break,
                    };
                    let send_res = match msg {
                        Message::Text(s) => tx.send(Message::Text(format!("echo: {s}"))).await,
                        Message::Binary(b) => tx.send(Message::Binary(b)).await,
                        Message::Close(c) => {
                            let _ = tx.send(Message::Close(c)).await;
                            break;
                        }
                        _ => continue,
                    };
                    if send_res.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_tunnel_end_to_end() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let local_port = free_tcp_port().await;
    start_ws_echo_server(local_port).await;

    let http_port = free_tcp_port().await;
    let quic_port = free_udp_port();
    let base = "localhost.relay.test".to_string();

    let sans = vec![base.clone(), format!("*.{base}"), format!("*.temporary.{base}")];
    let (cert, key) = generate_dev_cert(&sans).unwrap();
    let cfg = EdgeConfig {
        bind_quic: format!("127.0.0.1:{quic_port}").parse().unwrap(),
        bind_http: format!("127.0.0.1:{http_port}").parse().unwrap(),
        bind_https: None,
        base_domain: base.clone(),
        temporary_domain: format!("temporary.{base}"),
        marketing_url: None,
        public_url_scheme: "http".into(),
        public_port: None,
        tls_cert: cert,
        tls_key: key,
        tls_resolver: None,
        auth: Arc::new(AllowAllAuth::default()),
        reservations: Arc::new(AllowAllReservations),
        recorder: Arc::new(NoopRecorder),
        capture: Arc::new(NoopCaptureSink),
        http01: Arc::new(Http01Pending::new()),
        admin_hostname: None,
        admin_router: None,
        tcp_port_range: 29000..=29999,
        cookie_key: axum_extra::extract::cookie::Key::generate(),
    };

    let edge_task = tokio::spawn(async move { start(cfg).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // CLI side: connect QUIC, Hello, Register an HTTP tunnel with inspect=false
    // (upgrades bypass the inspector regardless, but this keeps the test
    // focused on the streaming path).
    let client_cfg = relay_cli::tls::build_client_config(true, None).unwrap();
    let quic_client =
        quinn::crypto::rustls::QuicClientConfig::try_from((*client_cfg).clone()).unwrap();
    let mut cc = quinn::ClientConfig::new(Arc::new(quic_client));
    let mut tp = quinn::TransportConfig::default();
    tp.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    tp.keep_alive_interval(Some(Duration::from_secs(10)));
    cc.transport_config(Arc::new(tp));

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    endpoint.set_default_client_config(cc);

    let server_addr: SocketAddr = format!("127.0.0.1:{quic_port}").parse().unwrap();
    let conn = endpoint.connect(server_addr, &base).unwrap().await.unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    relay_proto::write_frame(
        &mut send,
        &ClientMsg::Hello(ClientHello {
            protocol_version: PROTOCOL_VERSION,
            auth_token: "dev".into(),
            client_version: "test".into(),
            os: "test".into(),
            arch: "test".into(),
        }),
    )
    .await
    .unwrap();
    let hello = relay_proto::read_frame::<_, ServerMsg>(&mut recv).await.unwrap();
    assert!(matches!(hello, ServerMsg::Hello(_)));

    let req_id = Uuid::new_v4();
    relay_proto::write_frame(
        &mut send,
        &ClientMsg::Register(RegisterTunnel {
            req_id,
            kind: TunnelKind::Http,
            hostname: None,
            labels: vec![],
            inspect: false,
            password: None,
        }),
    )
    .await
    .unwrap();
    let public_url = match relay_proto::read_frame::<_, ServerMsg>(&mut recv).await.unwrap() {
        ServerMsg::Registered(r) => {
            assert_eq!(r.req_id, req_id);
            r.public_url
        }
        other => panic!("expected Registered, got {other:?}"),
    };
    let hostname = public_url.strip_prefix("http://").expect("url starts with http").to_string();

    tokio::spawn(relay_cli::client::accept_and_proxy(
        conn.clone(),
        relay_cli::client::LocalTarget::port(local_port),
        None,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Build a WS request pointed at 127.0.0.1:<http_port> but with the
    // tunnel hostname in the Host header so the edge routes to our tunnel.
    let url = format!("ws://127.0.0.1:{http_port}/");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert(http::header::HOST, http::HeaderValue::from_str(&hostname).unwrap());

    let (mut ws, response) = tokio_tungstenite::connect_async(request).await.expect("ws connect");
    assert_eq!(response.status().as_u16(), 101);

    ws.send(Message::Text("hello".into())).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed, Message::Text("echo: hello".into()));

    ws.send(Message::Binary(vec![1, 2, 3, 4])).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed, Message::Binary(vec![1, 2, 3, 4]));

    ws.close(None).await.unwrap();
    // Drain until the stream ends to confirm the close round-trips.
    while let Some(_msg) = ws.next().await {}

    conn.close(0u32.into(), b"bye");
    drop(endpoint);
    edge_task.abort();
}
