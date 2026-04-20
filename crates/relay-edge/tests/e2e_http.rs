//! End-to-end test: boot the edge, register a tunnel from the CLI library,
//! make an HTTP request to the public ingress, and assert it lands on the
//! local service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use relay_acme::Http01Pending;
use relay_edge::{
    AllowAllAuth, AllowAllReservations, EdgeConfig, NoopCaptureSink, NoopRecorder,
    generate_dev_cert, start,
};
use relay_proto::{
    ClientHello, ClientMsg, PROTOCOL_VERSION, RegisterTunnel, ServerMsg, TunnelKind,
};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Pick an unused TCP port and return it. The listener is dropped so the OS
/// may reuse it — tests tolerate the rare race.
async fn free_tcp_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Same, but for UDP (QUIC).
fn free_udp_port() -> u16 {
    use std::net::UdpSocket;
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

async fn start_echo_server(port: u16) {
    let app = axum::Router::new()
        .route("/", get(|| async { "hello from local service" }))
        .route("/echo", post(|body: String| async move { format!("echoed: {body}") }))
        .route(
            "/headers",
            get(|headers: axum::http::HeaderMap| async move {
                let mut out = String::new();
                let mut names: Vec<_> =
                    headers.iter().map(|(k, _)| k.as_str().to_string()).collect();
                names.sort();
                for name in names {
                    if let Some(v) = headers.get(&name).and_then(|v| v.to_str().ok()) {
                        out.push_str(&format!("{name}: {v}\n"));
                    }
                }
                out
            }),
        );
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_tunnel_end_to_end() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let local_port = free_tcp_port().await;
    start_echo_server(local_port).await;

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

    // Wait briefly for the listeners to come up.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- CLI side: connect QUIC, Hello, Register, spawn tunnel forwarder. ---
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
            inspect: true,
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
    tracing::info!(%hostname, "tunnel registered");

    // Spawn the CLI-side forwarder loop.
    tokio::spawn(relay_cli::client::accept_and_proxy(
        conn.clone(),
        relay_cli::client::LocalTarget::port(local_port),
        None,
    ));

    // Give the registrar + forwarder a moment to settle.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- Client request: hit the HTTP ingress with the tunnel host header. ---
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{http_port}/"))
        .header("host", &hostname)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello from local service");

    // Echo POST — verifies request body streaming.
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{http_port}/echo"))
        .header("host", &hostname)
        .body("ping")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "echoed: ping");

    // 404 for unknown host.
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{http_port}/"))
        .header("host", "no-such-tunnel.localhost.relay.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    // Tear down.
    conn.close(0u32.into(), b"bye");
    drop(endpoint);
    edge_task.abort();
}
