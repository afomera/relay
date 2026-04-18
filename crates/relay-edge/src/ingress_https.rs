//! HTTPS ingress: accepts TCP connections, terminates TLS via rustls (using a
//! pluggable `ResolvesServerCert`), and feeds requests to the shared axum
//! router.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::connect_info::Connected;
use hyper_util::rt::TokioIo;
use relay_proto::ALPN as QUIC_ALPN; // unused here — kept for dep tidiness
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::config::EdgeConfig;
use crate::ingress::AppState;
use crate::registry::TunnelRegistry;

pub async fn run(cfg: Arc<EdgeConfig>, reg: Arc<TunnelRegistry>) -> anyhow::Result<()> {
    let Some(addr) = cfg.bind_https else {
        // Config explicitly disables HTTPS ingress.
        std::future::pending::<()>().await;
        return Ok(());
    };

    let _ = QUIC_ALPN; // quiet unused-import lint; see module note.

    let resolver = match cfg.tls_resolver.clone() {
        Some(r) => r,
        None => Arc::new(StaticResolver::new(cfg.tls_cert.clone(), cfg.tls_key.clone_key())?) as _,
    };

    let mut tls =
        rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let state = AppState { reg, cfg: cfg.clone() };
    let app = Router::new().fallback(crate::ingress::handle).with_state(state);
    let make_svc = app.into_make_service_with_connect_info::<SocketAddr>();

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "edge HTTPS ingress bound");

    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(?e, "tcp accept");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let mut make_svc = make_svc.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(?e, %remote, "tls handshake failed");
                    return;
                }
            };
            let info = SocketConnectInfo(remote);
            let tower_service = match make_svc.call(info).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let hyper_service = hyper::service::service_fn(move |req| {
                let mut s = tower_service.clone();
                async move { s.call(req).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), hyper_service)
                .with_upgrades()
                .await
            {
                tracing::debug!(?e, %remote, "connection ended");
            }
        });
    }
}

/// Adapter so we can call `make_svc.call(socket_addr)` directly.
#[derive(Clone)]
struct SocketConnectInfo(SocketAddr);

impl Connected<SocketConnectInfo> for SocketAddr {
    fn connect_info(target: SocketConnectInfo) -> Self {
        target.0
    }
}

struct StaticResolver {
    ck: Arc<CertifiedKey>,
}

impl StaticResolver {
    fn new(
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> anyhow::Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| anyhow::anyhow!("load key: {e}"))?;
        Ok(Self { ck: Arc::new(CertifiedKey::new(vec![cert], signing_key)) })
    }
}

impl std::fmt::Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticResolver").finish()
    }
}

impl ResolvesServerCert for StaticResolver {
    fn resolve(&self, _: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.ck.clone())
    }
}
