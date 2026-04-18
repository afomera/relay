use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;

use crate::auth::{AuthProvider, ReservationStore};

/// Configuration for the edge data plane.
pub struct EdgeConfig {
    /// UDP socket for QUIC tunnel ingress from CLIs.
    pub bind_quic: SocketAddr,
    /// TCP socket for plain-HTTP public ingress (:80 in prod). Serves ACME
    /// HTTP-01 and redirects everything else to HTTPS.
    pub bind_http: SocketAddr,
    /// TCP socket for HTTPS public ingress (:443). If `None`, no HTTPS listener
    /// is started — useful for dev.
    pub bind_https: Option<SocketAddr>,

    pub base_domain: String,
    pub temporary_domain: String,
    /// Optional marketing site to redirect users to when they hit the apex
    /// of `base_domain` (no subdomain). Set for the hosted deployment where
    /// tunnels live under one domain and marketing content lives under
    /// another. Leave unset for self-hosted deploys that don't need this.
    pub marketing_url: Option<String>,
    /// `https` in prod, `http` in dev — used in rendered public URLs.
    pub public_url_scheme: String,
    /// When set, appended to rendered public URLs as `:<port>`. Used in dev
    /// where the HTTP listener isn't bound to :80.
    pub public_port: Option<u16>,

    /// Static TLS material used by the QUIC endpoint (the CLI always connects
    /// to the same address, so it's always one cert). In prod this will be the
    /// wildcard issued via ACME; in dev, a self-signed cert.
    pub tls_cert: CertificateDer<'static>,
    pub tls_key: PrivateKeyDer<'static>,

    /// Resolver for the HTTPS listener. When `None`, the listener binds but
    /// uses `tls_cert` / `tls_key` as a single static cert.
    pub tls_resolver: Option<Arc<dyn ResolvesServerCert>>,

    pub auth: Arc<dyn AuthProvider>,
    pub reservations: Arc<dyn ReservationStore>,
    pub recorder: Arc<dyn crate::auth::TunnelRecorder>,
    pub capture: Arc<dyn crate::auth::CaptureSink>,
    /// Shared store of pending ACME HTTP-01 challenges. The edge's HTTP
    /// ingress serves `/.well-known/acme-challenge/<token>` from this map.
    pub http01: Arc<relay_acme::Http01Pending>,

    /// Hostname that should route to the control-plane dashboard instead of
    /// being treated as a tunnel lookup (e.g. `dash.withrelay.dev`). When
    /// set, the edge serves the dashboard on both HTTP and HTTPS for this
    /// host and the cert issuer should mint its cert via HTTP-01.
    pub admin_hostname: Option<String>,
    /// The control plane's axum router. Only consulted when `admin_hostname`
    /// matches the incoming Host header. Both live in the same process so
    /// there's no internal HTTP hop.
    pub admin_router: Option<axum::Router>,

    /// Optional TCP tunnel port pool. Each TCP tunnel allocates a port from
    /// this range; the edge binds a listener per tunnel.
    pub tcp_port_range: std::ops::RangeInclusive<u16>,
}
