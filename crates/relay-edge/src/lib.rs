//! Relay edge: public listeners + QUIC tunnel server.
//!
//! See `SPEC.md` §3–§5 for architecture. Public entry point is [`start`].
//!
//! At M1 scope: HTTP tunneling only, no TLS on the public listener, in-memory
//! auth/reservations stubs. M3 layers TLS + real auth; M4 adds TCP.

mod auth;
mod config;
mod hostnames;
mod ingress;
mod ingress_https;
mod quic;
mod registry;
mod tcp;
mod tls;
mod wordlists;

pub use auth::{
    AllowAllAuth, AllowAllReservations, AuthError, AuthProvider, CaptureSink, HttpCapture,
    NoopCaptureSink, NoopRecorder, Principal, RecordError, ReservationError, ReservationStore,
    TunnelEvent, TunnelRecorder,
};
pub use config::EdgeConfig;
pub use registry::{TunnelHandle, TunnelRegistry};
pub use tls::generate_dev_cert;

use std::sync::Arc;

/// Start the edge data plane. Blocks until one of the listener tasks exits.
pub async fn start(config: EdgeConfig) -> anyhow::Result<()> {
    // Install a default rustls crypto provider. Safe to call repeatedly — the
    // `_ =` drops the error if another instance installed one first.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let registry = TunnelRegistry::new();
    let config = Arc::new(config);

    let quic_task = tokio::spawn(quic::run(config.clone(), registry.clone()));
    let http_task = tokio::spawn(ingress::run(config.clone(), registry.clone()));
    let https_task = tokio::spawn(ingress_https::run(config.clone(), registry.clone()));

    tokio::select! {
        res = quic_task => {
            tracing::error!(?res, "quic listener exited");
            res??;
        }
        res = http_task => {
            tracing::error!(?res, "http listener exited");
            res??;
        }
        res = https_task => {
            tracing::error!(?res, "https listener exited");
            res??;
        }
    }
    Ok(())
}
