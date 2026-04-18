//! Relay control plane: HTTP API + server-rendered dashboard.

pub mod auth;
pub mod cert_issuer;
pub mod config;
pub mod edge_bridge;
pub mod events;
pub mod icons;
pub mod routes;
pub mod state;
pub mod templates;
pub mod verify;

pub use cert_issuer::CertIssuerCtx;
pub use events::EventBus;

use axum::Router;
use tokio::net::TcpListener;

pub use config::ControlConfig;
pub use edge_bridge::{DbAuthProvider, DbCaptureSink, DbReservationStore, DbTunnelRecorder};
pub use state::AppState;

pub async fn start(
    config: ControlConfig,
    db: relay_db::Db,
    events: EventBus,
    cert_issuer: Option<std::sync::Arc<CertIssuerCtx>>,
) -> anyhow::Result<()> {
    let state = AppState::new(config, db, events, cert_issuer);
    let bind = state.config.bind_admin;
    let app = build_router(state);

    let listener = TcpListener::bind(bind).await?;
    tracing::info!(addr = %bind, "control plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    routes::router(state)
}
