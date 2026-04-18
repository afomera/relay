use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use base64::Engine as _;

use crate::config::ControlConfig;
use relay_db::Db;

/// Cheaply cloneable — `Db` is an Arc-wrapped pool, `Key` is an Arc-wrapped
/// byte slice, `ControlConfig` is `Clone`.
use std::sync::Arc;

use crate::cert_issuer::CertIssuerCtx;
use crate::events::EventBus;

#[derive(Clone)]
pub struct AppState {
    pub config: ControlConfig,
    pub db: Db,
    pub cookie_key: Key,
    pub events: EventBus,
    /// `None` in dev or when ACME/DNS aren't configured — verify succeeds but
    /// no cert is issued. `Some` in prod: verify spawns a background
    /// `ensure_cert` task so HTTPS is ready by the time the user hits the URL.
    pub cert_issuer: Option<Arc<CertIssuerCtx>>,
}

impl AppState {
    pub fn new(
        config: ControlConfig,
        db: Db,
        events: EventBus,
        cert_issuer: Option<Arc<CertIssuerCtx>>,
    ) -> Self {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&config.data_key_b64)
            .expect("RELAY_DATA_KEY must be valid base64");
        assert!(raw.len() >= 32, "RELAY_DATA_KEY must be at least 32 bytes");
        let mut material = raw.clone();
        while material.len() < 64 {
            material.extend_from_slice(&raw);
        }
        let cookie_key = Key::from(&material);
        Self { config, db, cookie_key, events, cert_issuer }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
