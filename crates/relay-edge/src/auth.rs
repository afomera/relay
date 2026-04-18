//! Auth + reservation traits used by the edge during tunnel registration.
//!
//! M1 provides no-op implementations. M2 wires in DB-backed versions.

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Principal {
    /// Organization id (what the tunnel is billed/owned by).
    pub org_id: Uuid,
    /// Specific user (for audit trails).
    pub user_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    InvalidToken,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ReservationError {
    #[error("hostname `{0}` is reserved by another account")]
    Reserved(String),
    #[error("hostname `{0}` is not allowed")]
    NotAllowed(String),
    #[error("{0}")]
    Other(String),
}

use async_trait::async_trait;
use relay_proto::TunnelKind;
use uuid::Uuid as _Uuid;

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, token: &str) -> Result<Principal, AuthError>;
}

/// Record tunnel lifecycle events to durable storage. The edge calls this on
/// register / unregister so the dashboard can show what's live.
///
/// `record_active` returns the canonical `tunnel_id`. DB-backed impls look up
/// an existing row keyed by `(org_id, hostname)` and reuse it; an existing
/// tunnel "reconnects" into the same row (same captures, same history) instead
/// of creating a ghost per reconnection.
#[async_trait]
pub trait TunnelRecorder: Send + Sync {
    async fn record_active(&self, evt: TunnelEvent) -> Result<_Uuid, RecordError>;
    async fn record_disconnected(&self, tunnel_id: _Uuid) -> Result<(), RecordError>;
}

#[derive(Debug, Clone)]
pub struct TunnelEvent {
    pub org_id: _Uuid,
    pub kind: TunnelKind,
    pub hostname: String,
    pub labels: Vec<(String, String)>,
    pub inspect: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{0}")]
    Other(String),
}

pub struct NoopRecorder;

#[async_trait]
impl TunnelRecorder for NoopRecorder {
    async fn record_active(&self, _evt: TunnelEvent) -> Result<_Uuid, RecordError> {
        Ok(_Uuid::new_v4())
    }
    async fn record_disconnected(&self, _tunnel_id: _Uuid) -> Result<(), RecordError> {
        Ok(())
    }
}

/// Persist captured HTTP request+response pairs for the inspector.
#[async_trait]
pub trait CaptureSink: Send + Sync {
    async fn record(&self, capture: HttpCapture) -> Result<(), RecordError>;
}

#[derive(Debug, Clone)]
pub struct HttpCapture {
    pub tunnel_id: _Uuid,
    pub org_id: _Uuid,
    pub request_id: _Uuid,
    pub started_at_unix: i64,
    pub completed_at_unix: i64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub req_headers: Vec<(String, String)>,
    pub req_body: Vec<u8>,
    pub resp_headers: Vec<(String, String)>,
    pub resp_body: Vec<u8>,
    pub truncated: bool,
    pub client_ip: String,
}

pub struct NoopCaptureSink;

#[async_trait]
impl CaptureSink for NoopCaptureSink {
    async fn record(&self, _capture: HttpCapture) -> Result<(), RecordError> {
        Ok(())
    }
}

#[async_trait]
pub trait ReservationStore: Send + Sync {
    /// Check whether `principal` may bind a tunnel to `hostname` (the full
    /// hostname including the base domain). Implementations decide whether
    /// it's a base-domain tunnel or a custom domain.
    async fn check_hostname(
        &self,
        principal: &Principal,
        hostname: &str,
    ) -> Result<(), ReservationError>;
}

/// Dev/test impl: accepts any token, assigns a fixed principal.
pub struct AllowAllAuth {
    pub org_id: Uuid,
    pub user_id: Uuid,
}

impl Default for AllowAllAuth {
    fn default() -> Self {
        Self { org_id: Uuid::nil(), user_id: Uuid::nil() }
    }
}

#[async_trait]
impl AuthProvider for AllowAllAuth {
    async fn authenticate(&self, _token: &str) -> Result<Principal, AuthError> {
        Ok(Principal { org_id: self.org_id, user_id: self.user_id })
    }
}

/// Dev/test impl: allows any hostname.
pub struct AllowAllReservations;

#[async_trait]
impl ReservationStore for AllowAllReservations {
    async fn check_hostname(
        &self,
        _principal: &Principal,
        _hostname: &str,
    ) -> Result<(), ReservationError> {
        Ok(())
    }
}
