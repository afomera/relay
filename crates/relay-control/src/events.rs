//! Live event bus — tunnel lifecycle + new-capture notifications.
//!
//! Per-process `tokio::sync::broadcast` channels. Publishers are the
//! `DbTunnelRecorder` and `DbCaptureSink` implementations of the edge's
//! traits (post-persistence). Subscribers are the SSE endpoints in
//! `routes.rs`.
//!
//! When the hosted split happens (edge process ≠ control process), swap
//! `EventBus` for a Redis-pubsub/NATS-backed impl behind the same interface.

use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

const CAPACITY: usize = 256;

#[derive(Clone)]
pub struct EventBus {
    pub tunnels: broadcast::Sender<TunnelLiveEvent>,
    pub captures: broadcast::Sender<CaptureLiveEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            tunnels: broadcast::channel(CAPACITY).0,
            captures: broadcast::channel(CAPACITY).0,
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunnelLiveEvent {
    Active {
        tunnel_id: Uuid,
        org_id: Uuid,
        hostname: String,
        kind: String,
    },
    Disconnected {
        tunnel_id: Uuid,
        org_id: Uuid,
    },
    /// Emitted on every captured request so the tunnels list can refresh
    /// last-seen without each row opening its own capture subscription.
    Touched {
        tunnel_id: Uuid,
        org_id: Uuid,
    },
}

impl TunnelLiveEvent {
    pub fn org_id(&self) -> Uuid {
        match self {
            Self::Active { org_id, .. }
            | Self::Disconnected { org_id, .. }
            | Self::Touched { org_id, .. } => *org_id,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Active { .. } => "active",
            Self::Disconnected { .. } => "disconnected",
            Self::Touched { .. } => "touched",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureLiveEvent {
    pub id: Uuid,
    pub tunnel_id: Uuid,
    pub org_id: Uuid,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub started_at: i64,
}
