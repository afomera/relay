//! Implementations of `relay_edge::AuthProvider` and `ReservationStore` backed
//! by `relay-db`. Used to wire the edge to real accounts + reservations.

use async_trait::async_trait;
use relay_db::{self as dao, Db};
use relay_edge::{
    AuthError, AuthProvider, CaptureSink, HttpCapture, Principal, RecordError, ReservationError,
    ReservationStore, TunnelEvent, TunnelRecorder,
};
use relay_proto::TunnelKind;
use uuid::Uuid;

use crate::auth::{TOKEN_PREFIX, verify_token};
use crate::events::{CaptureLiveEvent, EventBus, TunnelLiveEvent};

pub struct DbAuthProvider {
    pub db: Db,
}

#[async_trait]
impl AuthProvider for DbAuthProvider {
    async fn authenticate(&self, token: &str) -> Result<Principal, AuthError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(AuthError::InvalidToken);
        }
        let all = dao::list_all_api_tokens(&self.db)
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?;
        for row in all {
            if verify_token(token, &row.hashed_token) {
                let _ = dao::touch_token_use(&self.db, row.id).await;
                return Ok(Principal { org_id: row.org_id, user_id: row.user_id });
            }
        }
        Err(AuthError::InvalidToken)
    }
}

pub struct DbTunnelRecorder {
    pub db: Db,
    pub events: EventBus,
}

#[async_trait]
impl TunnelRecorder for DbTunnelRecorder {
    async fn record_active(&self, evt: TunnelEvent) -> Result<Uuid, RecordError> {
        let kind = match evt.kind {
            TunnelKind::Http => "http",
            TunnelKind::Tcp => "tcp",
            TunnelKind::TlsPassthrough => "tls_passthrough",
        };
        let tunnel_id = dao::upsert_tunnel_by_hostname(
            &self.db,
            evt.org_id,
            kind,
            &evt.hostname,
            &evt.labels,
            evt.inspect,
        )
        .await
        .map_err(|e| RecordError::Other(e.to_string()))?;
        let _ = self.events.tunnels.send(TunnelLiveEvent::Active {
            tunnel_id,
            org_id: evt.org_id,
            hostname: evt.hostname,
            kind: kind.to_string(),
        });
        Ok(tunnel_id)
    }
    async fn record_disconnected(&self, tunnel_id: Uuid) -> Result<(), RecordError> {
        // Fetch org_id before the mark so the event carries enough context for
        // per-org filtering. If the row has already vanished, skip the event.
        let org_id = dao::find_tunnel_org_id(&self.db, tunnel_id).await.ok().flatten();
        dao::mark_tunnel_disconnected(&self.db, tunnel_id)
            .await
            .map_err(|e| RecordError::Other(e.to_string()))?;
        if let Some(org_id) = org_id {
            let _ = self.events.tunnels.send(TunnelLiveEvent::Disconnected { tunnel_id, org_id });
        }
        Ok(())
    }
}

pub struct DbCaptureSink {
    pub db: Db,
    pub events: EventBus,
}

#[async_trait]
impl CaptureSink for DbCaptureSink {
    async fn record(&self, c: HttpCapture) -> Result<(), RecordError> {
        let id = dao::insert_full_capture(
            &self.db,
            c.tunnel_id,
            c.request_id,
            c.started_at_unix,
            c.completed_at_unix,
            &c.method,
            &c.path,
            c.status as i64,
            c.duration_ms as i64,
            &c.req_headers,
            &c.req_body,
            &c.resp_headers,
            &c.resp_body,
            c.truncated,
            &c.client_ip,
        )
        .await
        .map_err(|e| RecordError::Other(e.to_string()))?;
        // Bump the tunnel's last_seen so the dashboard reflects traffic, not
        // just (dis)connects. Failure is non-fatal — don't block capture on it.
        let _ = dao::touch_tunnel_last_seen(&self.db, c.tunnel_id).await;
        // Fanout to the tunnels stream so the home page's SSE subscription
        // can refresh last-seen without per-row capture subscriptions.
        let _ = self
            .events
            .tunnels
            .send(TunnelLiveEvent::Touched { tunnel_id: c.tunnel_id, org_id: c.org_id });
        let _ = self.events.captures.send(CaptureLiveEvent {
            id,
            tunnel_id: c.tunnel_id,
            org_id: c.org_id,
            method: c.method,
            path: c.path,
            status: Some(c.status),
            duration_ms: Some(c.duration_ms),
            started_at: c.started_at_unix,
        });
        Ok(())
    }
}

pub struct DbReservationStore {
    pub db: Db,
    pub base_domain: String,
    /// Ephemeral-subdomain label set; tunnels under the temporary domain
    /// require no reservation (hostname like `foo.temporary.base`).
    pub temporary_label: String,
}

#[async_trait]
impl ReservationStore for DbReservationStore {
    async fn check_hostname(
        &self,
        principal: &Principal,
        hostname: &str,
    ) -> Result<(), ReservationError> {
        // Path 1: hostname ends with .<base_domain> → it's under our apex.
        let suffix = format!(".{}", self.base_domain);
        if let Some(left) = hostname.strip_suffix(&suffix) {
            let parts: Vec<&str> = left.split('.').filter(|p| !p.is_empty()).collect();
            if parts.is_empty() {
                return Err(ReservationError::NotAllowed(hostname.to_string()));
            }

            // Ephemeral: any leaf under <temporary>.<base>.
            // For `foo.temporary.<base>` → parts = ["foo", "temporary"]; the
            // *last* label is the one immediately before the base.
            if parts.len() >= 2 && parts[parts.len() - 1] == self.temporary_label {
                return Ok(());
            }

            // Reservations are single labels. Look up the label adjacent to
            // the base domain — that label "owns" everything to its left.
            let label = parts[parts.len() - 1];
            return match dao::find_reservation_by_label(&self.db, label).await {
                Ok(Some(r)) if r.org_id == principal.org_id => Ok(()),
                Ok(Some(_)) => Err(ReservationError::Reserved(label.to_string())),
                Ok(None) => Err(ReservationError::NotAllowed(hostname.to_string())),
                Err(e) => Err(ReservationError::Other(e.to_string())),
            };
        }

        // Path 2: custom domain — exact match in custom_domains. Any
        // verified row belonging to this principal approves the hostname.
        match dao::find_custom_domain(&self.db, hostname).await {
            Ok(Some(cd)) if cd.org_id == principal.org_id && cd.verified_at.is_some() => {
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => return Err(ReservationError::Other(e.to_string())),
        }

        // Path 3: one-level subdomain of a verified wildcard custom domain.
        // Matches the rustls cert resolver which only tries a single
        // `*.<parent>` wildcard; anything deeper (`a.b.domain.com`) is not
        // covered by the cert we issue, so we refuse it here too.
        if let Some((_, parent)) = hostname.split_once('.') {
            match dao::find_custom_domain(&self.db, parent).await {
                Ok(Some(cd))
                    if cd.org_id == principal.org_id && cd.verified_at.is_some() && cd.wildcard =>
                {
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => return Err(ReservationError::Other(e.to_string())),
            }
        }

        Err(ReservationError::NotAllowed(hostname.to_string()))
    }
}
