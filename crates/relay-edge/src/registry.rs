//! In-memory tunnel registry. Maps hostname → active QUIC connection.

use std::sync::Arc;

use dashmap::DashMap;
use quinn::Connection;
use relay_proto::TunnelKind;
use uuid::Uuid;

#[derive(Clone)]
pub struct TunnelHandle {
    pub tunnel_id: Uuid,
    pub org_id: Uuid,
    pub kind: TunnelKind,
    /// Full hostname including the base domain (or `tcp://<addr>` for TCP).
    pub hostname: String,
    pub conn: Connection,
    pub inspect: bool,
    /// For TCP tunnels: the public port this tunnel is bound to.
    pub tcp_port: Option<u16>,
    /// Argon2 PHC string for `--password`-gated HTTP tunnels. `None` means the
    /// tunnel is public. Lives only in memory for the duration of the QUIC
    /// connection — never persisted.
    pub password_hash: Option<String>,
    /// Stable short fingerprint of the raw password, used to bind session
    /// cookies to the current password so that changing the password
    /// invalidates previously issued cookies. `Some` iff `password_hash` is.
    pub password_fingerprint: Option<String>,
}

#[derive(Default)]
pub struct TunnelRegistry {
    by_host: DashMap<String, TunnelHandle>,
}

#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    #[error("hostname already bound: {0}")]
    AlreadyBound(String),
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Insert a new tunnel. Fails if the hostname is already bound.
    pub fn insert(&self, handle: TunnelHandle) -> Result<(), InsertError> {
        let key = handle.hostname.to_ascii_lowercase();
        if self.by_host.contains_key(&key) {
            return Err(InsertError::AlreadyBound(handle.hostname));
        }
        self.by_host.insert(key, handle);
        Ok(())
    }

    /// Look up a tunnel by hostname (case-insensitive, exact match). Used by
    /// internal cleanup paths that already know the exact key.
    pub fn lookup_exact(&self, hostname: &str) -> Option<TunnelHandle> {
        self.by_host.get(&hostname.to_ascii_lowercase()).map(|e| e.clone())
    }

    /// Resolve an incoming public hostname to a tunnel.
    ///
    /// Lookup order:
    ///   1. Exact match.
    ///   2. `*.<host>` — so that binding `*.andrea.<base>` also catches a
    ///      request to the apex `andrea.<base>` (TLS wildcard behavior is
    ///      the opposite, but for tunnels matching the apex is what users
    ///      almost always mean).
    ///   3. Walk labels left-to-right, substituting each with `*`, so
    ///      `api.andrea.<base>` matches a `*.andrea.<base>` binding.
    ///
    /// Exact entries always win over wildcards, so a separate
    /// `andrea.<base>` binding can override the apex behavior of (2).
    pub fn lookup_for_request(&self, hostname: &str) -> Option<TunnelHandle> {
        let host = hostname.to_ascii_lowercase();
        if let Some(h) = self.by_host.get(&host) {
            return Some(h.clone());
        }
        let apex_wild = format!("*.{host}");
        if let Some(h) = self.by_host.get(&apex_wild) {
            return Some(h.clone());
        }
        let mut rest = host.as_str();
        while let Some((_, suffix)) = rest.split_once('.') {
            let wild = format!("*.{suffix}");
            if let Some(h) = self.by_host.get(&wild) {
                return Some(h.clone());
            }
            rest = suffix;
        }
        None
    }

    /// Remove a hostname binding, returning whether anything was removed.
    pub fn remove(&self, hostname: &str) -> bool {
        self.by_host.remove(&hostname.to_ascii_lowercase()).is_some()
    }

    pub fn is_bound(&self, hostname: &str) -> bool {
        self.by_host.contains_key(&hostname.to_ascii_lowercase())
    }

    pub fn active_count(&self) -> usize {
        self.by_host.len()
    }
}
