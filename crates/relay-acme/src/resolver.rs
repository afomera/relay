//! rustls `ResolvesServerCert` backed by an async cert store's in-memory cache.
//!
//! Because `resolve` is synchronous, we rely on a background task calling
//! `CertStore::refresh` to keep the cache warm. A fallback cert is used when
//! no match is found (typically the dev self-signed wildcard).

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::store::CertStore;

pub struct CertResolver {
    pub store: Arc<dyn CertStore>,
    pub fallback: Arc<CertifiedKey>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        if let Some(hit) = self.store.lookup(sni) {
            return Some(hit);
        }
        // Try wildcard match: `foo.bar.example.com` → `*.bar.example.com`.
        if let Some((_, rest)) = sni.split_once('.') {
            let wildcard = format!("*.{rest}");
            if let Some(hit) = self.store.lookup(&wildcard) {
                return Some(hit);
            }
        }
        Some(self.fallback.clone())
    }
}
