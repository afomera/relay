//! Cert store: loads certs from the DB (decrypting private keys), caches them
//! in memory for rustls's sync `ResolvesServerCert` callback.

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use relay_db::Db;
use relay_db as dao;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::sign::CertifiedKey;

use crate::encrypt::decrypt_key;

#[async_trait]
pub trait CertStore: Send + Sync {
    /// Refresh the in-memory cache from the backing store.
    async fn refresh(&self) -> anyhow::Result<()>;
    /// Best-effort lookup for a hostname (must not block). Returns `None` on miss.
    fn lookup(&self, hostname: &str) -> Option<Arc<CertifiedKey>>;
}

/// DB-backed cert store. Holds an in-memory cache keyed by hostname.
pub struct DbCertStore {
    pub db: Db,
    pub data_key: [u8; 32],
    cache: DashMap<String, Arc<CertifiedKey>>,
    provider: Arc<CryptoProvider>,
}

impl DbCertStore {
    pub fn new(db: Db, data_key: [u8; 32]) -> Self {
        Self {
            db,
            data_key,
            cache: DashMap::new(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    pub fn install(self: Arc<Self>, hostname: String, ck: Arc<CertifiedKey>) {
        self.cache.insert(hostname, ck);
    }
}

#[async_trait]
impl CertStore for DbCertStore {
    async fn refresh(&self) -> anyhow::Result<()> {
        let rows = dao::list_all_certs(&self.db).await?;
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            seen.insert(row.hostname.clone());
            match load(&self.data_key, &self.provider, &row) {
                Ok(ck) => {
                    self.cache.insert(row.hostname.clone(), Arc::new(ck));
                }
                Err(e) => tracing::warn!(?e, host = %row.hostname, "cert load failed"),
            }
        }
        // Evict entries that vanished from the DB.
        self.cache.retain(|k, _| seen.contains(k));
        Ok(())
    }

    fn lookup(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        self.cache.get(hostname).map(|e| e.clone())
    }
}

fn load(
    data_key: &[u8; 32],
    provider: &CryptoProvider,
    row: &relay_db::models::Cert,
) -> anyhow::Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(row.cert_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        anyhow::bail!("empty cert chain for {}", row.hostname);
    }
    let key_pem = decrypt_key(data_key, &row.key_pem_encrypted)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| anyhow::anyhow!("decode key pem: {e}"))?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| anyhow::anyhow!("rustls key load: {e}"))?;
    Ok(CertifiedKey::new(chain, signing_key))
}
