//! Ties together the ACME HTTP-01 issuance pieces for custom domains.
//!
//! Wired from `relay-server`'s prod boot path. The `verify_domain` route
//! clones the Arc'd `CertIssuerCtx` and spawns an `ensure_cert` task after
//! DNS verification succeeds, so the cert is ready by the time the user's
//! first HTTPS request arrives at `tunnel.mycompany.com`.

use std::sync::Arc;

use relay_acme::{CertStore, Http01Pending, IssueOptions, issue_http01};
use relay_db::Db;
use relay_db as dao;

pub struct CertIssuerCtx {
    pub db: Db,
    pub http01: Arc<Http01Pending>,
    pub store: Arc<dyn CertStore>,
    pub acme_directory: String,
    pub contact_email: String,
    pub data_key_b64: String,
}

impl CertIssuerCtx {
    /// Issue an HTTP-01 cert for `hostname`, persist it, and refresh the
    /// cert store cache. Idempotent — skips when a cert is already present
    /// and > 30 days from expiry.
    pub async fn ensure_cert(&self, hostname: &str) -> anyhow::Result<()> {
        if let Ok(Some(existing)) = dao::latest_cert_for(&self.db, hostname).await {
            let horizon =
                (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp();
            if existing.not_after > horizon {
                tracing::debug!(%hostname, "cert already valid, skipping issuance");
                return Ok(());
            }
        }

        let opts = IssueOptions {
            acme_directory: self.acme_directory.clone(),
            contact_email: self.contact_email.clone(),
            base_domain: hostname.to_string(),
            temporary_label: None,
        };

        tracing::info!(%hostname, "issuing HTTP-01 cert");
        let issued = issue_http01(&self.http01, hostname, &opts, &self.data_key_b64).await?;
        dao::upsert_cert(
            &self.db,
            hostname,
            &issued.cert_chain_pem,
            &issued.key_pem_encrypted,
            issued.not_after,
        )
        .await?;
        self.store.refresh().await?;
        tracing::info!(%hostname, "HTTP-01 cert installed");
        Ok(())
    }
}
