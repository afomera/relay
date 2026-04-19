//! Ties together the ACME issuance pieces for custom domains.
//!
//! Wired from `relay-server`'s prod boot path. The `verify_domain` route
//! clones the Arc'd `CertIssuerCtx` and spawns an `ensure_cert` task after
//! DNS verification succeeds, so the cert is ready by the time the user's
//! first HTTPS request arrives at `tunnel.mycompany.com`.
//!
//! Apex-only domains (`wildcard = false`) use HTTP-01. Wildcard domains
//! (`wildcard = true`) use DNS-01 with CNAME delegation — see
//! `relay_acme::issue::issue_dns01_custom` for the shape of that flow.

use std::sync::Arc;

use relay_acme::{CertStore, Http01Pending, IssueOptions, issue_dns01_custom, issue_http01};
use relay_db as dao;
use relay_db::Db;
use relay_dns::DnsProvider;

pub struct CertIssuerCtx {
    pub db: Db,
    pub http01: Arc<Http01Pending>,
    pub store: Arc<dyn CertStore>,
    pub acme_directory: String,
    pub contact_email: String,
    pub data_key_b64: String,
    /// DNS provider used when a wildcard custom domain needs a DNS-01 cert.
    /// Required for wildcard issuance; None means wildcard domains can't be
    /// issued (apex HTTP-01 still works).
    pub dns: Option<Arc<dyn DnsProvider>>,
    /// Delegation zone, e.g. `acme-delegate.withrelay.dev`. Must be paired
    /// with `dns`. Ignored for the HTTP-01 path.
    pub delegation_zone: Option<String>,
}

impl CertIssuerCtx {
    /// Issue a cert for `hostname`, persist it, and refresh the cert store
    /// cache. Idempotent — skips when a cert is already present and > 30
    /// days from expiry. Dispatches to HTTP-01 for apex-only custom domains
    /// (the caller passes `None` for `wildcard_slug`) or to DNS-01 with
    /// delegation when `wildcard_slug` is `Some(_)`.
    pub async fn ensure_cert(
        &self,
        hostname: &str,
        wildcard_slug: Option<&str>,
    ) -> anyhow::Result<()> {
        // For wildcard mode, timing-check the wildcard row (`*.<hostname>`);
        // for apex-only, the hostname row. Both entries share a not_after.
        let check_key =
            if wildcard_slug.is_some() { format!("*.{hostname}") } else { hostname.to_string() };
        if let Ok(Some(existing)) = dao::latest_cert_for(&self.db, &check_key).await {
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

        let issued = match wildcard_slug {
            None => {
                tracing::info!(%hostname, "issuing HTTP-01 cert (apex-only)");
                issue_http01(&self.http01, hostname, &opts, &self.data_key_b64).await?
            }
            Some(slug) => {
                let dns = self
                    .dns
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("wildcard cert requires [dns] provider"))?;
                let zone = self.delegation_zone.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "wildcard cert requires [acme].delegation_zone to be configured"
                    )
                })?;
                tracing::info!(%hostname, slug, zone, "issuing DNS-01 wildcard cert (delegated)");
                issue_dns01_custom(&**dns, hostname, zone, slug, &opts, &self.data_key_b64).await?
            }
        };

        // Apex row first — that's what the caller's request will hit if SNI
        // matches the bare hostname. For wildcard mode also persist the
        // `*.<hostname>` row so one-level SNI lookups find the same cert.
        dao::upsert_cert(
            &self.db,
            hostname,
            &issued.cert_chain_pem,
            &issued.key_pem_encrypted,
            issued.not_after,
        )
        .await?;
        if wildcard_slug.is_some() {
            let wild = format!("*.{hostname}");
            dao::upsert_cert(
                &self.db,
                &wild,
                &issued.cert_chain_pem,
                &issued.key_pem_encrypted,
                issued.not_after,
            )
            .await?;
        }
        self.store.refresh().await?;
        tracing::info!(%hostname, "cert installed");
        Ok(())
    }
}
