//! Background renewal worker.
//!
//! v1 policy: every hour, scan `certs`. For any row whose `not_after` is within
//! 30 days, call the configured issuer (if one is wired up) to mint a new cert.
//! Freshly issued certs end up in the `certs` table and the cert store refreshes
//! from there.

use std::sync::Arc;
use std::time::Duration;

use relay_db::Db;
use relay_db as dao;
use relay_dns::DnsProvider;

use crate::issue::{IssueOptions, issue_wildcard};
use crate::store::CertStore;

pub struct RenewalWorker {
    pub db: Db,
    pub dns: Arc<dyn DnsProvider>,
    pub opts: IssueOptions,
    pub data_key_b64: String,
    pub store: Arc<dyn CertStore>,
}

impl RenewalWorker {
    /// Run forever: kick an immediate tick on startup so first boot mints
    /// a wildcard cert without waiting an hour, then settle into an hourly
    /// renewal loop.
    pub async fn run(self) -> anyhow::Result<()> {
        if let Err(e) = self.tick().await {
            tracing::warn!(
                ?e,
                "initial renewal tick failed — HTTPS will use the self-signed fallback until the next attempt"
            );
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
        ticker.tick().await; // consume the immediate firing
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick().await {
                tracing::warn!(?e, "renewal tick failed");
            }
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        let wildcard_name = format!("*.{}", self.opts.base_domain);
        let horizon = (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp();

        let existing = dao::latest_cert_for(&self.db, &wildcard_name).await?;
        let needs_issuance = match &existing {
            None => true,
            Some(c) => c.not_after < horizon,
        };
        if !needs_issuance {
            return Ok(());
        }

        tracing::info!(hostname = %wildcard_name, "issuing/renewing wildcard cert via ACME DNS-01");
        let issued = issue_wildcard(&*self.dns, &self.opts, &self.data_key_b64).await?;
        dao::upsert_cert(
            &self.db,
            &wildcard_name,
            &issued.cert_chain_pem,
            &issued.key_pem_encrypted,
            issued.not_after,
        )
        .await?;
        self.store.refresh().await?;
        tracing::info!(hostname = %wildcard_name, "wildcard cert installed");
        Ok(())
    }
}
