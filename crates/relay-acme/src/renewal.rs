//! Background renewal worker.
//!
//! v1 policy: every hour, scan `certs`. For any row whose `not_after` is within
//! 30 days, call the configured issuer (if one is wired up) to mint a new cert.
//! Freshly issued certs end up in the `certs` table and the cert store refreshes
//! from there.

use std::sync::Arc;
use std::time::Duration;

use relay_db as dao;
use relay_db::Db;
use relay_dns::DnsProvider;

use crate::issue::{IssueOptions, issue_dns01_custom, issue_wildcard};
use crate::store::CertStore;

pub struct RenewalWorker {
    pub db: Db,
    pub dns: Arc<dyn DnsProvider>,
    pub opts: IssueOptions,
    pub data_key_b64: String,
    pub store: Arc<dyn CertStore>,
    /// Zone Relay uses for ACME DNS-01 delegation on custom wildcard
    /// domains. When `None`, verified wildcard custom domains are skipped
    /// at renewal time (logged at warn once per tick).
    pub delegation_zone: Option<String>,
}

impl RenewalWorker {
    /// Run forever: kick an immediate tick on startup so first boot mints
    /// a wildcard cert without waiting an hour, then settle into an hourly
    /// renewal loop.
    pub async fn run(self) -> anyhow::Result<()> {
        if let Err(e) = self.tick().await {
            tracing::warn!(
                e = %format!("{e:#}"),
                "initial renewal tick failed — HTTPS will use the self-signed fallback until the next attempt"
            );
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
        ticker.tick().await; // consume the immediate firing
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick().await {
                tracing::warn!(e = %format!("{e:#}"), "renewal tick failed");
            }
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        let horizon = (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp();
        self.tick_base(horizon).await?;
        self.tick_custom_wildcards(horizon).await?;
        Ok(())
    }

    async fn tick_base(&self, horizon: i64) -> anyhow::Result<()> {
        let wildcard_name = format!("*.{}", self.opts.base_domain);
        let apex_name = self.opts.base_domain.clone();
        // The issued cert carries `*.<temporary_label>.<base>` as a SAN so
        // tunnel URLs like `x.temporary.<base>` validate. rustls's resolver
        // only walks one wildcard level, so we persist a separate row
        // keyed on that name pointing at the same cert material.
        let temporary_name = self
            .opts
            .temporary_label
            .as_ref()
            .map(|label| format!("*.{label}.{}", self.opts.base_domain));

        // The wildcard row is the source of truth for renewal timing; the
        // apex and temporary-wildcard rows are stored alongside it so SNI
        // for the bare apex and `*.<temporary>.<base>` find the same cert
        // material.
        let existing = dao::latest_cert_for(&self.db, &wildcard_name).await?;
        let apex_existing = dao::latest_cert_for(&self.db, &apex_name).await?;
        let temporary_existing = match &temporary_name {
            Some(name) => dao::latest_cert_for(&self.db, name).await?,
            None => None,
        };
        let needs_issuance = match &existing {
            None => true,
            Some(c) => c.not_after < horizon,
        };
        let apex_missing = apex_existing.is_none();
        let temporary_missing = temporary_name.is_some() && temporary_existing.is_none();
        if !needs_issuance && !apex_missing && !temporary_missing {
            return Ok(());
        }

        // If the wildcard is still fresh but the apex or temporary-wildcard
        // rows are missing (e.g. upgraded from a pre-apex or pre-temporary
        // build), backfill them from the existing cert material rather
        // than re-hitting ACME.
        if !needs_issuance {
            if let Some(c) = existing {
                if apex_missing {
                    tracing::info!(hostname = %apex_name, "backfilling apex cert row from existing wildcard cert");
                    dao::upsert_cert(
                        &self.db,
                        &apex_name,
                        &c.cert_chain_pem,
                        &c.key_pem_encrypted,
                        c.not_after,
                    )
                    .await?;
                }
                if temporary_missing {
                    if let Some(name) = &temporary_name {
                        tracing::info!(hostname = %name, "backfilling temporary wildcard cert row from existing wildcard cert");
                        dao::upsert_cert(
                            &self.db,
                            name,
                            &c.cert_chain_pem,
                            &c.key_pem_encrypted,
                            c.not_after,
                        )
                        .await?;
                    }
                }
                self.store.refresh().await?;
            }
            return Ok(());
        }

        tracing::info!(hostname = %wildcard_name, apex = %apex_name, temporary = ?temporary_name, "issuing/renewing wildcard + apex cert via ACME DNS-01");
        let issued = issue_wildcard(&*self.dns, &self.opts, &self.data_key_b64).await?;
        dao::upsert_cert(
            &self.db,
            &wildcard_name,
            &issued.cert_chain_pem,
            &issued.key_pem_encrypted,
            issued.not_after,
        )
        .await?;
        dao::upsert_cert(
            &self.db,
            &apex_name,
            &issued.cert_chain_pem,
            &issued.key_pem_encrypted,
            issued.not_after,
        )
        .await?;
        if let Some(name) = &temporary_name {
            dao::upsert_cert(
                &self.db,
                name,
                &issued.cert_chain_pem,
                &issued.key_pem_encrypted,
                issued.not_after,
            )
            .await?;
        }
        self.store.refresh().await?;
        tracing::info!(hostname = %wildcard_name, apex = %apex_name, temporary = ?temporary_name, "wildcard + apex cert installed");
        Ok(())
    }

    async fn tick_custom_wildcards(&self, horizon: i64) -> anyhow::Result<()> {
        let domains = dao::list_verified_wildcard_domains(&self.db).await?;
        if domains.is_empty() {
            return Ok(());
        }
        let Some(zone) = self.delegation_zone.clone() else {
            tracing::warn!(
                "custom wildcard domains present but [acme].delegation_zone unset — skipping"
            );
            return Ok(());
        };

        for cd in domains {
            let Some(slug) = cd.acme_delegation_slug.as_deref() else {
                tracing::warn!(hostname = %cd.hostname, "wildcard row missing delegation slug; skipping");
                continue;
            };
            let wildcard_name = format!("*.{}", cd.hostname);
            let existing = match dao::latest_cert_for(&self.db, &wildcard_name).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(e = %format!("{e:#}"), hostname = %cd.hostname, "cert lookup failed");
                    continue;
                }
            };
            let apex_existing = match dao::latest_cert_for(&self.db, &cd.hostname).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(e = %format!("{e:#}"), hostname = %cd.hostname, "apex cert lookup failed");
                    continue;
                }
            };
            let needs_issuance = match &existing {
                None => true,
                Some(c) => c.not_after < horizon,
            };
            if !needs_issuance && apex_existing.is_some() {
                continue;
            }

            // Backfill apex row from wildcard material if only the apex is
            // missing (e.g. upgraded from an earlier build that persisted only
            // the wildcard row).
            if !needs_issuance {
                if let Some(c) = existing {
                    tracing::info!(hostname = %cd.hostname, "backfilling apex cert row from wildcard");
                    if let Err(e) = dao::upsert_cert(
                        &self.db,
                        &cd.hostname,
                        &c.cert_chain_pem,
                        &c.key_pem_encrypted,
                        c.not_after,
                    )
                    .await
                    {
                        tracing::warn!(e = %format!("{e:#}"), hostname = %cd.hostname, "apex backfill failed");
                    }
                }
                continue;
            }

            tracing::info!(hostname = %cd.hostname, slug, "renewing custom wildcard cert via DNS-01");
            let opts = IssueOptions {
                acme_directory: self.opts.acme_directory.clone(),
                contact_email: self.opts.contact_email.clone(),
                base_domain: cd.hostname.clone(),
                temporary_label: None,
            };
            match issue_dns01_custom(
                &*self.dns,
                &cd.hostname,
                &zone,
                slug,
                &opts,
                &self.data_key_b64,
            )
            .await
            {
                Ok(issued) => {
                    let r1 = dao::upsert_cert(
                        &self.db,
                        &wildcard_name,
                        &issued.cert_chain_pem,
                        &issued.key_pem_encrypted,
                        issued.not_after,
                    )
                    .await;
                    let r2 = dao::upsert_cert(
                        &self.db,
                        &cd.hostname,
                        &issued.cert_chain_pem,
                        &issued.key_pem_encrypted,
                        issued.not_after,
                    )
                    .await;
                    if let Err(e) = r1.or(r2) {
                        tracing::warn!(e = %format!("{e:#}"), hostname = %cd.hostname, "custom wildcard persist failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(e = %format!("{e:#}"), hostname = %cd.hostname, "custom wildcard issuance failed");
                }
            }
        }
        // One refresh at the end of the loop — individual failures don't
        // block others from being installed.
        let _ = self.store.refresh().await;
        Ok(())
    }
}
