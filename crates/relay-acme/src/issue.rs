//! ACME wildcard issuance via DNS-01.
//!
//! Hits whatever ACME directory is configured; defaults to Let's Encrypt prod.
//! Uses `instant-acme` for the protocol and `rcgen` for CSR generation so we
//! own the generated private key (and can encrypt it at rest).

use std::sync::Arc;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use relay_dns::DnsProvider;

use crate::encrypt::{decode_data_key, encrypt_key};
use crate::http01::Http01Pending;

#[derive(Debug)]
pub struct IssuedCert {
    pub cert_chain_pem: String,
    pub key_pem_encrypted: String,
    pub not_after: i64,
}

#[derive(Debug, Clone)]
pub struct IssueOptions {
    pub acme_directory: String,
    pub contact_email: String,
    /// Base domain, e.g. `sharedwithrelay.com`. Wildcard becomes `*.<base>`.
    pub base_domain: String,
    /// Ephemeral subdomain label (e.g. `temporary`). Second wildcard:
    /// `*.temporary.<base>`.
    pub temporary_label: Option<String>,
}

impl Default for IssueOptions {
    fn default() -> Self {
        Self {
            acme_directory: "https://acme-v02.api.letsencrypt.org/directory".into(),
            contact_email: "admin@example.com".into(),
            base_domain: "example.com".into(),
            temporary_label: Some("temporary".into()),
        }
    }
}

/// Obtain a wildcard certificate for `*.base_domain` (+ optional
/// `*.temporary.base_domain`) via ACME DNS-01. The resulting private key is
/// encrypted at rest with `data_key_b64`.
pub async fn issue_wildcard(
    dns: &dyn DnsProvider,
    opts: &IssueOptions,
    data_key_b64: &str,
) -> anyhow::Result<IssuedCert> {
    let data_key = decode_data_key(data_key_b64)?;

    tracing::info!(
        directory = %opts.acme_directory,
        domain = %opts.base_domain,
        "creating ACME account"
    );
    let contact = format!("mailto:{}", opts.contact_email);
    let (account, _creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            opts.acme_directory.clone(),
            None,
        )
        .await?;

    // Identifiers.
    let mut idents = vec![Identifier::Dns(opts.base_domain.clone())];
    if let Some(eph) = &opts.temporary_label {
        idents.push(Identifier::Dns(format!("{eph}.{}", opts.base_domain)));
    }

    let mut order = account.new_order(&NewOrder::new(&idents)).await?;

    // Publish DNS-01 challenges for each authorization in two phases:
    // upsert every TXT first, give Cloudflare's edge a moment to settle,
    // THEN mark each challenge ready. If we mark ready in the same loop
    // as upsert, ACME's validators race the DNS write and the order
    // flips to Invalid before the record is visible. ChallengeHandle
    // borrows from Order, so we can't stash handles across the sleep —
    // instead we re-iterate authorizations for the set_ready pass.
    let mut published: Vec<(String, String)> = Vec::new();
    {
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result?;
            if !matches!(authz.status, AuthorizationStatus::Pending) {
                continue;
            }
            let Some(challenge) = authz.challenge(ChallengeType::Dns01) else {
                anyhow::bail!("ACME did not offer a dns-01 challenge");
            };
            let apex = match challenge.identifier().identifier {
                Identifier::Dns(n) => n.clone(),
                _ => anyhow::bail!("unsupported identifier type"),
            };
            let record = format!("_acme-challenge.{apex}");
            let dns_value = challenge.key_authorization().dns_value();
            tracing::info!(%record, "publishing ACME challenge");
            dns.upsert_txt(&record, &dns_value).await?;
            published.push((record, dns_value));
        }
    }
    // Everything after the TXT upserts is wrapped so a single cleanup
    // pass at the bottom deletes records regardless of success/failure.
    // Without this, repeated failures (e.g. bad timing) left orphan TXTs
    // piling up under `_acme-challenge.<apex>`.
    let result: anyhow::Result<(String, rcgen::KeyPair)> = async {
        // Let's Encrypt runs multi-perspective validation from 4+ regions;
        // Cloudflare's edge can take ~15-30s to propagate an API write to
        // every PoP. 30s keeps us comfortably past that window.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        {
            let mut authzs = order.authorizations();
            while let Some(authz_result) = authzs.next().await {
                let mut authz = authz_result?;
                if !matches!(authz.status, AuthorizationStatus::Pending) {
                    continue;
                }
                let Some(mut challenge) = authz.challenge(ChallengeType::Dns01) else {
                    anyhow::bail!("ACME did not offer a dns-01 challenge");
                };
                challenge.set_ready().await?;
            }
        }

        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if !matches!(status, OrderStatus::Ready) {
            // Pull authz details so the log explains what LE actually saw,
            // rather than a bare "Invalid".
            let mut authzs = order.authorizations();
            while let Some(authz_result) = authzs.next().await {
                match authz_result {
                    Ok(authz) => {
                        let ident = authz.identifier();
                        let chal = authz
                            .challenges
                            .iter()
                            .find(|c| matches!(c.r#type, ChallengeType::Dns01));
                        tracing::warn!(
                            identifier = ?ident,
                            status = ?authz.status,
                            challenge_status = ?chal.map(|c| c.status),
                            error = ?chal.and_then(|c| c.error.as_ref()),
                            "ACME authz diagnostic"
                        );
                    }
                    Err(e) => tracing::warn!(?e, "failed to fetch authz on invalid order"),
                }
            }
            anyhow::bail!("ACME order did not reach Ready state: {status:?}");
        }

        let kp = rcgen::KeyPair::generate()?;
        let sans: Vec<String> = idents
            .iter()
            .map(|i| {
                let Identifier::Dns(n) = i else { unreachable!() };
                format!("*.{n}")
            })
            .collect();
        let mut params = rcgen::CertificateParams::new(sans.clone())?;
        // rcgen's default Subject CN is "rcgen self signed cert"; Let's
        // Encrypt treats the CSR's CN as an identifier and rejects that
        // literal string. Pin it to a SAN so the CN is an identified domain.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, sans[0].clone());
        let csr = params.serialize_request(&kp)?;
        order.finalize_csr(csr.der()).await?;

        let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok((chain_pem, kp))
    }
    .await;

    // Always clean up TXT records — orphan cleanup for failures, normal
    // cleanup for success. Errors here are logged but don't mask the real
    // issuance result.
    for (name, value) in &published {
        if let Err(e) = dns.delete_txt(name, value).await {
            tracing::warn!(?e, %name, "failed to delete ACME TXT record");
        }
    }

    let (chain_pem, kp) = result?;

    // Without pulling in an x509 parser we approximate not_after. Let's Encrypt
    // issues 90-day certs; the renewal worker just uses its own 30-day horizon
    // based on this stored value.
    let not_after = (time::OffsetDateTime::now_utc() + time::Duration::days(60)).unix_timestamp();

    let key_pem_encrypted = encrypt_key(&data_key, kp.serialize_pem().as_bytes());
    Ok(IssuedCert { cert_chain_pem: chain_pem, key_pem_encrypted, not_after })
}

/// Issue a certificate for a single hostname via ACME HTTP-01. The caller
/// must have the edge serving `/.well-known/acme-challenge/*` from
/// `pending` on port 80 so the ACME server can validate the token.
pub async fn issue_http01(
    pending: &Arc<Http01Pending>,
    hostname: &str,
    opts: &IssueOptions,
    data_key_b64: &str,
) -> anyhow::Result<IssuedCert> {
    let data_key = decode_data_key(data_key_b64)?;

    let contact = format!("mailto:{}", opts.contact_email);
    let (account, _creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            opts.acme_directory.clone(),
            None,
        )
        .await?;

    let idents = [Identifier::Dns(hostname.to_string())];
    let mut order = account.new_order(&NewOrder::new(&idents)).await?;

    let mut placed_tokens: Vec<String> = Vec::new();
    {
        let mut authzs = order.authorizations();
        while let Some(result) = authzs.next().await {
            let mut authz = result?;
            if !matches!(authz.status, AuthorizationStatus::Pending) {
                continue;
            }
            let Some(mut challenge) = authz.challenge(ChallengeType::Http01) else {
                anyhow::bail!("ACME did not offer an http-01 challenge");
            };
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();
            tracing::info!(%hostname, "publishing ACME HTTP-01 challenge");
            pending.put(&token, &key_auth);
            placed_tokens.push(token);
            challenge.set_ready().await?;
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    // Always clean up pending entries, even on failure.
    let cleanup = |pending: &Arc<Http01Pending>| {
        for t in &placed_tokens {
            pending.remove(t);
        }
    };
    if !matches!(status, OrderStatus::Ready) {
        cleanup(pending);
        anyhow::bail!("ACME order did not reach Ready state: {status:?}");
    }

    let kp = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])?;
    // See the DNS-01 path for why we clear rcgen's default CN.
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
    let csr = params.serialize_request(&kp)?;
    if let Err(e) = order.finalize_csr(csr.der()).await {
        cleanup(pending);
        return Err(e.into());
    }

    let chain_pem = match order.poll_certificate(&RetryPolicy::default()).await {
        Ok(pem) => pem,
        Err(e) => {
            cleanup(pending);
            return Err(e.into());
        }
    };
    cleanup(pending);

    let not_after = (time::OffsetDateTime::now_utc() + time::Duration::days(60)).unix_timestamp();
    let key_pem_encrypted = encrypt_key(&data_key, kp.serialize_pem().as_bytes());
    Ok(IssuedCert { cert_chain_pem: chain_pem, key_pem_encrypted, not_after })
}
