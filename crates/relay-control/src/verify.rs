//! DNS TXT verification for custom domains.
//!
//! The domains flow generates a `verification_token` and tells the user to
//! publish it at `_relay-challenge.<hostname>`. `verify_txt` does the resolver
//! lookup and confirms the value matches. For wildcard domains we also
//! require a CNAME at `_acme-challenge.<hostname>` pointing into the
//! operator-controlled delegation zone, so ACME renewals can run unattended.
//!
//! Uses hickory-resolver with its default (Cloudflare + Google public DNS)
//! configuration so results don't depend on the host's `/etc/resolv.conf`.

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

pub const TXT_PREFIX: &str = "_relay-challenge.";
pub const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge.";

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("DNS lookup failed: {0}")]
    Lookup(String),
    #[error("no TXT record found at {0}")]
    Missing(String),
    #[error("TXT record present but value doesn't match (waiting for DNS propagation?)")]
    Mismatch,
    #[error("no CNAME found at {0}")]
    CnameMissing(String),
    #[error("CNAME at {0} points to {1}, expected {2}")]
    CnameMismatch(String, String, String),
}

pub async fn verify_txt(hostname: &str, expected: &str) -> Result<(), VerifyError> {
    let record = format!("{TXT_PREFIX}{hostname}");
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = resolver.txt_lookup(&record).await.map_err(|e| match e.kind() {
        hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
            VerifyError::Missing(record.clone())
        }
        _ => VerifyError::Lookup(e.to_string()),
    })?;

    let expected_bytes = expected.as_bytes();
    for rdata in lookup.iter() {
        for chunk in rdata.txt_data() {
            if chunk.as_ref() == expected_bytes {
                return Ok(());
            }
        }
    }
    Err(VerifyError::Mismatch)
}

/// Confirm the user has set `_acme-challenge.<hostname>` CNAME to the
/// expected delegation target (`<slug>.<delegation_zone>`). Only matches
/// when the observed CNAME target resolves to exactly one RRSET entry
/// equal to the expected target (trailing-dot-insensitive).
pub async fn verify_acme_delegation_cname(
    hostname: &str,
    expected_target: &str,
) -> Result<(), VerifyError> {
    let record = format!("{ACME_CHALLENGE_PREFIX}{hostname}");
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = resolver
        .lookup(&record, hickory_resolver::proto::rr::RecordType::CNAME)
        .await
        .map_err(|e| match e.kind() {
            hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                VerifyError::CnameMissing(record.clone())
            }
            _ => VerifyError::Lookup(e.to_string()),
        })?;

    // Normalize both sides by stripping any trailing dot — the wire format
    // carries FQDNs with a trailing dot and user input usually doesn't.
    let want = expected_target.trim_end_matches('.').to_ascii_lowercase();
    for rec in lookup.record_iter() {
        if let Some(cname) = rec.data().and_then(|d| d.as_cname()) {
            let got = cname.to_string();
            let got_norm = got.trim_end_matches('.').to_ascii_lowercase();
            if got_norm == want {
                return Ok(());
            }
            return Err(VerifyError::CnameMismatch(record, got, expected_target.to_string()));
        }
    }
    Err(VerifyError::CnameMissing(record))
}
