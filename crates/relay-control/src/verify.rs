//! DNS TXT verification for custom domains.
//!
//! The domains flow generates a `verification_token` and tells the user to
//! publish it at `_relay-challenge.<hostname>`. `verify_txt` does the resolver
//! lookup and confirms the value matches.
//!
//! Uses hickory-resolver with its default (Cloudflare + Google public DNS)
//! configuration so results don't depend on the host's `/etc/resolv.conf`.

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

pub const TXT_PREFIX: &str = "_relay-challenge.";

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("DNS lookup failed: {0}")]
    Lookup(String),
    #[error("no TXT record found at {0}")]
    Missing(String),
    #[error("TXT record present but value doesn't match (waiting for DNS propagation?)")]
    Mismatch,
}

pub async fn verify_txt(hostname: &str, expected: &str) -> Result<(), VerifyError> {
    let record = format!("{TXT_PREFIX}{hostname}");
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = resolver
        .txt_lookup(&record)
        .await
        .map_err(|e| match e.kind() {
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
