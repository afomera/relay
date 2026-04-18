//! Pluggable DNS provider interface, used by `relay-acme` for DNS-01 challenges
//! on the wildcard apex domain (e.g. `*.sharedwithrelay.com`).
//!
//! v1 ships a fully-working Cloudflare implementation. Route53 and RFC2136 have
//! typed stubs — the trait surface is the same so swapping is drop-in.

pub mod cloudflare;
pub mod rfc2136;
pub mod route53;

use async_trait::async_trait;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create or replace a TXT record.
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError>;
    /// Delete a TXT record (by name+value). Idempotent.
    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), DnsError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("dns provider error: {0}")]
    Provider(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("provider not implemented")]
    NotImplemented,
}
