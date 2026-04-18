//! RFC2136 dynamic-DNS provider.
//!
//! Stub. Real implementation needs a DNS UDP/TCP client with TSIG signing;
//! `trust-dns-proto` (now `hickory-proto`) is the usual choice. Deferred — see
//! SPEC.md §6.

use async_trait::async_trait;

use crate::{DnsError, DnsProvider};

pub struct Rfc2136Provider {
    pub nameserver: String,
    pub tsig_key_name: String,
    pub tsig_secret_b64: String,
    pub tsig_algo: String,
}

#[async_trait]
impl DnsProvider for Rfc2136Provider {
    async fn upsert_txt(&self, _name: &str, _value: &str) -> Result<(), DnsError> {
        Err(DnsError::NotImplemented)
    }
    async fn delete_txt(&self, _name: &str, _value: &str) -> Result<(), DnsError> {
        Err(DnsError::NotImplemented)
    }
}
