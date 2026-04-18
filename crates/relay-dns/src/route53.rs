//! AWS Route53 DNS provider.
//!
//! Stub. Wiring this up means:
//!   1. Depending on `aws-sdk-route53`.
//!   2. Implementing `ChangeResourceRecordSets` with `UPSERT` / `DELETE` actions.
//!   3. Polling `GetChange` until `INSYNC` so ACME sees the TXT before validating.
//!
//! Intentionally not implemented yet so we don't lock in an AWS SDK dep we
//! don't use in production self-hosts.

use async_trait::async_trait;

use crate::{DnsError, DnsProvider};

pub struct Route53Provider {
    pub hosted_zone_id: String,
}

#[async_trait]
impl DnsProvider for Route53Provider {
    async fn upsert_txt(&self, _name: &str, _value: &str) -> Result<(), DnsError> {
        Err(DnsError::NotImplemented)
    }
    async fn delete_txt(&self, _name: &str, _value: &str) -> Result<(), DnsError> {
        Err(DnsError::NotImplemented)
    }
}
