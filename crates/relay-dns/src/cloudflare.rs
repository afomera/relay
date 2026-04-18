//! Cloudflare DNS provider.
//!
//! Talks to the Cloudflare v4 API. Requires:
//!   * An API token with `Zone:DNS:Edit` on the target zone.
//!   * The zone id.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{DnsError, DnsProvider};

pub struct CloudflareProvider {
    pub api_token: String,
    pub zone_id: String,
    client: reqwest::Client,
}

impl CloudflareProvider {
    pub fn new(api_token: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            api_token: api_token.into(),
            zone_id: zone_id.into(),
            client: reqwest::Client::new(),
        }
    }

    fn url(&self, suffix: &str) -> String {
        format!("https://api.cloudflare.com/client/v4/zones/{}{}", self.zone_id, suffix)
    }

    async fn find_record(&self, name: &str, value: &str) -> Result<Option<String>, DnsError> {
        let url = self.url(&format!("/dns_records?type=TXT&name={}", urlencoding::encode(name)));
        let resp: CfListResp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(DnsError::Provider(format!("{:?}", resp.errors)));
        }
        for rec in resp.result {
            if rec.content.trim_matches('"') == value {
                return Ok(Some(rec.id));
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
        // Cloudflare TXT values must be quoted on the wire. Their API stores
        // the raw value; we send it as-is.
        let body = json!({
            "type": "TXT",
            "name": name,
            "content": value,
            "ttl": 120,
        });

        // If a record with the same name+value already exists, we're done.
        if self.find_record(name, value).await?.is_some() {
            return Ok(());
        }

        let url = self.url("/dns_records");
        let resp: CfWriteResp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if !resp.success {
            return Err(DnsError::Provider(format!("{:?}", resp.errors)));
        }
        Ok(())
    }

    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), DnsError> {
        let Some(id) = self.find_record(name, value).await? else {
            return Ok(());
        };
        let url = self.url(&format!("/dns_records/{id}"));
        self.client
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CfListResp {
    success: bool,
    errors: Vec<serde_json::Value>,
    result: Vec<CfRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfWriteResp {
    success: bool,
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfRecord {
    id: String,
    content: String,
}
