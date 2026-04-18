//! Domain types mapped to DB rows.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub github_id: i64,
    pub login: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct OrgMember {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiToken {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub hashed_token: String,
    pub scopes: String,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct Reservation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub label: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct Tunnel {
    pub id: Uuid,
    pub org_id: Uuid,
    pub kind: String,
    pub hostname: String,
    pub state: String,
    pub labels_json: String,
    pub inspect: bool,
    pub created_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct CustomDomain {
    pub id: Uuid,
    pub org_id: Uuid,
    pub hostname: String,
    pub verification_token: String,
    pub verified_at: Option<i64>,
    pub cert_id: Option<Uuid>,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct Cert {
    pub id: Uuid,
    pub hostname: String,
    pub not_after: i64,
    pub cert_chain_pem: String,
    pub key_pem_encrypted: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct InspectionCapture {
    pub id: Uuid,
    pub tunnel_id: Uuid,
    pub request_id: Uuid,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub method: String,
    pub path: String,
    pub status: Option<i64>,
    pub duration_ms: Option<i64>,
    pub req_headers_json: String,
    pub req_body: Option<Vec<u8>>,
    pub resp_headers_json: Option<String>,
    pub resp_body: Option<Vec<u8>>,
    pub truncated: bool,
    pub client_ip: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
}
