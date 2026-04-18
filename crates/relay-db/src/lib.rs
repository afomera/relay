//! Database layer for relay.
//!
//! Per-engine backends live under `backend::{sqlite, postgres}`. The public
//! API is a flat set of dispatcher fns at crate root that match on `Db` and
//! forward to the right backend. Consumers call `relay_db::create_org(...)`
//! and never see the backend module directly.

pub mod models;
mod backend;

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

pub use sqlx;

use crate::models::*;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("not found")]
    NotFound,
    #[error("unique violation: {0}")]
    UniqueViolation(String),
    #[error("postgres support not implemented in this build")]
    PostgresUnsupported,
}

#[derive(Clone)]
pub enum Db {
    Sqlite(SqlitePool),
}

impl Db {
    /// Connect based on the URL scheme. Supports `sqlite:<path>` / `sqlite::memory:`.
    /// Postgres (`postgres:`, `postgresql:`) returns `PostgresUnsupported`.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        if url.starts_with("sqlite:") {
            let opts: SqliteConnectOptions = url.parse()?;
            let opts = opts.create_if_missing(true).foreign_keys(true);
            let pool = SqlitePoolOptions::new().max_connections(10).connect_with(opts).await?;
            Ok(Self::Sqlite(pool))
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Err(DbError::PostgresUnsupported)
        } else {
            Err(DbError::Sql(sqlx::Error::Configuration(
                format!("unrecognised db url: {url}").into(),
            )))
        }
    }

    pub async fn connect_sqlite_path(path: &Path) -> Result<Self, DbError> {
        let url = format!("sqlite://{}", path.display());
        Self::connect(&url).await
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        match self {
            Db::Sqlite(pool) => {
                sqlx::migrate!("../../migrations").run(pool).await?;
                Ok(())
            }
        }
    }

    pub fn sqlite(&self) -> &SqlitePool {
        match self {
            Db::Sqlite(p) => p,
        }
    }
}

/// Map sqlx "UNIQUE constraint failed" into our domain error.
pub fn map_sqlx_err(e: sqlx::Error) -> DbError {
    let s = format!("{e}");
    if s.contains("UNIQUE constraint failed") || s.contains("duplicate key") {
        DbError::UniqueViolation(s)
    } else if matches!(e, sqlx::Error::RowNotFound) {
        DbError::NotFound
    } else {
        DbError::Sql(e)
    }
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Re-exports commonly used alongside the DAL.
pub mod prelude {
    pub use super::models::*;
    pub use super::{Db, DbError, map_sqlx_err, now_unix};
    pub use sqlx::Sqlite;
    pub use time::OffsetDateTime;
    pub use uuid::Uuid;
}

// ===========================================================================
// DAL dispatchers — flat crate-root API. Each fn matches on `Db` and forwards
// to the selected backend. Keep signatures byte-for-byte in sync with the
// corresponding `backend::*` impls.
// ===========================================================================

// ---- organizations + users + membership -----------------------------------

pub async fn create_org(db: &Db, name: &str, slug: &str) -> Result<Organization, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::create_org(db, name, slug).await,
    }
}

pub async fn find_user_by_github_id(db: &Db, github_id: i64) -> Result<Option<User>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_user_by_github_id(db, github_id).await,
    }
}

pub async fn upsert_github_user(
    db: &Db,
    github_id: i64,
    login: &str,
    email: Option<&str>,
    name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<User, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::upsert_github_user(db, github_id, login, email, name, avatar_url)
                .await
        }
    }
}

pub async fn add_org_member(
    db: &Db,
    org_id: Uuid,
    user_id: Uuid,
    role: Role,
) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::add_org_member(db, org_id, user_id, role).await,
    }
}

pub async fn primary_org_for_user(db: &Db, user_id: Uuid) -> Result<Option<Organization>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::primary_org_for_user(db, user_id).await,
    }
}

// ---- sessions -------------------------------------------------------------

pub async fn create_session(
    db: &Db,
    user_id: Uuid,
    org_id: Uuid,
    ttl_secs: i64,
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::create_session(db, user_id, org_id, ttl_secs).await,
    }
}

pub async fn lookup_session(db: &Db, id: Uuid) -> Result<Option<Session>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::lookup_session(db, id).await,
    }
}

pub async fn delete_session(db: &Db, id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::delete_session(db, id).await,
    }
}

// ---- api tokens -----------------------------------------------------------

pub async fn create_api_token(
    db: &Db,
    org_id: Uuid,
    user_id: Uuid,
    name: &str,
    hashed_token: &str,
    scopes: &str,
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::create_api_token(db, org_id, user_id, name, hashed_token, scopes).await
        }
    }
}

pub async fn list_tokens_for_org(db: &Db, org_id: Uuid) -> Result<Vec<ApiToken>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_tokens_for_org(db, org_id).await,
    }
}

pub async fn delete_token(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::delete_token(db, id, org_id).await,
    }
}

pub async fn find_token_by_hash(db: &Db, hashed: &str) -> Result<Option<ApiToken>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_token_by_hash(db, hashed).await,
    }
}

pub async fn list_all_api_tokens(db: &Db) -> Result<Vec<ApiToken>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_all_api_tokens(db).await,
    }
}

pub async fn touch_token_use(db: &Db, id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::touch_token_use(db, id).await,
    }
}

// ---- reservations ---------------------------------------------------------

pub async fn create_reservation(
    db: &Db,
    org_id: Uuid,
    label: &str,
) -> Result<Reservation, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::create_reservation(db, org_id, label).await,
    }
}

pub async fn list_reservations_for_org(
    db: &Db,
    org_id: Uuid,
) -> Result<Vec<Reservation>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_reservations_for_org(db, org_id).await,
    }
}

pub async fn delete_reservation(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::delete_reservation(db, id, org_id).await,
    }
}

pub async fn find_reservation_by_label(
    db: &Db,
    label: &str,
) -> Result<Option<Reservation>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_reservation_by_label(db, label).await,
    }
}

// ---- tunnels --------------------------------------------------------------

pub async fn upsert_tunnel_by_hostname(
    db: &Db,
    org_id: Uuid,
    kind: &str,
    hostname: &str,
    labels: &[(String, String)],
    inspect: bool,
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::upsert_tunnel_by_hostname(
                db, org_id, kind, hostname, labels, inspect,
            )
            .await
        }
    }
}

pub async fn delete_disconnected_tunnels_for_org(db: &Db, org_id: Uuid) -> Result<u64, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::delete_disconnected_tunnels_for_org(db, org_id).await,
    }
}

pub async fn delete_tunnel_for_org(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::delete_tunnel_for_org(db, id, org_id).await,
    }
}

pub async fn touch_tunnel_last_seen(db: &Db, id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::touch_tunnel_last_seen(db, id).await,
    }
}

pub async fn mark_tunnel_disconnected(db: &Db, id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::mark_tunnel_disconnected(db, id).await,
    }
}

pub async fn mark_all_tunnels_disconnected(db: &Db) -> Result<u64, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::mark_all_tunnels_disconnected(db).await,
    }
}

pub async fn list_tunnels_for_org(db: &Db, org_id: Uuid) -> Result<Vec<Tunnel>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_tunnels_for_org(db, org_id).await,
    }
}

// ---- custom domains -------------------------------------------------------

pub async fn create_custom_domain(
    db: &Db,
    org_id: Uuid,
    hostname: &str,
    verification_token: &str,
) -> Result<CustomDomain, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::create_custom_domain(db, org_id, hostname, verification_token).await
        }
    }
}

pub async fn list_custom_domains(db: &Db, org_id: Uuid) -> Result<Vec<CustomDomain>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_custom_domains(db, org_id).await,
    }
}

pub async fn mark_custom_domain_verified(db: &Db, id: Uuid) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::mark_custom_domain_verified(db, id).await,
    }
}

pub async fn find_custom_domain_for_org(
    db: &Db,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<CustomDomain>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_custom_domain_for_org(db, id, org_id).await,
    }
}

pub async fn find_custom_domain(db: &Db, hostname: &str) -> Result<Option<CustomDomain>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_custom_domain(db, hostname).await,
    }
}

// ---- certs ----------------------------------------------------------------

pub async fn upsert_cert(
    db: &Db,
    hostname: &str,
    cert_chain_pem: &str,
    key_pem_encrypted: &str,
    not_after: i64,
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::upsert_cert(db, hostname, cert_chain_pem, key_pem_encrypted, not_after)
                .await
        }
    }
}

pub async fn latest_cert_for(db: &Db, hostname: &str) -> Result<Option<Cert>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::latest_cert_for(db, hostname).await,
    }
}

pub async fn list_all_certs(db: &Db) -> Result<Vec<Cert>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_all_certs(db).await,
    }
}

// ---- inspection captures --------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn insert_full_capture(
    db: &Db,
    tunnel_id: Uuid,
    request_id: Uuid,
    started_at: i64,
    completed_at: i64,
    method: &str,
    path: &str,
    status: i64,
    duration_ms: i64,
    req_headers: &[(String, String)],
    req_body: &[u8],
    resp_headers: &[(String, String)],
    resp_body: &[u8],
    truncated: bool,
    client_ip: &str,
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::insert_full_capture(
                db,
                tunnel_id,
                request_id,
                started_at,
                completed_at,
                method,
                path,
                status,
                duration_ms,
                req_headers,
                req_body,
                resp_headers,
                resp_body,
                truncated,
                client_ip,
            )
            .await
        }
    }
}

pub async fn find_tunnel_for_org(
    db: &Db,
    org_id: Uuid,
    tunnel_id: Uuid,
) -> Result<Option<Tunnel>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::find_tunnel_for_org(db, org_id, tunnel_id).await,
    }
}

pub async fn insert_capture(
    db: &Db,
    tunnel_id: Uuid,
    request_id: Uuid,
    method: &str,
    path: &str,
    req_headers: &[(String, String)],
) -> Result<Uuid, DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::insert_capture(db, tunnel_id, request_id, method, path, req_headers)
                .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn complete_capture(
    db: &Db,
    id: Uuid,
    status: i64,
    duration_ms: i64,
    resp_headers: &[(String, String)],
    req_body: Option<&[u8]>,
    resp_body: Option<&[u8]>,
    truncated: bool,
) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => {
            backend::sqlite::complete_capture(
                db,
                id,
                status,
                duration_ms,
                resp_headers,
                req_body,
                resp_body,
                truncated,
            )
            .await
        }
    }
}

pub async fn list_captures(
    db: &Db,
    tunnel_id: Uuid,
    limit: i64,
) -> Result<Vec<InspectionCapture>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::list_captures(db, tunnel_id, limit).await,
    }
}

pub async fn get_capture(db: &Db, id: Uuid) -> Result<Option<InspectionCapture>, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::get_capture(db, id).await,
    }
}

pub async fn clear_captures_for_tunnel(db: &Db, tunnel_id: Uuid) -> Result<u64, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::clear_captures_for_tunnel(db, tunnel_id).await,
    }
}

pub async fn prune_captures(db: &Db, older_than: i64) -> Result<u64, DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::prune_captures(db, older_than).await,
    }
}

// ---- audit ----------------------------------------------------------------

pub async fn log_audit(
    db: &Db,
    org_id: Uuid,
    actor_user_id: Option<Uuid>,
    kind: &str,
    payload: &serde_json::Value,
) -> Result<(), DbError> {
    match db {
        Db::Sqlite(_) => backend::sqlite::log_audit(db, org_id, actor_user_id, kind, payload).await,
    }
}
