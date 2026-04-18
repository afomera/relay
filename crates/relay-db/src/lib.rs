//! Database layer for relay.
//!
//! Per-engine backends live under `backend::{sqlite, postgres}`. The public
//! API is a flat set of dispatcher fns at crate root that match on `Db` and
//! forward to the right backend. Consumers call `relay_db::create_org(...)`
//! and never see the backend module directly.

mod backend;
pub mod models;

use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

pub use sqlx;

use crate::models::*;
use uuid::Uuid;

/// Pool tuning applied at `Db::connect` time. Both fields are optional so
/// callers can fall through to per-backend defaults (SQLite=10 / Postgres=20,
/// 5s acquire timeout on both).
#[derive(Debug, Clone)]
pub struct DbOpenOpts<'a> {
    pub url: &'a str,
    pub max_connections: Option<u32>,
    pub acquire_timeout: Option<Duration>,
}

impl<'a> DbOpenOpts<'a> {
    pub fn new(url: &'a str) -> Self {
        Self { url, max_connections: None, acquire_timeout: None }
    }
}

const SQLITE_DEFAULT_MAX_CONNS: u32 = 10;
const POSTGRES_DEFAULT_MAX_CONNS: u32 = 20;
const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

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
}

#[derive(Clone)]
pub enum Db {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl Db {
    /// Connect using the supplied options. The URL scheme picks the backend:
    /// * `sqlite:<path>` / `sqlite::memory:` → embedded SQLite.
    /// * `postgres://` / `postgresql://` → managed or self-hosted Postgres.
    pub async fn connect(opts: &DbOpenOpts<'_>) -> Result<Self, DbError> {
        let url = opts.url;
        let timeout = opts.acquire_timeout.unwrap_or(DEFAULT_ACQUIRE_TIMEOUT);

        if url.starts_with("sqlite:") {
            let sqlite_opts: SqliteConnectOptions = url.parse()?;
            let sqlite_opts = sqlite_opts.create_if_missing(true).foreign_keys(true);
            let max = opts.max_connections.unwrap_or(SQLITE_DEFAULT_MAX_CONNS);
            let pool = SqlitePoolOptions::new()
                .max_connections(max)
                .acquire_timeout(timeout)
                .connect_with(sqlite_opts)
                .await?;
            Ok(Self::Sqlite(pool))
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            let max = opts.max_connections.unwrap_or(POSTGRES_DEFAULT_MAX_CONNS);
            let pool = PgPoolOptions::new()
                .max_connections(max)
                .acquire_timeout(timeout)
                .connect(url)
                .await?;
            Ok(Self::Postgres(pool))
        } else {
            Err(DbError::Sql(sqlx::Error::Configuration(
                format!("unrecognised db url: {url}").into(),
            )))
        }
    }

    /// Convenience wrapper for callers that don't need to tune the pool —
    /// equivalent to `Db::connect(&DbOpenOpts::new(url))`.
    pub async fn connect_url(url: &str) -> Result<Self, DbError> {
        Self::connect(&DbOpenOpts::new(url)).await
    }

    pub async fn connect_sqlite_path(path: &Path) -> Result<Self, DbError> {
        let url = format!("sqlite://{}", path.display());
        Self::connect_url(&url).await
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        match self {
            Db::Sqlite(pool) => {
                sqlx::migrate!("../../migrations/sqlite").run(pool).await?;
                Ok(())
            }
            Db::Postgres(pool) => {
                sqlx::migrate!("../../migrations/postgres").run(pool).await?;
                Ok(())
            }
        }
    }

    pub(crate) fn sqlite(&self) -> &SqlitePool {
        match self {
            Db::Sqlite(p) => p,
            Db::Postgres(_) => unreachable!("sqlite() called on a Postgres connection"),
        }
    }

    pub(crate) fn postgres(&self) -> &PgPool {
        match self {
            Db::Postgres(p) => p,
            Db::Sqlite(_) => unreachable!("postgres() called on a SQLite connection"),
        }
    }
}

/// Map sqlx errors into our domain error using the typed driver API — works
/// across SQLite and Postgres without string-sniffing the message.
pub fn map_sqlx_err(e: sqlx::Error) -> DbError {
    if matches!(e, sqlx::Error::RowNotFound) {
        return DbError::NotFound;
    }
    if let Some(db_err) = e.as_database_error() {
        if db_err.is_unique_violation() {
            return DbError::UniqueViolation(db_err.message().to_string());
        }
    }
    DbError::Sql(e)
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

/// Shorthand that forwards to the matching fn in the backend module. Avoids
/// repeating `match db { Db::Sqlite(_) => …, Db::Postgres(_) => … }` for every
/// dispatcher.
macro_rules! dispatch {
    ($db:ident, $fn:ident ( $($arg:expr),* $(,)? )) => {
        match $db {
            Db::Sqlite(_) => backend::sqlite::$fn($db, $($arg),*).await,
            Db::Postgres(_) => backend::postgres::$fn($db, $($arg),*).await,
        }
    };
}

// ---- organizations + users + membership -----------------------------------

pub async fn create_org(db: &Db, name: &str, slug: &str) -> Result<Organization, DbError> {
    dispatch!(db, create_org(name, slug))
}

pub async fn find_user_by_github_id(db: &Db, github_id: i64) -> Result<Option<User>, DbError> {
    dispatch!(db, find_user_by_github_id(github_id))
}

pub async fn find_user_by_id(db: &Db, id: Uuid) -> Result<Option<User>, DbError> {
    dispatch!(db, find_user_by_id(id))
}

pub async fn find_org_by_id(db: &Db, id: Uuid) -> Result<Option<Organization>, DbError> {
    dispatch!(db, find_org_by_id(id))
}

pub async fn count_orgs_by_slug(db: &Db, slug: &str) -> Result<i64, DbError> {
    dispatch!(db, count_orgs_by_slug(slug))
}

pub async fn upsert_github_user(
    db: &Db,
    github_id: i64,
    login: &str,
    email: Option<&str>,
    name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<User, DbError> {
    dispatch!(db, upsert_github_user(github_id, login, email, name, avatar_url))
}

pub async fn add_org_member(
    db: &Db,
    org_id: Uuid,
    user_id: Uuid,
    role: Role,
) -> Result<(), DbError> {
    dispatch!(db, add_org_member(org_id, user_id, role))
}

pub async fn primary_org_for_user(db: &Db, user_id: Uuid) -> Result<Option<Organization>, DbError> {
    dispatch!(db, primary_org_for_user(user_id))
}

// ---- sessions -------------------------------------------------------------

pub async fn create_session(
    db: &Db,
    user_id: Uuid,
    org_id: Uuid,
    ttl_secs: i64,
) -> Result<Uuid, DbError> {
    dispatch!(db, create_session(user_id, org_id, ttl_secs))
}

pub async fn lookup_session(db: &Db, id: Uuid) -> Result<Option<Session>, DbError> {
    dispatch!(db, lookup_session(id))
}

pub async fn delete_session(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, delete_session(id))
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
    dispatch!(db, create_api_token(org_id, user_id, name, hashed_token, scopes))
}

pub async fn list_tokens_for_org(db: &Db, org_id: Uuid) -> Result<Vec<ApiToken>, DbError> {
    dispatch!(db, list_tokens_for_org(org_id))
}

pub async fn delete_token(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    dispatch!(db, delete_token(id, org_id))
}

pub async fn find_token_by_hash(db: &Db, hashed: &str) -> Result<Option<ApiToken>, DbError> {
    dispatch!(db, find_token_by_hash(hashed))
}

pub async fn list_all_api_tokens(db: &Db) -> Result<Vec<ApiToken>, DbError> {
    dispatch!(db, list_all_api_tokens())
}

pub async fn touch_token_use(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, touch_token_use(id))
}

// ---- reservations ---------------------------------------------------------

pub async fn create_reservation(
    db: &Db,
    org_id: Uuid,
    label: &str,
) -> Result<Reservation, DbError> {
    dispatch!(db, create_reservation(org_id, label))
}

pub async fn list_reservations_for_org(db: &Db, org_id: Uuid) -> Result<Vec<Reservation>, DbError> {
    dispatch!(db, list_reservations_for_org(org_id))
}

pub async fn delete_reservation(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    dispatch!(db, delete_reservation(id, org_id))
}

pub async fn find_reservation_by_label(
    db: &Db,
    label: &str,
) -> Result<Option<Reservation>, DbError> {
    dispatch!(db, find_reservation_by_label(label))
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
    dispatch!(db, upsert_tunnel_by_hostname(org_id, kind, hostname, labels, inspect))
}

pub async fn delete_disconnected_tunnels_for_org(db: &Db, org_id: Uuid) -> Result<u64, DbError> {
    dispatch!(db, delete_disconnected_tunnels_for_org(org_id))
}

pub async fn delete_tunnel_for_org(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    dispatch!(db, delete_tunnel_for_org(id, org_id))
}

pub async fn touch_tunnel_last_seen(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, touch_tunnel_last_seen(id))
}

pub async fn mark_tunnel_disconnected(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, mark_tunnel_disconnected(id))
}

pub async fn mark_all_tunnels_disconnected(db: &Db) -> Result<u64, DbError> {
    dispatch!(db, mark_all_tunnels_disconnected())
}

pub async fn list_tunnels_for_org(db: &Db, org_id: Uuid) -> Result<Vec<Tunnel>, DbError> {
    dispatch!(db, list_tunnels_for_org(org_id))
}

pub async fn find_tunnel_org_id(db: &Db, tunnel_id: Uuid) -> Result<Option<Uuid>, DbError> {
    dispatch!(db, find_tunnel_org_id(tunnel_id))
}

// ---- custom domains -------------------------------------------------------

pub async fn create_custom_domain(
    db: &Db,
    org_id: Uuid,
    hostname: &str,
    verification_token: &str,
) -> Result<CustomDomain, DbError> {
    dispatch!(db, create_custom_domain(org_id, hostname, verification_token))
}

pub async fn list_custom_domains(db: &Db, org_id: Uuid) -> Result<Vec<CustomDomain>, DbError> {
    dispatch!(db, list_custom_domains(org_id))
}

pub async fn mark_custom_domain_verified(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, mark_custom_domain_verified(id))
}

pub async fn find_custom_domain_for_org(
    db: &Db,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<CustomDomain>, DbError> {
    dispatch!(db, find_custom_domain_for_org(id, org_id))
}

pub async fn find_custom_domain(db: &Db, hostname: &str) -> Result<Option<CustomDomain>, DbError> {
    dispatch!(db, find_custom_domain(hostname))
}

pub async fn delete_custom_domain_by_id(db: &Db, id: Uuid) -> Result<(), DbError> {
    dispatch!(db, delete_custom_domain_by_id(id))
}

// ---- certs ----------------------------------------------------------------

pub async fn upsert_cert(
    db: &Db,
    hostname: &str,
    cert_chain_pem: &str,
    key_pem_encrypted: &str,
    not_after: i64,
) -> Result<Uuid, DbError> {
    dispatch!(db, upsert_cert(hostname, cert_chain_pem, key_pem_encrypted, not_after))
}

pub async fn latest_cert_for(db: &Db, hostname: &str) -> Result<Option<Cert>, DbError> {
    dispatch!(db, latest_cert_for(hostname))
}

pub async fn list_all_certs(db: &Db) -> Result<Vec<Cert>, DbError> {
    dispatch!(db, list_all_certs())
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
    dispatch!(
        db,
        insert_full_capture(
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
    )
}

pub async fn find_tunnel_for_org(
    db: &Db,
    org_id: Uuid,
    tunnel_id: Uuid,
) -> Result<Option<Tunnel>, DbError> {
    dispatch!(db, find_tunnel_for_org(org_id, tunnel_id))
}

pub async fn insert_capture(
    db: &Db,
    tunnel_id: Uuid,
    request_id: Uuid,
    method: &str,
    path: &str,
    req_headers: &[(String, String)],
) -> Result<Uuid, DbError> {
    dispatch!(db, insert_capture(tunnel_id, request_id, method, path, req_headers))
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
    dispatch!(
        db,
        complete_capture(id, status, duration_ms, resp_headers, req_body, resp_body, truncated)
    )
}

pub async fn list_captures(
    db: &Db,
    tunnel_id: Uuid,
    limit: i64,
) -> Result<Vec<InspectionCapture>, DbError> {
    dispatch!(db, list_captures(tunnel_id, limit))
}

pub async fn get_capture(db: &Db, id: Uuid) -> Result<Option<InspectionCapture>, DbError> {
    dispatch!(db, get_capture(id))
}

pub async fn clear_captures_for_tunnel(db: &Db, tunnel_id: Uuid) -> Result<u64, DbError> {
    dispatch!(db, clear_captures_for_tunnel(tunnel_id))
}

pub async fn prune_captures(db: &Db, older_than: i64) -> Result<u64, DbError> {
    dispatch!(db, prune_captures(older_than))
}

// ---- audit ----------------------------------------------------------------

pub async fn log_audit(
    db: &Db,
    org_id: Uuid,
    actor_user_id: Option<Uuid>,
    kind: &str,
    payload: &serde_json::Value,
) -> Result<(), DbError> {
    dispatch!(db, log_audit(org_id, actor_user_id, kind, payload))
}
