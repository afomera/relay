//! Database layer for relay.
//!
//! **Current status:** SQLite only. The Postgres variant is stubbed per
//! `DECISIONS.md` D21 and returns `unimplemented!` at runtime. Switch it on by
//! writing the matching migration set under `migrations/postgres/` and filling
//! in the Postgres arms of each DAL method.

pub mod models;
pub mod sqlite;

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Sqlite, SqlitePool};

pub use sqlx;

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

/// Convenience alias for a row-level executor usable by both transaction and pool.
pub type SqliteExec<'a> = &'a mut sqlx::SqliteConnection;

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

/// Re-exports used widely in DAL code.
pub mod prelude {
    pub use super::models::*;
    pub use super::sqlite::*;
    pub use super::{Db, DbError, map_sqlx_err, now_unix};
    pub use sqlx::Sqlite;
    pub use time::OffsetDateTime;
    pub use uuid::Uuid;
}

#[allow(dead_code)] // until used by control plane wiring
const _DRIVER_KIND_SQLITE: std::marker::PhantomData<Sqlite> = std::marker::PhantomData;
