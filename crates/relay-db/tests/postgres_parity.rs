//! Postgres side of the DAL smoke suite. Skips when `RELAY_PG_TEST_URL` is
//! unset so `cargo test` stays fast on dev machines without a local Postgres.
//! CI sets the env to the `postgres:18.3-alpine` service container.
//!
//! When a failure lands here but not in the SQLite mirror, it's a Postgres
//! backend bug (query shape, binding, schema mismatch) — not a DAL contract
//! issue. The shared suite in `tests/common/mod.rs` is the source of truth
//! for "what the DAL should do."

mod common;

const ENV_VAR: &str = "RELAY_PG_TEST_URL";

#[tokio::test]
async fn basic_crud_round_trip_postgres() {
    let Some(db) = common::maybe_postgres(ENV_VAR).await else {
        eprintln!("skipping postgres parity: {ENV_VAR} not set");
        return;
    };
    common::run_basic_crud_suite(&db).await;
}
