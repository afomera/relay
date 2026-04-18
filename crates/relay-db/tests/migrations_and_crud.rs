//! SQLite side of the DAL smoke suite. The actual test body lives in
//! `tests/common/mod.rs` so the Postgres mirror (`postgres_parity.rs`) can
//! exercise the identical scenarios.

mod common;

#[tokio::test]
async fn basic_crud_round_trip_sqlite() {
    let db = common::sqlite_mem().await;
    common::run_basic_crud_suite(&db).await;
}
