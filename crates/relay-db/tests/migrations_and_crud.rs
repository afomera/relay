//! Smoke test: in-memory SQLite, run migrations, exercise a few DAL paths.

use relay_db::{Db, prelude::*};

#[tokio::test]
async fn basic_crud_round_trip() {
    let db = Db::connect("sqlite::memory:").await.unwrap();
    db.migrate().await.unwrap();

    // Create a user + personal org.
    let user = relay_db::sqlite::upsert_github_user(
        &db,
        42,
        "andrea",
        Some("andrea@example.com"),
        Some("Andrea"),
        None,
    )
    .await
    .unwrap();
    let org = relay_db::sqlite::create_org(&db, "andrea's org", "andrea").await.unwrap();
    relay_db::sqlite::add_org_member(&db, org.id, user.id, relay_db::models::Role::Owner)
        .await
        .unwrap();

    // Resolve primary org.
    let primary = relay_db::sqlite::primary_org_for_user(&db, user.id).await.unwrap().unwrap();
    assert_eq!(primary.id, org.id);

    // Create + list a reservation.
    relay_db::sqlite::create_reservation(&db, org.id, "andrea").await.unwrap();
    let reservations = relay_db::sqlite::list_reservations_for_org(&db, org.id).await.unwrap();
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].label, "andrea");

    // Duplicate reservation → unique violation.
    let err = relay_db::sqlite::create_reservation(&db, org.id, "andrea").await.unwrap_err();
    assert!(matches!(err, relay_db::DbError::UniqueViolation(_)));

    // Token.
    let tok_id = relay_db::sqlite::create_api_token(
        &db,
        org.id,
        user.id,
        "laptop",
        "hash_of_secret",
        "tunnels:create,tunnels:manage",
    )
    .await
    .unwrap();
    let found = relay_db::sqlite::find_token_by_hash(&db, "hash_of_secret").await.unwrap().unwrap();
    assert_eq!(found.id, tok_id);
}

// Keep `OffsetDateTime` from being flagged as unused even if we add no current
// use — it's part of the prelude for callers.
#[allow(dead_code)]
fn _odt(_: OffsetDateTime, _: Uuid) {}
