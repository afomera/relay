//! Shared fixtures and test bodies for the DAL tests. Keeps a single test
//! suite (`run_basic_crud_suite`) that's called from two entry points — one
//! per backend — so adding coverage automatically applies to both.
//!
//! Each test binary pulls in this module with `mod common;` — only the helpers
//! it uses get linked, so the `dead_code` allow covers the subset the other
//! binary calls.
#![allow(dead_code)]

use relay_db::Db;

pub async fn sqlite_mem() -> Db {
    let db = Db::connect_url("sqlite::memory:").await.expect("connect sqlite in-memory");
    db.migrate().await.expect("sqlite migrate");
    db
}

/// Open a Postgres DB named by env var, wipe all relay tables (so leftover
/// state from previous runs doesn't leak in), and run migrations. Returns
/// `None` if the env var isn't set — callers use that to skip the test
/// gracefully on machines without a Postgres available.
pub async fn maybe_postgres(env_var: &str) -> Option<Db> {
    let url = std::env::var(env_var).ok()?;
    wipe_postgres(&url).await;
    let db = Db::connect_url(&url).await.expect("connect postgres");
    db.migrate().await.expect("postgres migrate");
    Some(db)
}

async fn wipe_postgres(url: &str) {
    use sqlx::postgres::PgPool;
    let pool = PgPool::connect(url).await.expect("connect postgres for wipe");
    // CASCADE across the full relay schema plus sqlx's migration table so the
    // next `migrate()` starts from a clean slate. Non-existent tables are
    // ignored thanks to `IF EXISTS`.
    let sql = "DROP TABLE IF EXISTS \
        sessions, audit_events, inspection_captures, custom_domains, certs, \
        tunnels, reservations, api_tokens, org_members, users, organizations, \
        _sqlx_migrations CASCADE";
    sqlx::query(sql).execute(&pool).await.expect("drop relay tables");
    pool.close().await;
}

/// The shared CRUD smoke suite. Runs through the core DAL paths (users, orgs,
/// reservations, tokens, tunnels, captures, custom domains, audit) and
/// asserts the same semantics on whichever backend the `Db` was opened for.
///
/// Both `tests/migrations_and_crud.rs` (SQLite) and `tests/postgres_parity.rs`
/// (Postgres) call this — adding a case here widens coverage for both.
pub async fn run_basic_crud_suite(db: &Db) {
    // ---- users + orgs + membership ----
    let user = relay_db::upsert_github_user(
        db,
        42,
        "andrea",
        Some("andrea@example.com"),
        Some("Andrea"),
        None,
    )
    .await
    .unwrap();
    let org = relay_db::create_org(db, "andrea's org", "andrea").await.unwrap();
    relay_db::add_org_member(db, org.id, user.id, relay_db::models::Role::Owner).await.unwrap();

    let primary = relay_db::primary_org_for_user(db, user.id).await.unwrap().unwrap();
    assert_eq!(primary.id, org.id);

    let by_id = relay_db::find_user_by_id(db, user.id).await.unwrap().unwrap();
    assert_eq!(by_id.github_id, 42);
    let org_by_id = relay_db::find_org_by_id(db, org.id).await.unwrap().unwrap();
    assert_eq!(org_by_id.slug, "andrea");
    assert_eq!(relay_db::count_orgs_by_slug(db, "andrea").await.unwrap(), 1);
    assert_eq!(relay_db::count_orgs_by_slug(db, "nobody").await.unwrap(), 0);

    // ---- reservations + unique-violation mapping ----
    relay_db::create_reservation(db, org.id, "andrea").await.unwrap();
    let reservations = relay_db::list_reservations_for_org(db, org.id).await.unwrap();
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].label, "andrea");

    let err = relay_db::create_reservation(db, org.id, "andrea").await.unwrap_err();
    assert!(
        matches!(err, relay_db::DbError::UniqueViolation(_)),
        "expected UniqueViolation, got {err:?}"
    );

    // ---- api tokens ----
    let tok_id = relay_db::create_api_token(
        db,
        org.id,
        user.id,
        "laptop",
        "hash_of_secret",
        "tunnels:create,tunnels:manage",
    )
    .await
    .unwrap();
    let found = relay_db::find_token_by_hash(db, "hash_of_secret").await.unwrap().unwrap();
    assert_eq!(found.id, tok_id);

    // ---- tunnels: upsert, list, disconnect sweep ----
    let labels = vec![("env".to_string(), "dev".to_string())];
    let tunnel_id = relay_db::upsert_tunnel_by_hostname(
        db,
        org.id,
        "http",
        "andrea.example.com",
        &labels,
        true,
    )
    .await
    .unwrap();
    // Second upsert with the same (org, hostname) must return the same id.
    let tunnel_id_again = relay_db::upsert_tunnel_by_hostname(
        db,
        org.id,
        "http",
        "andrea.example.com",
        &labels,
        false,
    )
    .await
    .unwrap();
    assert_eq!(tunnel_id, tunnel_id_again);

    let tunnels = relay_db::list_tunnels_for_org(db, org.id).await.unwrap();
    assert_eq!(tunnels.len(), 1);
    assert_eq!(tunnels[0].id, tunnel_id);
    assert!(!tunnels[0].inspect, "second upsert set inspect=false");

    let org_id_for_tunnel =
        relay_db::find_tunnel_org_id(db, tunnel_id).await.unwrap().expect("tunnel exists");
    assert_eq!(org_id_for_tunnel, org.id);

    let swept = relay_db::mark_all_tunnels_disconnected(db).await.unwrap();
    assert_eq!(swept, 1);
    let purged = relay_db::delete_disconnected_tunnels_for_org(db, org.id).await.unwrap();
    assert_eq!(purged, 1);

    // ---- custom domains ----
    let cd = relay_db::create_custom_domain(db, org.id, "hooks.example.com", "verify-token-1")
        .await
        .unwrap();
    let scoped = relay_db::find_custom_domain_for_org(db, cd.id, org.id).await.unwrap();
    assert!(scoped.is_some());
    relay_db::delete_custom_domain_by_id(db, cd.id).await.unwrap();
    let gone = relay_db::find_custom_domain(db, "hooks.example.com").await.unwrap();
    assert!(gone.is_none());

    // ---- inspection capture (full path) + client_ip ----
    let new_tunnel =
        relay_db::upsert_tunnel_by_hostname(db, org.id, "http", "captures.example.com", &[], true)
            .await
            .unwrap();
    let cap_id = relay_db::insert_full_capture(
        db,
        new_tunnel,
        uuid::Uuid::new_v4(),
        100,
        200,
        "GET",
        "/health",
        200,
        50,
        &[("accept".into(), "*/*".into())],
        b"",
        &[("content-type".into(), "text/plain".into())],
        b"ok",
        false,
        "198.51.100.7",
    )
    .await
    .unwrap();
    let captures = relay_db::list_captures(db, new_tunnel, 10).await.unwrap();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].id, cap_id);
    assert_eq!(captures[0].client_ip.as_deref(), Some("198.51.100.7"));
    assert!(!captures[0].truncated);

    let cleared = relay_db::clear_captures_for_tunnel(db, new_tunnel).await.unwrap();
    assert_eq!(cleared, 1);

    // ---- audit ----
    relay_db::log_audit(
        db,
        org.id,
        Some(user.id),
        "reservation.created",
        &serde_json::json!({"label": "andrea"}),
    )
    .await
    .unwrap();
}
