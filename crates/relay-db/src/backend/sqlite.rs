//! SQLite backend. All fns are `pub(crate)` — the crate-root dispatcher in
//! `lib.rs` is the public surface.
//!
//! Queries are runtime-checked (no `query!` macro): lets us avoid a
//! compile-time `DATABASE_URL` and keeps the SQL strings close to the Postgres
//! variants for easy parity review.

use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::models::*;
use crate::{Db, DbError, map_sqlx_err, now_unix};

fn pool(db: &Db) -> &SqlitePool {
    db.sqlite()
}

// ---------------------------------------------------------------------------
// organizations + users + membership
// ---------------------------------------------------------------------------

pub(crate) async fn create_org(db: &Db, name: &str, slug: &str) -> Result<Organization, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)")
        .bind(id)
        .bind(name)
        .bind(slug)
        .bind(now)
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(Organization { id, name: name.to_string(), slug: slug.to_string(), created_at: now })
}

pub(crate) async fn find_user_by_github_id(
    db: &Db,
    github_id: i64,
) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE github_id = ?")
        .bind(github_id)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn find_user_by_id(db: &Db, id: Uuid) -> Result<Option<User>, DbError> {
    let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn find_org_by_id(db: &Db, id: Uuid) -> Result<Option<Organization>, DbError> {
    let row = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(id)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn count_orgs_by_slug(db: &Db, slug: &str) -> Result<i64, DbError> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM organizations WHERE slug = ?")
        .bind(slug)
        .fetch_one(pool(db))
        .await?;
    Ok(n)
}

pub(crate) async fn upsert_github_user(
    db: &Db,
    github_id: i64,
    login: &str,
    email: Option<&str>,
    name: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<User, DbError> {
    if let Some(u) = find_user_by_github_id(db, github_id).await? {
        sqlx::query("UPDATE users SET login = ?, email = ?, name = ?, avatar_url = ? WHERE id = ?")
            .bind(login)
            .bind(email)
            .bind(name)
            .bind(avatar_url)
            .bind(u.id)
            .execute(pool(db))
            .await?;
        return Ok(User {
            login: login.to_string(),
            email: email.map(str::to_string),
            name: name.map(str::to_string),
            avatar_url: avatar_url.map(str::to_string),
            ..u
        });
    }
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO users (id, github_id, login, email, name, avatar_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(github_id)
        .bind(login)
        .bind(email)
        .bind(name)
        .bind(avatar_url)
        .bind(now)
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(User {
        id,
        github_id,
        login: login.to_string(),
        email: email.map(str::to_string),
        name: name.map(str::to_string),
        avatar_url: avatar_url.map(str::to_string),
        created_at: now,
    })
}

pub(crate) async fn add_org_member(
    db: &Db,
    org_id: Uuid,
    user_id: Uuid,
    role: Role,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO org_members (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)")
        .bind(org_id)
        .bind(user_id)
        .bind(role.as_str())
        .bind(now_unix())
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(())
}

pub(crate) async fn primary_org_for_user(
    db: &Db,
    user_id: Uuid,
) -> Result<Option<Organization>, DbError> {
    let row = sqlx::query_as::<_, Organization>(
        "SELECT o.* FROM organizations o \
         JOIN org_members m ON m.org_id = o.id \
         WHERE m.user_id = ? ORDER BY m.created_at ASC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool(db))
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

pub(crate) async fn create_session(
    db: &Db,
    user_id: Uuid,
    org_id: Uuid,
    ttl_secs: i64,
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, org_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(org_id)
    .bind(now + ttl_secs)
    .bind(now)
    .execute(pool(db))
    .await?;
    Ok(id)
}

pub(crate) async fn lookup_session(db: &Db, id: Uuid) -> Result<Option<Session>, DbError> {
    let row =
        sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = ? AND expires_at > ?")
            .bind(id)
            .bind(now_unix())
            .fetch_optional(pool(db))
            .await?;
    Ok(row)
}

pub(crate) async fn delete_session(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("DELETE FROM sessions WHERE id = ?").bind(id).execute(pool(db)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// api tokens
// ---------------------------------------------------------------------------

pub(crate) async fn create_api_token(
    db: &Db,
    org_id: Uuid,
    user_id: Uuid,
    name: &str,
    hashed_token: &str,
    scopes: &str,
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO api_tokens (id, org_id, user_id, name, hashed_token, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(org_id)
        .bind(user_id)
        .bind(name)
        .bind(hashed_token)
        .bind(scopes)
        .bind(now)
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(id)
}

pub(crate) async fn list_tokens_for_org(db: &Db, org_id: Uuid) -> Result<Vec<ApiToken>, DbError> {
    let rows = sqlx::query_as::<_, ApiToken>(
        "SELECT * FROM api_tokens WHERE org_id = ? ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(pool(db))
    .await?;
    Ok(rows)
}

pub(crate) async fn delete_token(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    let res = sqlx::query("DELETE FROM api_tokens WHERE id = ? AND org_id = ?")
        .bind(id)
        .bind(org_id)
        .execute(pool(db))
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

pub(crate) async fn find_token_by_hash(db: &Db, hashed: &str) -> Result<Option<ApiToken>, DbError> {
    let row = sqlx::query_as::<_, ApiToken>("SELECT * FROM api_tokens WHERE hashed_token = ?")
        .bind(hashed)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn list_all_api_tokens(db: &Db) -> Result<Vec<ApiToken>, DbError> {
    let rows =
        sqlx::query_as::<_, ApiToken>("SELECT * FROM api_tokens").fetch_all(pool(db)).await?;
    Ok(rows)
}

pub(crate) async fn touch_token_use(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(now_unix())
        .bind(id)
        .execute(pool(db))
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// reservations
// ---------------------------------------------------------------------------

pub(crate) async fn create_reservation(
    db: &Db,
    org_id: Uuid,
    label: &str,
) -> Result<Reservation, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO reservations (id, org_id, label, created_at) VALUES (?, ?, ?, ?)")
        .bind(id)
        .bind(org_id)
        .bind(label)
        .bind(now)
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(Reservation { id, org_id, label: label.to_string(), created_at: now })
}

pub(crate) async fn list_reservations_for_org(
    db: &Db,
    org_id: Uuid,
) -> Result<Vec<Reservation>, DbError> {
    let rows = sqlx::query_as::<_, Reservation>(
        "SELECT * FROM reservations WHERE org_id = ? ORDER BY label",
    )
    .bind(org_id)
    .fetch_all(pool(db))
    .await?;
    Ok(rows)
}

pub(crate) async fn delete_reservation(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    let res = sqlx::query("DELETE FROM reservations WHERE id = ? AND org_id = ?")
        .bind(id)
        .bind(org_id)
        .execute(pool(db))
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

pub(crate) async fn find_reservation_by_label(
    db: &Db,
    label: &str,
) -> Result<Option<Reservation>, DbError> {
    let row = sqlx::query_as::<_, Reservation>("SELECT * FROM reservations WHERE label = ?")
        .bind(label)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// tunnels
// ---------------------------------------------------------------------------

pub(crate) async fn upsert_tunnel_by_hostname(
    db: &Db,
    org_id: Uuid,
    kind: &str,
    hostname: &str,
    labels: &[(String, String)],
    inspect: bool,
) -> Result<Uuid, DbError> {
    let labels_json = serde_json::to_string(labels)?;
    let now = now_unix();

    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM tunnels WHERE org_id = ? AND hostname = ?")
            .bind(org_id)
            .bind(hostname)
            .fetch_optional(pool(db))
            .await?;

    if let Some(id) = existing {
        sqlx::query(
            "UPDATE tunnels SET state = 'active', last_seen_at = ?, kind = ?, \
             labels_json = ?, inspect = ? WHERE id = ?",
        )
        .bind(now)
        .bind(kind)
        .bind(&labels_json)
        .bind(inspect)
        .bind(id)
        .execute(pool(db))
        .await?;
        return Ok(id);
    }

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tunnels (id, org_id, kind, hostname, state, labels_json, inspect, \
         created_at, last_seen_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(org_id)
    .bind(kind)
    .bind(hostname)
    .bind(&labels_json)
    .bind(inspect)
    .bind(now)
    .bind(now)
    .execute(pool(db))
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

pub(crate) async fn delete_disconnected_tunnels_for_org(
    db: &Db,
    org_id: Uuid,
) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM tunnels WHERE org_id = ? AND state = 'disconnected'")
        .bind(org_id)
        .execute(pool(db))
        .await?;
    Ok(res.rows_affected())
}

pub(crate) async fn delete_tunnel_for_org(db: &Db, id: Uuid, org_id: Uuid) -> Result<(), DbError> {
    let res = sqlx::query("DELETE FROM tunnels WHERE id = ? AND org_id = ?")
        .bind(id)
        .bind(org_id)
        .execute(pool(db))
        .await?;
    if res.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

pub(crate) async fn touch_tunnel_last_seen(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("UPDATE tunnels SET last_seen_at = ? WHERE id = ?")
        .bind(now_unix())
        .bind(id)
        .execute(pool(db))
        .await?;
    Ok(())
}

pub(crate) async fn mark_tunnel_disconnected(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("UPDATE tunnels SET state = 'disconnected', last_seen_at = ? WHERE id = ?")
        .bind(now_unix())
        .bind(id)
        .execute(pool(db))
        .await?;
    Ok(())
}

pub(crate) async fn mark_all_tunnels_disconnected(db: &Db) -> Result<u64, DbError> {
    let res = sqlx::query(
        "UPDATE tunnels SET state = 'disconnected', last_seen_at = ? WHERE state = 'active'",
    )
    .bind(now_unix())
    .execute(pool(db))
    .await?;
    Ok(res.rows_affected())
}

pub(crate) async fn list_tunnels_for_org(db: &Db, org_id: Uuid) -> Result<Vec<Tunnel>, DbError> {
    // Active rows first, then by recency. CASE ordering is portable across
    // SQLite and Postgres.
    let rows = sqlx::query_as::<_, Tunnel>(
        "SELECT * FROM tunnels WHERE org_id = ? \
         ORDER BY CASE state WHEN 'active' THEN 0 ELSE 1 END, last_seen_at DESC \
         LIMIT 200",
    )
    .bind(org_id)
    .fetch_all(pool(db))
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// custom domains
// ---------------------------------------------------------------------------

pub(crate) async fn create_custom_domain(
    db: &Db,
    org_id: Uuid,
    hostname: &str,
    verification_token: &str,
) -> Result<CustomDomain, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO custom_domains (id, org_id, hostname, verification_token, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id)
        .bind(org_id)
        .bind(hostname)
        .bind(verification_token)
        .bind(now)
        .execute(pool(db))
        .await
        .map_err(map_sqlx_err)?;
    Ok(CustomDomain {
        id,
        org_id,
        hostname: hostname.to_string(),
        verification_token: verification_token.to_string(),
        verified_at: None,
        cert_id: None,
        created_at: now,
    })
}

pub(crate) async fn list_custom_domains(
    db: &Db,
    org_id: Uuid,
) -> Result<Vec<CustomDomain>, DbError> {
    let rows = sqlx::query_as::<_, CustomDomain>(
        "SELECT * FROM custom_domains WHERE org_id = ? ORDER BY hostname",
    )
    .bind(org_id)
    .fetch_all(pool(db))
    .await?;
    Ok(rows)
}

pub(crate) async fn mark_custom_domain_verified(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("UPDATE custom_domains SET verified_at = ? WHERE id = ?")
        .bind(now_unix())
        .bind(id)
        .execute(pool(db))
        .await?;
    Ok(())
}

pub(crate) async fn find_custom_domain_for_org(
    db: &Db,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<CustomDomain>, DbError> {
    let row = sqlx::query_as::<_, CustomDomain>(
        "SELECT * FROM custom_domains WHERE id = ? AND org_id = ?",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(pool(db))
    .await?;
    Ok(row)
}

pub(crate) async fn find_custom_domain(
    db: &Db,
    hostname: &str,
) -> Result<Option<CustomDomain>, DbError> {
    let row = sqlx::query_as::<_, CustomDomain>("SELECT * FROM custom_domains WHERE hostname = ?")
        .bind(hostname)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn delete_custom_domain_by_id(db: &Db, id: Uuid) -> Result<(), DbError> {
    sqlx::query("DELETE FROM custom_domains WHERE id = ?").bind(id).execute(pool(db)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// certs
// ---------------------------------------------------------------------------

pub(crate) async fn upsert_cert(
    db: &Db,
    hostname: &str,
    cert_chain_pem: &str,
    key_pem_encrypted: &str,
    not_after: i64,
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO certs (id, hostname, not_after, cert_chain_pem, key_pem_encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(hostname)
        .bind(not_after)
        .bind(cert_chain_pem)
        .bind(key_pem_encrypted)
        .bind(now)
        .execute(pool(db))
        .await?;
    Ok(id)
}

pub(crate) async fn latest_cert_for(db: &Db, hostname: &str) -> Result<Option<Cert>, DbError> {
    let row = sqlx::query_as::<_, Cert>(
        "SELECT * FROM certs WHERE hostname = ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(hostname)
    .fetch_optional(pool(db))
    .await?;
    Ok(row)
}

pub(crate) async fn list_all_certs(db: &Db) -> Result<Vec<Cert>, DbError> {
    let rows = sqlx::query_as::<_, Cert>("SELECT * FROM certs ORDER BY not_after ASC")
        .fetch_all(pool(db))
        .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// inspection captures
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_full_capture(
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
    let id = Uuid::new_v4();
    let req_h = serde_json::to_string(req_headers)?;
    let resp_h = serde_json::to_string(resp_headers)?;
    sqlx::query(
        "INSERT INTO inspection_captures \
         (id, tunnel_id, request_id, started_at, completed_at, method, path, status, duration_ms, \
          req_headers_json, req_body, resp_headers_json, resp_body, truncated, client_ip) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(tunnel_id)
    .bind(request_id)
    .bind(started_at)
    .bind(completed_at)
    .bind(method)
    .bind(path)
    .bind(status)
    .bind(duration_ms)
    .bind(&req_h)
    .bind(req_body)
    .bind(&resp_h)
    .bind(resp_body)
    .bind(truncated)
    .bind(client_ip)
    .execute(pool(db))
    .await?;
    Ok(id)
}

pub(crate) async fn find_tunnel_for_org(
    db: &Db,
    org_id: Uuid,
    tunnel_id: Uuid,
) -> Result<Option<Tunnel>, DbError> {
    let row = sqlx::query_as::<_, Tunnel>("SELECT * FROM tunnels WHERE id = ? AND org_id = ?")
        .bind(tunnel_id)
        .bind(org_id)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn find_tunnel_org_id(db: &Db, tunnel_id: Uuid) -> Result<Option<Uuid>, DbError> {
    let row: Option<Uuid> = sqlx::query_scalar("SELECT org_id FROM tunnels WHERE id = ?")
        .bind(tunnel_id)
        .fetch_optional(pool(db))
        .await?;
    Ok(row)
}

pub(crate) async fn insert_capture(
    db: &Db,
    tunnel_id: Uuid,
    request_id: Uuid,
    method: &str,
    path: &str,
    req_headers: &[(String, String)],
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    let headers = serde_json::to_string(req_headers)?;
    sqlx::query("INSERT INTO inspection_captures (id, tunnel_id, request_id, started_at, method, path, req_headers_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(tunnel_id)
        .bind(request_id)
        .bind(now)
        .bind(method)
        .bind(path)
        .bind(&headers)
        .execute(pool(db))
        .await?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete_capture(
    db: &Db,
    id: Uuid,
    status: i64,
    duration_ms: i64,
    resp_headers: &[(String, String)],
    req_body: Option<&[u8]>,
    resp_body: Option<&[u8]>,
    truncated: bool,
) -> Result<(), DbError> {
    let hdr_json = serde_json::to_string(resp_headers)?;
    let now = now_unix();
    sqlx::query(
        "UPDATE inspection_captures SET completed_at = ?, status = ?, duration_ms = ?, \
         resp_headers_json = ?, req_body = ?, resp_body = ?, truncated = ? WHERE id = ?",
    )
    .bind(now)
    .bind(status)
    .bind(duration_ms)
    .bind(&hdr_json)
    .bind(req_body)
    .bind(resp_body)
    .bind(truncated)
    .bind(id)
    .execute(pool(db))
    .await?;
    Ok(())
}

pub(crate) async fn list_captures(
    db: &Db,
    tunnel_id: Uuid,
    limit: i64,
) -> Result<Vec<InspectionCapture>, DbError> {
    let rows = sqlx::query_as::<_, InspectionCapture>(
        "SELECT * FROM inspection_captures WHERE tunnel_id = ? ORDER BY started_at DESC LIMIT ?",
    )
    .bind(tunnel_id)
    .bind(limit)
    .fetch_all(pool(db))
    .await?;
    Ok(rows)
}

pub(crate) async fn get_capture(db: &Db, id: Uuid) -> Result<Option<InspectionCapture>, DbError> {
    let row =
        sqlx::query_as::<_, InspectionCapture>("SELECT * FROM inspection_captures WHERE id = ?")
            .bind(id)
            .fetch_optional(pool(db))
            .await?;
    Ok(row)
}

pub(crate) async fn clear_captures_for_tunnel(db: &Db, tunnel_id: Uuid) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM inspection_captures WHERE tunnel_id = ?")
        .bind(tunnel_id)
        .execute(pool(db))
        .await?;
    Ok(res.rows_affected())
}

pub(crate) async fn prune_captures(db: &Db, older_than: i64) -> Result<u64, DbError> {
    let res = sqlx::query("DELETE FROM inspection_captures WHERE started_at < ?")
        .bind(older_than)
        .execute(pool(db))
        .await?;
    Ok(res.rows_affected())
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

pub(crate) async fn log_audit(
    db: &Db,
    org_id: Uuid,
    actor_user_id: Option<Uuid>,
    kind: &str,
    payload: &serde_json::Value,
) -> Result<(), DbError> {
    let id = Uuid::new_v4();
    let now = now_unix();
    sqlx::query("INSERT INTO audit_events (id, org_id, actor_user_id, kind, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(org_id)
        .bind(actor_user_id)
        .bind(kind)
        .bind(serde_json::to_string(payload)?)
        .bind(now)
        .execute(pool(db))
        .await?;
    Ok(())
}

// Silence warning until somebody uses it.
#[allow(dead_code)]
fn _touch_json() {
    let _ = json!({});
}
