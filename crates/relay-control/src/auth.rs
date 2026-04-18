//! Auth: session cookies, GitHub OAuth, API token hashing.

use argon2::password_hash::PasswordHasher;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use base64::Engine as _;
use rand::RngCore;
use relay_db as dao;
use relay_db::models::{Organization, User};
use relay_db::{Db, DbError};
use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

pub const SESSION_COOKIE: &str = "relay_session";
/// Short-lived (10 min) encrypted cookie that stashes a CLI login-in-progress
/// so the user can bounce through /login → GitHub → back to /cli/authorize
/// without losing their place.
pub const CLI_RETURN_COOKIE: &str = "relay_cli_pending";

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub user: User,
    pub org: Organization,
}

/// Load the session cookie from the jar and resolve the authenticated user.
/// Handlers call this at the top and bail out (via `?`) with a redirect
/// response on any failure.
pub async fn require_auth(
    state: &AppState,
    jar: &PrivateCookieJar,
) -> Result<AuthedUser, Response> {
    let sid = jar
        .get(SESSION_COOKIE)
        .and_then(|c| c.value().parse::<Uuid>().ok())
        .ok_or_else(|| Redirect::temporary("/login").into_response())?;
    let sess = dao::lookup_session(&state.db, sid)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Redirect::temporary("/login").into_response())?;
    let user = fetch_user(&state.db, sess.user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Redirect::temporary("/login").into_response())?;
    let org = fetch_org(&state.db, sess.org_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Redirect::temporary("/login").into_response())?;
    Ok(AuthedUser { user, org })
}

async fn fetch_user(db: &Db, id: Uuid) -> Result<Option<User>, DbError> {
    dao::find_user_by_id(db, id).await
}

async fn fetch_org(db: &Db, id: Uuid) -> Result<Option<Organization>, DbError> {
    dao::find_org_by_id(db, id).await
}

// ---------------------------------------------------------------------------
// GitHub OAuth
// ---------------------------------------------------------------------------

pub fn start_github_login(state: &AppState, jar: PrivateCookieJar) -> (PrivateCookieJar, String) {
    let github = state.config.github.as_ref().expect("github oauth not configured");
    let state_nonce = Uuid::new_v4().to_string();

    let cookie = Cookie::build(("relay_oauth_state", state_nonce.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build();
    let jar = jar.add(cookie);

    let redirect_uri = format!("{}/auth/github/callback", state.config.public_url);
    let scope_str = github.effective_scopes();
    let scopes = urlencoding::encode(&scope_str);
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={cid}&redirect_uri={ru}&scope={sc}&state={st}",
        cid = urlencoding::encode(&github.client_id),
        ru = urlencoding::encode(&redirect_uri),
        sc = scopes,
        st = urlencoding::encode(&state_nonce),
    );
    (jar, url)
}

#[derive(Debug, Deserialize)]
pub struct GithubCallback {
    pub code: String,
    pub state: String,
}

pub async fn complete_github_login(
    state: &AppState,
    jar: PrivateCookieJar,
    params: GithubCallback,
) -> Result<(PrivateCookieJar, Uuid), AuthError> {
    let Some(stored) = jar.get("relay_oauth_state").map(|c| c.value().to_string()) else {
        return Err(AuthError::StateMissing);
    };
    if stored != params.state {
        return Err(AuthError::StateMismatch);
    }
    let jar = jar.remove(Cookie::from("relay_oauth_state"));

    let github = state.config.github.as_ref().ok_or(AuthError::NotConfigured)?;
    let redirect_uri = format!("{}/auth/github/callback", state.config.public_url);

    let client = reqwest::Client::new();

    // 1. Exchange code for access token.
    let tok_resp: serde_json::Value = client
        .post("https://github.com/login/oauth/access_token")
        .header("accept", "application/json")
        .form(&[
            ("client_id", github.client_id.as_str()),
            ("client_secret", github.client_secret.as_str()),
            ("code", params.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
        .map_err(|e| AuthError::Other(format!("token exchange: {e}")))?
        .json()
        .await
        .map_err(|e| AuthError::Other(format!("token parse: {e}")))?;

    let access_token = tok_resp
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Other(format!("no access_token in response: {tok_resp}")))?
        .to_string();

    // 2. Fetch user info.
    let user_json: serde_json::Value = client
        .get("https://api.github.com/user")
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "relayd")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| AuthError::Other(format!("user fetch: {e}")))?
        .json()
        .await
        .map_err(|e| AuthError::Other(format!("user parse: {e}")))?;

    let github_id = user_json.get("id").and_then(|v| v.as_i64()).unwrap_or_default();
    let login = user_json.get("login").and_then(|v| v.as_str()).unwrap_or("user").to_string();
    let mut email = user_json.get("email").and_then(|v| v.as_str()).map(str::to_string);
    let name = user_json.get("name").and_then(|v| v.as_str()).map(str::to_string);
    let avatar = user_json.get("avatar_url").and_then(|v| v.as_str()).map(str::to_string);

    // /user only returns an email if the user has set a public one. Fall back to
    // /user/emails (permitted by the user:email scope) and pick the primary
    // verified address so we can always contact the user.
    if email.is_none() {
        email = fetch_primary_email(&client, &access_token).await;
    }

    // 2.5. Enforce allowed_orgs if configured.
    if !github.allowed_orgs.is_empty() {
        let orgs_json: serde_json::Value = client
            .get("https://api.github.com/user/orgs?per_page=100")
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "relayd")
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|e| AuthError::Other(format!("orgs fetch: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Other(format!("orgs parse: {e}")))?;
        let allowed: std::collections::HashSet<String> =
            github.allowed_orgs.iter().map(|s| s.to_ascii_lowercase()).collect();
        let in_allowed = orgs_json
            .as_array()
            .map(|arr| {
                arr.iter().any(|o| {
                    o.get("login")
                        .and_then(|v| v.as_str())
                        .map(|s| allowed.contains(&s.to_ascii_lowercase()))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        if !in_allowed {
            tracing::warn!(
                %login,
                "rejected login: user not a member of any allowed org"
            );
            return Err(AuthError::Other(format!(
                "sign-in blocked: your GitHub account isn't a member of any of the allowed orgs ({}). Ask an admin to add you, or contact the person who deployed this server.",
                github.allowed_orgs.join(", ")
            )));
        }
    }

    // 3. Upsert user + ensure personal org + membership.
    let user = dao::upsert_github_user(
        &state.db,
        github_id,
        &login,
        email.as_deref(),
        name.as_deref(),
        avatar.as_deref(),
    )
    .await
    .map_err(|e| AuthError::Other(format!("upsert user: {e}")))?;

    let org = match dao::primary_org_for_user(&state.db, user.id).await {
        Ok(Some(o)) => o,
        _ => {
            let slug = unique_slug(&state.db, &login).await;
            let org = dao::create_org(&state.db, &format!("{}'s workspace", login), &slug)
                .await
                .map_err(|e| AuthError::Other(format!("create org: {e}")))?;
            dao::add_org_member(&state.db, org.id, user.id, relay_db::models::Role::Owner)
                .await
                .map_err(|e| AuthError::Other(format!("add member: {e}")))?;
            org
        }
    };

    let sid = dao::create_session(&state.db, user.id, org.id, 60 * 60 * 24 * 30)
        .await
        .map_err(|e| AuthError::Other(format!("create session: {e}")))?;

    let cookie = Cookie::build((SESSION_COOKIE, sid.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::days(30))
        .build();
    let jar = jar.add(cookie);

    Ok((jar, sid))
}

async fn fetch_primary_email(client: &reqwest::Client, access_token: &str) -> Option<String> {
    let resp = match client
        .get("https://api.github.com/user/emails?per_page=100")
        .header("accept", "application/vnd.github+json")
        .header("user-agent", "relayd")
        .bearer_auth(access_token)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "github /user/emails fetch failed");
            return None;
        }
    };
    let emails: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "github /user/emails parse failed");
            return None;
        }
    };
    let arr = emails.as_array()?;
    let primary_verified = arr.iter().find(|e| {
        e.get("primary").and_then(|v| v.as_bool()).unwrap_or(false)
            && e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
    });
    let pick = primary_verified
        .or_else(|| arr.iter().find(|e| e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)))
        .or_else(|| arr.first());
    pick.and_then(|e| e.get("email").and_then(|v| v.as_str()).map(str::to_string))
}

async fn unique_slug(db: &Db, base: &str) -> String {
    let mut slug = sluggify(base);
    let mut n = 0u32;
    loop {
        let exists = dao::count_orgs_by_slug(db, &slug).await.unwrap_or(0);
        if exists == 0 {
            return slug;
        }
        n += 1;
        slug = format!("{}-{n}", sluggify(base));
    }
}

fn sluggify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if c == '-' || c == '_' {
            out.push('-');
        }
    }
    if out.is_empty() {
        out.push_str("user");
    }
    out
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

pub const TOKEN_PREFIX: &str = "rly_pat_";

pub fn generate_token() -> (String /* plaintext */, String /* hashed */) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let plaintext = format!("{TOKEN_PREFIX}{b64}");
    let hashed = hash_token(&plaintext);
    (plaintext, hashed)
}

/// We hash API tokens with Argon2id. They're high-entropy random strings, so
/// argon2's salt is included for defence-in-depth; verification is O(argon2)
/// per call which is OK for our token volume.
pub fn hash_token(plain: &str) -> String {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default().hash_password(plain.as_bytes(), &salt).expect("hash").to_string()
}

pub fn verify_token(plain: &str, hashed: &str) -> bool {
    match PasswordHash::new(hashed) {
        Ok(parsed) => Argon2::default().verify_password(plain.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("oauth state cookie missing")]
    StateMissing,
    #[error("oauth state mismatch — replay suspected")]
    StateMismatch,
    #[error("github oauth not configured on this server")]
    NotConfigured,
    #[error("{0}")]
    Other(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        tracing::warn!(?self, "auth error");
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}
