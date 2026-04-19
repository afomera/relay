//! HTTP routes for the control plane.

use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar};
use relay_db as dao;
use serde::Deserialize;
use uuid::Uuid;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use std::convert::Infallible;

use crate::auth::{
    AuthedUser, CLI_RETURN_COOKIE, GithubCallback, SESSION_COOKIE, complete_github_login,
    generate_token, require_auth, start_github_login,
};
use crate::state::AppState;
use crate::templates::{
    CapturePage, CliAuthorizePage, DomainsPage, HomePage, LoginPage, OrgCtx, ReservationsPage,
    TokensPage, TunnelPage,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/auth/github/login", get(github_start))
        .route("/auth/github/callback", get(github_callback))
        .route("/auth/logout", get(logout))
        .route("/auth/dev/login", get(dev_login))
        .route("/cli/authorize", get(cli_authorize))
        .route("/cli/authorize/approve", post(cli_authorize_approve))
        .route("/cli/authorize/cancel", post(cli_authorize_cancel))
        .route("/tokens", get(tokens_page).post(create_token))
        .route("/tokens/:id/delete", post(delete_token_route))
        .route("/reservations", get(reservations_page).post(create_reservation))
        .route("/reservations/:id/delete", post(delete_reservation_route))
        .route("/domains", get(domains_page).post(create_domain))
        .route("/domains/:id/verify", post(verify_domain))
        .route("/domains/:id/delete", post(delete_domain))
        .route("/tunnels/:id", get(tunnel_detail))
        .route("/tunnels/:id/delete", post(delete_tunnel_route))
        .route("/tunnels/delete-disconnected", post(delete_disconnected_route))
        .route("/tunnels/:id/captures/clear", post(clear_captures_route))
        .route("/tunnels/:tid/captures/:cid", get(capture_detail))
        .route("/_static/app.css", get(static_css))
        .route("/events/tunnels", get(sse_tunnel_events))
        .route("/tunnels/:id/events", get(sse_tunnel_captures))
        .route("/healthz", get(healthz))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// SSE streams
// ---------------------------------------------------------------------------

async fn sse_tunnel_events(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    let AuthedUser { org, .. } = require_auth(&state, &jar).await?;
    let mut rx = state.events.tunnels.subscribe();
    let stream = async_stream::stream! {
        while let Ok(evt) = rx.recv().await {
            if evt.org_id() != org.id {
                continue;
            }
            let data = serde_json::to_string(&evt).unwrap_or_else(|_| "{}".into());
            yield Ok(Event::default().event(evt.kind_str()).data(data));
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::new()))
}

async fn sse_tunnel_captures(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(tunnel_id): Path<Uuid>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    let AuthedUser { org, .. } = require_auth(&state, &jar).await?;
    let Some(tunnel) = dao::find_tunnel_for_org(&state.db, org.id, tunnel_id).await.ok().flatten()
    else {
        return Err((StatusCode::NOT_FOUND, "tunnel not found").into_response());
    };
    let mut rx = state.events.captures.subscribe();
    let stream = async_stream::stream! {
        while let Ok(evt) = rx.recv().await {
            if evt.tunnel_id != tunnel.id {
                continue;
            }
            let data = serde_json::to_string(&evt).unwrap_or_else(|_| "{}".into());
            yield Ok(Event::default().event("capture").data(data));
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::new()))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn static_css() -> Response {
    const CSS: &str = include_str!("../assets/app.css");
    // no-cache in dev so edits take effect on refresh; prod can flip this to
    // max-age once the stylesheet stabilizes and we add a content hash.
    Response::builder()
        .header("content-type", "text/css; charset=utf-8")
        .header("cache-control", "no-cache, must-revalidate")
        .body(axum::body::Body::from(CSS))
        .expect("static css response")
}

// ---------------------------------------------------------------------------
// tunnel detail + capture viewer
// ---------------------------------------------------------------------------

async fn tunnel_detail(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(tunnel) = dao::find_tunnel_for_org(&state.db, org.id, id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "tunnel not found").into_response();
    };
    let captures = dao::list_captures(&state.db, tunnel.id, 200).await.unwrap_or_default();
    let url = crate::templates::render_public_url(
        &state.config.tunnel_scheme,
        &state.config.tunnel_public_port,
        &tunnel.hostname,
    );
    TunnelPage { ctx: OrgCtx::from(&user, &org), nav: "tunnels", tunnel, url, captures }
        .into_response()
}

async fn delete_disconnected_route(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let removed = dao::delete_disconnected_tunnels_for_org(&state.db, org.id).await.unwrap_or(0);
    tracing::info!(?org.id, removed, "bulk-deleted disconnected tunnels");
    Redirect::to("/").into_response()
}

async fn delete_tunnel_route(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    // Refuse to delete a tunnel that's still active — the user almost
    // certainly wants to keep the row in the dashboard while the CLI is
    // still serving traffic. Disconnect first, then delete.
    if let Ok(Some(t)) = dao::find_tunnel_for_org(&state.db, org.id, id).await {
        if t.state == "active" {
            return (
                StatusCode::CONFLICT,
                "tunnel is active — stop the CLI (or wait for it to disconnect) before deleting",
            )
                .into_response();
        }
    }
    let _ = dao::delete_tunnel_for_org(&state.db, id, org.id).await;
    Redirect::to("/").into_response()
}

async fn clear_captures_route(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(tunnel) = dao::find_tunnel_for_org(&state.db, org.id, id).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "tunnel not found").into_response();
    };
    let removed = dao::clear_captures_for_tunnel(&state.db, tunnel.id).await.unwrap_or(0);
    tracing::info!(?tunnel.id, removed, "cleared captures");
    Redirect::to(&format!("/tunnels/{}", tunnel.id)).into_response()
}

async fn capture_detail(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path((tid, cid)): Path<(Uuid, Uuid)>,
) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(tunnel) = dao::find_tunnel_for_org(&state.db, org.id, tid).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "tunnel not found").into_response();
    };
    let Some(capture) = dao::get_capture(&state.db, cid).await.ok().flatten() else {
        return (StatusCode::NOT_FOUND, "capture not found").into_response();
    };
    if capture.tunnel_id != tunnel.id {
        return (StatusCode::NOT_FOUND, "capture not found").into_response();
    }
    let req_headers = crate::templates::parse_headers_json(&capture.req_headers_json);
    let resp_headers =
        crate::templates::parse_headers_json(capture.resp_headers_json.as_deref().unwrap_or("[]"));
    let req_body =
        crate::templates::classify_body(&req_headers, capture.req_body.as_deref().unwrap_or(&[]));
    let resp_body =
        crate::templates::classify_body(&resp_headers, capture.resp_body.as_deref().unwrap_or(&[]));
    CapturePage {
        ctx: OrgCtx::from(&user, &org),
        nav: "tunnels",
        tunnel,
        capture,
        req_headers,
        resp_headers,
        req_body,
        resp_body,
    }
    .into_response()
}

// ---------------------------------------------------------------------------
// login / oauth
// ---------------------------------------------------------------------------

async fn login(State(state): State<AppState>) -> Response {
    LoginPage { github_enabled: state.config.github.is_some(), dev_enabled: state.config.dev_mode }
        .into_response()
}

/// Dev-only: create-or-reuse a `dev@local` user, set a session cookie,
/// redirect to /. Disabled unless `dev_mode = true` on the control config.
async fn dev_login(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    if !state.config.dev_mode {
        return (StatusCode::NOT_FOUND, "dev login disabled").into_response();
    }
    let user = match dao::upsert_github_user(
        &state.db,
        0, // sentinel github_id for the dev user
        "dev",
        Some("dev@local"),
        Some("Dev User"),
        None,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let org = match dao::primary_org_for_user(&state.db, user.id).await {
        Ok(Some(o)) => o,
        _ => {
            let org = match dao::create_org(&state.db, "Dev workspace", "dev").await {
                Ok(o) => o,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };
            let _ = dao::add_org_member(&state.db, org.id, user.id, relay_db::models::Role::Owner)
                .await;
            org
        }
    };
    let sid = match dao::create_session(&state.db, user.id, org.id, 60 * 60 * 24 * 30).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let cookie = Cookie::build((SESSION_COOKIE, sid.to_string()))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(30))
        .build();
    let jar = jar.add(cookie);
    (jar, Redirect::to("/")).into_response()
}

async fn github_start(State(state): State<AppState>, jar: PrivateCookieJar) -> impl IntoResponse {
    let (jar, url) = start_github_login(&state, jar);
    (jar, Redirect::to(&url))
}

async fn github_callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    axum::extract::Query(params): axum::extract::Query<GithubCallback>,
) -> Response {
    match complete_github_login(&state, jar, params).await {
        Ok((jar, _sid)) => {
            // If a CLI login was in progress before the GitHub detour, bounce
            // the user back to the authorize page; otherwise land on home.
            let target = if jar.get(CLI_RETURN_COOKIE).is_some() { "/cli/authorize" } else { "/" };
            (jar, Redirect::to(target)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// CLI authorize flow: browser → /cli/authorize?callback=&state= →
// (optional login) → confirmation → POST approve → redirect back to callback
// with a freshly-minted token.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CliAuthorizeQuery {
    // Optional because after a login detour the GitHub callback redirects
    // here with no query string — we then restore callback+state from the
    // pending cookie.
    callback: Option<String>,
    state: Option<String>,
}

/// Only accept loopback callbacks. Anything else risks handing a token to a
/// remote party. We parse loosely (no full URL crate) — just enough to check
/// the scheme and host.
fn validate_loopback_callback(raw: &str) -> Result<(), &'static str> {
    let after_scheme = raw.strip_prefix("http://").ok_or("callback must use http (loopback)")?;
    // host is everything before the next '/', ':', or '?'.
    let host_end = after_scheme.find(['/', ':', '?']).unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    if host.is_empty() {
        return Err("callback has no host");
    }
    match host {
        "127.0.0.1" | "localhost" | "[::1]" => Ok(()),
        _ => Err("callback must be a loopback address (127.0.0.1 / localhost / ::1)"),
    }
}

async fn cli_authorize(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    axum::extract::Query(q): axum::extract::Query<CliAuthorizeQuery>,
) -> Response {
    // Resolve callback+state: prefer the URL query (fresh entry), fall back
    // to the pending cookie (post-login detour — GitHub's callback lands us
    // back here with no query string).
    let (callback, cli_state) = match (q.callback, q.state) {
        (Some(cb), Some(st)) => (cb, st),
        _ => match jar.get(CLI_RETURN_COOKIE).map(|c| c.value().to_string()) {
            Some(raw) => match raw.split_once('\n') {
                Some((cb, st)) => (cb.to_string(), st.to_string()),
                None => {
                    return (StatusCode::BAD_REQUEST, "malformed pending CLI cookie")
                        .into_response();
                }
            },
            None => return (StatusCode::BAD_REQUEST, "missing callback + state").into_response(),
        },
    };
    if let Err(reason) = validate_loopback_callback(&callback) {
        return (StatusCode::BAD_REQUEST, format!("invalid callback: {reason}")).into_response();
    }
    // (Re-)stash so the confirmation POST and any login detour pick it back up.
    let payload = format!("{}\n{}", callback, cli_state);
    let cookie = Cookie::build((CLI_RETURN_COOKIE, payload))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build();
    let jar = jar.add(cookie);

    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        // Redirect into login; cookie persists the pending CLI auth.
        Err(_) => return (jar, Redirect::to("/login")).into_response(),
    };

    (jar, CliAuthorizePage { ctx: OrgCtx::from(&user, &org), callback, state: cli_state })
        .into_response()
}

async fn cli_authorize_approve(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(raw) = jar.get(CLI_RETURN_COOKIE).map(|c| c.value().to_string()) else {
        return (StatusCode::BAD_REQUEST, "no pending CLI login").into_response();
    };
    let Some((callback, cli_state)) = raw.split_once('\n') else {
        return (StatusCode::BAD_REQUEST, "malformed pending CLI cookie").into_response();
    };
    // Re-validate so a stale cookie can't smuggle in a non-loopback URL.
    if let Err(reason) = validate_loopback_callback(callback) {
        return (StatusCode::BAD_REQUEST, format!("invalid callback: {reason}")).into_response();
    }

    let (plain, hashed) = generate_token();
    let name = format!("relay cli ({})", time::OffsetDateTime::now_utc().date());
    if let Err(e) = dao::create_api_token(
        &state.db,
        org.id,
        user.id,
        &name,
        &hashed,
        "tunnels:create,tunnels:manage,domains:manage",
    )
    .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let sep = if callback.contains('?') { '&' } else { '?' };
    let redirect_url = format!(
        "{callback}{sep}token={tok}&state={st}",
        tok = urlencoding::encode(&plain),
        st = urlencoding::encode(cli_state),
    );
    let jar = jar.remove(Cookie::from(CLI_RETURN_COOKIE));
    (jar, Redirect::to(&redirect_url)).into_response()
}

/// Cancel a pending CLI auth: tells the local CLI listener so it can exit
/// cleanly instead of sitting on the 5-minute timeout. No auth required —
/// the cancel cookie is the only thing a malicious caller could touch, and
/// the worst outcome is a "you cancelled" message in someone else's terminal.
async fn cli_authorize_cancel(jar: PrivateCookieJar) -> Response {
    let Some(raw) = jar.get(CLI_RETURN_COOKIE).map(|c| c.value().to_string()) else {
        return (StatusCode::BAD_REQUEST, "no pending CLI login").into_response();
    };
    let Some((callback, cli_state)) = raw.split_once('\n') else {
        return (StatusCode::BAD_REQUEST, "malformed pending CLI cookie").into_response();
    };
    if validate_loopback_callback(callback).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid callback").into_response();
    }
    let sep = if callback.contains('?') { '&' } else { '?' };
    let redirect_url =
        format!("{callback}{sep}error=cancelled&state={st}", st = urlencoding::encode(cli_state),);
    let jar = jar.remove(Cookie::from(CLI_RETURN_COOKIE));
    (jar, Redirect::to(&redirect_url)).into_response()
}

async fn logout(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        if let Ok(sid) = c.value().parse::<Uuid>() {
            let _ = dao::delete_session(&state.db, sid).await;
        }
    }
    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    (jar, Redirect::to("/login")).into_response()
}

// ---------------------------------------------------------------------------
// home (tunnels)
// ---------------------------------------------------------------------------

async fn home(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let tunnels = dao::list_tunnels_for_org(&state.db, org.id).await.unwrap_or_default();
    let port_str = state.config.tunnel_public_port.map(|p| p.to_string()).unwrap_or_default();
    let has_disconnected = tunnels.iter().any(|t| t.state != "active");
    HomePage {
        ctx: OrgCtx::from(&user, &org),
        nav: "tunnels",
        tunnels,
        base_domain: state.config.base_domain.clone(),
        tunnel_scheme: state.config.tunnel_scheme.clone(),
        tunnel_public_port: state.config.tunnel_public_port,
        tunnel_public_port_str: port_str,
        has_disconnected,
    }
    .into_response()
}

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

async fn tokens_page(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let tokens = dao::list_tokens_for_org(&state.db, org.id).await.unwrap_or_default();
    TokensPage { ctx: OrgCtx::from(&user, &org), nav: "tokens", tokens, fresh_token: None }
        .into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    name: String,
}

async fn create_token(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Form(form): Form<TokenForm>,
) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let (plain, hashed) = generate_token();
    let _id = match dao::create_api_token(
        &state.db,
        org.id,
        user.id,
        &form.name,
        &hashed,
        "tunnels:create,tunnels:manage,domains:manage",
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let tokens = dao::list_tokens_for_org(&state.db, org.id).await.unwrap_or_default();
    TokensPage { ctx: OrgCtx::from(&user, &org), nav: "tokens", tokens, fresh_token: Some(plain) }
        .into_response()
}

async fn delete_token_route(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = dao::delete_token(&state.db, id, org.id).await;
    Redirect::to("/tokens").into_response()
}

// ---------------------------------------------------------------------------
// reservations
// ---------------------------------------------------------------------------

async fn reservations_page(State(state): State<AppState>, jar: PrivateCookieJar) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let reservations = dao::list_reservations_for_org(&state.db, org.id).await.unwrap_or_default();
    ReservationsPage {
        ctx: OrgCtx::from(&user, &org),
        nav: "reservations",
        reservations,
        base_domain: state.config.base_domain.clone(),
    }
    .into_response()
}

#[derive(Deserialize)]
struct ReservationForm {
    label: String,
}

async fn create_reservation(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Form(form): Form<ReservationForm>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let label = form.label.trim().to_ascii_lowercase();
    if !valid_label(&label) {
        return (StatusCode::BAD_REQUEST, "label must be [a-z0-9-]+ and not start/end with '-'")
            .into_response();
    }
    let _ = dao::create_reservation(&state.db, org.id, &label).await;
    Redirect::to("/reservations").into_response()
}

async fn delete_reservation_route(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = dao::delete_reservation(&state.db, id, org.id).await;
    Redirect::to("/reservations").into_response()
}

fn valid_label(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') || s.ends_with('-') {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

// ---------------------------------------------------------------------------
// domains
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DomainsQuery {
    verify_err: Option<String>,
    host: Option<String>,
}

async fn domains_page(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    axum::extract::Query(q): axum::extract::Query<DomainsQuery>,
) -> Response {
    let AuthedUser { user, org } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let domains = dao::list_custom_domains(&state.db, org.id).await.unwrap_or_default();
    let verify_error = match (q.verify_err, q.host) {
        (Some(e), Some(h)) => Some((h, e)),
        _ => None,
    };
    DomainsPage {
        ctx: OrgCtx::from(&user, &org),
        nav: "domains",
        domains,
        apex_target: state.config.base_domain.clone(),
        delegation_zone: state.config.acme_delegation_zone.clone(),
        verify_error,
    }
    .into_response()
}

#[derive(Deserialize)]
struct DomainForm {
    hostname: String,
    /// Checkbox from the create form. Missing = unchecked = false.
    #[serde(default)]
    wildcard: Option<String>,
}

async fn create_domain(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Form(form): Form<DomainForm>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let hostname = form.hostname.trim().to_ascii_lowercase();
    if !valid_domain(&hostname) {
        return (StatusCode::BAD_REQUEST, "invalid hostname").into_response();
    }
    // An HTML checkbox POSTs nothing when unchecked and the literal value
    // ("on") when checked. Treat anything present as true.
    let wildcard = form.wildcard.is_some();
    if wildcard && state.config.acme_delegation_zone.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "wildcard domains require [acme].delegation_zone to be configured",
        )
            .into_response();
    }
    let token = Uuid::new_v4().to_string();
    let slug = if wildcard { Some(generate_delegation_slug()) } else { None };
    let _ =
        dao::create_custom_domain(&state.db, org.id, &hostname, &token, wildcard, slug.as_deref())
            .await;
    Redirect::to("/domains").into_response()
}

/// 16 hex chars is plenty of entropy for a per-domain label and short
/// enough that users won't squint when pasting the CNAME target.
fn generate_delegation_slug() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn verify_domain(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let AuthedUser { org, .. } = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(domain) = dao::find_custom_domain_for_org(&state.db, id, org.id).await.ok().flatten()
    else {
        return (StatusCode::NOT_FOUND, "domain not found").into_response();
    };

    // Step 1: ownership TXT. Required for both apex-only and wildcard.
    if let Err(e) = crate::verify::verify_txt(&domain.hostname, &domain.verification_token).await {
        tracing::info!(hostname = %domain.hostname, error = %e, "custom domain TXT verification failed");
        return Redirect::to(&format!(
            "/domains?verify_err={}&host={}",
            urlencoding::encode(&e.to_string()),
            urlencoding::encode(&domain.hostname)
        ))
        .into_response();
    }

    // Step 2 (wildcard only): the user must also CNAME _acme-challenge to
    // our delegation target so renewals work unattended.
    if domain.wildcard {
        let (Some(zone), Some(slug)) =
            (state.config.acme_delegation_zone.as_ref(), domain.acme_delegation_slug.as_ref())
        else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "wildcard domain is missing delegation metadata — re-create it",
            )
                .into_response();
        };
        let target = format!("{slug}.{zone}");
        if let Err(e) = crate::verify::verify_acme_delegation_cname(&domain.hostname, &target).await
        {
            tracing::info!(hostname = %domain.hostname, error = %e, "custom domain CNAME verification failed");
            return Redirect::to(&format!(
                "/domains?verify_err={}&host={}",
                urlencoding::encode(&e.to_string()),
                urlencoding::encode(&domain.hostname)
            ))
            .into_response();
        }
    }

    let _ = dao::mark_custom_domain_verified(&state.db, id).await;
    tracing::info!(?id, hostname = %domain.hostname, wildcard = domain.wildcard, "custom domain verified");

    if let Some(issuer) = state.cert_issuer.clone() {
        let hostname = domain.hostname.clone();
        let slug = domain.acme_delegation_slug.clone();
        tokio::spawn(async move {
            let res = issuer.ensure_cert(&hostname, slug.as_deref()).await;
            if let Err(e) = res {
                tracing::warn!(%hostname, ?e, "custom-domain cert issuance failed");
            }
        });
    } else {
        tracing::warn!(
            hostname = %domain.hostname,
            "verified but no cert issuer configured — no HTTPS cert will be issued"
        );
    }
    Redirect::to("/domains").into_response()
}

async fn delete_domain(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = match require_auth(&state, &jar).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = dao::delete_custom_domain_by_id(&state.db, id).await;
    Redirect::to("/domains").into_response()
}

fn valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !s.starts_with('.')
        && !s.ends_with('.')
}
