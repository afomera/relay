//! Askama templates for the dashboard. One struct per page; `base.html` is
//! inherited for nav and layout.

use askama::Template;
use relay_db::models::{
    ApiToken, CustomDomain, InspectionCapture, Organization, Reservation, Tunnel, User,
};

pub struct OrgCtx {
    pub org_name: String,
    pub user_login: String,
}

impl OrgCtx {
    pub fn from(user: &User, org: &Organization) -> Self {
        Self { org_name: org.name.clone(), user_login: user.login.clone() }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub github_enabled: bool,
    pub dev_enabled: bool,
}

/// Shown when a CLI (or any off-dashboard client) sends the user to
/// `/cli/authorize` to mint an API token bound to a local callback URL.
/// The `callback` has already been origin-validated by the handler.
#[derive(Template)]
#[template(path = "cli_authorize.html")]
pub struct CliAuthorizePage {
    pub ctx: OrgCtx,
    pub callback: String,
    pub state: String,
}

#[derive(Template)]
#[template(path = "home.html")]
pub struct HomePage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub tunnels: Vec<Tunnel>,
    pub base_domain: String,
    pub tunnel_scheme: String,
    pub tunnel_public_port: Option<u16>,
    /// Pre-rendered port string (empty when `None`) so the template can emit
    /// it cleanly onto a data- attribute for the live-updates JS.
    pub tunnel_public_port_str: String,
    /// `true` if any tunnel in the list is currently disconnected. Used to
    /// show/hide the bulk-delete button (askama 0.12 doesn't support closure
    /// methods like `.iter().any(|t| ...)` inside a template).
    pub has_disconnected: bool,
}

#[derive(Template)]
#[template(path = "tokens.html")]
pub struct TokensPage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub tokens: Vec<ApiToken>,
    /// Set just-created token shown once.
    pub fresh_token: Option<String>,
}

#[derive(Template)]
#[template(path = "reservations.html")]
pub struct ReservationsPage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub reservations: Vec<Reservation>,
    pub base_domain: String,
}

#[derive(Template)]
#[template(path = "domains.html")]
pub struct DomainsPage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub domains: Vec<CustomDomain>,
    pub apex_target: String,
    /// Zone this deploy operates for ACME DNS-01 delegation (e.g.
    /// `acme-delegate.withrelay.dev`). When `Some`, the wildcard toggle
    /// and the per-domain `_acme-challenge` CNAME hint are rendered.
    pub delegation_zone: Option<String>,
    /// Set when a /domains/:id/verify attempt failed — rendered as a banner.
    pub verify_error: Option<(String, String)>,
}

#[derive(Template)]
#[template(path = "tunnel.html")]
pub struct TunnelPage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub tunnel: Tunnel,
    pub url: String,
    pub captures: Vec<InspectionCapture>,
}

#[derive(Template)]
#[template(path = "capture.html")]
pub struct CapturePage {
    pub ctx: OrgCtx,
    pub nav: &'static str,
    pub tunnel: Tunnel,
    pub url: String,
    pub captures: Vec<InspectionCapture>,
    pub capture: InspectionCapture,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub req_body: RenderedBody,
    pub resp_body: RenderedBody,
}

/// Renders only the capture detail panel — no base layout, no page chrome.
/// Returned to HTMX swap requests so the list stays put and just the right
/// pane updates.
#[derive(Template)]
#[template(path = "capture_panel.html")]
pub struct CapturePanelPartial {
    pub tunnel: Tunnel,
    pub capture: InspectionCapture,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub req_body: RenderedBody,
    pub resp_body: RenderedBody,
}

/// Body rendering state — flat so askama's `{% match %}` can use simple
/// variant arms without `with { ... }` destructuring syntax.
#[derive(Debug, Clone)]
pub enum RenderedBody {
    Empty,
    Text { text: String, language: &'static str },
    /// Parsed `application/x-www-form-urlencoded` body: percent-decoded
    /// key/value pairs ready to render as a table.
    FormParams { params: Vec<(String, String)> },
    Binary { bytes: usize },
}

pub fn classify_body(headers: &[(String, String)], body: &[u8]) -> RenderedBody {
    if body.is_empty() {
        return RenderedBody::Empty;
    }
    let ct = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    // Form bodies get their own renderer — a table is easier to scan than a
    // blob of `k=v&k=v` urlencoded text.
    if ct.contains("x-www-form-urlencoded") {
        if let Ok(text) = std::str::from_utf8(body) {
            return RenderedBody::FormParams { params: parse_form_urlencoded(text) };
        }
        return RenderedBody::Binary { bytes: body.len() };
    }

    let language: &'static str = if ct.contains("json") {
        "json"
    } else if ct.contains("html") {
        "html"
    } else if ct.contains("xml") {
        "xml"
    } else if ct.contains("javascript") || ct.contains("ecmascript") {
        "javascript"
    } else if ct.contains("yaml") {
        "yaml"
    } else if ct.contains("css") {
        "css"
    } else if ct.starts_with("text/") {
        "plaintext"
    } else {
        return RenderedBody::Binary { bytes: body.len() };
    };

    let Ok(text) = std::str::from_utf8(body) else {
        return RenderedBody::Binary { bytes: body.len() };
    };

    let rendered = if language == "json" {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or_else(|| text.to_string())
    } else {
        text.to_string()
    };

    RenderedBody::Text { text: rendered, language }
}

/// Parse an `application/x-www-form-urlencoded` string into decoded key/value
/// pairs. Form encoding uses `+` for space (distinct from generic percent
/// encoding), so we replace `+` → ` ` before running percent decoding.
fn parse_form_urlencoded(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_component(raw_k), decode_form_component(raw_v))
        })
        .collect()
}

fn decode_form_component(s: &str) -> String {
    let spaced = s.replace('+', " ");
    urlencoding::decode(&spaced).map(|cow| cow.into_owned()).unwrap_or(spaced)
}

pub fn parse_headers_json(s: &str) -> Vec<(String, String)> {
    serde_json::from_str(s).unwrap_or_default()
}

pub fn duration_short(ms: &Option<i64>) -> String {
    match ms {
        Some(n) if *n < 1000 => format!("{n}ms"),
        Some(n) => format!("{:.2}s", *n as f64 / 1000.0),
        None => "—".into(),
    }
}

pub fn opt_status(s: &Option<i64>) -> String {
    match s {
        Some(n) => n.to_string(),
        None => "—".into(),
    }
}

/// CSS class bucket for an HTTP status — lets the dashboard tint the list
/// row without hardcoding colors per code. 1xx covers informational replies
/// like 101 Switching Protocols (WebSocket upgrades).
pub fn status_class(s: &Option<i64>) -> &'static str {
    match s {
        Some(n) if (100..200).contains(n) => "1xx",
        Some(n) if (200..300).contains(n) => "2xx",
        Some(n) if (300..400).contains(n) => "3xx",
        Some(n) if (400..500).contains(n) => "4xx",
        Some(n) if (500..600).contains(n) => "5xx",
        _ => "none",
    }
}

pub fn format_time(unix: &i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(*unix) {
        Ok(t) => t
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| unix.to_string()),
        Err(_) => unix.to_string(),
    }
}

pub fn opt_time(unix: &Option<i64>) -> String {
    match unix {
        Some(u) => format_time(u),
        None => "never".into(),
    }
}

/// Compact "x ago" formatter for relative timestamps. Matches how most ops
/// dashboards render recency (uptime, last-seen, queue lag, etc).
pub fn time_ago(unix: &i64) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let diff = now - *unix;
    if diff < 2 {
        return "just now".into();
    }
    if diff < 60 {
        return format!("{diff}s ago");
    }
    let mins = diff / 60;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    let days = hours / 24;
    if days < 30 {
        return format!("{days}d ago");
    }
    let months = days / 30;
    if months < 12 {
        return format!("{months}mo ago");
    }
    format!("{}y ago", months / 12)
}

pub fn opt_time_ago(unix: &Option<i64>) -> String {
    match unix {
        Some(u) => time_ago(u),
        None => "never".into(),
    }
}

/// Render a tunnel's public URL. Hostnames stored as `tcp://host:port` (TCP
/// tunnels) are returned verbatim; HTTP/TLS hostnames get the configured
/// scheme + optional dev port.
pub fn render_public_url(scheme: &str, port: &Option<u16>, hostname: &str) -> String {
    if hostname.contains("://") {
        return hostname.to_string();
    }
    match port {
        Some(p) => format!("{scheme}://{hostname}:{p}"),
        None => format!("{scheme}://{hostname}"),
    }
}
