//! Library surface for the `relay` CLI. Also used by integration tests that
//! want to drive a tunnel programmatically.

pub mod client;
pub mod config;
pub mod tls;
pub mod ui;

/// Given a `host:port` server address (as stored in config or passed via
/// `--server`), return the dashboard's HTTPS URL — the dashboard is co-hosted
/// on the same host as the QUIC edge.
pub fn dashboard_url_from(server: &str) -> String {
    let host = server.split(':').next().unwrap_or(server);
    format!("https://{host}")
}

/// Default the server port to 443 (UDP/QUIC + HTTPS) when the user types a
/// bare hostname. Keeps `localhost:7443` and other explicit ports intact.
pub fn normalize_server(s: &str) -> String {
    let has_port = s
        .rsplit_once(':')
        .is_some_and(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if has_port { s.to_string() } else { format!("{s}:443") }
}
