//! Terminal UI for the connected view: a styled header + a streaming table
//! of requests as they arrive. Colors degrade gracefully (TTY detection +
//! `NO_COLOR`) via `owo-colors`'s `if_supports_color`.

use owo_colors::{OwoColorize, Stream::Stdout};
use tokio::sync::mpsc;

/// A completed HTTP request as observed by the CLI — enough to render one row.
pub struct ReqEvent {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
}

pub fn print_http_banner(
    dashboard: &str,
    public_url: &str,
    port: u16,
    inspect: bool,
    password_protected: bool,
) {
    println!();
    println!("  {}", "relay tunnel established".if_supports_color(Stdout, |t| t.bold()));
    println!();
    print_kv("dashboard", dashboard);
    print_forwarding(public_url, &format!("http://127.0.0.1:{port}"));
    print_kv("inspection", if inspect { "on" } else { "off" });
    if password_protected {
        print_kv("password", "required");
    }
    println!();
    print_request_header();
}

pub fn print_tcp_banner(dashboard: &str, public_url: &str, port: u16) {
    println!();
    println!("  {}", "relay tcp tunnel established".if_supports_color(Stdout, |t| t.bold()));
    println!();
    print_kv("dashboard", dashboard);
    print_forwarding(public_url, &format!("127.0.0.1:{port}"));
    println!();
}

fn print_kv(label: &str, value: &str) {
    println!(
        "  {:<12} {}",
        label.if_supports_color(Stdout, |t| t.dimmed()),
        value.if_supports_color(Stdout, |t| t.cyan()),
    );
}

fn print_forwarding(public_url: &str, local: &str) {
    println!(
        "  {:<12} {}  {}  {}",
        "forwarding".if_supports_color(Stdout, |t| t.dimmed()),
        public_url.if_supports_color(Stdout, |t| t.cyan()),
        "→".if_supports_color(Stdout, |t| t.dimmed()),
        local.if_supports_color(Stdout, |t| t.cyan()),
    );
}

fn print_request_header() {
    let header =
        format!("{:<8}  {:<7}  {:<6}  {:>8}  {}", "TIME", "METHOD", "STATUS", "DURATION", "PATH");
    println!("  {}", header.if_supports_color(Stdout, |t| t.dimmed()));
}

/// Spawn a background task that prints each `ReqEvent` as a table row.
pub fn spawn_request_printer(mut rx: mpsc::UnboundedReceiver<ReqEvent>) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            print_request_row(&ev);
        }
    });
}

fn print_request_row(ev: &ReqEvent) {
    let time = chrono::Local::now().format("%H:%M:%S").to_string();
    let method = format!("{:<7}", truncate(&ev.method, 7));
    let status_padded = format!("{:<6}", ev.status);
    let dur = format!("{:>8}", format_duration(ev.duration_ms));

    let status_colored = match ev.status {
        200..=299 => status_padded.if_supports_color(Stdout, |t| t.green()).to_string(),
        300..=399 => status_padded.if_supports_color(Stdout, |t| t.cyan()).to_string(),
        400..=499 => status_padded.if_supports_color(Stdout, |t| t.yellow()).to_string(),
        _ => status_padded.if_supports_color(Stdout, |t| t.red()).to_string(),
    };

    println!(
        "  {}  {}  {}  {}  {}",
        time.if_supports_color(Stdout, |t| t.dimmed()),
        method,
        status_colored,
        dur.if_supports_color(Stdout, |t| t.dimmed()),
        ev.path,
    );
}

fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}s", ms / 60_000, (ms / 1000) % 60)
    }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}
