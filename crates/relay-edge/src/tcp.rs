//! TCP tunnel support: per-tunnel port allocation + TcpListener → QUIC bidi
//! forwarding.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use parking_lot::Mutex as PMutex;
use relay_proto::{StreamOpen, TcpConnectHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::config::EdgeConfig;

/// Tracks which ports in the config's `tcp_port_range` are currently bound.
#[derive(Default)]
pub struct TcpPortPool {
    used: PMutex<HashSet<u16>>,
}

impl TcpPortPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allocate(&self, range: &std::ops::RangeInclusive<u16>) -> Option<u16> {
        let mut used = self.used.lock();
        for port in range.clone() {
            if !used.contains(&port) {
                used.insert(port);
                return Some(port);
            }
        }
        None
    }

    pub fn release(&self, port: u16) {
        self.used.lock().remove(&port);
    }
}

/// Spawns a listener on `0.0.0.0:port` that forwards accepted TCP connections
/// to the CLI's QUIC connection via fresh bidi streams. Returns when the
/// handle's cancel signal fires.
pub async fn run_listener(
    _cfg: Arc<EdgeConfig>,
    tunnel_id: Uuid,
    conn: quinn::Connection,
    port: u16,
    mut cancel: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let bind: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, ?tunnel_id, "tcp tunnel listener bound");

    loop {
        tokio::select! {
            _ = &mut cancel => {
                tracing::info!(%bind, ?tunnel_id, "tcp listener shutting down");
                return Ok(());
            }
            accept = listener.accept() => {
                let (mut tcp, remote) = match accept {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(e = %format!("{e:#}"), "tcp accept");
                        continue;
                    }
                };
                let conn = conn.clone();
                tokio::spawn(async move {
                    let Ok((mut send, mut recv)) = conn.open_bi().await else { return };
                    let connection_id = Uuid::new_v4();
                    let hdr = StreamOpen::Tcp(TcpConnectHeader {
                        tunnel_id,
                        connection_id,
                        remote_ip: remote.ip().to_string(),
                    });
                    if relay_proto::write_frame(&mut send, &hdr).await.is_err() {
                        return;
                    }
                    // Bidirectional byte copy.
                    let (mut tcp_r, mut tcp_w) = tcp.split();
                    let to_quic = async {
                        let mut buf = [0u8; 16 * 1024];
                        loop {
                            match tcp_r.read(&mut buf).await {
                                Ok(0) => { let _ = send.finish(); break; }
                                Ok(n) => if send.write_all(&buf[..n]).await.is_err() { break; },
                                Err(_) => break,
                            }
                        }
                    };
                    let from_quic = async {
                        let mut buf = [0u8; 16 * 1024];
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(0)) => break,
                                Ok(Some(n)) => if tcp_w.write_all(&buf[..n]).await.is_err() { break; },
                                Ok(None) => break,
                                Err(_) => break,
                            }
                        }
                    };
                    tokio::join!(to_quic, from_quic);
                });
            }
        }
    }
}

// Dead imports kept intentionally — some will be used once the cancellation
// wiring lands at the registry level.
#[allow(dead_code)]
fn _silence_unused(_: Arc<Mutex<()>>) {}
