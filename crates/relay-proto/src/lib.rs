//! Wire protocol between `relay` (CLI) and `relayd` (server).
//!
//! Framing: length-prefixed CBOR. Every frame is `[u32 LE length] [CBOR payload]`,
//! max 16 MiB per frame. Message bodies (HTTP req/resp bodies, TCP payload) are
//! *not* framed — they are raw bytes after the CBOR header on the same QUIC stream
//! and terminate when the peer calls `finish()`.
//!
//! See `SPEC.md` §4 and `DECISIONS.md` D2–D3, D18 for the full design.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const ALPN: &[u8] = b"relay/1";
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Hello / handshake
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub auth_token: String,
    pub client_version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub protocol_version: u16,
    pub account_id: Uuid,
    pub features: Vec<Feature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Feature {
    Inspection,
    TcpTunnels,
    TlsPassthrough,
    CustomDomains,
}

// ---------------------------------------------------------------------------
// Tunnel registration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelKind {
    Http,
    Tcp,
    TlsPassthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterTunnel {
    pub req_id: Uuid,
    pub kind: TunnelKind,
    /// Desired hostname — `None` → random temporary name.
    ///
    /// For HTTP/TLS this is a fully-qualified hostname the CLI wants to claim.
    /// For TCP this is ignored by the server (it allocates a port).
    pub hostname: Option<String>,
    pub labels: Vec<(String, String)>,
    /// Inspection requested by the CLI. Server may refuse for non-HTTP kinds.
    pub inspect: bool,
    /// Optional plaintext password gating public access to this tunnel. The
    /// server argon2-hashes it on receipt and holds the hash in memory for the
    /// life of the connection only — never written to a database. `None` (the
    /// default, including for older CLIs that don't know about this field)
    /// leaves the tunnel public.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRegistered {
    pub req_id: Uuid,
    pub tunnel_id: Uuid,
    /// Human-friendly URL to display — `https://foo.example.com` or `tcp://edge:29734`.
    pub public_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRejected {
    pub req_id: Uuid,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Control-stream message envelopes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    Hello(ClientHello),
    Register(RegisterTunnel),
    Unregister { tunnel_id: Uuid },
    Ping { seq: u64 },
    Pong { seq: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    Hello(ServerHello),
    Registered(TunnelRegistered),
    Rejected(TunnelRejected),
    Ping { seq: u64 },
    Pong { seq: u64 },
}

// ---------------------------------------------------------------------------
// Per-request stream headers (one fresh bidi stream per public request)
// ---------------------------------------------------------------------------

/// First frame on a per-request stream opened by the edge toward the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum StreamOpen {
    Http(HttpRequestHeader),
    Tcp(TcpConnectHeader),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestHeader {
    pub tunnel_id: Uuid,
    pub request_id: Uuid,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub remote_ip: String,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseHeader {
    pub request_id: Uuid,
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConnectHeader {
    pub tunnel_id: Uuid,
    pub connection_id: Uuid,
    pub remote_ip: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("cbor encode: {0}")]
    Encode(String),
    #[error("cbor decode: {0}")]
    Decode(String),
    #[error("frame too large: {0} bytes")]
    Oversize(usize),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| ProtoError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtoError> {
    ciborium::from_reader(bytes).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// Write a single length-prefixed CBOR frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    let bytes = encode(msg)?;
    if bytes.len() > MAX_FRAME as usize {
        return Err(ProtoError::Oversize(bytes.len()));
    }
    let len = (bytes.len() as u32).to_le_bytes();
    w.write_all(&len).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

/// Read a single length-prefixed CBOR frame.
pub async fn read_frame<R, T>(r: &mut R) -> Result<T, ProtoError>
where
    R: AsyncRead + Unpin + ?Sized,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(ProtoError::Oversize(len as usize));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    decode(&buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = duplex(64 * 1024);
        let msg = ClientMsg::Hello(ClientHello {
            protocol_version: PROTOCOL_VERSION,
            auth_token: "rly_pat_abc".into(),
            client_version: "0.1.0".into(),
            os: "darwin".into(),
            arch: "arm64".into(),
        });
        write_frame(&mut a, &msg).await.unwrap();
        let got: ClientMsg = read_frame(&mut b).await.unwrap();
        match got {
            ClientMsg::Hello(h) => assert_eq!(h.auth_token, "rly_pat_abc"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn stream_open_variants() {
        let (mut a, mut b) = duplex(4096);
        let m = StreamOpen::Http(HttpRequestHeader {
            tunnel_id: Uuid::nil(),
            request_id: Uuid::nil(),
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("host".into(), "x".into())],
            remote_ip: "127.0.0.1".into(),
            tls: false,
        });
        write_frame(&mut a, &m).await.unwrap();
        let _: StreamOpen = read_frame(&mut b).await.unwrap();
    }

    #[tokio::test]
    async fn oversize_rejected_on_read() {
        let (mut a, mut b) = duplex(16);
        let len: u32 = MAX_FRAME + 1;
        use tokio::io::AsyncWriteExt;
        a.write_all(&len.to_le_bytes()).await.unwrap();
        let err = read_frame::<_, ClientMsg>(&mut b).await.unwrap_err();
        assert!(matches!(err, ProtoError::Oversize(_)));
    }
}
