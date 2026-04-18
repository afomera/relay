# Wire protocol

See [`../SPEC.md`](../SPEC.md) §4 for the overview. This document is the
canonical reference for the bytes on the wire.

## Transport

- QUIC over UDP with TLS 1.3.
- ALPN: `relay/1` (see `relay_proto::ALPN`).
- Keepalive: CLI sends a QUIC PING every 10s; edge closes connections idle
  for >30s.

## Framing

Every message on a QUIC stream is:

```
[u32 little-endian length] [CBOR payload]
```

- 16 MiB max frame (`MAX_FRAME`).
- HTTP/TCP bodies are *not* framed — they're raw bytes immediately after the
  CBOR header frame, terminated by `send.finish()`.

## Control-stream messages

On the first bidi stream the CLI opens, both sides exchange the `ClientMsg`
and `ServerMsg` enums from `crates/relay-proto/src/lib.rs`:

- `ClientMsg::Hello(ClientHello)` → `ServerMsg::Hello(ServerHello)` with a
  version check.
- `ClientMsg::Register(RegisterTunnel)` → `ServerMsg::Registered` or
  `ServerMsg::Rejected` with a `req_id` that matches.
- `ClientMsg::Unregister { tunnel_id }` (no reply).
- `Ping { seq }` / `Pong { seq }` in either direction.

## Per-request streams

For every public request, the edge opens a fresh bidi stream toward the CLI
and sends:

- `StreamOpen::Http(HttpRequestHeader)` — then raw request body bytes.
  The CLI responds with `HttpResponseHeader` + raw response body bytes.
- `StreamOpen::Tcp(TcpConnectHeader)` — then raw payload bytes, bidirectional
  until either side calls `finish()`.

## Versioning

- `PROTOCOL_VERSION = 1`. Sent in `ClientHello` / `ServerHello`; mismatches
  cause a hard close.
- Adding message variants is backwards-compatible (CBOR-tagged unions in Rust,
  `#[serde(tag = "t", rename_all = "snake_case")]`).
- Breaking changes bump the version and the ALPN (e.g. `relay/2`).
