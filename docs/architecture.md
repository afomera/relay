# Architecture

See [`../SPEC.md`](../SPEC.md) §3 for the overview diagram and §4 for the wire
protocol. This document maps those concepts onto the code.

## Crates

```
relay-proto    wire protocol types (CBOR) + length-prefixed frame codec
relay-db       sqlx-backed DAL; schema lives in `migrations/`
relay-dns      DnsProvider trait + Cloudflare impl + Route53/RFC2136 stubs
relay-acme     ACME DNS-01 issuance, cert store, renewal worker, encryption
relay-edge     QUIC tunnel server, HTTP(S) ingress, TCP port pool, routing
relay-control  axum API + Askama dashboard (GitHub OAuth, tokens, reservations, domains)
relay-cli      the `relay` CLI binary + reusable client library
relay-server   the `relayd` binary — wires edge + control into one process
```

Single `relayd` binary by default. A future hosted deployment can split edge
and control into two binaries — they're already separate library crates.

## Request path (HTTP tunnel)

1. CLI opens QUIC to the edge, sends `ClientHello`, gets `ServerHello` back.
2. CLI sends `RegisterTunnel { kind: Http, hostname: Some("api.andrea") }`.
3. Edge validates the hostname via the `ReservationStore` trait (DB-backed in
   prod, allow-all in `--dev`).
4. Edge inserts into the in-memory tunnel registry, replies `Registered`.
5. Public request to `https://api.andrea.sharedwithrelay.com/path` hits the
   HTTPS listener, TLS terminates via the cert resolver.
6. axum routes by Host header, looks up the tunnel in the registry.
7. Edge opens a fresh bidi QUIC stream, writes `StreamOpen::Http(header)`, then
   streams the request body onto the stream.
8. CLI reads the header, reconstitutes an HTTP/1.1 request with `reqwest`,
   sends to the local service, streams the response back over the same QUIC
   stream (header frame + raw bytes).
9. Edge reads the response header, builds an axum Response, streams the body
   out to the public client.

## Cert store & TLS

- `relay-acme::DbCertStore` loads every row from `certs` at startup and
  refreshes on a polling loop.
- `relay-acme::CertResolver` implements `rustls::server::ResolvesServerCert`
  and consults the store by SNI (with a wildcard fallback).
- The HTTPS ingress is a raw `TcpListener` + `tokio_rustls::TlsAcceptor`, then
  hands each TLS stream to `hyper::server::conn::http1::Builder` serving the
  shared axum `Router`.
- QUIC uses its own cert (matching the wildcard). The cert *material* is the
  same but quinn owns a separate `rustls::ServerConfig`.

## ACME wildcard issuance

`relay-acme::issue_wildcard` (DNS-01):

1. Create an ACME account at the configured directory (Let's Encrypt prod by
   default). Account credentials are discarded in v1 — every boot creates a
   fresh account until we persist them.
2. Place an order for `*.<base>` and `*.<temporary>.<base>`.
3. For each authorization, ask for the DNS-01 challenge, compute
   `KeyAuthorization::dns_value()`, publish it via the configured
   `DnsProvider::upsert_txt`, call `set_ready`.
4. `Order::poll_ready` blocks until the ACME server validates.
5. Generate a `rcgen::KeyPair`, build a CSR, `finalize_csr(csr.der())`.
6. `poll_certificate` returns the PEM chain.
7. Clean up TXT records, encrypt the private key with AES-GCM-SIV, upsert into
   `certs`.

The `RenewalWorker` re-runs this when a cert is within 30 days of
`not_after`, or when the store is empty on first boot.

## Auth

- Dashboard users authenticate with **GitHub OAuth**. Sessions are signed
  cookies (`tower-cookies`/`axum-extra::PrivateCookieJar`) over a DB-backed
  session table.
- CLI clients authenticate with **API tokens** (`rly_pat_...`). Tokens are
  hashed with argon2id at rest. The edge calls
  `DbAuthProvider::authenticate(token)`, which scans all rows and verifies
  one by one — fine for v1 volumes, a short-prefix index is the obvious
  upgrade path.

## Concurrency model

- Every QUIC connection is one task. Its control stream runs the register /
  unregister / ping message loop.
- Every public HTTP request is served by an axum handler that opens a fresh
  QUIC bidi stream to the CLI — concurrent requests get concurrent streams.
- TCP tunnels spawn one listener task per tunnel, plus one task per accepted
  TCP connection that bidirectionally copies bytes to the QUIC peer.
- The cert resolver is shared-ref (`Arc<dyn ResolvesServerCert>`), the
  tunnel registry is a `DashMap`, the TCP port pool is a `parking_lot::Mutex`
  around a `HashSet<u16>`.
