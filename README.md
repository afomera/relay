# Relay

Self-hostable tunneling service. A Rust-based alternative to ngrok.

- **CLI**: `relay` — expose a local port to the internet over QUIC.
- **Server**: `relayd` — single binary, SQLite or Postgres, pluggable DNS provider for wildcard TLS.
- **License**: MIT.

Status: pre-alpha. Spec lives in [`SPEC.md`](./SPEC.md).

## Install (Apple Silicon macOS)

```sh
brew tap afomera/relay https://github.com/afomera/relay.git
brew install relay
```

or, without Homebrew:

```sh
curl -fsSL https://raw.githubusercontent.com/afomera/relay/main/scripts/install.sh | sh
```

Intel macOS / Linux / Windows: build from source — `cargo install --git https://github.com/afomera/relay relay-cli`.

## Quick glance

```sh
# hosted
relay auth login --token rly_pat_...
relay http 3000
# → https://bright-otter.temporary.sharedwithrelay.com

# reserved subdomain (wildcard)
relay http 3000 --hostname api.andrea
# → https://api.andrea.sharedwithrelay.com

# custom domain
relay http 3000 --domain tunnel.mycompany.com

# raw tcp
relay tcp 5432
# → tcp.sharedwithrelay.com:29734
```

## Self-hosting

See [`docs/self-hosting.md`](./docs/self-hosting.md) (WIP). Minimum requirements:

- One host with public `:80` / `:443` (TCP + UDP).
- DNS control over some base domain (e.g. `*.tunnels.example.com`).
- A DNS provider API token (Cloudflare / Route53 / RFC2136).
- SQLite or Postgres.

## Development

Workspace layout and milestones in [`SPEC.md`](./SPEC.md).
