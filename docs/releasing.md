# Releasing the relay CLI

Covers how a new CLI version reaches users' laptops.

## Distribution paths

| Audience | Path |
|---|---|
| **Apple Silicon macOS** (v1 target) | Homebrew (in-repo tap) or install script |
| Intel macOS, Linux, Windows | Source build only for now |
| Rust developers | `cargo install --git https://github.com/afomera/relay relay-cli` |

Expanding to more platforms is one matrix line in
`.github/workflows/release.yml` + a matching `on_intel` / `on_linux`
stanza in `Formula/relay.rb`. Deferred until there's demand — each
target adds a runner-minute of CI.

## Cutting a release

```sh
# 1. Bump the workspace version.
$EDITOR Cargo.toml                   # [workspace.package] version = "0.2.0"
cargo build --workspace              # refresh Cargo.lock

# 2. Commit, tag, push. The Makefile wraps the last two steps.
git commit -am "relay 0.2.0"
make release VERSION=0.2.0
```

Pushing the `v0.2.0` tag triggers `.github/workflows/release.yml`:

1. **build** — builds `relay` for `aarch64-apple-darwin` on an M1 runner.
2. **release** — packages `relay-v0.2.0-aarch64-apple-darwin.tar.gz`
   + a `.sha256`, attaches to a new GitHub Release with auto-generated
   notes.
3. **bump-formula** — regenerates `Formula/relay.rb` with the new
   version + sha256 and commits it back to `main`.

Nothing else to do — no second repo, no separate `make` command for the
formula bump.

## End-user install paths

### Homebrew (in-repo tap)

Formula lives at `Formula/relay.rb` at the root of this repo. Because
Homebrew's standard tap naming (`user/homebrew-tapname`) doesn't apply,
users tap once with the explicit URL:

```sh
brew tap afomera/relay https://github.com/afomera/relay.git
brew install relay
brew upgrade relay                    # future versions
```

The `tap` command runs once per machine. After that, `brew upgrade` (or
`brew update && brew upgrade relay`) pulls in new versions as the
release workflow commits formula bumps to `main`.

### Install script

```sh
curl -fsSL https://raw.githubusercontent.com/afomera/relay/main/scripts/install.sh | sh
```

Detects platform, downloads the latest release, installs to
`/usr/local/bin/relay`. Bails cleanly on non-Apple-Silicon platforms.

Once `withrelay.dev` is live, serve the script directly so the URL
becomes the more familiar `curl -fsSL https://withrelay.dev/install | sh`.

### From source

```sh
cargo install --git https://github.com/afomera/relay relay-cli
```

Always works regardless of target; requires a Rust toolchain. Useful
for dev previews of un-released branches.

## Versioning

Semver:
- **patch** — bugfix, UX copy, small UI changes
- **minor** — new CLI flags, new dashboard features, new DNS providers
- **major** — breaking changes to `PROTOCOL_VERSION` or `relayd.toml`
  schema. Bumping either means CLIs from the previous major can't talk
  to the new edge; also bump the ALPN (`relay/1` → `relay/2`) and
  announce loudly.

CLI + server versions are coupled in v1. Split them once older CLIs
in the wild need to keep working against a newer hosted edge.
