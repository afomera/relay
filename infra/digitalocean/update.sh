#!/usr/bin/env bash
# Runs *on* the droplet. Idempotent.
#
#   git fetch, checkout requested ref, rebuild image, restart relayd.
#
# DB migrations auto-run on startup. Certs live in the SQLite DB; a restart
# doesn't lose them. Active CLI tunnels drop during the ~3s container restart
# and reconnect on their own via the built-in backoff loop.
#
# Usage on the droplet:
#   sudo -u relay /home/relay/relay/infra/digitalocean/update.sh           # defaults to main
#   sudo -u relay /home/relay/relay/infra/digitalocean/update.sh v0.2.0    # pin a tag

set -euo pipefail

REF="${1:-main}"
REPO_DIR="/home/relay/relay"
COMPOSE_DIR="${REPO_DIR}/infra/docker"

if [ "$(whoami)" != "relay" ]; then
    echo "refusing to run as $(whoami) — run as 'relay'" >&2
    exit 1
fi

cd "$REPO_DIR"
git fetch --all --tags --prune
git checkout --force "$REF"
git reset --hard "origin/$REF" 2>/dev/null || true

cd "$COMPOSE_DIR"
docker compose build relayd
docker compose up -d relayd
docker compose logs --tail=20 relayd
echo "done. tail: docker compose -f $COMPOSE_DIR/docker-compose.yml logs -f"
