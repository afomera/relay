#!/usr/bin/env bash
# Runs from your laptop. SSHes into the droplet and triggers update.sh.
#
# Usage:
#   DROPLET_HOST=relay@1.2.3.4 ./infra/digitalocean/remote-update.sh            # main
#   DROPLET_HOST=relay@1.2.3.4 ./infra/digitalocean/remote-update.sh v0.2.0     # tag

set -euo pipefail

if [ -z "${DROPLET_HOST:-}" ]; then
    # Try to read the reserved IP from Terraform state.
    if command -v terraform >/dev/null 2>&1 && [ -d "$(dirname "$0")/terraform/.terraform" ]; then
        IP=$(terraform -chdir="$(dirname "$0")/terraform" output -raw reserved_ip 2>/dev/null || true)
        if [ -n "$IP" ]; then
            DROPLET_HOST="relay@${IP}"
        fi
    fi
fi

if [ -z "${DROPLET_HOST:-}" ]; then
    echo "set DROPLET_HOST=relay@<ip> (or run from a dir with terraform state)" >&2
    exit 1
fi

REF="${1:-main}"
echo "updating ${DROPLET_HOST} to ${REF}"
ssh "${DROPLET_HOST}" "/home/relay/relay/infra/digitalocean/update.sh ${REF}"
