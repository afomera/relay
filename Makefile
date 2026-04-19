# relay — operations Makefile
#
# `make` with no args prints available targets.
# Override the droplet host:  DROPLET_HOST=relay@1.2.3.4 make logs
# Override the git ref:        make update REF=v0.2.0

.DEFAULT_GOAL := help
SHELL := /bin/bash

DO_TF_DIR  := infra/digitalocean/terraform
DO_DIR     := infra/digitalocean
COMPOSE_ON_DROPLET := cd /home/relay/relay/infra/docker && docker compose

# Auto-detect the droplet's public IP from Terraform state when available.
# Set DROPLET_HOST=relay@<ip> to override. Only runs terraform output when
# a state file exists (otherwise terraform prints noisy warnings).
ifndef DROPLET_HOST
  ifneq (,$(wildcard $(DO_TF_DIR)/terraform.tfstate))
    RESERVED_IP := $(shell cd $(DO_TF_DIR) && terraform output -raw reserved_ip 2>/dev/null \
                   | grep -E '^[0-9a-fA-F.:]+$$' | head -1)
    ifneq ($(strip $(RESERVED_IP)),)
      DROPLET_HOST := relay@$(RESERVED_IP)
    endif
  endif
endif

# ---------------------------------------------------------------------------
# local dev
# ---------------------------------------------------------------------------

.PHONY: build test fmt clippy run-dev

build:            ## cargo build --workspace
	cargo build --workspace

test:             ## cargo test --workspace
	cargo test --workspace

fmt:              ## cargo fmt --all
	cargo fmt --all

clippy:           ## cargo clippy, warnings are errors
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt clippy test  ## fmt + clippy + test (pre-commit pass)

run-dev:          ## run relayd in --dev mode
	cargo run -p relay-server --bin relayd -- --dev

# ---------------------------------------------------------------------------
# release — tag a version and push; CI cross-compiles + publishes binaries
# ---------------------------------------------------------------------------

.PHONY: bump release

# Usage: make bump VERSION=0.0.3
VERSION ?=
bump:             ## bump [workspace.package] version in Cargo.toml + Cargo.lock
	@test -n "$(VERSION)" || (echo "usage: make bump VERSION=0.0.3" && exit 1)
	@# Only the workspace.package `version` line matches `^version = "..."`;
	@# dependency versions live on inline-table lines.
	@python3 -c "import re,pathlib; p=pathlib.Path('Cargo.toml'); \
s=p.read_text(); \
new,n=re.subn(r'^version = \"[^\"]*\"', 'version = \"$(VERSION)\"', s, count=1, flags=re.M); \
assert n==1, 'no version line matched'; \
p.write_text(new); print(f'bumped Cargo.toml → $(VERSION)')"
	cargo update --workspace --quiet
	@echo ""
	@echo "next:"
	@echo "  git commit -am 'relay $(VERSION)'"
	@echo "  make release VERSION=$(VERSION)"

release:          ## tag + push, triggering GitHub release workflow
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=0.0.3" && exit 1)
	@git diff --quiet || (echo "tree dirty — commit first (did you forget after 'make bump'?)" && exit 1)
	@grep -q '^version = "$(VERSION)"' Cargo.toml || \
		(echo "Cargo.toml doesn't match VERSION=$(VERSION) — run 'make bump VERSION=$(VERSION)' first" && exit 1)
	git tag v$(VERSION)
	git push origin main v$(VERSION)
	@echo ""
	@echo "tag v$(VERSION) pushed. watch:"
	@echo "  https://github.com/afomera/relay/actions"
	@echo ""
	@echo "release workflow will auto-bump Formula/relay.rb on main."

# ---------------------------------------------------------------------------
# infra — DigitalOcean + Cloudflare via Terraform
# ---------------------------------------------------------------------------

.PHONY: tf-init tf-fmt tf-plan tf-apply tf-destroy tf-output

tf-init:          ## terraform init
	cd $(DO_TF_DIR) && terraform init

tf-fmt:           ## terraform fmt
	cd $(DO_TF_DIR) && terraform fmt

tf-plan:          ## terraform plan
	cd $(DO_TF_DIR) && terraform plan

tf-apply:         ## terraform apply (creates/updates DO + DNS + DNS)
	cd $(DO_TF_DIR) && terraform apply

tf-destroy:       ## terraform destroy (requires confirm)
	cd $(DO_TF_DIR) && terraform destroy

tf-output:        ## show terraform outputs (reserved_ip, dashboard_url, …)
	cd $(DO_TF_DIR) && terraform output

# ---------------------------------------------------------------------------
# remote ops — needs DROPLET_HOST (auto-detected from terraform output)
# ---------------------------------------------------------------------------

.PHONY: guard-host update logs ssh ps restart backup

guard-host:
	@if [ -z "$(DROPLET_HOST)" ]; then \
		echo "error: DROPLET_HOST not set and no Terraform state found."; \
		echo "       run 'make tf-apply' first, or set DROPLET_HOST=relay@<ip>"; \
		exit 1; \
	fi

REF ?= main
update: guard-host   ## git pull + rebuild relay on the droplet; REF=<ref> to pin
	@echo "updating $(DROPLET_HOST) to ref=$(REF)"
	DROPLET_HOST=$(DROPLET_HOST) $(DO_DIR)/remote-update.sh $(REF)

update-config: guard-host   ## re-render relayd.toml from tfvars, ship it, restart relayd
	@echo "rendering relayd.toml from $(DO_TF_DIR)"
	cd $(DO_TF_DIR) && terraform apply -target=local_file.relayd_toml -auto-approve >/dev/null
	@echo "shipping to $(DROPLET_HOST):/home/relay/relay/infra/docker/relayd.toml"
	scp -q $(DO_TF_DIR)/build/relayd.toml $(DROPLET_HOST):/home/relay/relay/infra/docker/relayd.toml
	@echo "restarting relayd"
	ssh $(DROPLET_HOST) -- '$(COMPOSE_ON_DROPLET) restart relayd'
	@echo "done. tail logs: make logs"

logs: guard-host     ## tail relayd logs (ctrl-c to stop)
	ssh $(DROPLET_HOST) -- '$(COMPOSE_ON_DROPLET) logs -f --tail=100 relayd'

ssh: guard-host      ## open an interactive ssh into the droplet
	ssh $(DROPLET_HOST)

ps: guard-host       ## docker compose ps on the droplet
	ssh $(DROPLET_HOST) -- '$(COMPOSE_ON_DROPLET) ps'

restart: guard-host  ## docker compose restart relayd (no rebuild)
	ssh $(DROPLET_HOST) -- '$(COMPOSE_ON_DROPLET) restart relayd'

backup: guard-host   ## stream the SQLite db down to ./relay-backup-<ts>.db
	@ts=$$(date +%F-%H%M%S); \
	out="./relay-backup-$$ts.db"; \
	echo "best-effort SQLite snapshot → $$out"; \
	ssh $(DROPLET_HOST) -- '$(COMPOSE_ON_DROPLET) exec -T relayd cat /var/lib/relay/relay.db' > "$$out"; \
	ls -lh "$$out"

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------

.PHONY: help
help:             ## show this help
	@awk 'BEGIN {FS = ":.*?## "; printf "\nrelay operations:\n\n"} \
	     /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' \
	     $(MAKEFILE_LIST)
	@if [ -n "$(DROPLET_HOST)" ]; then \
		echo ""; echo "  target droplet: $(DROPLET_HOST) (from terraform state)"; \
	fi
	@echo ""
