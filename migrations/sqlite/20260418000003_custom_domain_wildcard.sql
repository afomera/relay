-- Wildcard custom domains via ACME DNS-01 + CNAME delegation.
--
-- `wildcard = 1` means the verified domain covers both the apex and
-- `*.<domain>`, with certs issued via DNS-01. Relay publishes TXT records
-- under `<acme_delegation_slug>.<acme_delegation_zone>`; the user is expected
-- to CNAME `_acme-challenge.<domain>` there once, and renewals then run
-- unattended. Existing rows default to `0` (today's HTTP-01 apex-only flow).
ALTER TABLE custom_domains ADD COLUMN wildcard INTEGER NOT NULL DEFAULT 0;
ALTER TABLE custom_domains ADD COLUMN acme_delegation_slug TEXT;
