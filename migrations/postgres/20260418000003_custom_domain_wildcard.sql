-- Wildcard custom domains via ACME DNS-01 + CNAME delegation. See the sqlite
-- variant for context; columns mirror that schema one-to-one (BOOLEAN here,
-- INTEGER there, same defaults).
ALTER TABLE custom_domains ADD COLUMN wildcard BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE custom_domains ADD COLUMN acme_delegation_slug TEXT;
