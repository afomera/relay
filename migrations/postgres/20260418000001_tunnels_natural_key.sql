-- Postgres equivalent of the SQLite migration at the same timestamp. A fresh
-- Postgres deploy has no pre-natural-key duplicate rows to collapse (that's a
-- SQLite-only leftover from early reconnect bugs), so we just install the
-- unique index. `upsert_tunnel_by_hostname` in the DAL relies on it to keep
-- one row per (org_id, hostname).
CREATE UNIQUE INDEX tunnels_by_org_hostname ON tunnels(org_id, hostname);
