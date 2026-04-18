-- Collapse duplicate tunnel rows that accumulated during reconnects (pre
-- natural-key refactor). Keep one row per (org_id, hostname) — the one with
-- the highest rowid, which is the most recently inserted. Captures are
-- attached by tunnel_id; rows we drop here will cascade-delete their captures.
DELETE FROM tunnels
WHERE rowid NOT IN (
    SELECT MAX(rowid) FROM tunnels GROUP BY org_id, hostname
);

-- Enforce the natural key going forward. With this index, a rogue second
-- INSERT would fail — but the new DAL code goes through upsert_tunnel_by_hostname
-- which always tries UPDATE first.
CREATE UNIQUE INDEX tunnels_by_org_hostname ON tunnels(org_id, hostname);
