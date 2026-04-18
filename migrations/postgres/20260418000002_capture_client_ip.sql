-- Client IP seen at the edge for each captured HTTP request. Nullable so
-- captures recorded before this migration remain valid.
ALTER TABLE inspection_captures ADD COLUMN client_ip TEXT;
