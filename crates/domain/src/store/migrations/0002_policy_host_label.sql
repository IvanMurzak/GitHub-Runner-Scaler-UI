-- owner: f2-cli-policy-commands
-- A monitor-only policy reserves no routing label, but still has to remember
-- which host identity to use if set-capacity later promotes it.
ALTER TABLE policies ADD COLUMN requested_host_label TEXT NOT NULL DEFAULT 'host';
