-- Forward-only profile identity. All pre-existing policy columns remain untouched.
ALTER TABLE policies ADD COLUMN profile_name TEXT NOT NULL DEFAULT 'default';
ALTER TABLE policies ADD COLUMN profile_selector TEXT;
UPDATE policies SET profile_selector = json_extract(routing_labels, '$.host_label')
WHERE routing_labels IS NOT NULL;

-- A profile is an identity under one host and target, independent of PolicyId.
CREATE UNIQUE INDEX one_profile_per_host_target
ON policies (host_id, target_scope COLLATE NOCASE, target_slug COLLATE NOCASE, profile_name COLLATE NOCASE);
