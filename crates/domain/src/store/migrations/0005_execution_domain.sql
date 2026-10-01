-- Forward-only execution allocation. Historical rows remain native and the
-- legacy process_id/start-token sidecar remain the native recovery authority.
ALTER TABLE policies ADD COLUMN execution_policy TEXT NOT NULL DEFAULT '{"mode":"native"}';
ALTER TABLE attempts ADD COLUMN execution TEXT NOT NULL DEFAULT '{"kind":"native","process_id":null}';
UPDATE attempts SET execution = json_object('kind', 'native', 'process_id', process_id);
