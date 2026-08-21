-- owner: b2-sqlite-persistence
--
-- Schema version 1. Forward-only: this file is APPLIED ONCE per database and is
-- then history. Editing it changes what a fresh install gets while leaving every
-- existing install on the old shape, with nothing to reconcile the two -- which
-- is the whole failure mode a recorded version exists to prevent. A change to
-- the schema is a NEW numbered file, never an edit to this one.
--
-- Every table is STRICT. That is not decoration: SQLite's default type affinity
-- would let a hand-edited `host_capacity = 'two'` sit in an INTEGER column and
-- surface as a load-time surprise far from the edit. STRICT rejects it at the
-- point of the write.
--
-- THERE IS NO CREDENTIAL COLUMN HERE, AND NONE MAY BE ADDED.
-- `05-infrastructure.md` puts the user access token in the machine-scoped secret
-- store (`d2`) and the encoded JIT configuration in a restrictive temporary file
-- that is deleted after handoff. SQLite holds configuration and recovery
-- metadata only. `store::tests` scans a fully populated database and its dump
-- for token-shaped values; a new column carrying one would fail that scan.

CREATE TABLE hosts (
    -- A `HostId` as a hyphenated UUID. Text rather than a BLOB so that a
    -- `sqlite3 .dump` an operator reads is legible and greppable.
    id                    TEXT    NOT NULL PRIMARY KEY,
    display_name          TEXT    NOT NULL,
    -- `Os` / `Arch` as their serde tokens -- `windows`, `mac_os`, `linux`,
    -- `x64`, `arm64`, `arm32`. `store::tests::the_on_disk_tokens_are_pinned`
    -- fixes them, so a rename in the domain breaks a test here rather than
    -- silently changing the on-disk format.
    os                    TEXT    NOT NULL,
    architecture          TEXT    NOT NULL,
    -- `NonZeroU16`. Re-checked on load: zero capacity is not a configured host.
    host_capacity         INTEGER NOT NULL,
    service_start_mode    TEXT    NOT NULL,
    -- Re-validated on load against `RefreshInterval`'s 30-second floor, so a
    -- hand-edited `1` cannot make this host poll every second.
    refresh_interval_secs INTEGER NOT NULL,
    -- RFC 3339 with nanosecond precision and a `Z` suffix, fixed width, so the
    -- text sorts in the same order as the instant.
    created_at            TEXT    NOT NULL
) STRICT;

CREATE TABLE policies (
    id              TEXT    NOT NULL PRIMARY KEY,
    -- `ScaleTarget` is split into its scope and its slug rather than stored as
    -- one opaque blob, so that the load path rebuilds it through
    -- `ScaleTarget::repository` / `::organization` and re-runs GitHub's naming
    -- rules. A row claiming scope `organization` with slug `owner/repo` is
    -- refused on load rather than loaded as an organization named `owner/repo`.
    target_scope    TEXT    NOT NULL,
    target_slug     TEXT    NOT NULL,
    installation_id INTEGER NOT NULL,
    host_id         TEXT    NOT NULL,
    -- D19's shape, flat, exactly as `PolicyMode::from_persisted` expects it:
    -- NULL/NULL is MonitorOnly, both present is Autoscale, and the two mixed
    -- combinations are rejected on load with a named error. Nothing here writes
    -- a `mode` column, because a `mode` column plus these two would admit
    -- states that disagree with each other.
    routing_labels  TEXT,
    min_capacity    INTEGER NOT NULL,
    max_capacity    INTEGER,
    enabled         INTEGER NOT NULL,
    state           TEXT    NOT NULL,
    cache_policy    TEXT    NOT NULL,
    -- The optimistic-concurrency token. Every write matches on it and every
    -- successful domain mutation advances it; see `Store::update_policy`.
    revision        INTEGER NOT NULL
) STRICT;

CREATE INDEX policies_host_id ON policies (host_id);

CREATE TABLE attempts (
    id                   TEXT    NOT NULL PRIMARY KEY,
    -- Deliberately NOT a foreign key onto `policies`. An attempt that outlives
    -- its policy row still owns a runtime directory and possibly a live child
    -- process, and `e3`'s startup recovery is the only thing that can clean
    -- them; `ON DELETE CASCADE` would destroy exactly the recovery metadata
    -- this table exists to hold, and `ON DELETE RESTRICT` would block `repo
    -- remove` behind an attempt nobody can see. The index is what the join
    -- actually needs.
    policy_id            TEXT    NOT NULL,
    github_runner_id     INTEGER,
    state                TEXT    NOT NULL,
    -- `AttemptOutcome` as JSON, NULL while the attempt is non-terminal. The
    -- pairing with `state` is re-checked on load by
    -- `RunnerAttempt::from_persisted`, so a `failed` row claiming it ran a job
    -- does not load.
    outcome              TEXT,
    process_id           INTEGER,
    runtime_path         TEXT    NOT NULL,
    -- Three timestamps, and the reason they are three separate columns is the
    -- reason `PersistedAttempt` is a struct: `created_at` is when the runtime
    -- directory was allocated and never moves, `last_state_change_at` is what
    -- every recovery timeout is measured from, and `terminal_at` is set when and
    -- only when the attempt concluded. Transposing the first two would make
    -- every timeout measure from allocation.
    created_at           TEXT    NOT NULL,
    terminal_at          TEXT,
    last_state_change_at TEXT    NOT NULL
) STRICT;

CREATE INDEX attempts_policy_id ON attempts (policy_id);
CREATE INDEX attempts_state ON attempts (state);
