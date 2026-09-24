#!/usr/bin/env python3
"""Exercise a release candidate against old and fresh isolated databases."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

HOST_ID = "00000000-0000-0000-0000-000000000001"
POLICY_ID = "00000000-0000-0000-0000-000000000010"
ATTEMPT_ID = "00000000-0000-0000-0000-000000000100"
STAMP = "2026-01-01T00:00:00.000000000Z"
LABELS = '{"host_label":"rm-home-win-x64","additional":[]}'


def reject(message: str) -> None:
    raise SystemExit(f"REJECTED: {message}")


def guarded_root(raw: str) -> Path:
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        reject("RUNNER_TEMP is required; release validation may only use CI temporary storage")
    runner_temp = Path(runner_temp_raw).resolve()
    root = Path(raw).resolve()
    if root == runner_temp or runner_temp not in root.parents:
        reject(f"work root must be a child of RUNNER_TEMP ({runner_temp}), got {root}")
    if root.exists():
        reject(f"work root already exists: {root}")
    root.mkdir(parents=True)
    return root


def migrations(source_root: Path, through: int) -> list[tuple[int, str, str]]:
    migration_dir = source_root / "crates" / "domain" / "src" / "store" / "migrations"
    files = sorted(migration_dir.glob("[0-9][0-9][0-9][0-9]_*.sql"))
    selected = []
    for path in files:
        version = int(path.name[:4])
        if version <= through:
            selected.append((version, path.stem[5:], path.read_text(encoding="utf-8")))
    if [version for version, _, _ in selected] != list(range(1, through + 1)):
        reject(f"source does not contain a contiguous migration chain through schema {through}")
    return selected


def source_schema_version(source_root: Path) -> int:
    source = (source_root / "crates" / "domain" / "src" / "store.rs").read_text(
        encoding="utf-8"
    )
    prefix = "pub const SCHEMA_VERSION: u32 = "
    matches = [line for line in source.splitlines() if line.startswith(prefix)]
    if len(matches) != 1 or not matches[0].endswith(";"):
        reject("source must declare exactly one public SCHEMA_VERSION")
    try:
        return int(matches[0][len(prefix) : -1])
    except ValueError:
        reject(f"source SCHEMA_VERSION is not an integer: {matches[0]!r}")


def seed_schema_three(source_root: Path, database: Path) -> None:
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER NOT NULL PRIMARY KEY, "
            "name TEXT NOT NULL, applied_at TEXT NOT NULL) STRICT"
        )
        for version, name, sql in migrations(source_root, 3):
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, STAMP),
            )
        os_name = "windows" if os.name == "nt" else ("mac_os" if sys.platform == "darwin" else "linux")
        architecture = "x64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() in {"AMD64", "X86"} else "arm64"
        if os.name != "nt":
            architecture = "arm64" if os.uname().machine.lower() in {"arm64", "aarch64"} else "x64"
        connection.execute(
            "INSERT INTO hosts(id, display_name, os, architecture, host_capacity, "
            "service_start_mode, refresh_interval_secs, created_at, runner_root_override) "
            "VALUES (?, 'release-gate', ?, ?, 2, 'boot', 60, ?, NULL)",
            (HOST_ID, os_name, architecture, STAMP),
        )
        connection.execute(
            "INSERT INTO policies(id, target_scope, target_slug, installation_id, host_id, "
            "routing_labels, min_capacity, max_capacity, enabled, state, cache_policy, revision, "
            "requested_host_label, workspace_mode, workspace_path) "
            "VALUES (?, 'repository', 'release/schema-compat', 1, ?, ?, 0, 2, 1, 'active', "
            "'retain_runner_package', 7, 'host', 'ephemeral', NULL)",
            (POLICY_ID, HOST_ID, LABELS),
        )
        connection.execute(
            "INSERT INTO attempts(id, policy_id, state, runtime_path, created_at, "
            "last_state_change_at, workspace_mode, workspace_slot) "
            "VALUES (?, ?, 'idle', 'runtime/release-gate', ?, ?, 'ephemeral', NULL)",
            (ATTEMPT_ID, POLICY_ID, STAMP, STAMP),
        )


def status(binary: Path, data_dir: Path) -> dict:
    completed = subprocess.run(
        [str(binary), "--data-dir", str(data_dir), "status", "--json"],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        reject(f"candidate status failed ({completed.returncode}): {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        reject(f"candidate status did not emit JSON: {error}")


def max_schema(database: Path) -> int:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        value = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    return int(value or 0)


def assert_migrated(database: Path, expected: int) -> None:
    actual = max_schema(database)
    if actual != expected:
        reject(f"candidate migrated database to {actual}, source expects {expected}")
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        host = connection.execute(
            "SELECT host_capacity, runner_root_override FROM hosts WHERE id = ?", (HOST_ID,)
        ).fetchone()
        policy = connection.execute(
            "SELECT revision, workspace_mode, profile_name, profile_selector, execution_policy "
            "FROM policies WHERE id = ?", (POLICY_ID,)
        ).fetchone()
        attempt = connection.execute(
            "SELECT runtime_path, workspace_mode, execution FROM attempts WHERE id = ?", (ATTEMPT_ID,)
        ).fetchone()
    if host != (2, None):
        reject(f"schema-3 host invariants changed: {host!r}")
    if policy != (7, "ephemeral", "default", "rm-home-win-x64", '{"mode":"native"}'):
        reject(f"schema-3 policy invariants changed: {policy!r}")
    expected_execution = '{"kind":"native","process_id":null}'
    if attempt != ("runtime/release-gate", "ephemeral", expected_execution):
        reject(f"schema-3 attempt invariants changed: {attempt!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        reject(f"candidate binary does not exist: {binary}")
    source_root = Path(args.source_root).resolve()
    root = guarded_root(args.work_root)
    expected_schema = source_schema_version(source_root)

    migrated_root = root / "schema3"
    migrated_db = migrated_root / "config" / "runner-manager.sqlite3"
    seed_schema_three(source_root, migrated_db)
    document = status(binary, migrated_root)
    build_version = document.get("product", {}).get("build_version")
    if build_version is None:
        reject("status --json does not expose product.build_version")
    if args.expected_version and build_version != args.expected_version:
        reject(
            f"candidate build identity is {build_version!r}, expected release {args.expected_version!r}"
        )
    if document.get("host", {}).get("capacity") != 2 or len(document.get("policies", [])) != 1:
        reject("status --json did not load the representative schema-3 rows")
    assert_migrated(migrated_db, expected_schema)

    fresh_root = root / "fresh"
    fresh_root.mkdir()
    fresh_document = status(binary, fresh_root)
    fresh_db = fresh_root / "config" / "runner-manager.sqlite3"
    if max_schema(fresh_db) != expected_schema:
        reject("fresh candidate database does not match source SCHEMA_VERSION")
    if fresh_document.get("product", {}).get("build_version") is None:
        reject("fresh status --json omitted product.build_version")

    print(
        f"schema compatibility OK: schema 3 -> {expected_schema}; "
        f"fresh -> {expected_schema}; build {build_version}"
    )


if __name__ == "__main__":
    main()
