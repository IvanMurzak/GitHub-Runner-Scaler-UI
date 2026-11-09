#!/bin/sh
# Daily online backup of the coordinator's SQLite database; docs/coordinator.md
# ("Back up and restore") says how to use and restore it.
#
#   backup.sh once       one copy, then the oldest beyond the last 7 are removed
#   backup.sh            that, now and then every day, for ever
#
# VACUUM INTO reads a consistent snapshot through SQLite's own locking while the
# coordinator keeps writing, which a plain file copy of a WAL database does not.
# A copy goes live only once it is complete and passes an integrity check, so a
# failed run leaves nothing that looks like a backup and removes no good one.
set -eu

DATABASE="${COORDINATOR_DB:-/data/coordinator.db}"
BACKUP_DIR="${COORDINATOR_BACKUP_DIR:-/backups}"
KEEP="${COORDINATOR_BACKUP_KEEP:-7}"
INTERVAL_SECS="${COORDINATOR_BACKUP_INTERVAL_SECS:-86400}"

backup_once() {
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    partial="$BACKUP_DIR/.coordinator-$stamp.partial"
    final="$BACKUP_DIR/coordinator-$stamp.db"
    rm -f "$BACKUP_DIR"/.coordinator-*.partial
    sqlite3 -cmd '.timeout 30000' "file:$DATABASE?mode=ro" "VACUUM INTO '$partial'"
    if [ "$(sqlite3 "$partial" 'PRAGMA integrity_check')" != "ok" ]; then
        rm -f "$partial"
        echo "backup: the copy failed its integrity check; nothing kept" >&2
        return 1
    fi
    chmod 600 "$partial"
    mv "$partial" "$final"
    # The names sort by time. Only after a good copy, so failures remove nothing.
    # shellcheck disable=SC2012
    ls -1 "$BACKUP_DIR"/coordinator-*.db | sort -r | tail -n "+$((KEEP + 1))" |
        while IFS= read -r old; do rm -f "$old"; done
    echo "backup: wrote $final"
}

if [ "${1:-}" = "once" ]; then
    backup_once
    exit
fi

while :; do
    # One failure is logged and tried again tomorrow, and shows as no new file.
    backup_once || echo "backup: failed; trying again at the next interval" >&2
    sleep "$INTERVAL_SECS"
done
