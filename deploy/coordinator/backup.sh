#!/bin/sh
# Daily online backup of the coordinator's SQLite database; docs/coordinator.md
# ("Back up and restore") says how to use and restore it.
#
#   backup.sh once          one copy, then the oldest beyond the last 7 are removed
#   backup.sh restore NAME  the copy NAME (coordinator-<UTC time>.db) in place of
#                           the database; only while the coordinator is stopped
#   backup.sh               `once`, once a day, for ever: an hour after one that failed
#
# VACUUM INTO reads a consistent snapshot through SQLite's own locking while the
# coordinator keeps writing, which a plain file copy of a WAL database does not.
# A copy goes live only once it is complete and passes an integrity check, so a
# failed run leaves nothing that looks like a backup and removes no good one.
set -eu

DATABASE="${COORDINATOR_DB:-/data/coordinator.db}"
BACKUP_DIR="${COORDINATOR_BACKUP_DIR:-/backups}"
KEEP="${COORDINATOR_BACKUP_KEEP-7}"
INTERVAL_SECS="${COORDINATOR_BACKUP_INTERVAL_SECS:-86400}"
RETRY_SECS="${COORDINATOR_BACKUP_RETRY_SECS:-3600}"

# Nothing with a leading zero: 00 would remove every copy, and 08 is not a number
# to the shell's arithmetic.
for setting in "$KEEP" "$INTERVAL_SECS" "$RETRY_SECS"; do
    case "$setting" in
        '' | 0* | *[!0-9]*)
            echo "backup: the keep, interval and retry settings must be whole numbers above 0" >&2
            exit 2
            ;;
    esac
done

backup_once() {
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    partial="$BACKUP_DIR/.coordinator-$stamp.partial"
    final="$BACKUP_DIR/coordinator-$stamp.db"
    rm -f "$BACKUP_DIR"/.coordinator-*.partial
    sqlite3 -cmd '.timeout 30000' "file:$DATABASE?mode=ro" "VACUUM INTO '$partial'"
    # An empty file passes an integrity check, and opening a missing one makes one.
    if [ ! -s "$partial" ] ||
        [ "$(sqlite3 "$partial" 'PRAGMA integrity_check')" != "ok" ] ||
        [ "$(sqlite3 "$partial" 'SELECT count(*) > 0 FROM sqlite_master')" != "1" ]; then
        rm -f "$partial"
        echo "backup: the copy failed its check; nothing kept" >&2
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

# Stops nothing itself: the coordinator must not be running. The copy is checked
# beside the database before anything changes, so a refused one leaves the
# database as it was.
restore() {
    name="$1"
    # A bare file name in the backup directory: no slash can match.
    case "$name" in
        coordinator-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.db) ;;
        *)
            echo "backup: '$name' is not the name of a backup (coordinator-<UTC time>.db, as in $BACKUP_DIR)" >&2
            return 2
            ;;
    esac
    if [ ! -s "$BACKUP_DIR/$name" ]; then
        echo "backup: there is no $BACKUP_DIR/$name" >&2
        return 1
    fi
    staged="$DATABASE.restore"
    rm -f "$staged"
    if ! cp "$BACKUP_DIR/$name" "$staged" ||
        [ "$(sqlite3 "$staged" 'PRAGMA integrity_check' 2>&1)" != "ok" ] ||
        [ "$(sqlite3 "$staged" 'SELECT count(*) > 0 FROM sqlite_master' 2>&1)" != "1" ]; then
        rm -f "$staged"
        echo "backup: $name failed its integrity check; the database is unchanged" >&2
        return 1
    fi
    # The old database's WAL first: applied to the copy, it would damage it.
    rm -f "$DATABASE-wal" "$DATABASE-shm"
    mv "$staged" "$DATABASE"
    echo "backup: restored $DATABASE from $name"
}

case "${1:-}" in
    once)
        backup_once
        exit
        ;;
    restore)
        if [ $# -ne 2 ]; then
            echo "usage: backup.sh restore coordinator-<UTC time>.db" >&2
            exit 2
        fi
        restore "$2"
        exit
        ;;
esac

while :; do
    # A restart does not make a copy of its own: seven restarts during a bad
    # upgrade must not push out every copy from before it.
    recent="$(find "$BACKUP_DIR" -name 'coordinator-*.db' -mmin "-$((INTERVAL_SECS / 60))" | head -n 1)"
    if [ -n "$recent" ]; then
        sleep "$RETRY_SECS"
        continue
    fi
    # Its own process: as a condition, `set -e` would not stop a failed function.
    if sh "$0" once; then
        sleep "$INTERVAL_SECS"
    else
        echo "backup: failed; trying again in $RETRY_SECS seconds" >&2
        sleep "$RETRY_SECS"
    fi
done
