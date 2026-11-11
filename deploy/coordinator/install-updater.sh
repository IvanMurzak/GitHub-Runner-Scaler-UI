#!/bin/sh
# Installs runner-coordinator-update.service and .timer for THIS checkout and
# starts the timer (docs/coordinator.md, "Updates"):
#
#   sudo ./install-updater.sh [--user NAME]
#
# The service runs update.sh from this directory as NAME: by default the
# account that ran sudo, which must own the checkout and be in the docker
# group. Running it again rewrites the units, so it also moves them to another
# checkout or account. To remove: sudo systemctl disable --now
# runner-coordinator-update.timer, then delete both units from
# /etc/systemd/system and run sudo systemctl daemon-reload.
set -eu

UNIT_DIR=/etc/systemd/system
NAME=runner-coordinator-update

user="${SUDO_USER:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            [ $# -ge 2 ] || { echo "install-updater: --user takes a name" >&2; exit 2; }
            user="$2"
            shift
            ;;
        *)
            echo "usage: sudo ./install-updater.sh [--user NAME]" >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install-updater: run it with sudo" >&2
    exit 1
fi
if [ -z "$user" ] || [ "$user" = root ]; then
    echo "install-updater: name the deploy account with --user (not root)" >&2
    exit 2
fi
if ! id "$user" >/dev/null 2>&1; then
    echo "install-updater: no account '$user'" >&2
    exit 1
fi

dir="$(cd "$(dirname "$0")" && pwd -P)"
for file in docker-compose.yml update.sh "$NAME.service" "$NAME.timer"; do
    [ -f "$dir/$file" ] || { echo "install-updater: $dir/$file is missing" >&2; exit 1; }
done
# systemd reads `%` and whitespace in these settings, and sed below reads `|`.
case "$dir$user" in
    *[!A-Za-z0-9._/-]*)
        echo "install-updater: '$dir' or '$user' has a character a unit file cannot take as-is" >&2
        exit 1
        ;;
esac
if ! git -C "$dir" rev-parse --git-dir >/dev/null 2>&1; then
    echo "install-updater: $dir is not in a git checkout; update.sh moves the checkout between release tags" >&2
    exit 1
fi
if [ "$(stat -c %U "$dir")" != "$user" ]; then
    echo "install-updater: $dir is owned by $(stat -c %U "$dir"), not $user; update.sh must be able to check out tags there" >&2
    exit 1
fi
# A git command once run here with sudo leaves objects only root may write
# beside, and update.sh, running as $user, then fails to fetch the next tag.
git_dir="$(git -C "$dir" rev-parse --absolute-git-dir)"
foreign="$(find "$git_dir" ! -user "$user" | wc -l)"
if [ "$foreign" -gt 0 ]; then
    chown -R "$user:$(id -gn "$user")" "$git_dir"
    echo "install-updater: gave $user the $foreign entries of $git_dir another account owned"
fi
if ! id -nG "$user" | tr ' ' '\n' | grep -qx docker; then
    echo "install-updater: $user is not in the docker group" >&2
    exit 1
fi
if [ ! -f "$dir/.env" ]; then
    echo "install-updater: $dir/.env is missing; deploy first (docs/coordinator.md, Deploy)" >&2
    exit 1
fi
if ! grep -q '^COORDINATOR_VERSION=' "$dir/.env"; then
    echo "install-updater: note: .env names no COORDINATOR_VERSION, so the first run updates to the newest release" >&2
fi

# The status directory the compose file mounts, owned by the account that
# writes it, before Docker would create it as root.
install -d -o "$user" -m 755 "$dir/state"

sed -e "s|^User=.*|User=$user|" \
    -e "s|^WorkingDirectory=.*|WorkingDirectory=$dir|" \
    "$dir/$NAME.service" >"$UNIT_DIR/$NAME.service"
install -m 644 "$dir/$NAME.timer" "$UNIT_DIR/$NAME.timer"
chmod 644 "$UNIT_DIR/$NAME.service"

systemctl daemon-reload
systemctl enable --now "$NAME.timer"
echo "install-updater: runs update.sh in $dir as $user every 15 minutes"
echo "  status:   systemctl list-timers $NAME.timer; journalctl -u $NAME"
echo "  run now:  sudo systemctl start $NAME.service"
echo "  pause:    sudo systemctl disable --now $NAME.timer"
