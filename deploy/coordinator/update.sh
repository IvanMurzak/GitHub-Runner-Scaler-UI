#!/usr/bin/env bash
# Keeps this coordinator deployment on the newest release (docs/coordinator.md,
# "Updates"). Run from deploy/coordinator of a git checkout, by
# runner-coordinator-update.timer or by hand:
#
#   ./update.sh                    move to the newest release if it is newer
#   ./update.sh --check            say what would happen; change nothing
#   ./update.sh --version X.Y.Z    move to that release, older or newer
#
# One move: a fresh database backup, the release tag checked out (compose file,
# Caddyfile and this script are the release's), COORDINATOR_VERSION in .env,
# `docker compose up -d` with the release's images (pulled before anything
# changed, so a release without them is refused), and up to two minutes for the
# coordinator to report the new version and answer /healthz. If it does not,
# everything goes back: the previous checkout and version, and the database
# from the backup just taken, because a coordinator refuses a database a newer
# one has upgraded. Untracked files (.env, the override, secrets, state/) are
# never touched; a checkout with local changes to tracked files is not moved.
#
# A version that was rolled back is not tried again by the timer; moving to it
# with --version is. The outcome is in state/status.json, which the coordinator
# shows on its dashboard, and on stdout (journald under the timer). The exit
# status is non-zero when a check or a move failed.
#
# Everything runs from `main`, called on the last line: bash has then read the
# whole file before the checkout replaces it.

set -uo pipefail

readonly REPOSITORY="IvanMurzak/GitHub-Runner-Scaler-UI"
readonly COORDINATOR_IMAGE="ghcr.io/ivanmurzak/runner-manager-coordinator"
readonly BACKUP_IMAGE="ghcr.io/ivanmurzak/runner-manager-coordinator-backup"
readonly STATE_DIR="state"
readonly STATUS_FILE="$STATE_DIR/status.json"
# A version rolled back once, so the timer does not try it every 15 minutes.
readonly HELD_FILE="$STATE_DIR/held-version"
readonly HEALTH_WAIT_SECS="${COORDINATOR_UPDATE_HEALTH_WAIT_SECS:-120}"

log() { printf 'update: %s\n' "$*"; }

usage() {
    cat <<'EOF'
usage: update.sh [--check] [--version X.Y.Z]
  (none)           move to the newest release if it is newer than the running one
  --check          report the running and newest versions; change nothing
  --version X.Y.Z  move to release vX.Y.Z (also to roll back by hand)
EOF
}

is_version() {
    [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# 0 when $1 is a strictly newer X.Y.Z than $2.
version_gt() {
    local a b i
    IFS=. read -r -a a <<<"$1"
    IFS=. read -r -a b <<<"$2"
    for i in 0 1 2; do
        if ((10#${a[i]} > 10#${b[i]})); then return 0; fi
        if ((10#${a[i]} < 10#${b[i]})); then return 1; fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# .env
# ---------------------------------------------------------------------------

env_get() {
    [[ -f .env ]] || return 0
    sed -n "s/^$1=//p" .env | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# Sets (or, with an empty value, removes) COORDINATOR_VERSION in .env, keeping
# every other line and the file's mode.
env_set_version() {
    local value="$1" tmp
    tmp="$(mktemp .env.update.XXXXXX)" || return 1
    if [[ -f .env ]]; then
        chmod --reference=.env "$tmp" 2>/dev/null || true
        grep -v '^COORDINATOR_VERSION=' .env >"$tmp"
    fi
    if [[ -n "$value" ]]; then
        printf 'COORDINATOR_VERSION=%s\n' "$value" >>"$tmp"
    fi
    mv -f "$tmp" .env
}

# ---------------------------------------------------------------------------
# state/status.json
# ---------------------------------------------------------------------------

json_string() {
    if [[ -z "$1" ]]; then
        printf 'null'
        return
    fi
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="$(printf '%s' "$s" | tr -d '\000-\037')"
    printf '"%s"' "$s"
}

json_number() {
    if [[ -z "$1" ]]; then printf 'null'; else printf '%s' "$1"; fi
}

# One field of the last status written (this script writes it on one line).
status_get() {
    [[ -f "$STATUS_FILE" ]] || return 0
    sed -n "s/.*\"$1\":\(\"\([^\"]*\)\"\|\([0-9][0-9]*\)\).*/\2\3/p" "$STATUS_FILE" | head -n 1
}

# write_status STATE CURRENT PREVIOUS LATEST CHANGED_AT MESSAGE; atomically.
write_status() {
    local tmp
    tmp="$(mktemp "$STATE_DIR/.status.XXXXXX")" || return 1
    printf '{"state":%s,"current":%s,"previous":%s,"latest":%s,"checked_at":%s,"changed_at":%s,"message":%s}\n' \
        "$(json_string "$1")" "$(json_string "$2")" "$(json_string "$3")" "$(json_string "$4")" \
        "$(date +%s)" "$(json_number "$5")" "$(json_string "$6")" >"$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$STATUS_FILE"
}

# A status that records no move: previous and changed_at stay as they were.
write_status_unchanged() {
    write_status "$1" "$2" "$(status_get previous)" "$3" "$(status_get changed_at)" "$4"
}

# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

# Prints the newest published release's X.Y.Z (the API's "latest" is the
# newest release that is neither a draft nor a prerelease). Returns 2 when
# GitHub is rate limiting this address, 1 on any other failure.
latest_release() {
    local body code tag
    # The body, then the status code on a line of its own.
    body="$(curl -sS --connect-timeout 10 --max-time 30 -w '\n%{http_code}' \
        -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/repos/$REPOSITORY/releases/latest")" || return 1
    code="${body##*$'\n'}"
    body="${body%$'\n'*}"
    if [[ "$code" == 403 || "$code" == 429 ]] && grep -qi 'rate limit' <<<"$body"; then
        return 2
    fi
    if [[ "$code" != 200 ]]; then
        log "GitHub answered HTTP $code" >&2
        return 1
    fi
    tag="$(sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"$body" | head -n 1)"
    tag="${tag#v}"
    is_version "$tag" || {
        log "the newest release's tag is not vX.Y.Z: '$tag'" >&2
        return 1
    }
    printf '%s\n' "$tag"
}

# decide LATEST CURRENT HELD: prints `up-to-date` when LATEST is not newer than
# CURRENT (an empty CURRENT is older than anything), `held` when it is the
# version held back, else `update`.
decide() {
    if [[ -n "$2" ]] && ! version_gt "$1" "$2"; then
        echo up-to-date
    elif [[ "$1" == "$3" ]]; then
        echo held
    else
        echo update
    fi
}

# ---------------------------------------------------------------------------
# The deployment
# ---------------------------------------------------------------------------

# What .env says is running; empty when it does not say.
recorded_version() {
    local v
    v="$(env_get COORDINATOR_VERSION)"
    if is_version "$v"; then printf '%s\n' "$v"; fi
}

# What the running coordinator says it is; empty when it does not answer.
running_version() {
    local out
    out="$(docker compose exec -T coordinator runner-manager-coordinator --version 2>/dev/null)" || return 0
    out="${out##* }"
    if is_version "$out"; then printf '%s\n' "$out"; fi
}

# The checkout to come back to: the branch if on one, else the commit.
current_ref() {
    git symbolic-ref --quiet --short HEAD 2>/dev/null || git rev-parse --verify HEAD
}

tree_is_clean() {
    [[ -z "$(git status --porcelain --untracked-files=no)" ]]
}

# 0 when the coordinator reports version $1 (any, when empty) and
# https://$COORDINATOR_HOST/healthz answers ok, within HEALTH_WAIT_SECS.
# Connects to this machine's port 443 under the public name, so the
# certificate is checked and no hairpin NAT is needed.
wait_healthy() {
    local want="$1" host deadline got health
    host="$(env_get COORDINATOR_HOST)"
    if [[ -z "$host" ]]; then
        log "COORDINATOR_HOST is not set in .env"
        return 1
    fi
    deadline=$((SECONDS + HEALTH_WAIT_SECS))
    while :; do
        got="$(running_version)"
        health="$(curl -fsS --connect-timeout 5 --max-time 10 \
            --resolve "$host:443:127.0.0.1" "https://$host/healthz" 2>/dev/null)"
        if [[ "$health" == ok && -n "$got" && (-z "$want" || "$got" == "$want") ]]; then
            log "healthy: coordinator $got, /healthz ok"
            return 0
        fi
        if ((SECONDS >= deadline)); then
            log "not healthy after ${HEALTH_WAIT_SECS}s: version '${got:-none}', /healthz '${health:-no answer}'"
            return 1
        fi
        sleep 5
    done
}

# A fresh backup through the backup service; prints its file name.
take_backup() {
    local out name
    out="$(docker compose run --rm --no-deps -T backup once 2>&1)"
    local status=$?
    printf '%s\n' "$out" | sed 's/^/update: /' >&2
    ((status == 0)) || return 1
    name="$(printf '%s\n' "$out" | sed -n 's|^backup: wrote /backups/\(coordinator-[0-9TZ]*\.db\)$|\1|p' | tail -n 1)"
    [[ -n "$name" ]] || return 1
    printf '%s\n' "$name"
}

# The restore of docs/coordinator.md ("Back up and restore"), from backup $1.
restore_backup() {
    docker compose stop coordinator backup &&
        docker compose run --rm --no-deps -T backup restore "$1" 2>&1 | sed 's/^/update: /'
}

# A Caddyfile replaced by a checkout is a new file, and a container that bind
# mounts a single file keeps seeing the old one until it is created again.
caddyfile_hash() {
    sha256sum Caddyfile 2>/dev/null | cut -d ' ' -f 1
}

reload_caddy_if_changed() {
    if [[ "$(caddyfile_hash)" != "$1" ]]; then
        log "the Caddyfile changed; recreating caddy"
        docker compose up -d --no-deps --force-recreate caddy
    fi
}

# move_to TARGET MODE LATEST: moves to TARGET ("timer" or "manual" MODE; LATEST
# is the newest release, empty when unknown), writes the status, and returns
# non-zero on failure.
move_to() {
    local target="$1" mode="$2" latest="${3:-$1}" tag="v$1"
    local from known shown from_ref backup_name caddy_before
    # What .env records goes back into it on a rollback; what is known of the
    # running version, recorded or not, goes into the status.
    from="$(recorded_version)"
    known="${from:-$(running_version)}"
    shown="${known:-unknown}"

    # A refusal before anything changed: the status says so, nothing to undo.
    refuse() {
        log "failed: $1 (nothing was changed)"
        write_status_unchanged failed "$shown" "$latest" "$1"
        return 1
    }

    log "moving from ${from:-an unrecorded version${known:+ ($known running)}} to $target"

    tree_is_clean || {
        git status --short --untracked-files=no
        refuse "the checkout has local changes to tracked files; commit or stash them, then run update.sh again"
        return
    }
    git fetch --quiet --tags origin || {
        # Most often part of .git belongs to root, from a git command once
        # run with sudo; install-updater.sh hands it back.
        refuse "git fetch failed; if part of .git is not $(id -un)'s, run sudo ./install-updater.sh"
        return
    }
    git rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null || {
        refuse "the repository has no tag $tag"
        return
    }
    # A release from before update.sh existed would leave the timer nothing to
    # run and a compose file that builds instead of pulling.
    git cat-file -e "$tag:deploy/coordinator/update.sh" 2>/dev/null || {
        refuse "$tag predates update.sh; move to it by hand (docs/coordinator.md, Updates)"
        return
    }
    # The release's compose file names these same tags, so `up -d` below finds
    # them here and pulls nothing again.
    log "pulling the $target images"
    if ! docker pull --quiet "$COORDINATOR_IMAGE:$target" || ! docker pull --quiet "$BACKUP_IMAGE:$target"; then
        refuse "could not pull the $target images: not published yet, private, or no network"
        return
    fi
    log "taking a backup of the database"
    backup_name="$(take_backup)" || {
        refuse "the database backup failed"
        return
    }
    log "backup: $backup_name"

    # From here on, a failure rolls back.
    from_ref="$(current_ref)"
    caddy_before="$(caddyfile_hash)"
    log "checking out $tag (was $from_ref)"
    if git checkout --quiet --detach "$tag" &&
        env_set_version "$target" &&
        docker compose up -d &&
        reload_caddy_if_changed "$caddy_before" &&
        wait_healthy "$target"; then
        # A move by hand to an older release holds back the newer one, or the
        # timer would undo it; a release newer than that is taken again.
        if [[ "$mode" == manual ]] && version_gt "$latest" "$target"; then
            printf '%s\n' "$latest" >"$HELD_FILE"
            log "holding back $latest until a newer release"
        else
            rm -f "$HELD_FILE"
        fi
        log "updated to $target"
        write_status updated "$target" "$known" "$latest" "$(date +%s)" \
            "moved from $shown to $target; database backup $backup_name"
        return 0
    fi

    log "$target failed; rolling back to $shown"
    caddy_before="$(caddyfile_hash)"
    if [[ "$mode" != manual ]]; then
        printf '%s\n' "$target" >"$HELD_FILE"
    fi
    if git checkout --quiet "$from_ref" &&
        env_set_version "$from" &&
        restore_backup "$backup_name" &&
        docker compose up -d &&
        reload_caddy_if_changed "$caddy_before" &&
        wait_healthy "$known"; then
        # Not `$from`: with no version recorded, compose runs `:latest`, which
        # is likely the very $target that failed, and an empty want accepts it.
        log "rolled back to $shown"
        write_status rolled_back "$shown" "$target" "$latest" "$(date +%s)" \
            "$target did not become healthy; rolled back to $shown and restored database backup $backup_name"
    else
        log "THE ROLLBACK FAILED; the coordinator needs a hand (docs/coordinator.md, Updates)"
        write_status failed "$shown" "$target" "$latest" "$(date +%s)" \
            "$target did not become healthy and the rollback to $shown failed; see journalctl -u runner-coordinator-update"
    fi
    return 1
}

main() {
    local check=false wanted=""
    while (($#)); do
        case "$1" in
        --check) check=true ;;
        --version)
            [[ $# -ge 2 ]] || {
                usage >&2
                exit 2
            }
            wanted="${2#v}"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
        esac
        shift
    done
    if [[ -n "$wanted" ]] && ! is_version "$wanted"; then
        echo "update: --version takes X.Y.Z, not '$wanted'" >&2
        exit 2
    fi
    if [[ ! -f docker-compose.yml || ! -f Caddyfile ]]; then
        echo "update: run this from deploy/coordinator of the checkout" >&2
        exit 2
    fi

    local current latest held rc
    current="$(recorded_version)"
    held="$(cat "$HELD_FILE" 2>/dev/null || true)"

    if $check; then
        latest="$(latest_release)"
        rc=$?
        echo "running (COORDINATOR_VERSION in .env): ${current:-not recorded}"
        case $rc in
        0) echo "newest release: $latest" ;;
        2) echo "newest release: unknown, GitHub is rate limiting this address" ;;
        *) echo "newest release: unknown, the GitHub API did not answer" ;;
        esac
        [[ -n "$held" ]] && echo "held back: $held was rolled back and is not retried by the timer"
        if [[ -n "$wanted" ]]; then
            echo "would move to $wanted"
        elif ((rc == 0)); then
            case "$(decide "$latest" "$current" "$held")" in
            up-to-date) echo "would do nothing: up to date" ;;
            held) echo "would do nothing: $latest is held back" ;;
            update) echo "would update to $latest" ;;
            esac
        fi
        if [[ -f "$STATUS_FILE" ]]; then
            echo "last status: $(cat "$STATUS_FILE")"
        fi
        if ! tree_is_clean; then
            echo "the checkout has local changes to tracked files; an update would refuse to start"
        fi
        exit 0
    fi

    mkdir -p "$STATE_DIR"
    if [[ ! -w "$STATE_DIR" ]]; then
        echo "update: $PWD/$STATE_DIR is not writable by $(id -un); sudo chown $(id -un) $STATE_DIR" >&2
        exit 1
    fi
    exec 9>"$STATE_DIR/update.lock"
    if ! flock -n 9; then
        echo "update: another update.sh is running" >&2
        exit 1
    fi

    if [[ -n "$wanted" ]]; then
        latest="$(latest_release)" || latest=""
        if [[ "$wanted" == "$current" ]]; then
            log "already at $wanted"
            exit 0
        fi
        move_to "$wanted" manual "$latest"
        exit
    fi

    latest="$(latest_release)"
    rc=$?
    local shown="${current:-unknown}"
    local last_state
    last_state="$(status_get state)"
    if ((rc != 0)); then
        # A rate limit passes; anything else fails the unit.
        local msg="the GitHub API did not answer" code=1
        ((rc == 2)) && msg="GitHub API rate limit" code=0
        log "not checked: $msg; trying again next time"
        write_status_unchanged "${last_state:-current}" "$shown" "$(status_get latest)" "not checked: $msg"
        exit "$code"
    fi
    log "running ${current:-an unrecorded version}; newest release $latest"

    case "$(decide "$latest" "$current" "$held")" in
    up-to-date)
        write_status_unchanged current "$current" "$latest" ""
        ;;
    held)
        log "$latest was rolled back before; not trying it again (./update.sh --version $latest does)"
        write_status_unchanged "${last_state:-rolled_back}" "$shown" "$latest" \
            "$latest was rolled back and is held back; ./update.sh --version $latest tries it again"
        ;;
    update)
        move_to "$latest" timer "$latest"
        return
        ;;
    esac
    return 0
}

main "$@"
exit
