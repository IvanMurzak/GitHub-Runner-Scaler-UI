#!/bin/sh
# D24 — sample a repository's workflow-run status against its jobs' statuses.
#
# Answers: can a run report `in_progress` while one of its jobs is still
# `queued`? See d24-run-status-versus-job-status.md for the result.
#
# READ-ONLY. Creates nothing, deletes nothing, cancels nothing. It observes runs
# that CI produced on its own, so point it at a repository that has work in
# flight or it will print nothing at all.
#
# Requires `gh` authenticated with `actions:read` on the target.
#
# Usage: d24-run-status-probe.sh <owner/repo> [samples] [interval-seconds]

set -eu

REPO="${1:?usage: d24-run-status-probe.sh <owner/repo> [samples] [interval-seconds]}"
SAMPLES="${2:-40}"
INTERVAL="${3:-15}"

i=0
while [ "$i" -lt "$SAMPLES" ]; do
    i=$((i + 1))
    ts=$(date -u +%H:%M:%S)

    # Both statuses, deduplicated: a run appears in exactly one of the two.
    for status in queued in_progress; do
        gh api "repos/$REPO/actions/runs?status=$status&per_page=20" \
            --jq ".workflow_runs[] | \"$ts RUN \(.id) runstatus=\(.status)\"" 2>/dev/null || true
    done | sort -u | while read -r line; do
        id=$(echo "$line" | awk '{print $3}')
        jobs=$(gh api "repos/$REPO/actions/runs/$id/jobs?per_page=100" \
            --jq '[.jobs[] | .status] | group_by(.) | map("\(.[0]):\(length)") | join(" ")' \
            2>/dev/null || echo "unreadable")
        echo "$line jobs=[$jobs]"
    done

    [ "$i" -lt "$SAMPLES" ] && sleep "$INTERVAL"
done
