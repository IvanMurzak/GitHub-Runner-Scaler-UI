#!/usr/bin/env bash
#
# Release helpers for .github/workflows/release.yml (task a2).
#
# ----------------------------------------------------------------------------
# WHY THE LOGIC IS HERE AND NOT INLINE IN THE WORKFLOW.
# ----------------------------------------------------------------------------
# Four of a2's Definition-of-Done items are behavioural claims about decisions
# this file makes:
#
#   * `1.2`, `v1.2.3` and `abc` are rejected as version inputs;
#   * a version equal to or below the current one is rejected, and rejected
#     independently by each of its two sources;
#   * a macOS binary carrying no signature fails the run;
#   * a released artifact set carries a checksum file and an SBOM.
#
# A step body written inline in a workflow can only be exercised by dispatching
# the workflow, and dispatching THIS workflow publishes under the project's
# name. Behaviour that can only be checked by publishing is behaviour that is
# never checked before publishing. Extracted here, every one of those decisions
# is a subcommand that `crates/app/tests/release_workflow.rs` runs directly, on
# every pull request, with no credential and nothing published.
#
# The workflow keeps what genuinely needs the runner — checkout, toolchain,
# `cargo`, `gh`, `git push` — and delegates every *decision* to a subcommand
# below. Read `release.yml` for the ordering and this file for the rules.
#
# ----------------------------------------------------------------------------
# INVOKED AS `bash .github/scripts/release.sh <subcommand>`.
# ----------------------------------------------------------------------------
# Deliberately not as `./.github/scripts/release.sh`: that depends on the
# executable bit surviving a checkout, which it does not on Windows, and the
# test suite runs on all three operating systems.
#
# `.gitattributes` pins `*.sh` to LF. Without it a Windows checkout rewrites
# this file to CRLF and every line ends in a stray carriage return that `bash`
# passes on to the command it runs.

set -euo pipefail

readonly PROGRAM="release.sh"

die() {
    printf '%s: %s\n' "$PROGRAM" "$*" >&2
    exit 1
}

reject() {
    printf 'REJECTED: %s\n' "$*" >&2
}

usage() {
    cat <<'USAGE'
Usage: bash .github/scripts/release.sh <subcommand> [args]

  check-format <version>
      Step 1. Exit non-zero unless <version> is exactly X.Y.Z.

  manifest-version <Cargo.toml>
      Print the [workspace.package] version.

  check-monotonic <version> <manifest-version> [<latest-release-version>]
      Step 2. Exit non-zero unless <version> is strictly greater than BOTH
      sources. An empty third argument means no release is published yet.

  latest-release-version <gh-api--i-response>
      Step 2. Read the output of
      `gh api -i repos/OWNER/REPO/releases/latest` and print the latest
      published version, or nothing at all on a 404. Exit non-zero on any
      other status: a second source that could not be READ is not a second
      source that is ABSENT.

  set-version <version> <Cargo.toml>
      Step 4. Write <version> to every [workspace.dependencies] entry that
      pins a path by version, plus [workspace.package], then verify it.

  verify-version <version> <Cargo.toml>
      Assert that the manifest pins <version> in every such entry, and that
      no entry was skipped because of the shape it is written in.

  check-native-runner <target> <runner-os> <runner-arch>
      Steps 1-2 and 5. Exit non-zero unless the runner's OS and architecture
      are both native for <target>. Nothing here cross-compiles.

  verify-macos-signature <binary>
      Step 5. Exit non-zero unless <binary> carries a valid signature.

  sha256 <file>
      Print "<hash>  <basename>" for <file>.

  sbom <Cargo.lock> <output.json> <product-name> <product-version> [<in-scope>]
      Step 6. Write a CycloneDX 1.5 SBOM of the locked dependency graph.
      <in-scope> is a file of "<name> <version>" lines naming the packages
      that reach the released binary; everything else is marked
      "scope": "excluded" rather than being claimed as a dependency of it.
USAGE
}

# ----------------------------------------------------------------------------
# Semantic versions.
# ----------------------------------------------------------------------------
# Strict X.Y.Z and nothing else. Not "semver as the specification defines it":
# this project's version is also a Cargo package version and a `vX.Y.Z` tag,
# and a pre-release or build-metadata suffix would make the tag, the archive
# names and the install script's asset lookup disagree about what was released.
#
# Leading zeros are refused because `01.2.3` and `1.2.3` name the same Cargo
# version but two different tags, so admitting both admits two releases that
# claim to be the same version.
readonly SEMVER_PATTERN='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

is_semver() {
    [[ "${1-}" =~ $SEMVER_PATTERN ]]
}

# Prints -1, 0 or 1 for a<b, a==b, a>b. Both arguments must already be valid.
semver_cmp() {
    local left="$1" right="$2"
    local -a l r
    IFS=. read -r -a l <<<"$left"
    IFS=. read -r -a r <<<"$right"
    local i
    for i in 0 1 2; do
        # `10#` forces base ten. Without it a component that ever reaches a
        # leading zero would be read as octal, and `08` is not a number at all.
        if ((10#${l[i]} > 10#${r[i]})); then
            printf '1\n'
            return 0
        fi
        if ((10#${l[i]} < 10#${r[i]})); then
            printf -- '-1\n'
            return 0
        fi
    done
    printf '0\n'
}

# ----------------------------------------------------------------------------
# Step 1 — validate the format.
# ----------------------------------------------------------------------------
cmd_check_format() {
    local version="${1-}"

    if is_semver "$version"; then
        printf 'version format OK: %s\n' "$version"
        return 0
    fi

    reject "version input '${version}' is not X.Y.Z."
    cat >&2 <<'EXPLAIN'
  The `version` input is the version itself, not a tag and not a range:

    1.2.3      accepted
    v1.2.3     rejected  - the `v` belongs to the tag, which this workflow adds
    1.2        rejected  - a Cargo version has exactly three components
    01.2.3     rejected  - leading zeros make two tags for one version
    1.2.3-rc1  rejected  - pre-releases are not a v1 channel (D12)
    abc        rejected
EXPLAIN
    exit 1
}

# ----------------------------------------------------------------------------
# Reading the manifest.
# ----------------------------------------------------------------------------
# Scoped to the `[workspace.package]` section on purpose. The root manifest
# carries the string `version = "..."` five times -- once here and once in each
# `[workspace.dependencies]` entry that pins a workspace member -- so an
# unscoped grep reads whichever happens to come first.
manifest_version_of() {
    local manifest="$1"
    awk '
        { line = $0; sub(/\r$/, "", line) }
        line ~ /^\[/ { section = line; next }
        section == "[workspace.package]" && line ~ /^version[[:space:]]*=/ {
            if (match(line, /"[^"]*"/)) {
                print substr(line, RSTART + 1, RLENGTH - 2)
                exit
            }
        }
    ' "$manifest"
}

cmd_manifest_version() {
    local manifest="${1-}"
    [[ -n "$manifest" ]] || die "manifest-version: no manifest given"
    [[ -f "$manifest" ]] || die "manifest-version: no such file: $manifest"

    local version
    version="$(manifest_version_of "$manifest")"
    [[ -n "$version" ]] || die "manifest-version: no [workspace.package] version in $manifest"
    is_semver "$version" ||
        die "manifest-version: [workspace.package] version '$version' is not X.Y.Z"

    printf '%s\n' "$version"
}

# ----------------------------------------------------------------------------
# Step 2 — validate monotonicity, against both sources.
# ----------------------------------------------------------------------------
# The two sources are checked INDEPENDENTLY and both are reported, rather than
# short-circuiting on the first failure. Checking one alone lets a manual edit
# to the other regress the version, which is the whole reason there are two;
# short-circuiting would leave an operator fixing one rejection only to meet the
# other on the next dispatch.
cmd_check_monotonic() {
    local version="${1-}" manifest_version="${2-}" release_version="${3-}"

    is_semver "$version" ||
        die "check-monotonic: '$version' is not X.Y.Z; step 1 should have caught this"
    is_semver "$manifest_version" ||
        die "check-monotonic: manifest version '$manifest_version' is not X.Y.Z"

    local failed=0

    if [[ "$(semver_cmp "$version" "$manifest_version")" == "1" ]]; then
        printf 'monotonic vs Cargo.toml OK: %s > %s\n' "$version" "$manifest_version"
    else
        reject "version ${version} is not greater than the Cargo.toml version ${manifest_version}."
        failed=1
    fi

    if [[ -z "$release_version" ]]; then
        printf 'no published GitHub Release yet; the release source cannot regress a first release\n'
    else
        is_semver "$release_version" ||
            die "check-monotonic: latest release version '$release_version' is not X.Y.Z"

        if [[ "$(semver_cmp "$version" "$release_version")" == "1" ]]; then
            printf 'monotonic vs latest release OK: %s > %s\n' "$version" "$release_version"
        else
            reject "version ${version} is not greater than the latest published release ${release_version}."
            failed=1
        fi
    fi

    if ((failed != 0)); then
        printf 'A release must increase the version against BOTH sources.\n' >&2
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# Step 2 — reading the second source.
# ----------------------------------------------------------------------------
# `gh` needs a runner and a token, so the CALL stays in release.yml. The
# DECISION it feeds lives here: which answer from the GitHub API means "nothing
# has been released yet", and which means "the second source could not be read".
#
# THOSE ARE NOT THE SAME ANSWER, AND `gh api`'s EXIT CODE CANNOT TELL THEM
# APART. It exits non-zero for a 404, for a rate limit, for a network blip, and
# for a token whose scope was reduced. Treating all of them as "no release yet"
# hands `check-monotonic` an empty third argument, which it correctly reads as
# "a first release cannot regress" -- so the two-source gate silently becomes a
# one-source gate at precisely the moment the second source stopped working.
# The equal-version case would still be caught by the tag-collision check, but a
# LOWER one would not: a manually reversed manifest plus one transient API
# failure publishes 1.0.0 while 2.0.0 is the latest release.
#
# `gh api -i` prints the status line ahead of the body, and prints it for a
# failing request too, so the STATUS is recoverable where the exit code is not.
# Only 404 means "no release yet". Every other status stops the run.
#
# The version goes to stdout because the caller captures it; everything else
# goes to stderr, so that a progress line can never be read as a version.
cmd_latest_release_version() {
    local response="${1-}"
    [[ -n "$response" ]] || die "latest-release-version: no response file given"
    [[ -f "$response" ]] || die "latest-release-version: no such file: $response"

    local status_line http_status
    status_line="$(head -n 1 "$response" | tr -d '\r')"

    if [[ -z "$status_line" ]]; then
        reject "the GitHub API returned no response for the latest release."
        printf 'Expected an HTTP status line from `gh api -i`. Nothing was\n' >&2
        printf 'produced at all, so the published-release source -- one of the two\n' >&2
        printf 'sources step 2 compares against -- could not be read. That is a\n' >&2
        printf 'failure, not an empty result: a release must be checked against\n' >&2
        printf 'BOTH sources or against neither.\n' >&2
        exit 1
    fi

    http_status="$(printf '%s\n' "$status_line" | awk '{ print $2 }')"

    case "$http_status" in
    404)
        # The documented address of the latest PUBLISHED release. A 404 is the
        # legitimate first-release state and the only status that is.
        printf 'no published release yet (HTTP 404)\n' >&2
        return 0
        ;;
    200) ;;
    *)
        reject "the GitHub API answered HTTP ${http_status} for the latest release."
        printf '%s\n' "$status_line" >&2
        printf 'Only 404 means "nothing has been released yet". Any other status\n' >&2
        printf 'means the published-release source could not be read, and a run\n' >&2
        printf 'that continued would be checking monotonicity against Cargo.toml\n' >&2
        printf 'alone -- which a manual edit to Cargo.toml is enough to defeat.\n' >&2
        printf 'Re-dispatch once the API is reachable.\n' >&2
        exit 1
        ;;
    esac

    local tag
    tag="$(awk '
        match($0, /"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"/) {
            field = substr($0, RSTART, RLENGTH)
            sub(/^"tag_name"[[:space:]]*:[[:space:]]*"/, "", field)
            sub(/"$/, "", field)
            print field
            exit
        }
    ' "$response")"

    [[ -n "$tag" ]] ||
        die "latest-release-version: HTTP 200 carried no tag_name"

    local version="${tag#v}"
    is_semver "$version" ||
        die "latest-release-version: latest release tag '$tag' is not vX.Y.Z"

    printf 'latest published release: %s\n' "$tag" >&2
    printf '%s\n' "$version"
}

# ----------------------------------------------------------------------------
# Step 4 — write the version.
# ----------------------------------------------------------------------------
# THIS EDITS FIVE LINES, NOT ONE, AND IT HAS TO.
#
# `[workspace.package].version` is single-sourced for the member packages --
# each one says `version.workspace = true` -- but the root manifest ALSO pins
# each member in `[workspace.dependencies]` with a `path` and a `version`, so
# that the published crate resolves from the registry. Cargo requires a path
# dependency to satisfy the version requirement stated alongside it, so bumping
# only `[workspace.package]` does not produce a manifest with a stale comment:
# it produces a workspace that will not resolve at all.
#
#     error: failed to select a version for the requirement
#            `runner-manager-domain = "^0.1.0"`
#            candidate versions found which didn't match: 1.2.3
#
# `verify-version` below is what keeps that from being rediscovered mid-release.
#
# ----------------------------------------------------------------------------
# MATCHED ON `path`, NOT ON `path = "crates/`.
# ----------------------------------------------------------------------------
# Members do not all live under `crates/`: the root manifest already declares
# `tests` as a member (it is `runner-manager-e2e` in the lock), and nothing
# stops a later one from living anywhere else. A rewrite keyed to the `crates/`
# prefix leaves such an entry pinning the old version, and -- worse -- the
# check below used to AFFIRM success anyway, because its only floor was "at
# least one entry matched" and four others did.
#
# So both halves key on the presence of a `path` key inside
# `[workspace.dependencies]`, in any of the shapes TOML allows it to be written
# in, and `verify-version` cross-checks its own coverage against the
# `[workspace] members` list rather than reporting a count of one as enough.
#
# ----------------------------------------------------------------------------
# TWO PASSES OVER THE MANIFEST, BECAUSE `path` NEED NOT PRECEDE `version`.
# ----------------------------------------------------------------------------
# In a one-line inline table both keys are on the line being rewritten, but in
# an expanded `[workspace.dependencies.<name>]` table -- or a multi-line inline
# table -- they are separate lines in either order. A single line-oriented pass
# reaching `version` does not yet know whether the entry it belongs to has a
# `path` at all. Pass one decides which lines to rewrite; pass two rewrites
# them.
readonly MANIFEST_ENTRY_SCANNER='
    function reset_entry() {
        entry_open = 0
        entry_expanded = 0
        entry_has_path = 0
        entry_depth = 0
        entry_versions = 0
        entry_path = ""
    }
    # An entry written as `name = { ... }` ends when its braces balance, and
    # one written with no braces at all ends on the line it started. An
    # expanded `[workspace.dependencies.<name>]` table ends only at the next
    # section header, so brace counting must not close it on its first line.
    function advance(text) {
        if (entry_expanded) { return }
        entry_depth += gsub(/\{/, "\\&", text)
        entry_depth -= gsub(/\}/, "\\&", text)
        if (entry_depth <= 0) { close_entry() }
    }
    function quoted(text) {
        if (match(text, /"[^"]*"/)) {
            return substr(text, RSTART + 1, RLENGTH - 2)
        }
        return ""
    }
    function value_of(text, key,   field) {
        if (!match(text, key "[[:space:]]*=[[:space:]]*\"[^\"]*\"")) { return "" }
        field = substr(text, RSTART, RLENGTH)
        return quoted(substr(field, index(field, "=")))
    }
    # Records what an entry line contributes. `path` may arrive before or after
    # `version`, and both may arrive on the same line as each other.
    function note(text, number) {
        if (text ~ /path[[:space:]]*=[[:space:]]*"/) {
            entry_has_path = 1
            entry_path = value_of(text, "path")
        }
        if (text ~ /version[[:space:]]*=[[:space:]]*"/) {
            entry_versions++
            entry_version_line[entry_versions] = number
            entry_version[entry_versions] = value_of(text, "version")
        }
    }
'

cmd_set_version() {
    local version="${1-}" manifest="${2-}"
    [[ -n "$version" ]] || die "set-version: no version given"
    [[ -n "$manifest" ]] || die "set-version: no manifest given"
    [[ -f "$manifest" ]] || die "set-version: no such file: $manifest"
    is_semver "$version" || die "set-version: '$version' is not X.Y.Z"

    local previous
    previous="$(manifest_version_of "$manifest")"
    [[ -n "$previous" ]] || die "set-version: no [workspace.package] version in $manifest"

    # The manifest is read TWICE -- hence the file named twice below.
    local rewritten="${manifest}.a2-set-version"
    awk -v new="$version" "$MANIFEST_ENTRY_SCANNER"'
        function close_entry(   i) {
            if (entry_open && entry_has_path) {
                for (i = 1; i <= entry_versions; i++) {
                    rewrite[entry_version_line[i]] = 1
                }
            }
            reset_entry()
        }

        # ---- pass one: decide which lines carry a version to rewrite -------
        NR == FNR {
            line = $0
            sub(/\r$/, "", line)

            if (line ~ /^\[/) {
                close_entry()
                section = line
                in_dependencies = (section ~ /^\[workspace\.dependencies(\]|\.)/)
                # An expanded `[workspace.dependencies.<name>]` table IS the
                # entry: it runs until the next section header.
                if (section ~ /^\[workspace\.dependencies\./) {
                    entry_open = 1
                    entry_expanded = 1
                }
                next
            }

            if (section == "[workspace.package]" && line ~ /^version[[:space:]]*=/) {
                package_version_line[FNR] = 1
                next
            }

            if (!in_dependencies) { next }
            if (line ~ /^[[:space:]]*#/) { next }

            if (!entry_open) {
                # A new entry begins at a bare key at the start of a line.
                if (line !~ /^[^#[:space:]=][^=]*=/) { next }
                entry_open = 1
            }

            note(line, FNR)
            advance(line)
            next
        }

        # The end of pass one: an entry still open at EOF has to be closed
        # before its version lines are consulted. `END` cannot do it -- by then
        # pass two has run -- so it happens at the first line of pass two.
        NR != FNR && FNR == 1 { close_entry() }

        # ---- pass two: rewrite exactly those lines -------------------------
        {
            line = $0
            eol = ""
            if (sub(/\r$/, "", line)) { eol = "\r" }

            if (FNR in package_version_line) {
                print "version = \"" new "\"" eol
                next
            }
            if (FNR in rewrite) {
                sub(/version[[:space:]]*=[[:space:]]*"[^"]*"/,
                    "version = \"" new "\"", line)
                print line eol
                next
            }
            print line eol
        }
    ' "$manifest" "$manifest" >"$rewritten"

    mv -f "$rewritten" "$manifest"

    # Verify what was written rather than trusting that it was. A rewrite that
    # silently matched nothing leaves a manifest that still says the old
    # version, and the next thing to notice would be the release page.
    cmd_verify_version "$version" "$manifest"

    printf 'set version %s -> %s in %s\n' "$previous" "$version" "$manifest"
}

# ----------------------------------------------------------------------------
# THIS MUST NOT AFFIRM SUCCESS OVER AN ENTRY IT NEVER LOOKED AT.
# ----------------------------------------------------------------------------
# Its whole purpose is to move a resolution failure from `cargo build` -- which
# in a release run happens AFTER the tag is pushed -- to before the commit. An
# affirmation that means "every entry my scan happened to match is correct" is
# worth nothing, because the entry that broke the release is by definition the
# one the scan did not match.
#
# So there are two independent readings of the same file. The structured one
# attributes every `path` to an entry. The dumb one records every `path` value
# stated anywhere in the section, by regex, with no notion of entries at all. A
# shape the structured reader does not understand shows up as a path the dumb
# reader saw and the structured one did not, and that is a failure -- not a
# silently smaller count.
#
# `[workspace] members` is the third reading, and it is what makes "how many
# members should be pinned here?" answerable at all rather than assumed. It
# also keeps the success line honest: it reports coverage instead of claiming
# completeness.
cmd_verify_version() {
    local version="${1-}" manifest="${2-}"
    [[ -n "$version" ]] || die "verify-version: no version given"
    [[ -f "$manifest" ]] || die "verify-version: no such file: $manifest"

    # `if awk ...` and not `awk ... && { ... }`: under `set -e` a failing
    # command at the head of an AND-list still terminates the shell, which
    # would skip the explanation below and report the failure as a crash.
    if awk -v want="$version" "$MANIFEST_ENTRY_SCANNER"'
        function close_entry(   i, found) {
            if (entry_open && entry_has_path) {
                examined++
                structured_path[entry_path] = 1
                if (entry_versions > 0) {
                    pinned++
                    if (entry_path in declared) { pinned_members[entry_path] = 1 }
                    for (i = 1; i <= entry_versions; i++) {
                        found = entry_version[i]
                        if (found != want) {
                            printf("  the entry pinning path \"%s\" says version \"%s\", expected \"%s\"\n",
                                   entry_path, found, want)
                            bad++
                        }
                    }
                }
            }
            reset_entry()
        }
        # Every quoted string on the line, added to the declared member set.
        function collect_members(text) {
            while (match(text, /"[^"]*"/)) {
                declared[substr(text, RSTART + 1, RLENGTH - 2)] = 1
                declared_count++
                text = substr(text, RSTART + RLENGTH)
            }
        }
        # The dumb reading: every `path = "..."` stated in the section, found
        # by regex, with no notion of what entry it belongs to.
        function collect_paths(text,   field) {
            while (match(text, /path[[:space:]]*=[[:space:]]*"[^"]*"/)) {
                field = substr(text, RSTART, RLENGTH)
                stated_path[quoted(substr(field, index(field, "=")))] = 1
                text = substr(text, RSTART + RLENGTH)
            }
        }

        {
            line = $0
            sub(/\r$/, "", line)
        }

        line ~ /^\[/ {
            close_entry()
            section = line
            in_dependencies = (section ~ /^\[workspace\.dependencies(\]|\.)/)
            if (section ~ /^\[workspace\.dependencies\./) {
                entry_open = 1
                entry_expanded = 1
            }
            collecting_members = 0
            next
        }

        section == "[workspace]" && line ~ /^members[[:space:]]*=/ {
            collecting_members = 1
        }
        collecting_members {
            collect_members(line)
            if (line ~ /\]/) { collecting_members = 0 }
            next
        }

        section == "[workspace.package]" && line ~ /^version[[:space:]]*=/ {
            package_versions++
            found = quoted(line)
            if (found != want) {
                printf("  [workspace.package] version is \"%s\", expected \"%s\"\n", found, want)
                bad++
            }
            next
        }

        in_dependencies {
            if (line ~ /^[[:space:]]*#/) { next }
            collect_paths(line)

            if (!entry_open) {
                if (line !~ /^[^#[:space:]=][^=]*=/) { next }
                entry_open = 1
            }
            note(line, FNR)
            advance(line)
            next
        }

        END {
            close_entry()

            if (package_versions != 1) {
                printf("  expected exactly one [workspace.package] version line, found %d\n",
                       package_versions)
                bad++
            }

            # Positive assertions first: each of the three readings has to have
            # read something, or the comparisons between them are vacuous.
            if (declared_count < 1) {
                printf("  no [workspace] members list could be parsed, so the coverage\n")
                printf("  cross-check below would pass over an empty set\n")
                bad++
            }
            if (pinned < 1) {
                printf("  no [workspace.dependencies] entry pins a path by version\n")
                bad++
            }

            # The reading the whole check turns on: a path the dumb reader saw
            # and the structured reader did not is an entry written in a shape
            # this check cannot understand -- so it was neither rewritten by
            # set-version nor checked here, and reporting success over it is
            # exactly the failure this function exists to prevent.
            for (path in stated_path) {
                if (!(path in structured_path)) {
                    printf("  a [workspace.dependencies] entry declares path \"%s\" in a shape\n", path)
                    printf("  this check does not understand, so nothing verified its version\n")
                    bad++
                }
            }

            members_pinned = 0
            for (path in pinned_members) { members_pinned++ }

            if (bad > 0) {
                printf("  (%d of %d declared workspace members are pinned by path and version;\n",
                       members_pinned, declared_count)
                printf("   %d [workspace.dependencies] entries carry a path in total)\n", examined)
                exit 1
            }

            printf("%d of %d declared workspace members are pinned by path and version, and\n",
                   members_pinned, declared_count)
            printf("all %d [workspace.dependencies] entries carrying a path were checked\n", examined)
        }
    ' "$manifest"; then
        printf 'manifest pins %s in every entry that pins a path by version\n' "$version"
        return 0
    fi

    reject "the manifest does not pin ${version} consistently (see above)."
    printf 'Cargo refuses a path dependency whose version does not satisfy the\n' >&2
    printf 'requirement stated beside it, so this workspace would not resolve.\n' >&2
    exit 1
}

# ----------------------------------------------------------------------------
# Steps 1-2 and 5 — is this runner native for the target it is building?
# ----------------------------------------------------------------------------
# "Build on native runners" is a requirement, not a preference: nothing here
# cross-compiles, which is what lets the macOS signature check below look at a
# real Mach-O for its own architecture. Two of the five `runs-on` labels are
# overridable by repository variable, and `macos-15-intel` is a hosted label
# GitHub has moved more than once -- so what a label resolves to is a fact to
# check, not one to assume.
#
# BOTH HALVES OF "NATIVE" ARE CHECKED, AND THE OS HALF IS THE ONE THAT MATTERS
# MOST. `runner.os` is the single value deciding whether the macOS signature
# gate runs at all, so an override pointing the macOS-x64 label at a Linux x64
# runner passes an architecture-only assertion, produces an ELF named as a macOS
# artifact, and skips the one check that would have noticed.
#
# It lives here rather than inline for the usual reason, plus one more:
# release.yml calls it from TWO jobs -- `preflight`, so an unresolvable or
# mispointed label refuses the release before step 4 writes anything, and
# `build`, so each leg's own runner is proved for the binary it is about to
# produce. Written twice in step bodies it would be two decisions that nothing
# compares. `crates/app/tests/release_workflow.rs` drives every combination
# directly.
cmd_check_native_runner() {
    local target="${1-}" runner_os="${2-}" runner_arch="${3-}"
    [[ -n "$target" ]] || die "check-native-runner: no target given"
    [[ -n "$runner_os" ]] || die "check-native-runner: no runner OS given"
    [[ -n "$runner_arch" ]] || die "check-native-runner: no runner architecture given"

    # An unrecognised target is a rejection, not a pass. A `*)` arm that shrugged
    # would make every future target native by default.
    local want_arch want_os
    case "$target" in
    x86_64-*) want_arch="X64" ;;
    aarch64-*) want_arch="ARM64" ;;
    *) die "check-native-runner: unknown architecture in target '${target}'" ;;
    esac

    case "$target" in
    *-apple-darwin) want_os="macOS" ;;
    *-windows-*) want_os="Windows" ;;
    *-linux-*) want_os="Linux" ;;
    *) die "check-native-runner: unknown operating system in target '${target}'" ;;
    esac

    printf 'target=%s wants=%s/%s runner=%s/%s\n' \
        "$target" "$want_os" "$want_arch" "$runner_os" "$runner_arch"

    # Both mismatches are reported, not just the first: an operator repointing a
    # repository variable should learn everything wrong with the label in one
    # run rather than one fact per dispatch.
    local failed=0
    if [[ "$runner_os" != "$want_os" ]]; then
        reject "${target} must be built on a ${want_os} runner; this one reports ${runner_os}."
        failed=1
    fi
    if [[ "$runner_arch" != "$want_arch" ]]; then
        reject "${target} must be built on a ${want_arch} runner; this one reports ${runner_arch}."
        failed=1
    fi

    if ((failed != 0)); then
        printf 'Point the matching RUNNER_MANAGER_RELEASE_RUNS_ON_* repository\n' >&2
        printf 'variable at a native label. Nothing here cross-compiles, and the\n' >&2
        printf 'macOS signature gate is conditional on the OS this reports.\n' >&2
        exit 1
    fi

    printf 'native %s %s runner\n' "$runner_os" "$runner_arch"
}

# ----------------------------------------------------------------------------
# Step 5 — the macOS signature check.
# ----------------------------------------------------------------------------
# An arm64 Mach-O carrying no signature does not execute on Apple Silicon at
# all, so this is a functional gate and not a trust one (D12: no paid signing).
# The linker normally applies an ad-hoc signature by itself, which is exactly
# why this VERIFIES rather than assumes: "the linker usually does it" is not a
# property anyone checked on the artifact that shipped.
cmd_verify_macos_signature() {
    local binary="${1-}"
    [[ -n "$binary" ]] || die "verify-macos-signature: no binary given"
    [[ -f "$binary" ]] || die "verify-macos-signature: no such file: $binary"
    command -v codesign >/dev/null 2>&1 ||
        die "verify-macos-signature: codesign not found; this must run on a macOS runner"

    local display status
    set +e
    display="$(codesign --display --verbose=2 "$binary" 2>&1)"
    status=$?
    set -e

    printf '%s\n' "$display"

    if ((status != 0)); then
        reject "codesign could not read a signature from ${binary}."
        printf 'An unsigned arm64 binary is killed by the kernel on Apple Silicon.\n' >&2
        exit 1
    fi

    # `codesign --display` exits zero on some inputs while saying, in words,
    # that there is nothing there. Match the message as well as the status.
    case "$display" in
    *"not signed at all"* | *"code object is not signed"*)
        reject "${binary} carries no signature."
        exit 1
        ;;
    esac

    if ! printf '%s\n' "$display" | grep -Eq '^(Signature|Authority)='; then
        reject "codesign reported no signature type for ${binary}."
        exit 1
    fi

    if ! codesign --verify --strict --verbose=2 "$binary"; then
        reject "the signature on ${binary} is present but does not verify."
        exit 1
    fi

    printf 'signature OK: %s\n' "$binary"
}

# ----------------------------------------------------------------------------
# Step 6 — checksums.
# ----------------------------------------------------------------------------
# `sha256sum` on Linux and in Git Bash, `shasum -a 256` on macOS, which has no
# `sha256sum`.
#
# The line is REASSEMBLED from the hash rather than printed as the tool emitted
# it, because the two tools do not agree on the separator. GNU `sha256sum`
# reading in binary mode -- which is what it does by default on Windows, where
# the Windows build leg runs under Git Bash -- writes `<hash> *<name>`, while
# on Linux and macOS the same file comes out as `<hash>  <name>`. Both forms
# verify, but a SHA256SUMS assembled from five build legs would carry both, and
# the install script (a3) and every package manifest read this file. One
# format, produced here, is cheaper than three consumers tolerating two.
#
# Hashing runs from the file's own directory so the recorded name is the bare
# asset name. A SHA256SUMS carrying build-machine paths cannot be checked by
# anyone who downloaded the assets into a directory of their own.
cmd_sha256() {
    local file="${1-}"
    [[ -n "$file" ]] || die "sha256: no file given"
    [[ -f "$file" ]] || die "sha256: no such file: $file"

    local directory base raw hash
    directory="$(dirname "$file")"
    base="$(basename "$file")"

    # `-b` is stated rather than relied on. MSYS2 coreutils -- the `sha256sum`
    # the Windows build leg reaches under Git Bash -- already defaults to binary
    # mode, so this changes no byte today. But the consumer is a3's install
    # script, which ABORTS the install on a mismatch, and "correct because the
    # default happens to be right" is not a property this file gets to assume
    # about a coreutils build it does not pin. `shasum` needs no flag: it runs
    # only on macOS, where there is no text mode for binary mode to differ from.
    if command -v sha256sum >/dev/null 2>&1; then
        raw="$(cd "$directory" && sha256sum -b "$base")"
    elif command -v shasum >/dev/null 2>&1; then
        raw="$(cd "$directory" && shasum -a 256 "$base")"
    else
        die "sha256: neither sha256sum nor shasum is available"
    fi

    hash="${raw%% *}"
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] ||
        die "sha256: '$hash' is not a SHA-256 digest (tool said: $raw)"

    printf '%s  %s\n' "$hash" "$base"
}

# ----------------------------------------------------------------------------
# Step 6 — the SBOM.
# ----------------------------------------------------------------------------
# Generated from `Cargo.lock` rather than from a third-party SBOM tool, and the
# reason is the workflow this runs in. release.yml holds the only credential
# able to publish (`07-security.md`, operational requirement 7); adding a tool
# fetched at release time -- a marketplace action, or a `cargo install` of a
# crate -- puts third-party code inside that workflow and adds a version pin
# that nothing in this repository can check. `Cargo.lock` is already the
# authoritative resolved graph, it is committed and reviewed, and it carries
# the SHA-256 of every registry package, which is precisely an SBOM's payload.
#
# `awk` rather than `jq`: the SBOM is then generated by the same tool the rest
# of this file already depends on, and the result is parsed and asserted by
# `crates/app/tests/release_workflow.rs` on every pull request.
#
# What this deliberately does NOT carry is licence text. `Cargo.lock` does not
# record licences, and inventing them from crate names would be worse than
# omitting them. CycloneDX does not require them.
#
# ----------------------------------------------------------------------------
# `Cargo.lock` IS THE WHOLE WORKSPACE, AND THE BINARY IS NOT.
# ----------------------------------------------------------------------------
# Every `[[package]]` in the lock is listed, because omitting one would be a
# hole in the inventory. But the lock is the resolved graph of the WORKSPACE:
# it contains `wiremock`, `insta`, `assert_cmd`, `predicates`, `serial_test`
# and the two internal test crates, which no released binary links; and it
# contains `security-framework`, `windows-service` and `redox_syscall`, which
# are conditional on operating systems a given artifact was not built for.
# An SBOM that simply asserted all of them as contents of the binary would be a
# false-positive generator for anyone running a CVE scan against the artifact
# -- reporting an advisory in a crate the binary does not contain.
#
# So the optional <in-scope> argument carries the packages that actually reach
# the released binary, and everything else is emitted with CycloneDX's
# `"scope": "excluded"`: present in the document, explicitly NOT claimed as
# part of the product. The caller produces that list with `cargo tree -e normal
# -p <product> --target <triple>`, unioned over the published targets, which
# needs no third-party tool and no marketplace action -- the whole reason this
# generator exists rather than a fetched one.
#
# Omit the argument and no `scope` key is emitted at all: the document then
# makes no claim either way, which is the honest thing for it to do when
# nothing established one.
cmd_sbom() {
    local lock="${1-}" output="${2-}" product="${3-}" product_version="${4-}"
    local in_scope="${5-}"
    [[ -n "$lock" ]] || die "sbom: no Cargo.lock given"
    [[ -f "$lock" ]] || die "sbom: no such file: $lock"
    [[ -n "$output" ]] || die "sbom: no output path given"
    [[ -n "$product" ]] || die "sbom: no product name given"
    [[ -n "$product_version" ]] || die "sbom: no product version given"

    if [[ -n "$in_scope" ]]; then
        [[ -f "$in_scope" ]] || die "sbom: no such in-scope list: $in_scope"
        # An empty list would mark the ENTIRE graph excluded and say so with a
        # straight face, which is a worse document than one that claims nothing.
        grep -q '[^[:space:]]' "$in_scope" ||
            die "sbom: the in-scope list $in_scope is empty; every component would be marked excluded"
    fi

    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    awk -v product="$product" \
        -v product_version="$product_version" \
        -v timestamp="$timestamp" \
        -v in_scope="$in_scope" '
        function escape(text) {
            gsub(/\\/, "\\\\", text)
            gsub(/"/, "\\\"", text)
            return text
        }
        function quoted(text) {
            if (match(text, /"[^"]*"/)) {
                return substr(text, RSTART + 1, RLENGTH - 2)
            }
            return ""
        }
        function flush(   ) {
            if (name == "") { return }
            # The product itself is metadata.component, not one of its own
            # dependencies.
            if (name != product) {
                if (emitted++ > 0) { printf(",\n") }
                printf("    {\n")
                printf("      \"type\": \"library\",\n")
                printf("      \"name\": \"%s\",\n", escape(name))
                printf("      \"version\": \"%s\",\n", escape(version))
                if (in_scope != "") {
                    printf("      \"scope\": \"%s\",\n",
                           ((name " " version) in scoped) ? "required" : "excluded")
                }
                if (checksum != "") {
                    printf("      \"hashes\": [\n")
                    printf("        { \"alg\": \"SHA-256\", \"content\": \"%s\" }\n",
                           escape(checksum))
                    printf("      ],\n")
                }
                printf("      \"purl\": \"pkg:cargo/%s@%s\"\n",
                       escape(name), escape(version))
                printf("    }")
            }
            name = ""; version = ""; checksum = ""
        }
        BEGIN {
            emitted = 0
            if (in_scope != "") {
                # "<name> <version>" per line. Matched on both, because two
                # versions of one crate routinely coexist in a locked graph and
                # only one of them may reach the binary.
                while ((getline scope_line < in_scope) > 0) {
                    sub(/\r$/, "", scope_line)
                    if (scope_line != "") { scoped[scope_line] = 1 }
                }
                close(in_scope)
            }
            printf("{\n")
            printf("  \"bomFormat\": \"CycloneDX\",\n")
            printf("  \"specVersion\": \"1.5\",\n")
            printf("  \"version\": 1,\n")
            printf("  \"metadata\": {\n")
            printf("    \"timestamp\": \"%s\",\n", escape(timestamp))
            printf("    \"component\": {\n")
            printf("      \"type\": \"application\",\n")
            printf("      \"name\": \"%s\",\n", escape(product))
            printf("      \"version\": \"%s\",\n", escape(product_version))
            printf("      \"purl\": \"pkg:cargo/%s@%s\"\n",
                   escape(product), escape(product_version))
            printf("    }\n")
            printf("  },\n")
            printf("  \"components\": [\n")
        }
        {
            line = $0
            sub(/\r$/, "", line)
        }
        line == "[[package]]" { flush(); next }
        # Anchored at column zero so the indented entries inside a
        # `dependencies = [ ... ]` array are never mistaken for fields.
        line ~ /^name = "/     { name = quoted(line);     next }
        line ~ /^version = "/  { version = quoted(line);  next }
        line ~ /^checksum = "/ { checksum = quoted(line); next }
        END {
            flush()
            if (emitted > 0) { printf("\n") }
            printf("  ]\n")
            printf("}\n")
        }
    ' "$lock" >"$output"

    if [[ -n "$in_scope" ]]; then
        printf 'wrote SBOM for %s %s to %s (scoped against %s)\n' \
            "$product" "$product_version" "$output" "$in_scope"
    else
        printf 'wrote SBOM for %s %s to %s (no scope claimed)\n' \
            "$product" "$product_version" "$output"
    fi
}

# ----------------------------------------------------------------------------

main() {
    local subcommand="${1-}"
    [[ -n "$subcommand" ]] || {
        usage >&2
        exit 1
    }
    shift

    case "$subcommand" in
    check-format) cmd_check_format "$@" ;;
    manifest-version) cmd_manifest_version "$@" ;;
    check-monotonic) cmd_check_monotonic "$@" ;;
    latest-release-version) cmd_latest_release_version "$@" ;;
    set-version) cmd_set_version "$@" ;;
    verify-version) cmd_verify_version "$@" ;;
    check-native-runner) cmd_check_native_runner "$@" ;;
    verify-macos-signature) cmd_verify_macos_signature "$@" ;;
    sha256) cmd_sha256 "$@" ;;
    sbom) cmd_sbom "$@" ;;
    -h | --help | help)
        usage
        ;;
    *)
        printf '%s: unknown subcommand: %s\n\n' "$PROGRAM" "$subcommand" >&2
        usage >&2
        exit 1
        ;;
    esac
}

main "$@"
