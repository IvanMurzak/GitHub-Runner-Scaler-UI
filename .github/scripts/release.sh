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

  set-version <version> <Cargo.toml>
      Step 4. Write <version> to every line of the manifest that pins a
      workspace member, then verify the result.

  verify-version <version> <Cargo.toml>
      Assert that the manifest pins <version> everywhere it pins a member.

  verify-macos-signature <binary>
      Step 5. Exit non-zero unless <binary> carries a valid signature.

  sha256 <file>
      Print "<hash>  <basename>" for <file>.

  sbom <Cargo.lock> <output.json> <product-name> <product-version>
      Step 6. Write a CycloneDX 1.5 SBOM of the locked dependency graph.
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
cmd_set_version() {
    local version="${1-}" manifest="${2-}"
    [[ -n "$version" ]] || die "set-version: no version given"
    [[ -n "$manifest" ]] || die "set-version: no manifest given"
    [[ -f "$manifest" ]] || die "set-version: no such file: $manifest"
    is_semver "$version" || die "set-version: '$version' is not X.Y.Z"

    local previous
    previous="$(manifest_version_of "$manifest")"
    [[ -n "$previous" ]] || die "set-version: no [workspace.package] version in $manifest"

    local rewritten="${manifest}.a2-set-version"
    awk -v new="$version" '
        {
            line = $0
            eol = ""
            if (sub(/\r$/, "", line)) { eol = "\r" }
        }
        line ~ /^\[/ { section = line; print line eol; next }
        section == "[workspace.package]" && line ~ /^version[[:space:]]*=/ {
            print "version = \"" new "\"" eol
            next
        }
        section == "[workspace.dependencies]" &&
        line ~ /path[[:space:]]*=[[:space:]]*"crates\// &&
        line ~ /version[[:space:]]*=[[:space:]]*"/ {
            sub(/version[[:space:]]*=[[:space:]]*"[^"]*"/, "version = \"" new "\"", line)
            print line eol
            next
        }
        { print line eol }
    ' "$manifest" >"$rewritten"

    mv -f "$rewritten" "$manifest"

    # Verify what was written rather than trusting that it was. A rewrite that
    # silently matched nothing leaves a manifest that still says the old
    # version, and the next thing to notice would be the release page.
    cmd_verify_version "$version" "$manifest"

    printf 'set version %s -> %s in %s\n' "$previous" "$version" "$manifest"
}

cmd_verify_version() {
    local version="${1-}" manifest="${2-}"
    [[ -n "$version" ]] || die "verify-version: no version given"
    [[ -f "$manifest" ]] || die "verify-version: no such file: $manifest"

    # `if awk ...` and not `awk ... && { ... }`: under `set -e` a failing
    # command at the head of an AND-list still terminates the shell, which
    # would skip the explanation below and report the failure as a crash.
    if awk -v want="$version" '
        function quoted(text,   inner) {
            if (match(text, /"[^"]*"/)) {
                return substr(text, RSTART + 1, RLENGTH - 2)
            }
            return ""
        }
        {
            line = $0
            sub(/\r$/, "", line)
        }
        line ~ /^\[/ { section = line; next }
        section == "[workspace.package]" && line ~ /^version[[:space:]]*=/ {
            package_versions++
            found = quoted(line)
            if (found != want) {
                printf("  [workspace.package] version is \"%s\", expected \"%s\"\n", found, want)
                bad++
            }
            next
        }
        section == "[workspace.dependencies]" &&
        line ~ /path[[:space:]]*=[[:space:]]*"crates\// {
            if (line !~ /version[[:space:]]*=[[:space:]]*"/) { next }
            member_versions++
            if (match(line, /version[[:space:]]*=[[:space:]]*"[^"]*"/)) {
                found = quoted(substr(line, RSTART, RLENGTH))
                if (found != want) {
                    printf("  %s\n", line)
                    printf("    pins \"%s\", expected \"%s\"\n", found, want)
                    bad++
                }
            }
            next
        }
        END {
            if (package_versions != 1) {
                printf("  expected exactly one [workspace.package] version line, found %d\n",
                       package_versions)
                bad++
            }
            if (member_versions < 1) {
                printf("  no [workspace.dependencies] entry pins a workspace member by path\n")
                bad++
            }
            if (bad > 0) { exit 1 }
        }
    ' "$manifest"; then
        printf 'manifest pins %s everywhere it pins a workspace member\n' "$version"
        return 0
    fi

    reject "the manifest does not pin ${version} consistently (see above)."
    printf 'Cargo refuses a path dependency whose version does not satisfy the\n' >&2
    printf 'requirement stated beside it, so this workspace would not resolve.\n' >&2
    exit 1
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

    if command -v sha256sum >/dev/null 2>&1; then
        raw="$(cd "$directory" && sha256sum "$base")"
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
cmd_sbom() {
    local lock="${1-}" output="${2-}" product="${3-}" product_version="${4-}"
    [[ -n "$lock" ]] || die "sbom: no Cargo.lock given"
    [[ -f "$lock" ]] || die "sbom: no such file: $lock"
    [[ -n "$output" ]] || die "sbom: no output path given"
    [[ -n "$product" ]] || die "sbom: no product name given"
    [[ -n "$product_version" ]] || die "sbom: no product version given"

    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    awk -v product="$product" \
        -v product_version="$product_version" \
        -v timestamp="$timestamp" '
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

    printf 'wrote SBOM for %s %s to %s\n' "$product" "$product_version" "$output"
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
    set-version) cmd_set_version "$@" ;;
    verify-version) cmd_verify_version "$@" ;;
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
