#!/usr/bin/env bash
#
# Downstream channel helpers for step 8 of .github/workflows/release.yml
# (task a3, D11).
#
# ----------------------------------------------------------------------------
# WHY THIS IS A SEPARATE FILE FROM release.sh.
# ----------------------------------------------------------------------------
# Same reason release.sh exists at all -- a decision written inline in a step
# body can only be exercised by dispatching the release workflow, and
# dispatching it publishes under the project's name. Everything below is a
# subcommand that `crates/app/tests/release_channels.rs` runs directly on every
# pull request, with no credential, nothing tagged and nothing published.
#
# It is a3's file rather than more of a2's because a2's tests bind release.sh's
# subcommand list to release.yml's steps. Growing that list from here would make
# a2's assertions fail for a2 reasons they do not own.
#
# ----------------------------------------------------------------------------
# EVERY GENERATOR HERE FAILS CLOSED.
# ----------------------------------------------------------------------------
# The Definition of Done says "the Homebrew formula and npm package resolve to
# the same checksums the release published". The failure that claim exists to
# prevent is not a wrong digest -- it is a MISSING one, rendered as an empty
# string or a placeholder into a manifest that then installs whatever it is
# handed. So a lookup that finds no line, or more than one, is an error and
# stops the run. There is no default, and no `|| echo ""` anywhere below.
#
# ----------------------------------------------------------------------------
# INVOKED AS `bash .github/scripts/channels.sh <subcommand>`.
# ----------------------------------------------------------------------------
# Not as `./.github/scripts/channels.sh`: the executable bit does not survive a
# Windows checkout, and the test suite runs on all three operating systems.
# `.gitattributes` pins `*.sh` to LF for the same reason.

set -euo pipefail

readonly PROGRAM="channels.sh"

die() {
    printf '%s: %s\n' "$PROGRAM" "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage: bash .github/scripts/channels.sh <subcommand> [args]

  checksum <SHA256SUMS> <asset-name>
      Print the SHA-256 recorded for exactly <asset-name>. Exit non-zero if
      the file records no line for it, or more than one.

  asset-name <version> <target>
      Print the published archive name for <target> at <version>.

  brew-formula <version> <SHA256SUMS> <owner/repo> <output.rb>
      Render the Homebrew tap formula, one url/sha256 pair per supported
      platform, each pinned to the digest <SHA256SUMS> records.

  npm-manifests <version> <SHA256SUMS> <output-directory>
      Render the npm wrapper's package.json files: the root package with
      every platform package as an optionalDependency, and one manifest per
      platform carrying its os/cpu constraints and the published digest of
      the archive its binary came from.

  npm-package-name <target>
      Print the npm platform package name for <target>.

  npm-stage <version> <SHA256SUMS> <archive-directory> <output-directory>
      Assemble the publishable npm tree: render the manifests, RE-VERIFY each
      release archive against <SHA256SUMS>, and unpack its binary into the
      matching platform package. Writes <output-directory>/PUBLISH_ORDER.
      Aborts, having published nothing, if any archive is missing or its
      digest does not match.
USAGE
}

# ----------------------------------------------------------------------------
# The published matrix, in one place.
# ----------------------------------------------------------------------------
# `target|npm os|npm cpu|archive extension|binary file name`, in the same order
# as `RELEASE_TARGETS` in release.yml. `crates/app/tests/release_channels.rs`
# asserts that this list and that one name the same five targets, because two
# lists of platforms that disagree is how a release ships a channel quietly
# missing one.
readonly PUBLISHED_TARGETS='x86_64-pc-windows-msvc|win32|x64|zip|runner-manager.exe
aarch64-apple-darwin|darwin|arm64|tar.gz|runner-manager
x86_64-apple-darwin|darwin|x64|tar.gz|runner-manager
x86_64-unknown-linux-gnu|linux|x64|tar.gz|runner-manager
aarch64-unknown-linux-gnu|linux|arm64|tar.gz|runner-manager'

readonly PRODUCT="runner-manager"
readonly PRODUCT_DESCRIPTION="Local-first autoscaling manager for ephemeral GitHub Actions self-hosted runners, with a CLI and a Ratatui TUI."

readonly SEMVER_PATTERN='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

require_semver() {
    [[ "${1-}" =~ $SEMVER_PATTERN ]] || die "'${1-}' is not X.Y.Z"
}

field_of() {
    # field_of <target> <1-based index>
    local row
    row="$(printf '%s\n' "$PUBLISHED_TARGETS" | awk -F'|' -v t="$1" '$1 == t { print; exit }')"
    [[ -n "$row" ]] || die "unknown target: $1"
    printf '%s\n' "$row" | cut -d'|' -f"$2"
}

# ----------------------------------------------------------------------------
# Reading SHA256SUMS.
# ----------------------------------------------------------------------------
# The format is a2's, and it is fixed: `<64 lower-case hex><two spaces><bare
# asset name>` (`release.sh sha256`, asserted by
# `a_checksum_line_is_the_bare_asset_name_and_two_spaces`).
#
# THE NAME IS MATCHED WHOLE, NOT AS A SUBSTRING. `runner-manager-1.2.3-\
# x86_64-apple-darwin.tar.gz` is a substring of nothing else in a well-formed
# release, but it would be a substring of `...-x86_64-apple-darwin.tar.gz.sig`
# the moment anything else is published beside it -- and a formula pinned to a
# signature file's digest installs nothing and explains nothing.
cmd_checksum() {
    local sums="${1-}" asset="${2-}"
    [[ -n "$sums" ]] || die "checksum: no SHA256SUMS given"
    [[ -f "$sums" ]] || die "checksum: no such file: $sums"
    [[ -n "$asset" ]] || die "checksum: no asset name given"

    local hits
    hits="$(awk -v want="$asset" '
        { line = $0; sub(/\r$/, "", line) }
        {
            n = split(line, field, /[ \t]+/)
            if (n == 2 && field[1] ~ /^[0-9a-f]{64}$/ && field[2] == want) {
                print field[1]
            }
        }
    ' "$sums")"

    local count
    count="$(printf '%s' "$hits" | grep -c . || true)"
    case "$count" in
    1) ;;
    0) die "checksum: ${sums} records no digest for '${asset}'. Refusing to render a manifest with an unpinned artifact." ;;
    *) die "checksum: ${sums} records ${count} digests for '${asset}'; refusing to guess which one is meant." ;;
    esac

    printf '%s\n' "$hits"
}

cmd_asset_name() {
    local version="${1-}" target="${2-}"
    require_semver "$version"
    local extension
    extension="$(field_of "$target" 4)"
    printf '%s-%s-%s.%s\n' "$PRODUCT" "$version" "$target" "$extension"
}

cmd_npm_package_name() {
    local target="${1-}"
    local os cpu
    os="$(field_of "$target" 2)"
    cpu="$(field_of "$target" 3)"
    printf '%s-%s-%s\n' "$PRODUCT" "$os" "$cpu"
}

# ----------------------------------------------------------------------------
# The Homebrew formula.
# ----------------------------------------------------------------------------
# Four platforms, not five: Homebrew has no Windows. The urls are pinned to
# `download/v<version>/`, never to `latest/download/`, because a formula names
# a specific version and Homebrew caches the download by url -- a `latest` url
# would serve one bottle's bytes under another version's cache key.
#
# `version` is stated explicitly rather than inferred from the url, because
# Homebrew's inference reads `-1.2.3-` out of the file name only for a small
# set of shapes and silently produces a wrong version for the rest.
cmd_brew_formula() {
    local version="${1-}" sums="${2-}" repository="${3-}" output="${4-}"
    require_semver "$version"
    [[ -f "$sums" ]] || die "brew-formula: no such file: $sums"
    [[ -n "$repository" ]] || die "brew-formula: no owner/repo given"
    [[ -n "$output" ]] || die "brew-formula: no output path given"

    local base="https://github.com/${repository}/releases/download/v${version}"

    local mac_arm mac_intel linux_arm linux_intel
    local mac_arm_sha mac_intel_sha linux_arm_sha linux_intel_sha
    mac_arm="$(cmd_asset_name "$version" aarch64-apple-darwin)"
    mac_intel="$(cmd_asset_name "$version" x86_64-apple-darwin)"
    linux_arm="$(cmd_asset_name "$version" aarch64-unknown-linux-gnu)"
    linux_intel="$(cmd_asset_name "$version" x86_64-unknown-linux-gnu)"
    mac_arm_sha="$(cmd_checksum "$sums" "$mac_arm")"
    mac_intel_sha="$(cmd_checksum "$sums" "$mac_intel")"
    linux_arm_sha="$(cmd_checksum "$sums" "$linux_arm")"
    linux_intel_sha="$(cmd_checksum "$sums" "$linux_intel")"

    mkdir -p "$(dirname "$output")"
    cat >"$output" <<FORMULA
# Generated by .github/scripts/channels.sh at release time. Do not edit by
# hand: the next release overwrites this file, and every digest below is the
# one release ${version} actually published.
class RunnerManager < Formula
  desc "${PRODUCT_DESCRIPTION}"
  homepage "https://github.com/${repository}"
  version "${version}"
  license "MIT"

  on_macos do
    on_arm do
      url "${base}/${mac_arm}"
      sha256 "${mac_arm_sha}"
    end
    on_intel do
      url "${base}/${mac_intel}"
      sha256 "${mac_intel_sha}"
    end
  end

  on_linux do
    on_arm do
      url "${base}/${linux_arm}"
      sha256 "${linux_arm_sha}"
    end
    on_intel do
      url "${base}/${linux_intel}"
      sha256 "${linux_intel_sha}"
    end
  end

  def install
    # Each archive holds a single top-level directory, which Homebrew strips
    # when it stages the download, so the binary is at the staging root here.
    bin.install "${PRODUCT}"
  end

  def caveats
    <<~CAVEATS
      Installing the published GitHub App grants Repository -> Administration:
      Read and write. That permission also allows deleting, renaming and
      transferring the repository, and it applies even if you only ever use
      ${PRODUCT} as a dashboard. See
      https://github.com/${repository}#what-you-are-granting
    CAVEATS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/${PRODUCT} --version")
  end
end
FORMULA

    printf 'wrote %s for %s %s (4 platforms, each digest from %s)\n' \
        "$output" "$PRODUCT" "$version" "$sums"
}

# ----------------------------------------------------------------------------
# The npm wrapper.
# ----------------------------------------------------------------------------
# esbuild's shape: a thin root package whose `bin` shim resolves one of five
# per-platform packages, each declaring `os` and `cpu` so npm installs only the
# one that fits. They are `optionalDependencies` because a package whose `os`
# does not match is SKIPPED there and is a hard install failure anywhere else --
# so on a normal `dependencies` line every user on four of the five platforms
# would fail to install at all.
#
# UNSCOPED NAMES, DELIBERATELY. `@runner-manager/linux-x64` would read better
# and matches esbuild, but a scoped name requires the npm organisation to exist
# before anything can be published, and this repository cannot create one. An
# unscoped name that publishes is worth more than a scoped one that blocks the
# first release.
#
# Each platform manifest records the archive its binary was taken from and that
# archive's published digest. npm does not check it -- nothing in npm can --
# but it is what makes "the npm package resolves to the same checksum the
# release published" a fact somebody can verify after the fact rather than a
# claim about a process.
cmd_npm_manifests() {
    local version="${1-}" sums="${2-}" outdir="${3-}"
    require_semver "$version"
    [[ -f "$sums" ]] || die "npm-manifests: no such file: $sums"
    [[ -n "$outdir" ]] || die "npm-manifests: no output directory given"

    local repository="IvanMurzak/GitHub-Runner-Scaler-UI"

    # Every digest is looked up BEFORE anything is written. A generator that
    # wrote three manifests and then died on the fourth would leave a staging
    # directory that looks publishable.
    local -a names=() targets=() oses=() cpus=() assets=() digests=() binaries=()
    local target os cpu extension binary asset digest
    while IFS='|' read -r target os cpu extension binary; do
        [[ -n "$target" ]] || continue
        # Assigned to a plain variable first, never inline into `array+=(...)`:
        # a `die` inside a command substitution ends only the subshell, and its
        # non-zero status is easy to lose. If a digest is missing, this is where
        # the run has to stop.
        asset="$(cmd_asset_name "$version" "$target")"
        digest="$(cmd_checksum "$sums" "$asset")"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
            die "npm-manifests: refusing to record '${digest}' as the digest of ${asset}"
        targets+=("$target")
        oses+=("$os")
        cpus+=("$cpu")
        binaries+=("$binary")
        assets+=("$asset")
        digests+=("$digest")
        names+=("${PRODUCT}-${os}-${cpu}")
    done <<<"$PUBLISHED_TARGETS"

    ((${#names[@]} == 5)) ||
        die "npm-manifests: expected five platform packages, prepared ${#names[@]}"

    mkdir -p "${outdir}/${PRODUCT}"

    # ---- the root package ---------------------------------------------------
    {
        printf '{\n'
        printf '  "name": "%s",\n' "$PRODUCT"
        printf '  "version": "%s",\n' "$version"
        printf '  "description": "%s",\n' "$PRODUCT_DESCRIPTION"
        printf '  "license": "MIT",\n'
        printf '  "homepage": "https://github.com/%s",\n' "$repository"
        printf '  "repository": { "type": "git", "url": "git+https://github.com/%s.git" },\n' "$repository"
        printf '  "engines": { "node": ">=18" },\n'
        printf '  "bin": { "%s": "bin/%s.cjs" },\n' "$PRODUCT" "$PRODUCT"
        printf '  "files": [ "bin/", "README.md" ],\n'
        printf '  "optionalDependencies": {\n'
        local index
        for index in "${!names[@]}"; do
            printf '    "%s": "%s"' "${names[index]}" "$version"
            if ((index + 1 < ${#names[@]})); then printf ','; fi
            printf '\n'
        done
        printf '  }\n'
        printf '}\n'
    } >"${outdir}/${PRODUCT}/package.json"

    # ---- one package per platform -------------------------------------------
    for index in "${!names[@]}"; do
        mkdir -p "${outdir}/${names[index]}"
        {
            printf '{\n'
            printf '  "name": "%s",\n' "${names[index]}"
            printf '  "version": "%s",\n' "$version"
            printf '  "description": "The %s binary for %s.",\n' "${targets[index]}" "$PRODUCT"
            printf '  "license": "MIT",\n'
            printf '  "homepage": "https://github.com/%s",\n' "$repository"
            printf '  "repository": { "type": "git", "url": "git+https://github.com/%s.git" },\n' "$repository"
            printf '  "os": [ "%s" ],\n' "${oses[index]}"
            printf '  "cpu": [ "%s" ],\n' "${cpus[index]}"
            printf '  "files": [ "bin/" ],\n'
            printf '  "runnerManager": {\n'
            printf '    "target": "%s",\n' "${targets[index]}"
            printf '    "binary": "%s",\n' "${binaries[index]}"
            printf '    "asset": "%s",\n' "${assets[index]}"
            printf '    "sha256": "%s"\n' "${digests[index]}"
            printf '  }\n'
            printf '}\n'
        } >"${outdir}/${names[index]}/package.json"
    done

    printf 'wrote %s root manifest and %d platform manifests under %s\n' \
        "$PRODUCT" "${#names[@]}" "$outdir"
}

# ----------------------------------------------------------------------------
# Assembling the publishable npm tree.
# ----------------------------------------------------------------------------
# THE DIGEST IS CHECKED AGAIN HERE, AND THAT IS NOT BELT-AND-BRACES.
#
# `npm-manifests` above copies a digest OUT of SHA256SUMS into a manifest. That
# proves the two documents agree with each other; it proves nothing about the
# archive the binary is actually taken from. The Definition of Done says the
# npm package must resolve to the same checksum the release published, and the
# only way to establish that is to hash the bytes being unpacked and compare.
#
# So this recomputes every archive's SHA-256 before it opens it. A mismatch
# aborts with nothing staged -- which is also what makes "a corrupted archive
# never reaches a published package" a property `release_channels.rs` can drive
# on every pull request, by corrupting a fixture archive and watching this
# refuse.
digest_of() {
    local file="$1" raw
    if command -v sha256sum >/dev/null 2>&1; then
        raw="$(sha256sum -b "$file")"
    elif command -v shasum >/dev/null 2>&1; then
        raw="$(shasum -a 256 "$file")"
    else
        die "no SHA-256 tool found (looked for sha256sum, shasum)"
    fi
    printf '%s\n' "${raw%% *}"
}

cmd_npm_stage() {
    local version="${1-}" sums="${2-}" archives="${3-}" outdir="${4-}"
    require_semver "$version"
    [[ -f "$sums" ]] || die "npm-stage: no such file: $sums"
    [[ -d "$archives" ]] || die "npm-stage: no such directory: $archives"
    [[ -n "$outdir" ]] || die "npm-stage: no output directory given"

    # `<repo>/.github/scripts/channels.sh` -> `<repo>`.
    local repository_root
    repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    local shim="${repository_root}/npm/bin/${PRODUCT}.cjs"
    local wrapper_readme="${repository_root}/npm/README.md"
    [[ -f "$shim" ]] || die "npm-stage: the wrapper entry point is missing: $shim"
    [[ -f "$wrapper_readme" ]] || die "npm-stage: the wrapper README is missing: $wrapper_readme"

    rm -rf "$outdir"
    cmd_npm_manifests "$version" "$sums" "$outdir" >/dev/null

    local target os cpu extension binary asset expected actual package unpack produced
    local -a order=()
    while IFS='|' read -r target os cpu extension binary; do
        [[ -n "$target" ]] || continue
        package="${PRODUCT}-${os}-${cpu}"
        asset="$(cmd_asset_name "$version" "$target")"
        expected="$(cmd_checksum "$sums" "$asset")"

        [[ -f "${archives}/${asset}" ]] ||
            die "npm-stage: ${archives}/${asset} is missing; the release did not publish ${target} or it was not downloaded"

        actual="$(digest_of "${archives}/${asset}")"
        if [[ "$actual" != "$expected" ]]; then
            printf '%s: DIGEST MISMATCH for %s\n' "$PROGRAM" "$asset" >&2
            printf '  SHA256SUMS says: %s\n' "$expected" >&2
            printf '  the file is:     %s\n' "$actual" >&2
            die "npm-stage: refusing to publish a package built from an archive that does not match its published digest"
        fi

        unpack="${outdir}/.unpack-${target}"
        rm -rf "$unpack"
        mkdir -p "$unpack"
        case "$extension" in
        tar.gz) tar -xzf "${archives}/${asset}" -C "$unpack" ;;
        zip)
            command -v unzip >/dev/null 2>&1 ||
                die "npm-stage: unzip is required to unpack ${asset}"
            unzip -q "${archives}/${asset}" -d "$unpack"
            ;;
        *) die "npm-stage: unknown archive extension '${extension}' for ${target}" ;;
        esac

        produced="${unpack}/${PRODUCT}-${version}-${target}/${binary}"
        [[ -f "$produced" ]] ||
            die "npm-stage: ${asset} does not contain ${PRODUCT}-${version}-${target}/${binary}"

        mkdir -p "${outdir}/${package}/bin"
        cp "$produced" "${outdir}/${package}/bin/${binary}"
        chmod 755 "${outdir}/${package}/bin/${binary}"
        cp "$wrapper_readme" "${outdir}/${package}/README.md"
        rm -rf "$unpack"

        order+=("$package")
        printf 'staged %s from %s (%s)\n' "$package" "$asset" "$expected"
    done <<<"$PUBLISHED_TARGETS"

    ((${#order[@]} == 5)) || die "npm-stage: staged ${#order[@]} platform packages, expected 5"

    mkdir -p "${outdir}/${PRODUCT}/bin"
    cp "$shim" "${outdir}/${PRODUCT}/bin/${PRODUCT}.cjs"
    chmod 755 "${outdir}/${PRODUCT}/bin/${PRODUCT}.cjs"
    cp "$wrapper_readme" "${outdir}/${PRODUCT}/README.md"

    # THE ROOT PACKAGE IS PUBLISHED LAST, AND THE ORDER IS WRITTEN DOWN RATHER
    # THAN LEFT TO WHOEVER LOOPS OVER THE DIRECTORY. It declares every platform
    # package at an exact version; published first, it is installable for the
    # minutes before its dependencies exist, and every install in that window
    # fails at the point where npm resolves them.
    {
        printf '%s\n' "${order[@]}"
        printf '%s\n' "$PRODUCT"
    } >"${outdir}/PUBLISH_ORDER"

    printf 'staged %d packages under %s; publish in the order in %s/PUBLISH_ORDER\n' \
        "$((${#order[@]} + 1))" "$outdir" "$outdir"
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
    checksum) cmd_checksum "$@" ;;
    asset-name) cmd_asset_name "$@" ;;
    npm-package-name) cmd_npm_package_name "$@" ;;
    brew-formula) cmd_brew_formula "$@" ;;
    npm-manifests) cmd_npm_manifests "$@" ;;
    npm-stage) cmd_npm_stage "$@" ;;
    -h | --help | help) usage ;;
    *)
        printf '%s: unknown subcommand: %s\n\n' "$PROGRAM" "$subcommand" >&2
        usage >&2
        exit 1
        ;;
    esac
}

main "$@"
