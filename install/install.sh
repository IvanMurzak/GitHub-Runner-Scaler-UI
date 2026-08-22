#!/bin/sh
#
# runner-manager installer for macOS and Linux (task a3, D11/D12/D14).
#
#     curl -fsSL https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.sh | sh
#
# Pinned to a version, which needs `sh -s --` because a piped script gets no
# arguments of its own:
#
#     curl -fsSL .../install.sh | sh -s -- --version 1.2.3
#
# ----------------------------------------------------------------------------
# WHY THIS IS `/bin/sh` AND NOT BASH.
# ----------------------------------------------------------------------------
# The documented command pipes into `sh`. On Debian and Ubuntu that is `dash`,
# on Alpine it is BusyBox ash, and neither has arrays, `[[`, or `local -n`.
# A bashism here fails on the exact hosts the script exists to serve, and it
# fails halfway through, after the download.
#
# ----------------------------------------------------------------------------
# WHY IT INSTALLS TO ~/.local/bin AND NOWHERE ELSE.
# ----------------------------------------------------------------------------
# `runner-manager service install` records the ABSOLUTE path of the binary at
# install time (`05-infrastructure.md`, service behaviour 6). An install
# location that moves when a toolchain moves -- which is exactly what an
# `npm i -g` prefix does -- leaves an installed service pointing at a path that
# no longer exists, and the failure surfaces at the next unattended boot rather
# than at install time. `~/.local/bin` belongs to the user, not to a toolchain,
# so it does not move.
#
# ----------------------------------------------------------------------------
# WHY THE CHECKSUM IS NOT OPTIONAL AND HAS NO --skip FLAG.
# ----------------------------------------------------------------------------
# `07-security.md` lists "a published release artifact is tampered with in
# transit" as a threat whose only control is the SHA-256 published beside the
# artifact. A verification that can be turned off is a verification an attacker
# can ask to have turned off, so there is no flag for it: if the digest cannot
# be computed, or does not match, nothing is installed and the exit status is
# non-zero.
#
# ----------------------------------------------------------------------------
# WHY IT READS SHA256SUMS FIRST AND DERIVES THE ASSET NAME FROM IT.
# ----------------------------------------------------------------------------
# `releases/latest/download/<asset>` is GitHub's stable address for the latest
# release, but it needs the EXACT asset name -- and every asset name carries the
# version, which is the one thing "latest" does not tell you. So the first fetch
# is `SHA256SUMS`, which names every asset in the release. The archive name and
# its expected digest come out of the same document, in one round trip, and the
# script never needs editing when a version changes (`09-release-distribution.md`,
# install-script requirement 2).
#
# ----------------------------------------------------------------------------
# THE SEAMS THE TEST SUITE DRIVES.
# ----------------------------------------------------------------------------
# `crates/app/tests/install_scripts.rs` runs THIS FILE end to end on every pull
# request, on all three operating systems, against a directory of fixture
# assets. That is only possible because of the four overrides below, and they
# are documented here rather than hidden because each is also useful to a real
# operator:
#
#   RUNNER_MANAGER_INSTALL_BASE_URL   an `https://` release base, OR a local
#                                     directory holding the release assets flat
#                                     (an air-gapped or mirrored install)
#   RUNNER_MANAGER_INSTALL_DIR        where the binary lands
#   RUNNER_MANAGER_INSTALL_VERSION    same as --version, for `| sh` with no args
#   RUNNER_MANAGER_INSTALL_UNAME_S    override the detected platform, for a host
#   RUNNER_MANAGER_INSTALL_UNAME_M    whose `uname` reports something unusual
#
# `--print-plan` resolves everything that can be resolved without the network
# and prints it, touching neither the network nor the disk.

set -eu

PROGRAM="install.sh"
REPOSITORY="IvanMurzak/GitHub-Runner-Scaler-UI"
BINARY="runner-manager"

# ----------------------------------------------------------------------------

say() {
    printf '%s\n' "$*"
}

fail() {
    printf '%s: %s\n' "$PROGRAM" "$*" >&2
    exit 1
}

usage() {
    cat <<USAGE
Usage: install.sh [--version X.Y.Z] [--dir DIRECTORY] [--print-plan]

  --version X.Y.Z   Install exactly this release instead of the latest one.
  --dir DIRECTORY   Install into DIRECTORY instead of \$HOME/.local/bin.
  --print-plan      Print what would be installed and exit. Downloads nothing.
  --help            This text.

Piped into a shell, arguments need an explicit separator:

  curl -fsSL <url>/install.sh | sh -s -- --version 1.2.3

or set RUNNER_MANAGER_INSTALL_VERSION in the environment instead.
USAGE
}

# ----------------------------------------------------------------------------
# Arguments.
# ----------------------------------------------------------------------------

version="${RUNNER_MANAGER_INSTALL_VERSION-}"
install_dir="${RUNNER_MANAGER_INSTALL_DIR-}"
print_plan=0

while [ "$#" -gt 0 ]; do
    case "$1" in
    --version)
        [ "$#" -ge 2 ] || fail "--version needs a value, for example --version 1.2.3"
        version="$2"
        shift 2
        ;;
    --version=*)
        version="${1#--version=}"
        shift
        ;;
    --dir)
        [ "$#" -ge 2 ] || fail "--dir needs a value"
        install_dir="$2"
        shift 2
        ;;
    --dir=*)
        install_dir="${1#--dir=}"
        shift
        ;;
    --print-plan)
        print_plan=1
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        printf '%s: unknown option: %s\n\n' "$PROGRAM" "$1" >&2
        usage >&2
        exit 1
        ;;
    esac
done

# Checked here rather than at the point of use so a typo costs no download.
# The pattern is the release workflow's, minus the pre-release forms it also
# rejects: a tag this script cannot construct is a release it cannot fetch.
if [ -n "$version" ]; then
    case "$version" in
    v*) fail "--version takes 1.2.3, not v1.2.3: the 'v' belongs to the tag." ;;
    esac
    if ! printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
        fail "--version '${version}' is not X.Y.Z."
    fi
fi

[ -n "$install_dir" ] || install_dir="${HOME:-}/.local/bin"
[ "$install_dir" != "/.local/bin" ] || fail "neither --dir nor \$HOME is set, so there is nowhere to install to."

# ----------------------------------------------------------------------------
# Which artifact does this host need?
# ----------------------------------------------------------------------------
# An unrecognised platform is a refusal, not a guess. Downloading "probably the
# right one" produces a binary that fails to exec with a message about the
# dynamic loader, which is a far worse thing for a user to debug than a
# refusal that names what it saw.

uname_s="${RUNNER_MANAGER_INSTALL_UNAME_S:-$(uname -s 2>/dev/null || echo unknown)}"
uname_m="${RUNNER_MANAGER_INSTALL_UNAME_M:-$(uname -m 2>/dev/null || echo unknown)}"

case "$uname_s" in
Linux) os="linux" ;;
Darwin) os="darwin" ;;
MINGW* | MSYS* | CYGWIN* | Windows_NT)
    printf '%s: this is Windows. Use the PowerShell installer instead:\n\n' "$PROGRAM" >&2
    printf '  irm https://github.com/%s/releases/latest/download/install.ps1 | iex\n\n' "$REPOSITORY" >&2
    printf 'install.sh installs a Linux or macOS binary, which will not run here\n' >&2
    printf 'even under Git Bash or WSL-on-the-Windows-filesystem.\n' >&2
    exit 1
    ;;
*) fail "unsupported operating system: uname -s says '${uname_s}'. Supported: Linux, Darwin (macOS)." ;;
esac

case "$uname_m" in
x86_64 | amd64 | x64) arch="x86_64" ;;
arm64 | aarch64) arch="aarch64" ;;
*) fail "unsupported architecture: uname -m says '${uname_m}'. Supported: x86_64, aarch64/arm64. Build from source with 'cargo install ${BINARY}'." ;;
esac

case "${os}-${arch}" in
darwin-aarch64) target="aarch64-apple-darwin" ;;
darwin-x86_64) target="x86_64-apple-darwin" ;;
linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
*) fail "internal error: no target for ${os}-${arch}" ;;
esac

# The published Linux artifacts are `-gnu`, and a glibc binary does not run on
# a musl system at all. Catching it here costs one `ldd` and turns "Error
# relocating ...: symbol not found" into a sentence naming the cause.
if [ "$os" = "linux" ] && command -v ldd >/dev/null 2>&1; then
    if ldd --version 2>&1 | grep -qi musl; then
        printf '%s: this host uses musl libc, and the published Linux builds are glibc\n' "$PROGRAM" >&2
        printf '(%s). A glibc binary does not run on musl.\n\n' "$target" >&2
        printf 'Build from source instead:  cargo install %s\n' "$BINARY" >&2
        exit 1
    fi
fi

# ----------------------------------------------------------------------------
# Where the assets come from.
# ----------------------------------------------------------------------------
# An `https://` base gets GitHub's release layout. Anything else is treated as
# a local directory holding the assets flat, which is what an air-gapped
# install looks like and what the test suite uses.

base_url="${RUNNER_MANAGER_INSTALL_BASE_URL:-https://github.com/${REPOSITORY}/releases}"

case "$base_url" in
http://* | https://*)
    remote=1
    if [ -n "$version" ]; then
        assets="${base_url}/download/v${version}"
    else
        assets="${base_url}/latest/download"
    fi
    ;;
*)
    remote=0
    assets="$base_url"
    [ -d "$assets" ] || fail "RUNNER_MANAGER_INSTALL_BASE_URL is not an http(s) URL and not a directory: ${assets}"
    ;;
esac

if [ "$print_plan" -eq 1 ]; then
    say "os=${os}"
    say "arch=${arch}"
    say "target=${target}"
    say "version=${version:-latest}"
    say "assets=${assets}"
    say "install_dir=${install_dir}"
    say "binary=${install_dir}/${BINARY}"
    exit 0
fi

# ----------------------------------------------------------------------------
# Fetching.
# ----------------------------------------------------------------------------

fetch() {
    # fetch <name> <destination>
    if [ "$remote" -eq 0 ]; then
        [ -f "${assets}/$1" ] || return 1
        cp "${assets}/$1" "$2" || return 1
        return 0
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${assets}/$1" -o "$2" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "${assets}/$1" || return 1
    else
        fail "neither curl nor wget is available, so nothing can be downloaded."
    fi
}

# Fails closed. A host with no SHA-256 tool gets no install, because the
# alternative is an install nobody verified (`07-security.md`).
digest_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -b "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/.*[= ]//'
    else
        fail "no SHA-256 tool found (looked for sha256sum, shasum, openssl). Refusing to install an unverified binary."
    fi
}

work=""
staged=""
cleanup() {
    [ -z "$work" ] || rm -rf "$work"
    # The staging file is the one temporary thing that does NOT live under
    # $work, and it cannot: a rename is only atomic within a filesystem, so it
    # has to be written beside the destination. That means a failure between
    # `cp` and `mv` -- a full disk, a `chmod` refused by a mount option, a
    # destination that is a running executable -- leaves
    # `.runner-manager.install-tmp` sitting in the user's install directory
    # with nothing to remove it. install.ps1 already deletes its own in the
    # `catch` that wraps the same two steps; this is the missing half.
    [ -z "$staged" ] || rm -f "$staged"
}
trap cleanup EXIT HUP INT TERM

work="$(mktemp -d 2>/dev/null || mktemp -d -t runner-manager)"
[ -n "$work" ] || fail "could not create a temporary directory."

# ----------------------------------------------------------------------------
# 1. SHA256SUMS, which names the assets and pins their digests.
# ----------------------------------------------------------------------------

say "Resolving ${BINARY} for ${target} from ${assets}"

if ! fetch "SHA256SUMS" "${work}/SHA256SUMS"; then
    if [ -n "$version" ]; then
        fail "no release ${version} found at ${assets} (SHA256SUMS could not be fetched)."
    fi
    fail "could not fetch SHA256SUMS from ${assets}."
fi

# ----------------------------------------------------------------------------
# READING SHA256SUMS IS PARSING AN INTERFACE, NOT GREPPING A FILE.
# ----------------------------------------------------------------------------
# Deriving the asset name from this document is what lets the script survive a
# version bump untouched -- and it makes SHA256SUMS a format this script has to
# accept as widely as the tools that produce it. TWO FORMS ARE IN CIRCULATION,
# and `sha256sum -c` verifies both:
#
#     <hash>  <name>     text mode: two spaces, no marker
#     <hash> *<name>     binary mode: one space and a `*` -- what `sha256sum -b`
#                        writes everywhere, and what GNU sha256sum writes on
#                        Windows BY DEFAULT
#
# The README tells a reader to check a release by hand with
# `sha256sum -c SHA256SUMS`. A parser here that is STRICTER than the tool the
# documentation recommends refuses files that command accepts -- and refuses
# them by announcing "this release does not publish that platform", which sends
# the reader to entirely the wrong conclusion about an intact release. So the
# `*` is stripped, and the two failures are then told apart below.
parsed="$(
    awk -v target="$target" '
        { line = $0; sub(/\r$/, "", line) }
        {
            n = split(line, field, /[ \t]+/)
            if (n != 2 || field[1] !~ /^[0-9a-f]{64}$/) { next }
            name = field[2]
            sub(/^\*/, "", name)
            usable = usable + 1
            if (name ~ ("^runner-manager-[0-9]+\\.[0-9]+\\.[0-9]+-" target "\\.tar\\.gz$")) {
                print "match " field[1] " " name
            }
        }
        END { print "usable " usable + 0 }
    ' "${work}/SHA256SUMS"
)"

usable="$(printf '%s\n' "$parsed" | sed -n 's/^usable //p')"
matches="$(printf '%s\n' "$parsed" | sed -n 's/^match //p')"

# A checksum file NOTHING could be read out of is a different failure from one
# that simply carries no line for this host, and it needs a different sentence.
# The first is a truncated download, a proxy's error page, or a file that is
# not SHA256SUMS at all; the second is a release that genuinely skipped a
# platform. Reporting the first as the second is how an operator comes away
# believing their platform was dropped from a release that is perfectly fine.
if [ "${usable:-0}" -eq 0 ]; then
    fail "SHA256SUMS at ${assets} has no line this script can read. Expected '<64 hex digits><spaces><asset name>' on each line; this file is empty, truncated, or not a checksum file at all."
fi

# Exactly one archive per target per release. Zero means this release does not
# publish this platform; more than one means the release is malformed, and
# picking either would pin a digest to the wrong file.
count="$(printf '%s' "$matches" | grep -c . || true)"
case "$count" in
1) ;;
0) fail "SHA256SUMS at ${assets} lists ${usable} assets but no archive for ${target}. This release does not publish that platform." ;;
*) fail "SHA256SUMS at ${assets} lists ${count} archives for ${target}; refusing to guess which one is meant." ;;
esac

expected="${matches%% *}"
asset="${matches#* }"

resolved_version="$(printf '%s' "$asset" | sed -n 's/^runner-manager-\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-.*$/\1/p')"
[ -n "$resolved_version" ] || fail "could not read a version out of the asset name '${asset}'."

# With `--version`, the requested version and the one that arrived must agree.
# On the remote path a wrong version is normally a 404 above; on a local mirror
# it is not, and a mirror serving 1.0.0 to someone who asked for 1.2.3 must be
# a refusal rather than a surprise.
if [ -n "$version" ] && [ "$version" != "$resolved_version" ]; then
    fail "asked for ${version} but ${assets} publishes ${resolved_version} for ${target}."
fi

say "Release ${resolved_version}, asset ${asset}"

# ----------------------------------------------------------------------------
# 2. The archive, and the digest that decides whether it is used.
# ----------------------------------------------------------------------------

fetch "$asset" "${work}/${asset}" || fail "could not fetch ${asset} from ${assets}."

actual="$(digest_of "${work}/${asset}")"
actual="$(printf '%s' "$actual" | tr 'ABCDEF' 'abcdef')"

if [ "$actual" != "$expected" ]; then
    printf '%s: CHECKSUM MISMATCH -- refusing to install %s\n' "$PROGRAM" "$asset" >&2
    printf '  expected (SHA256SUMS): %s\n' "$expected" >&2
    printf '  actually downloaded:   %s\n' "$actual" >&2
    printf '\nThe archive does not match the digest published beside it. That is\n' >&2
    printf 'either a corrupted download or a tampered artifact; nothing has been\n' >&2
    printf 'installed either way. Retry, and if it happens again report it at\n' >&2
    printf 'https://github.com/%s/issues rather than installing by hand.\n' "$REPOSITORY" >&2
    exit 1
fi

say "SHA-256 OK: ${expected}"

# ----------------------------------------------------------------------------
# 3. Unpack and install.
# ----------------------------------------------------------------------------

mkdir -p "${work}/unpacked"
tar -xzf "${work}/${asset}" -C "${work}/unpacked" ||
    fail "could not unpack ${asset}."

unpacked="${work}/unpacked/runner-manager-${resolved_version}-${target}/${BINARY}"
[ -f "$unpacked" ] || fail "${asset} does not contain runner-manager-${resolved_version}-${target}/${BINARY}."

mkdir -p "$install_dir" || fail "could not create ${install_dir}."

# Staged beside the destination and renamed, so a second run over a first one
# replaces the binary in a single step rather than truncating it: the file is
# never half-written, and on Unix a rename over a running binary is safe.
# This is what makes the script idempotent -- two runs leave exactly one file.
staged="${install_dir}/.${BINARY}.install-tmp"
rm -f "$staged"
cp "$unpacked" "$staged" || fail "could not write to ${install_dir}."
chmod 755 "$staged"
mv -f "$staged" "${install_dir}/${BINARY}" || fail "could not install into ${install_dir}."

say ""
say "Installed ${BINARY} ${resolved_version} to ${install_dir}/${BINARY}"

# ----------------------------------------------------------------------------
# 4. PATH.
# ----------------------------------------------------------------------------
# Reported, never edited. Rewriting a shell profile from a piped installer is
# the kind of thing that leaves duplicated lines in a file the user did not
# expect anyone to touch.

case ":${PATH:-}:" in
*":${install_dir}:"*)
    say ""
    say "Next:  ${BINARY} --version"
    ;;
*)
    say ""
    say "${install_dir} is not on your PATH. Add it:"
    say ""
    say "  export PATH=\"${install_dir}:\$PATH\""
    say ""
    say "and to keep it, append that line to ~/.profile, ~/.bashrc or ~/.zshrc."
    say ""
    say "Until then, run it by path:  ${install_dir}/${BINARY} --version"
    ;;
esac

say ""
say "Before you connect it to GitHub: installing the published GitHub App grants"
say "Repository -> Administration: Read and write, which also permits deleting,"
say "renaming and transferring the repository. See the README for the full"
say "permission set and why organization scope is the narrower option."
