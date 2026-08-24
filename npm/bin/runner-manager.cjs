#!/usr/bin/env node
//
// The npm wrapper's entry point (task a3, D11).
//
// ---------------------------------------------------------------------------
// WHY A SHIM AND NOT A postinstall DOWNLOAD.
// ---------------------------------------------------------------------------
// The other common shape for shipping a binary through npm is a `postinstall`
// script that downloads it. That shape needs network access at install time,
// breaks behind a proxy and inside an offline CI cache, and -- the part that
// matters here -- it fetches an artifact that npm's own integrity hashes never
// covered. The esbuild shape used instead puts each binary inside a real npm
// package, so npm's registry integrity hash covers the exact bytes that end up
// on disk, and `--ignore-scripts` (increasingly a default in locked-down CI)
// does not silently produce an installation with no binary in it.
//
// ---------------------------------------------------------------------------
// WHY THE PLATFORM PACKAGES ARE `optionalDependencies`.
// ---------------------------------------------------------------------------
// A package whose `os`/`cpu` do not match the host is SKIPPED when it is
// optional and is a hard install failure when it is not. Five platform
// packages on a normal `dependencies` line would therefore fail the install
// for every user on four of the five platforms. The cost is that a genuinely
// missing package is indistinguishable from a skipped one at install time,
// which is what the diagnostics below exist to untangle at run time.
//
// ---------------------------------------------------------------------------
// THIS FILE IS COMMITTED; THE package.json FILES BESIDE IT ARE GENERATED.
// ---------------------------------------------------------------------------
// `.github/scripts/channels.sh npm-manifests` writes the manifests at release
// time so every version and every published digest comes from the release that
// is happening. This file has no version in it and never needs one.

"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

// Must agree with `PUBLISHED_TARGETS` in `.github/scripts/channels.sh`.
// `crates/app/tests/release_channels.rs` compares the two, because a package
// renamed on one side and not the other produces a wrapper that installs
// cleanly and then cannot find its own binary.
const PLATFORMS = {
  "darwin arm64": ["@ivan-murzak/runner-manager-darwin-arm64", "runner-manager"],
  "darwin x64": ["@ivan-murzak/runner-manager-darwin-x64", "runner-manager"],
  "linux arm64": ["@ivan-murzak/runner-manager-linux-arm64", "runner-manager"],
  "linux x64": ["@ivan-murzak/runner-manager-linux-x64", "runner-manager"],
  "win32 x64": ["@ivan-murzak/runner-manager-win32-x64", "runner-manager.exe"],
};

function fail(lines) {
  for (const line of lines) {
    process.stderr.write(line + "\n");
  }
  process.exit(1);
}

const key = process.platform + " " + process.arch;
const entry = PLATFORMS[key];

if (!entry) {
  const extra = [];
  if (process.platform === "win32") {
    // Windows on ARM runs the x64 build through the built-in emulation layer,
    // but npm will not install an `"cpu": ["x64"]` package onto an arm64 host,
    // so this is the one platform npm cannot serve and the install script can.
    extra.push(
      "",
      "Windows on ARM is supported by the install script, which uses the x64",
      "build through the built-in emulation layer:",
      "",
      "  irm https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI/releases/latest/download/install.ps1 | iex",
    );
  }
  fail([
    `runner-manager: no published binary for ${process.platform} ${process.arch}.`,
    "",
    "Published platforms: " + Object.keys(PLATFORMS).join(", ") + ".",
    "Build from source instead:  cargo install runner-manager",
    ...extra,
  ]);
}

const [packageName, binaryName] = entry;

let binary;
try {
  // Resolved through `package.json` rather than through the package's main
  // entry point: these packages have no JavaScript in them at all, so there is
  // no main to resolve.
  binary = path.join(
    path.dirname(require.resolve(packageName + "/package.json")),
    "bin",
    binaryName,
  );
} catch (error) {
  fail([
    `runner-manager: the platform package ${packageName} is not installed.`,
    "",
    "It is an optionalDependency, so npm skips it silently in three cases:",
    "",
    "  * the install ran with --no-optional or --omit=optional",
    "  * the install ran on a different platform (a lockfile or a Docker",
    "    image built on one OS and used on another)",
    "  * the registry was unreachable when the optional dependency was fetched",
    "",
    "Reinstall with optional dependencies enabled:",
    "",
    "  npm install -g @ivan-murzak/runner-manager",
    "",
    `(resolution error: ${error && error.message ? error.message : error})`,
  ]);
}

// `stdio: "inherit"` because this is a TUI as well as a CLI: the child needs
// the real terminal, not a pipe, or Ratatui has no size to draw into and no
// key events to read.
//
// The child's exit code is propagated. A wrapper that always exits 0 makes
// every `runner-manager` invocation look successful to a shell script, to a
// CI step, and to the service manager that restarts it on failure.
const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  fail([
    `runner-manager: could not execute ${binary}`,
    "",
    String(result.error.message || result.error),
  ]);
}

// Killed by a signal: report it as a shell does, rather than as exit 0.
if (result.signal) {
  process.stderr.write(`runner-manager: terminated by signal ${result.signal}\n`);
  process.exit(1);
}

process.exit(result.status === null ? 1 : result.status);
