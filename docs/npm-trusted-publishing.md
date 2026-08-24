# npm trusted publishing

`release.yml` publishes the npm channel with **trusted publishing**: npm authenticates the
release run by its GitHub OIDC claims — repository, workflow file name, ref — instead of by
a stored token. There is no `NPM_TOKEN` secret in this repository, and there must not be
one: a token in scope would be preferred over the OIDC exchange and would put the release
back on a long-lived credential.

npm also generates a provenance attestation automatically for every package published this
way. No `--provenance` flag is passed, and none is needed.

## What is published

Six packages, all in the `@ivan-murzak` scope. The five platform packages carry the
binaries; the root package is the shim that resolves whichever one matches the host.

| Package | Contents |
|---|---|
| `@ivan-murzak/runner-manager` | the `runner-manager` command (shim) |
| `@ivan-murzak/runner-manager-win32-x64` | `x86_64-pc-windows-msvc` binary |
| `@ivan-murzak/runner-manager-darwin-arm64` | `aarch64-apple-darwin` binary |
| `@ivan-murzak/runner-manager-darwin-x64` | `x86_64-apple-darwin` binary |
| `@ivan-murzak/runner-manager-linux-x64` | `x86_64-unknown-linux-gnu` binary |
| `@ivan-murzak/runner-manager-linux-arm64` | `aarch64-unknown-linux-gnu` binary |

**Each one needs its own trusted publisher.** A publisher is configured per package, so all
six must be set up or the release fails partway through the publish loop.

## One-time setup

**Done for all six packages on 2026-08-24.** They exist on the registry as public packages
at `0.0.0-bootstrap.1`, and each carries a GitHub trusted publisher naming
`IvanMurzak/GitHub-Runner-Scaler-UI`, workflow `release.yml`, permission `publish`, with no
environment constraint. `npm trust list <package>` prints the current configuration.

The steps below are kept for the next package this project adds — a sixth platform target
means a new package name, and a new name starts out with neither a version nor a publisher.

### 1. Create each package

npm can only add a trusted publisher to a package that already exists, and the first version
cannot be published over OIDC. So each package is created once by hand, from a machine
logged in with `npm login` as `ivan-murzak`.

Publish a placeholder under a `bootstrap` dist-tag, so the `latest` tag stays unset until a
real release fills it:

```sh
for pkg in runner-manager \
           runner-manager-win32-x64 \
           runner-manager-darwin-arm64 \
           runner-manager-darwin-x64 \
           runner-manager-linux-x64 \
           runner-manager-linux-arm64; do
  mkdir -p bootstrap/$pkg && cd bootstrap/$pkg
  cat > package.json <<JSON
{
  "name": "@ivan-murzak/$pkg",
  "version": "0.0.0-bootstrap.1",
  "description": "Placeholder so a trusted publisher can be configured. Not a release.",
  "license": "MIT",
  "author": "Ivan Murzak (https://github.com/IvanMurzak)",
  "homepage": "https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI"
}
JSON
  npm publish --access public --tag bootstrap
  cd ../..
done
```

### 2. Add the trusted publisher to each package

On npmjs.com, open each package's **Settings → Trusted Publisher → GitHub Actions** and
enter exactly:

| Field | Value |
|---|---|
| Organization or user | `IvanMurzak` |
| Repository | `GitHub-Runner-Scaler-UI` |
| Workflow filename | `release.yml` |
| Environment | *(leave empty)* |
| Allowed actions | `npm publish` |

The workflow filename is matched literally. Renaming `release.yml` breaks publishing for all
six packages until every publisher is updated.

### 3. Remove any `NPM_TOKEN` secret

If a repository secret named `NPM_TOKEN` exists from before, delete it. Nothing reads it,
and a stray publishing token is exactly the exposure trusted publishing removes.

## What the workflow does

The `channels` job (step 8) is the only job in `release.yml` that requests
`id-token: write`; `crates/app/tests/workflow_triggers.rs` refuses that permission
everywhere else, so the grant cannot spread by inheritance. Before it touches anything the
job checks that `ACTIONS_ID_TOKEN_REQUEST_URL` is set — the endpoint the runner exposes only
under that permission — and fails with a named cause if it is not.

It then sets up Node 24, asserts `npm --version` is at least 11.5.1 (older npm cannot
exchange an OIDC token and fails with a misleading authentication error), and publishes in
the order recorded in `dist-npm/PUBLISH_ORDER`: the five platform packages first, the root
package last, because the root depends on all five at an exact version.

## When a publish is rejected

`npm publish` failing with an authentication or permission error in a job that reached the
publish step means the OIDC claims did not match a configured publisher. Check, in order:

1. the package has a trusted publisher at all (a newly added platform package will not);
2. the publisher names `IvanMurzak` / `GitHub-Runner-Scaler-UI` / `release.yml`;
3. the workflow file was not renamed or moved;
4. `npm --version` in the job log is 11.5.1 or newer.

Nothing about this is recoverable by re-dispatching the workflow — step 2 would refuse the
same version. Fix the publisher, then **re-run the failed `channels` job** from the run page.
