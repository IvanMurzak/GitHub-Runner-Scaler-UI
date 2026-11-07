# The optional coordinator

The coordinator is a small server you host yourself. It receives GitHub's `workflow_job`
webhooks and wakes the `runner-manager` hosts that serve the job's repository and labels, so a
new job starts as soon as a host polls, not up to a minute later. It is optional: without it,
every host polls GitHub on its own exactly as before.

Design and owner decisions: [`.taskflow/2026-11-07-coordinator-server/README.md`](../.taskflow/2026-11-07-coordinator-server/README.md).
Stage 1: the coordinator wakes hosts. Stage 2: with its own GitHub App configured, it also runs a
**reconciliation sweep** over the hosts' repositories, and hosts it covers poll GitHub rarely (see
[Poll modes](#poll-modes)). Hosts still compute demand themselves.

## What it can and cannot do

- It receives `workflow_job` events signed with your webhook secret, and tells connected hosts
  "poll target X now".
- With a GitHub App configured, it reads the queued jobs of the repositories its hosts serve with
  the App's own installation tokens (read-only), and tells the hosts which of their targets that
  sweep covers. Nothing else.
- It never sees a host's GitHub token, a JIT configuration, a job log or source code. A host checks
  every wake against nothing: it simply polls, and its own policies, capacity and `host doctor`
  checks decide whether a runner starts.
- A woken target is polled at most once every 5 seconds, and never while GitHub has asked that
  host to slow down. A compromised coordinator can at worst make hosts poll a little more often,
  or (by claiming coverage it does not have) poll a covered idle target only every 5 minutes.
- Hosts connect **out** over `wss://`, so they keep working behind NAT. If the coordinator is
  down, hosts poll on their own; nothing waits for it.

## Deploy

You need a machine with Docker, a DNS name pointing at it (for example `runners.example.com`),
and ports 80 and 443 open. Caddy obtains the TLS certificate.

```bash
git clone https://github.com/IvanMurzak/GitHub-Runner-Scaler-UI.git
cd GitHub-Runner-Scaler-UI/deploy/coordinator
echo "COORDINATOR_HOST=runners.example.com" > .env
openssl rand -hex 32 > webhook_secret && chmod 600 webhook_secret
docker compose up -d --build
curl https://runners.example.com/healthz          # ok
```

The webhook secret is read from the file only; it is never an argument and never logged.
The SQLite database (enrolled hosts and invites) lives in the `coordinator-data` volume.

Without Docker, build `cargo build --release -p runner-manager-coordinator` and run

```bash
COORDINATOR_PUBLIC_URL=https://runners.example.com \
COORDINATOR_WEBHOOK_SECRET_FILE=/etc/runner-manager-coordinator/webhook_secret \
COORDINATOR_DB=/var/lib/runner-manager-coordinator/coordinator.db \
runner-manager-coordinator serve --listen 127.0.0.1:8080
```

behind any TLS proxy that forwards `/webhook`, `/connect` (WebSocket), `/enroll` and
`/healthz`. Pass `--trust-forwarded-for` only when the proxy is the sole client, so per-address
rate limits see real client addresses.

## Connect GitHub: a personal GitHub App

The webhook comes from a GitHub App you own (one URL per coordinator, so the shared
`runner-manager` App cannot be used). The same App's installation tokens are what the
reconciliation sweep reads the queue with.

1. GitHub, **Settings > Developer settings > GitHub Apps > New GitHub App**.
2. **Webhook**: active. **Webhook URL** `https://runners.example.com/webhook`.
   **Webhook secret**: the contents of `webhook_secret`.
3. **Repository permissions**: **Actions: Read-only** and **Metadata: Read-only** (GitHub
   selects Metadata itself). Nothing else.
4. **Subscribe to events**: **Workflow job**.
5. **Where can this GitHub App be installed?** Only on this account.
6. Create it. Note the **App ID** on its page, and under **Private keys** click **Generate a
   private key**: GitHub downloads a `.pem` file.
7. **Install App** on the repositories or the organization your hosts serve. An organization
   target is covered by the sweep only when the App is installed on **All repositories** of
   that organization; a repository target, when the App is installed on that repository.

GitHub sends a `ping` at once; the App's **Advanced > Recent Deliveries** should show it
answered `200`. An unsigned or wrongly signed delivery is answered `401` with no body.

### Turn on the reconciliation sweep

Put the private key next to the compose file and give the coordinator its path and the App ID:

```bash
cp ~/Downloads/your-app.*.private-key.pem github_app_key.pem && chmod 600 github_app_key.pem
echo "COORDINATOR_GITHUB_APP_ID=123456" >> .env
cat > docker-compose.override.yml <<'YAML'
services:
  coordinator:
    environment:
      COORDINATOR_GITHUB_APP_ID: ${COORDINATOR_GITHUB_APP_ID}
      COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE: /run/secrets/github_app_key
      # COORDINATOR_RECONCILE_INTERVAL: 2m   # at least 30s
    secrets:
      - github_app_key
secrets:
  github_app_key:
    file: ./github_app_key.pem
YAML
docker compose up -d --build
docker compose logs coordinator | grep "reconciliation sweep"
```

Without Docker, set `COORDINATOR_GITHUB_APP_ID` and `COORDINATOR_GITHUB_APP_PRIVATE_KEY_FILE`
(or `COORDINATOR_GITHUB_APP_PRIVATE_KEY` with the PEM itself) for `serve`. The key is read from
the file or the environment only, never an argument, and neither it, the JWTs signed with it
nor the installation tokens are ever logged. Both the downloaded PKCS#1 key (`BEGIN RSA PRIVATE
KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`) are accepted. For GitHub Enterprise Server, also set
`COORDINATOR_GITHUB_API_URL`.

What the sweep does, every `COORDINATOR_RECONCILE_INTERVAL` (2 minutes by default):

- Every 10 minutes, it lists the App's installations and the repositories each can read, signing
  a short JWT (RS256, nine minutes) with the key. Each installation gets an installation token,
  replaced when less than 10 minutes of its hour are left.
- For each repository a connected host serves, it lists the queued and in-progress runs and the
  queued jobs in them, with conditional requests: an unchanged listing is a `304`, free against
  the installation's hourly quota. A rate-limited installation is left alone until the time
  GitHub names.
- For each queued job that no wake was sent for within the interval (by the webhook or an
  earlier sweep), it wakes the hosts whose enabled profiles can take it. A job is identified by
  its repository and required labels.
- It tells every host, in a `hello_ack`, which of its targets the sweep covers.

## Poll modes

Each of a host's targets is in one of three modes, shown per target by `runner-manager status`
(`coordinator.targets` in `--json`), `host doctor` (`github.polling`, `coordinator.link`),
`coordinator status` and the TUI dashboard:

| Mode | When | Polling |
|---|---|---|
| `standalone` | the host has not joined a coordinator | idle 10 s / active 60 s |
| `coordinated` | the link is up and the coordinator's sweep covers the target | every 300 s (`host set-poll-interval --coordinated 300s`, at least 60 s) |
| `fallback` | joined, but the link has been down for 30 s, or the target is not covered | idle 10 s / active 60 s |

In `coordinated`, wakes still bring a poll forward (at most one every 5 seconds), and a target this
host is running a runner for keeps the normal intervals, so a slot that frees up is used for work
that is already queued. A link that drops keeps `coordinated` for 30 seconds, so a quick reconnect
changes nothing; after that every target polls on its own again at once. A coordinator without a
GitHub App covers nothing, so its hosts are in `fallback` and behave as in stage 1.

The protocol is versioned: a stage-1 host and this coordinator, or this host and a stage-1
coordinator, settle on version 1 and work as stage 1 did (the host is then in `fallback`).

## Enroll a host

On the coordinator's machine, issue a one-time code (valid 15 minutes by default, usable once;
only its hash is stored):

```bash
docker compose exec coordinator runner-manager-coordinator invite --name win-big [--ttl 30m]
```

On the host:

```bash
runner-manager coordinator join https://runners.example.com --code rmc_...
runner-manager coordinator status
```

`join` creates an Ed25519 key pair. The private key goes into the same secret store as the
GitHub credential (System Keychain, DPAPI, or the protected file on Linux, per the host's start
mode); the coordinator stores only the public key. On a boot-mode host run `join` with
administrator rights, as `auth login`. The running service picks the setting up within 15
seconds; no restart is needed. Every connection is a fresh challenge: the coordinator sends a
random nonce and the host signs it together with the coordinator's origin.

`status`, `host doctor` (check `coordinator.link`, information only) and the TUI dashboard show
whether the link is connected, or disconnected since when and why.

## Administer

```bash
docker compose exec coordinator runner-manager-coordinator hosts list [--json]
docker compose exec coordinator runner-manager-coordinator hosts revoke win-big   # name or id
```

A revoked host's live connection is closed within about ten seconds and it cannot reconnect.
To move a host to a new key, revoke it, issue a new invite, then on the host run
`runner-manager coordinator leave` and `join` again.

## Security notes

- Public endpoints: `/webhook` (HMAC-SHA256 checked in constant time before anything else,
  1 MiB body limit, repeated `X-GitHub-Delivery` ids ignored), `/connect` (signed challenge),
  `/enroll` (one-time code), `/healthz`. Connection and enrollment attempts are rate-limited
  per client address.
- The admin commands run on the coordinator's own machine against its database; there is no
  remote admin endpoint.
- Logs carry identifiers, counts and fixed words: never the secret, a code, a key, a signature,
  or text from a webhook body.
