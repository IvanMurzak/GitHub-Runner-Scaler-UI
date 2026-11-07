# The optional coordinator

The coordinator is a small server you host yourself. It receives GitHub's `workflow_job`
webhooks and wakes the `runner-manager` hosts that serve the job's repository and labels, so a
new job starts as soon as a host polls, not up to a minute later. It is optional: without it,
every host polls GitHub on its own exactly as before.

Design and owner decisions: [`.taskflow/2026-11-07-coordinator-server/README.md`](../.taskflow/2026-11-07-coordinator-server/README.md).
This is **stage 1**: the coordinator only wakes hosts. Hosts still compute demand themselves and
still poll at their normal intervals.

## What it can and cannot do

- It receives `workflow_job` events signed with your webhook secret, and tells connected hosts
  "poll target X now". That is all.
- It never sees a GitHub token, a JIT configuration, a job log or source code. A host checks
  every wake against nothing: it simply polls, and its own policies, capacity and `host doctor`
  checks decide whether a runner starts.
- A woken target is polled at most once every 5 seconds, and never while GitHub has asked that
  host to slow down. A compromised coordinator can at worst make hosts poll a little more often.
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
`runner-manager` App cannot be used).

1. GitHub, **Settings > Developer settings > GitHub Apps > New GitHub App**.
2. **Webhook**: active. **Webhook URL** `https://runners.example.com/webhook`.
   **Webhook secret**: the contents of `webhook_secret`.
3. **Repository permissions**: **Actions: Read-only**. Nothing else.
4. **Subscribe to events**: **Workflow job**.
5. **Where can this GitHub App be installed?** Only on this account.
6. Create it, then **Install App** on the repositories or the organization your hosts serve.

GitHub sends a `ping` at once; the App's **Advanced > Recent Deliveries** should show it
answered `200`. An unsigned or wrongly signed delivery is answered `401` with no body.

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
