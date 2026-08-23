<!-- owner: d3-service-installers -->

# The service account, and what it may do

`05-infrastructure.md`, "Service behavior", item 2:

> run under a least-privilege account that can read the machine-scoped secret
> store and write its configured cache and runtime directories

`07-security.md` states the same requirement as a release gate: *"Service
account permissions are documented and verified least privilege."* This file is
the documentation half. The verification half is
`crates/platform/src/service.rs`: `review_least_privilege` reads each rendered
definition back and reports anything it grants beyond the requirement, and the
unit tests in that file construct a widened version of every definition and
watch the review reject it.

Two clauses in that sentence pull in opposite directions on every platform.
"Read the machine-scoped secret store" is a floor — an account that cannot read
the token produces a service that starts and then fails, which is worse than one
that never started. "And no more" is a ceiling. What follows is where each
platform's floor turned out to be, and what holds the ceiling down.

---

## The account, per platform and start mode

| Platform | `--start-at boot` | `--start-at login` |
|---|---|---|
| Windows | `NT AUTHORITY\SYSTEM`, as a Service Control Manager service | the operator, as a Task Scheduler task at `LeastPrivilege` |
| macOS | `root`, as a LaunchDaemon in `/Library/LaunchDaemons` | the operator, as a LaunchAgent in `~/Library/LaunchAgents` |
| Linux | `root`, as a systemd system unit | the operator, as a systemd user unit |

Nothing here is an operator choice. The account is a function of the start mode
and the platform, because the start mode decides which secret store the daemon
must read and the store's own access control decides which accounts can read it.

### Windows: why `LocalSystem` and not `LocalService`

`LocalService` and `NetworkService` are the two accounts a "least privilege
service" reflex reaches for, and **neither can read this product's token.**

`d2` protects the machine-scoped store with a DACL it writes itself:

```text
D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)
```

That is: `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and OWNER RIGHTS —
and nothing else. `D:P` means the DACL is protected, so nothing is inherited
either. `LocalService` (`LS`) and `NetworkService` (`NS`) appear nowhere in it.

This is not a detail that could drift silently:
`the_account_this_installer_registers_is_one_the_stores_own_dacl_admits` in
`service.rs` writes a value into a machine-scoped store, reads the DACL back
through `d2`'s own `Protection`, and asserts that it names `SY` and does not
name `LS` or `NS`. If `d2`'s DACL ever changes, that test fails and this file is
wrong.

**The DACL was not widened to reach a smaller account, and must not be.** A
machine-scope DPAPI blob is decryptable by any process on the host — `d2` says
so at length — so the DACL *is* the access control, not a second layer on top of
encryption. An ACE letting `LocalService` read the file would let **every**
service on the host running as `LocalService` read the one credential this
product holds. Running as `LocalSystem` and keeping the DACL narrow is the
smaller exposure of the two, and `secrets.rs` belongs to `d2` besides.

What bounds `LocalSystem` here instead:

- the service is `SERVICE_WIN32_OWN_PROCESS` and never
  `SERVICE_INTERACTIVE_PROCESS`, so nothing this product runs reaches the
  operator's desktop;
- no account password is ever requested, stored, or passed to `CreateServiceW`;
- the service has no dependencies, so it acquires nothing by association;
- `07-security.md` handling rule 3 — *"service installation does not create a
  privileged interactive command channel"* — holds by construction: the product
  exposes no inbound HTTP, socket, or RPC surface at all, and
  `review_least_privilege` fails any definition that asks the service manager to
  open one on the daemon's behalf.

### macOS: why `root`

A LaunchDaemon runs as `root` unless told otherwise, and here it must be told to
stay there. The macOS machine-scoped store is the System Keychain, and what
decides who can decrypt it is `/var/db/SystemKey`, which is root-only. A
LaunchDaemon under any other account starts and then finds no credential.

The plist states `UserName = root` explicitly rather than relying on launchd's
default, so the account is a reviewable fact rather than an implicit one, and
`review_least_privilege` reports a shortfall if it is absent.

What bounds it:

- `SessionCreate` is `false`: a job that runs outside every login session is not
  given a security session it has no use for;
- `ProcessType` is `Background`, so the daemon yields CPU and I/O to whatever
  the operator is doing;
- no `MachServices` and no `Sockets`, which is `07-security.md` rule 2 enforced
  in the definition rather than only in review.

A LaunchAgent (`--start-at login`) names **no** `UserName` at all: it already
runs as the operator, and naming an account there would be asking launchd for a
switch a login-mode registration has no reason to want.

### Linux: why `root`, and what would make it not `root`

A systemd system unit runs as `root`. The machine-scoped store is a `0600` file
under `/var/lib/runner-manager`, which only `root` can open before any session
exists.

**There is a way out of that, and the unit already takes the first half of it.**
`d2` publishes a systemd credential name (`runner-manager.user-access-token`)
and the guard file it reads, and the generated boot unit carries:

```ini
LoadCredential=runner-manager.user-access-token:/var/lib/runner-manager/secrets/user-access-token
```

systemd reads that file **as root** and hands the contents to the service
through `$CREDENTIALS_DIRECTORY`, which means a future version could add
`User=runner-manager` — or `DynamicUser=yes` — and the daemon would still get
its token while running unprivileged.

This installer does not do that, deliberately: creating a system account on
somebody's home machine is not something a `service install` should do without
being asked, and `05-infrastructure.md` does not ask for it. The credential line
is there so that the change is a one-line unit edit rather than a redesign.

---

## What the daemon may write, and nothing else

Every definition restricts the daemon to the four directories
`05-infrastructure.md` gives it, recorded at install time in
`config/service.toml`:

```text
config/      non-secret TOML and the SQLite database
state/       the agent lock, the attempt journal, the runner package cache
runtime/     per-attempt disposable runner workspaces
logs/        rotating redacted diagnostics
```

On Linux this is enforced, not merely intended:

```ini
ProtectSystem=strict
ReadWritePaths=<config> <state> <runtime> <logs>
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

`ProtectSystem=strict` makes the entire filesystem read-only except for the
paths named in `ReadWritePaths`, plus the private `/tmp` that `PrivateTmp=yes`
supplies. `review_least_privilege` fails a unit that names a fifth path there,
that drops any of the directives above, or that weakens one of them.

### The consequence a Linux operator will actually notice

**The runner inherits this sandbox.** The agent starts the GitHub Actions runner
as a child process, so a workflow running on this host runs inside the same
restrictions:

- it can write to the attempt workspace under `runtime/` and to its private
  `/tmp`, and to nothing else on the filesystem;
- `NoNewPrivileges=yes` means it cannot `sudo`, and no setuid binary gains
  privilege inside it;
- an action that installs tooling into `/usr`, `/opt`, or the account's home
  directory fails.

`07-security.md` assumes a hostile workflow may run on this host, so that is the
intended direction rather than an accident. It is still a real behavioural
limit, and it is the one thing in this file most likely to surprise somebody.
An operator who needs a workflow to write outside those directories should add
the path to `ReadWritePaths` in `/etc/systemd/system/runner-manager.service`
deliberately — and should know that `service status` reads the unit back, so the
addition will be reported.

Windows and macOS have no equivalent of `ProtectSystem=strict` that this
installer can set without shipping a sandbox policy of its own. There the four
directories are recorded, and `service status` reports them, but the operating
system does not confine the daemon to them. That asymmetry is real and is stated
rather than papered over.

---

## What `service uninstall` may delete

Exactly one thing: the registration, plus the install record
(`config/service.toml`) that describes it. No backend may delete anything else,
and `Uninstalled::preserved` names the four directories that survive so that
`service uninstall` can print them.

The stored GitHub token is untouched too. Purging it is `auth logout`, which is
a separate, deliberate act — `05-infrastructure.md`: *"The installer rollback is
binary replacement plus service removal. It never deletes the stored user access
token automatically."*

---

## What is not claimed

- **The reboot is unproven here.** Every check in this repository is about the
  configuration a boot-time start depends on. That the machine comes back up
  and the agent resumes is human gate 3 in `06-migration-rollout.md`.
- **A local administrator or `root` can read the token.** `07-security.md`
  records this as an accepted trade-off of machine-scoped storage, with
  `--start-at login` as the escape hatch for operators who reject it. No account
  policy in this file changes that.
- **On macOS and Linux, the privileged installer paths have not yet been
  exercised.** The definitions are asserted line by line on every leg of the CI
  matrix and both backends are type-checked everywhere, but only Windows has
  registered a real service in CI. `d3`'s scope note puts macOS and Linux
  installation in Wave 3.
