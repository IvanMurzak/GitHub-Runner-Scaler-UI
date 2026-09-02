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

## The runner root, and who may write inside it

The four directories above are *application data*. The directory jobs actually
run in is separate, and on Windows it is not under the operator's profile at
all: `%SystemDrive%\rman`, short enough that a deep `_work` checkout does not
hit `MAX_PATH`.

That location has a problem the four application-data directories do not. The
security descriptor of `C:\` carries an inherit-only entry of roughly this
shape:

```text
(A;OICIIO;SDGXGWGR;;;AU)
```

— *Authenticated Users*, delete plus generic read, write and execute, inherited
by every child of `C:\`. A directory created there with inheritance left on is
writable by **every account that can log in to the machine**. Runner workspaces
hold executable content that a later job re-enters, so this is a
code-execution boundary rather than an untidiness.

`service install` therefore creates the directory with a *protected* descriptor
— `SE_DACL_PROTECTED`, the `P` in SDDL — which severs inheritance, and admits
exactly:

| Trustee | Rights | Why |
|---|---|---|
| `SY` — LocalSystem | Full control, `(OI)(CI)` | A boot registration runs as LocalSystem |
| `BA` — Administrators | Full control, `(OI)(CI)` | Already outside this threat model, per `07-security.md`; without it an operator cannot clean up after a service account they are not signed in as |
| the selected account | `FRFWFXSD`, `(OI)(CI)` | A login registration or a foreground daemon runs as an ordinary user |

The third row is the one that is easy to get wrong. A login-mode registration is
a Task Scheduler task rendered with `RunLevel = LeastPrivilege`, so it runs
under the operator's **filtered** token — in which the Administrators group is
present but *deny-only*. A descriptor naming only `SY` and `BA` grants such a
task nothing at all, even when the operator is an administrator. So the account
is named explicitly, and `service set-start-mode` reconciles it: the account
admitted for login mode is not the account boot mode needs, and the two move
together.

The selected account gets modify rather than full control on purpose.
`FILE_ALL_ACCESS` includes `WRITE_DAC` and `WRITE_OWNER`, the two rights that
would let the admitted account undo the protection. Read, write, execute and
delete is everything "create a child, materialize a runner into it, clean it up
again" needs; deleting a whole attempt tree works because the inherited entry
grants `DELETE` on every entry below it.

### What it refuses, and what it never touches

- **An existing broad root fails the install, and is not repaired.** If
  `%SystemDrive%\rman` is already there and ordinary local users can write it,
  `service install` refuses and says so. Tightening it instead would silently
  adopt whatever a local account had already put inside a directory whose
  contents get executed. The remedy is to remove or empty it, or to point the
  runner root somewhere else.
- **A custom root is reported, never re-permissioned.** An operator's
  `host set-runtime-root` path is theirs. `service status` describes what it
  grants; nothing in this feature rewrites it. The enforcement is structural
  rather than a check: the function that applies a descriptor resolves the
  platform default itself and takes no path argument.
- **Rollback is real, and what cannot be rolled back is said.** A failed install
  removes a directory it created and restores a descriptor it replaced. A
  directory that existed beforehand is never deleted, and when its previous
  descriptor cannot be put back the failure message says so rather than leaving
  the operator to discover it.
- **`service status` reports but does not fail.** A broad root appears as a note
  with the remedy. It does not make an otherwise healthy host report an error,
  because a directory that predates this feature is not a fault in the
  registration — refusing it is `service install`'s job, and `service install`
  runs as the account with the authority to know.

macOS and Linux are unaffected. Their default runner root is the `runtime/`
directory attempts have always used, whose permissions `AppPaths` already
establishes; there is no inherited broad grant to sever and relocating live
workspaces to solve a problem those platforms do not have would be a
regression.

---

## What `service uninstall` may delete

Exactly one thing: the registration, plus the install record
(`config/service.toml`) that describes it. No backend may delete anything else,
and `Uninstalled::preserved` names the four directories that survive so that
`service uninstall` can print them.

The runner root survives too, and is deliberately absent from that list because
it is not application data: it may hold an operator's retained workspaces, and
deleting a directory this product created but did not fill is not `uninstall`'s
call to make.

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
