# Does a credential survive its eighth hour? — result

**GREEN. It renews itself, on both platforms, to the second, with nobody
watching.** **Confirmed:** 2026-08-29. **Shipped in:** 0.1.11.

This was an [`docs/open/`](../open/README.md) note from 2026-08-27 until the
eight-hour boundary actually passed on two real hosts. It is here rather than
there because the question is answered.

## The evidence

macOS keeps the two timestamps that settle it. The keychain item:

```
cdat = 20260828103322Z   the sign-in
mdat = 20260829023345Z   the most recent rewrite
```

Sixteen hours and twenty-three seconds apart. `mdat` only keeps the latest
write, so that span is two renewals — one at about `18:33Z`, one at about
`02:33Z` — each landing within a half-minute of its eight-hour mark. Across
both days the macOS daemon logged **zero** `unauthorized` events, held one
process up for 21 hours, and kept a runner listening.

Windows took the long way and proved the same thing more sharply. Its daemon
had been logging 180 `unauthorized` events an hour, unbroken, for 28 hours. It
was restarted at `07:56:35Z`; the DPAPI blob was rewritten at `07:56:36Z`. One
second. In that second the daemon loaded the stored pair, was refused, spent
the refresh half, and wrote the replacement. The `unauthorized` events stopped
dead and did not come back. No sign-in, no person.

`the user access token was renewed` is logged at `INFO` and neither host's file
captures `INFO`, so the store's own mtime is the practical signal. That is a
better one anyway: it is written by the code path under test.

## What the original complaint actually was

Before 0.1.11 this product believed its tokens did not expire. `c2` said so in
a comment, a test enforced it by forbidding the crate from naming a refresh
token, and the CLI reported an expired token as `revoked` because it had no
notion of expiry to report instead.

The published App has **User-to-server token expiration** switched on, and
always had: a device-flow exchange returns `expires_in: 28800` and a
`refresh_token`. The product read the access token and dropped the rest. So
every host stopped working eight hours after its own sign-in and was fixed by
signing in again, which bought exactly eight more hours.

Two hosts were signing in about eight hours apart, so each one's expiry landed
near the other one's sign-in. That produced a clean symmetric correlation —
sign in here, the other host dies nine minutes later, in both directions — and
it was explained twice with two different wrong mechanisms before the timings
were lined up against each host's **own** sign-in. The nine minutes was the
poll interval noticing an expiry that had already happened.

**If this ever returns, check the timing against each host's own sign-in
first.** Eight hours means expiry. Anything else means something else.

## Three defects this uncovered, all still open

The eight-hour question is closed. These are not, and none of them is about
expiry — they are about what happens around the credential.

### A running daemon never re-reads the store

This is what cost Windows 28 hours. `auth login` writes the file; a daemon
already running holds its credential in a `Mutex<UserAccessToken>` loaded once
at startup and has no reason to look again. The Windows daemon started at
`2026-08-28T04:08:04Z`, when the stored token was already dead. The sign-in at
`10:43Z` wrote a good pair the daemon never read. The `unauthorized` stream did
not pause for a single minute across that sign-in.

macOS escaped it by luck: its daemon happened to start at `10:33Z`, the same
minute as its sign-in, so it loaded the new pair as its first act.

`auth login` should tell the running daemon that the credential changed, or the
daemon should re-read on `unauthorized` before giving up on a target.

### Renewal moves the store's owner, and locks the operator out

Windows only, and it fires the first time renewal ever runs. The DACL is

```
D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)
```

and `secrets.rs` explains `OW` — OWNER RIGHTS — as *"the account that ran `auth
login` keeps access to what it stored"*. That holds while `auth login` is the
only writer. Renewal makes the daemon a second writer with a different
identity: `store` writes a temporary and renames it over the target, the
temporary is created by `LocalSystem`, so `LocalSystem` becomes the owner and
`OW` stops resolving to the operator. An unelevated operator then matches none
of the three ACEs and cannot read the file, or even its ACL — `Get-Acl` and
`icacls` both answer `Access is denied`.

Observed on 2026-08-29 immediately after the restart above: `auth status` read
the store fine at `07:50Z` and could not read it at `07:58Z`, with only a
renewal in between.

macOS has the same shape by a different mechanism — a keychain ACL is granted
per application, so replacing the binary during self-upgrade costs the new one
access and it reads `-25293`.

### A host already locked out never heals itself

Carrying the previous owner onto every replacement stops the lockout
*starting*; it cannot end one that already happened. Such a file grants `SY`,
`BA` and `OW` and nothing else, its owner is the service account, and its DACL
has nothing left to carry -- so every renewal rebuilds the same DACL, forever.

Watched on 2026-08-30, on 0.1.13. `auth login` from an elevated prompt reported
`Already signed in` and wrote nothing: with `BA` it could read the credential,
found it valid, and resumed. The blob's mtime did not move, and an unelevated
`auth status` still answered `Access is denied`.

The repair is an **explicit grant**, from an elevated prompt:

```powershell
icacls "C:\ProgramData\IvanMurzak\runner-manager\secrets\user-access-token.dpapi" /grant "%USERNAME%:(F)"
```

Access returns immediately and stays: the next renewal reads that ACE and
carries it forward.

### `takeown` is not the repair, and it makes the damage permanent

It was offered as one, on this host, and it appeared to work. It does not.

**Changing an object's owner makes Windows delete its OWNER RIGHTS ACE.** So
taking ownership removes the one thing that would have granted the new owner
access. What is left is an account that owns a file it cannot read, holding
`READ_CONTROL` and `WRITE_DAC` and nothing else -- enough to read the ACL,
which is exactly what made this look repaired.

Two readings hid it for an hour. The `auth status` that answered
`Credential: authenticated` ran in the **same elevated prompt** as the
`takeown`, so it succeeded through `BA` and said nothing about ownership. And
`(Get-Acl).Owner` answered `IVANPC\IvanD` from an unelevated session -- because
an owner always holds `READ_CONTROL`. Both were true and neither meant what
they were taken to mean.

The store afterwards, which is the whole proof:

```text
O:S-1-5-21-...-1001 G:SY D:P(A;;FA;;;SY)(A;;FA;;;BA)
```

The operator owns it. `OW` is gone. No renewal brings it back.

### `OW` is no longer load-bearing

The module chose `OW` to say *"the account that wrote this keeps access"*
without a SID lookup. The sentence is true until anybody changes the owner, and
then the system silently deletes the ACE that carried it -- so the guarantee
rested on nobody ever running a command that Windows documents as the way to
regain access to a file.

Every write now names its writer by SID as well, from the first one. `OW`
stays, because it costs nothing and still covers the ordinary case, but nothing
depends on it. `ALREADY_GRANTED` keeps the service accounts out, so a daemon
renewing under `LocalSystem` adds no ACE and the set stays at the one operator
who signed in.

### `auth login` refuses to run when the old credential is unreadable

It reads the existing credential first, to decide whether to resume rather than
start a device flow, and aborts if that read fails. So the one command that
would repair an unreadable store is the one that will not run against an
unreadable store.

On its own this is a papercut. Behind either of the two defects above it is the
whole trap: renewal takes the store away from the operator, and then the repair
refuses. **Fixing this one is what makes every other store-access failure
recoverable**, on both platforms, including ones not yet found.

## Two readings that were trusted and should not have been

**`auth status` cannot tell expiry from revocation.** GitHub answers `401` for
both and the message says `revoked` either way. It said `revoked` throughout
the 28 hours when the truth was `expired, and renewable`.

**`service status` said `healthy` for 28 hours while nothing worked.** It was
used as evidence twice during this investigation, and it was wrong twice.

The first explanation for it was also wrong, and is recorded here because it
survived into a fix before anybody checked it: *"`contacts.record()` runs when
`report.failure.is_none()`, and an unauthorized target lands in
`report.unreadable`, not in `failure`."* The second half is false.
`report.unreadable` is pushed only from the `PollOutcome::Failed` arm,
`report.failure` is the maximum over every `Failed` reading, and
`RefreshState::Unauthorized` scores 2 — so a non-empty `unreadable` always
implies `failure.is_some()`. Guarding on both would have changed nothing.

What actually writes a contact record without touching GitHub is a pass that
polls **nothing**: every policy draining, owned by another host, or
monitor-only. No reading exists, no failure is computed, and the old guard
passed. The fix is to ask for positive evidence — `ReconcileReport::
reached_github`, which counts targets GitHub answered for — rather than for the
absence of a complaint.

## The App setting this all rests on

Settings → Developer settings → GitHub Apps → `runner-manager-scaler` →
**Optional features**. The button reads `Opt-out` while expiration is *on*.
Turning it off would strand every host on 0.1.11+ at its next sign-in: they
would get no refresh token, and this product no longer expects to need one
twice.

If a host ever dies right after an interrupted renewal, suspect a spent refresh
token. GitHub rotates on use and answers `incorrect_client_credentials` for a
spent one — a message naming a client id and a secret, and about neither. Only
an interactive sign-in recovers. `StoringRenewal` writes before it returns
specifically to keep that from happening.
