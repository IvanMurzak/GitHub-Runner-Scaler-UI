# Does a credential survive its eighth hour?

**Open since:** 2026-08-27. **Answerable from:** 2026-08-28 ~18:45 UTC.
**Answered by:** looking at two hosts. **Fixed in:** 0.1.11.

## The check

Both hosts hold a renewable pair for the first time as of `2026-08-28`: macOS
signed in at `10:34Z`, Windows at about `10:45Z`. Their access tokens expire
eight hours later, at about `18:34Z` and `18:45Z`. If renewal works, neither
needs a person and neither stops.

An earlier attempt at this check was void: both hosts still held bare tokens,
because `auth login` had resumed rather than signed in (see below). The tell is
the store -- on Windows the DPAPI blob went from 262 bytes to 486 when a pair
was finally written. A blob that does not grow means no refresh half was
stored, and nothing will renew.

Windows:

```powershell
runner-manager auth status                                  # expect: authenticated
type "$env:LOCALAPPDATA\IvanMurzak\runner-manager\data\state\github-contact.toml"
```

macOS:

```bash
grep last_success ~/Library/Application\ Support/io.github.IvanMurzak.runner-manager/state/github-contact.toml
grep -c re-authentication ~/Library/Application\ Support/io.github.IvanMurzak.runner-manager/logs/runner-manager.log.*
```

`last_success` within a minute or two of now, on both, past `06:29Z`, is the
answer. A `401` count that grows after that time is the failure.

The log line to look for on success is `the user access token was renewed`,
emitted by `AuthenticatedClient::renew_once`. It should appear roughly every
eight hours per host and never require anybody to do anything.

## Why this was in doubt

Before 0.1.11 this product believed its own tokens did not expire. `c2` said so
in a comment, a test in `c2` enforced it by forbidding the crate from even
naming a refresh token, and the CLI reported an expired token as `revoked` —
because it had no notion of expiry to report instead.

None of that was true. The published App has **User-to-server token expiration**
switched on, and always had: a device-flow exchange against
`Iv23liUGaKmwt8p3ZxRc` returns `expires_in: 28800` and a `refresh_token`
alongside the access token. The product read the access token and discarded the
rest.

So every host stopped working eight hours after its sign-in, reported the
credential as revoked, and was fixed by signing in again — which bought another
eight hours. That is the whole of the original complaint this work started
from.

## What sent the investigation wrong, twice

Two hosts were signing in about eight hours apart, so each one's expiry landed
close to the other one's sign-in. That produced a clean, repeatable, symmetric
correlation — sign in here, the other host dies about nine minutes later, in
both directions — and it was explained twice with two different wrong
mechanisms before the timings were lined up against each host's *own* sign-in
rather than the other's.

The nine minutes was the poll interval discovering an expiry that had already
happened.

**If this returns, check the timing against each host's own sign-in first.**
Eight hours means expiry. Anything else means something else.

## If it comes back

`auth status` cannot tell expiry from revocation — GitHub answers `401` for
both, and the message says `revoked` either way. So:

1. **Is there a refresh half at all?** A credential stored before 0.1.11 is a
   bare token with nothing to renew, and signing in once replaces it with a
   pair. `UserAccessToken::from_stored_document` accepts both shapes on
   purpose.
2. **Did the exchange fail, or the store?** `StoringRenewal` writes before it
   returns and reports a store failure as a renewal failure. The distinction is
   in the warning text.
3. **Was the refresh token spent twice?** GitHub rotates on use and answers
   `incorrect_client_credentials` for a spent one — a message naming a client
   id and a secret and about neither. Only an interactive sign-in recovers.
   This is the failure mode the write-before-use ordering exists to prevent,
   and the one to suspect if a host dies after an interrupted renewal.
4. **Check the App's setting.** Settings → Developer settings → GitHub Apps →
   `runner-manager-scaler` → **Optional features**. The button reads `Opt-out`
   while expiration is *on*. Turning it off would strand every host on 0.1.11+
   at its next sign-in, because they would get no refresh token and this
   product no longer expects to need one twice.

## Two things that hid this for half a day

**`auth login` resumes instead of signing in, and says nothing useful about
it.** A still-valid credential short-circuits the device flow -- reasonable, and
it means that upgrading to a version which stores a *pair* changes nothing until
the old token dies. A host told to sign in again, which did, and which then
failed eight hours later anyway, is this: the sign-in never happened. Watched on
2026-08-27, where a login at 22:29 left the 17:58 credential in place and the
host expired on the original schedule at 01:58.

The tell is the store: a bare token and a pair are different sizes, and the
blob did not change. `auth login` should say which of the two it did.

**`last GitHub contact` is recorded even when every target answered `401`.**
`contacts.record()` runs when `report.failure.is_none()`, and an unauthorized
target goes to `report.unreadable`, not to `failure`. So a daemon that can reach
nothing keeps a fresh contact record and `service status` keeps saying
`healthy`. Both of those readings were used as evidence during this
investigation, twice, and both were wrong.

## Known, unfixed, and related

Found while confirming the above, all still open:

- **A revoked or expired credential crash-loops the daemon.** Startup recovery
  reads `Unreachable` from GitHub, treats it as fatal, and exits `14`. The
  service manager restarts it, forever. It cannot report the problem and cannot
  self-upgrade past it, because it dies before either. Seen on macOS; the fix
  is to let startup recovery wait rather than die.
- **`auth login` refuses to run when the old credential cannot be read.** It
  reads first to decide whether to resume, and aborts if that read fails — so
  the one action that would fix an unreadable store is the one it will not
  take. Seen on macOS after a binary upgrade changed the keychain item's ACL.
- **Self-upgrade breaks the credential on macOS, and only there.** The upgrade
  works: the daemon drains, replaces its copy, exits `21`, and launchd restarts
  it. But the replacement is a *different binary*, and a macOS keychain grants
  access per application -- so the restarted daemon reads `-25293` from its own
  credential, exits `13`, and loops. Seen on 2026-08-28 upgrading 0.1.11 to
  0.1.12: `state/bin/runner-manager` became 0.1.12, `.old` held 0.1.11, the
  keychain item was intact, and the daemon could not read it. Windows is
  unaffected, because DPAPI binds to the account rather than to the executable.
  Recovery is `auth login` from a GUI Terminal and **Always Allow** on the
  prompt. The feature is worse than useless on macOS until this is fixed: it
  upgrades a working host into a broken one.
- **The start-mode warning fires when it should not.** It says the host records
  no start mode whenever `--start-at` was not passed, which is not the same
  thing.
