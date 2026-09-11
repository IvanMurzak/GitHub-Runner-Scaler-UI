---
id: "c2-device-flow-auth"
title: "OAuth device flow, user access token, installation discovery, and the shared authenticated HTTP client"
group: "C"
sequence: 2
repo: "."
depends_on: ["c1-d17-scale-set-spike", "b1-domain-core"]
importance: 10
complexity: 7
security_critical: true
production_touching: false
model_hint: "top"
taskflow_refs: ["07-security.md", "03-control-flows.md", "04-subsystem-contracts.md", "01-current-architecture.md"]
---

## Goal

Implement the only authentication path the product has (D3, D16): the OAuth 2.0
Device Authorization Grant against the single published App, using a public
`client_id` compiled into the binary, with no client secret, no redirect
listener, and no server anywhere in the design.

## Scope & seams

Owns `crates/github/src/device_flow.rs` and the shared authenticated HTTP
client the rest of the crate builds on.

**Device flow.** Start with `client_id` only; surface the verification URL and
user code for display; poll to completion. Handle the full documented error
matrix as distinct, testable outcomes, not as one generic failure:
`authorization_pending` (keep polling at the given interval), `slow_down`
(increase the interval as instructed), `expired_token` (restart required),
`access_denied` (user refused — terminal, and not an error to retry).

**Token semantics.** The published App opts **out** of user-token expiration
(`01-current-architecture.md`), so the returned user access token does not
expire, there is no refresh token, and there is nothing to renew. Do not build
a refresh path; refreshing a user token requires the client secret, and adding
one would put a server back into the design. Revocation happens at GitHub when
the user uninstalls the App or revokes the authorization.

**Storage boundary.** This crate **returns** the token and never persists it.
The machine-scoped secret store is `d2`; wiring is `f1`. Keeping the gateway
storage-free is what lets it be tested with no platform dependency.

**Installation discovery.** Query the repositories and organizations the App is
installed on for the authenticated user, so `auth status` can show which
targets the token can actually reach — an over-broad installation must be
visible rather than assumed (`07-security.md`). Provide the canonical
installation URL for a user with no installation yet.

**Shared client.** Every `api.github.com` request sets `X-GitHub-Api-Version`
and an explicit `Accept` header. Implement the auth-failure taxonomy here once,
because `c3` and `f1` both depend on the distinction: a `401` triggers exactly
one refresh attempt under a single-flight mutex and one retry, while a `403`
following repeated `401`s is GitHub's **temporary authentication lockout** and
must back off without further attempts and be reported distinctly from
`authentication_failed` (`03-control-flows.md`, flow 4.3).

**Phishing control.** Print the canonical `github.com/login/device` URL. Never
proxy, embed, or imitate the approval page.

**Redaction.** The user code is displayed by design and only during login. The
device code, the token, and every header carrying either are absent from logs,
errors, and diagnostics.

## Definition of Done

- A device-flow round trip against fixtures succeeds, and each of
  `authorization_pending`, `slow_down`, `expired_token`, and `access_denied`
  produces its own distinct, asserted outcome — with `slow_down` demonstrably
  increasing the poll interval.
- No refresh-token code path exists, and no client secret appears anywhere in
  the crate or its configuration.
- The crate persists nothing: it has no dependency on `crates/platform` and no
  filesystem write in its non-test code.
- Installation discovery returns the reachable repository and organization set,
  and returns the installation URL when the set is empty.
- A `401` triggers exactly one single-flight refresh-and-retry; concurrent
  callers hitting `401` together produce **one** attempt, not N.
- A `403` after repeated `401`s is surfaced as an authentication *lockout*,
  distinct from `authentication_failed`, and backs off without retrying.
- A secret-injection log scan over the full flow finds no device code, no
  token, and no `Authorization` header value.
