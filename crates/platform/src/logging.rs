// owner: d1-platform-core

//! The structured log sink, and the redaction that is not optional.
//!
//! `07-security.md`'s threat table, on *"Logs disclose repository secrets"*:
//! **"Structured allowlist logging with unconditional redaction of tokens,
//! headers, JIT blobs, and paths."** Its security gate is a *secret-injection
//! log scan*, and its release gate is that *"the user access token and the
//! encoded JIT configuration are absent from logs, databases, snapshots, crash
//! reports, and CLI output"*.
//!
//! # Allowlist, not denylist — and why that is the whole design
//!
//! A denylist redacts the fields somebody remembered to name. It is correct on
//! the day it is written and wrong on the day a later task adds a field, which
//! is the day it matters. So this sink inverts the default: **a field whose
//! name is not in [`ALLOWED_FIELDS`] has its value replaced outright.** A task
//! that adds `runner_token` to a log call gets `[redacted]` with no review, no
//! ceremony, and no leak. Adding a field to the allowlist is a deliberate edit
//! to this file that shows up in a diff.
//!
//! The field name itself is kept. Knowing that an event carried a
//! `runner_token` field is useful, and the name is not the secret.
//!
//! # Two layers, because one is not enough
//!
//! The allowlist protects *fields*. It cannot protect the message body, which
//! has to be allowed or the logs say nothing — and a message body is exactly
//! where a secret ends up when somebody writes
//! `info!("failed with {authorization}")`. So every string that survives the
//! allowlist is then scrubbed by value shape ([`redact`]): GitHub token
//! prefixes, credential header names, long opaque runs such as an encoded JIT
//! configuration, and filesystem paths.
//!
//! Scrubbing by shape over-redacts, deliberately. Some of that is worth knowing
//! about before it surprises somebody:
//!
//! - A slash-rooted word is treated as a filesystem path, and a URL *path* on
//!   its own looks exactly like one. Log a full URL — `https://api.github.com/…`
//!   — and it survives intact; log a bare `/repos/owner/repo` and it becomes
//!   `[path]`.
//! - Any unbroken run of 40 or more base64, base64url, or hex characters is
//!   treated as an opaque secret. There is exactly one carve-out: a value that
//!   is precisely 64 lowercase hex characters is a SHA-256 digest, and renders
//!   as a labelled 12-character prefix rather than disappearing. A digest is
//!   not a secret, and `07-security.md` makes checksum verification a security
//!   gate whose most useful diagnostic is expected-versus-actual.
//! - A JSON Web Token is redacted whole. Its `.` separators split it into runs
//!   the opaque-run rule is too short-sighted to catch, so it is recognised by
//!   shape instead: two or three base64url segments whose header begins `eyJ`.
//! - A URL keeps its scheme, host and path and loses everything that
//!   authenticates it: the `user:password@` userinfo, the query string, and the
//!   fragment. The userinfo matters more than it looks — a
//!   token-authenticated git remote is
//!   `https://x-access-token:ghu_…@github.com/owner/repo.git`, so it is the
//!   shape a clone or fetch failure arrives in.
//! - A word ending in `:` or `=` whose stem is a credential header name causes
//!   the next two words to be redacted, so `Authorization: Bearer ghu_…` loses
//!   both the scheme and the token.
//!
//! A word is cut on structural punctuation — `,`, `{`, `}`, `[`, `]` and `&` —
//! before any of that runs, and each fragment is judged on its own. Without
//! that cut only the *first* key/value pair in a compact structure is ever
//! examined, and redaction becomes a function of field order:
//! `{"encoded_jit_config":"…"}` was caught and
//! `{"runner_id":42,"encoded_jit_config":"…"}` was not, while
//! `serde_json::to_string` is what decides which of the two an error body is.
//! Nesting and a form-encoded body were the same defect in different
//! punctuation.
//!
//! A key is also trimmed of backslashes, which a value never is: `Debug` on a
//! `String` escapes the quotes inside it, so a body reached through
//! `error!(reason = ?err)` spells its keys `\"password\"`. The `trim_key`
//! function documents why the same trim must not be applied to a value; it is
//! named rather than linked because it is private and this module's
//! documentation is not.
//!
//! Every one of those is a case where being wrong costs a slightly less
//! readable log line, against a case where being wrong the other way costs a
//! disclosed credential.
//!
//! # What this does not do
//!
//! It does not stop a caller printing to standard output, and it does not
//! redact a `Debug` derive somewhere else in the program. Those are held by
//! different controls: `secrecy::SecretString` for the two values that matter
//! (`07-security.md`'s credential inventory), and
//! [`crate::process::SpawnSpec::spawn_with_handoff`] for the command line.

use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// What replaces a value this sink will not emit.
pub const REDACTION: &str = "[redacted]";

/// What replaces something that was recognisably a filesystem path. Distinct
/// from [`REDACTION`] so a reader can tell "a path was here" from "a secret was
/// here" without either being disclosed.
pub const PATH_REDACTION: &str = "[path]";

/// The field names this sink emits verbatim. Everything else is replaced with
/// [`REDACTION`].
///
/// ---
///
/// **Read this before adding a name.** A field on this list still passes
/// through [`redact`], so adding one does not switch redaction off — but it
/// does mean the field's value reaches the scrubber instead of being discarded,
/// and the scrubber only recognises shapes it was taught. Add a name only when
/// the value is structurally incapable of carrying a credential: an
/// identifier, an enumerated state, a count, a duration. Never add a name whose
/// value is free text supplied by GitHub or by a workflow.
///
/// Kept sorted, and a test enforces that, so an addition is one line in a diff
/// rather than a name buried in the middle of a list.
pub const ALLOWED_FIELDS: &[&str] = &[
    "arch",
    "attempt",
    "attempt_id",
    "attempt_state",
    "capacity",
    "count",
    "demand",
    "desired",
    "duration_ms",
    "elapsed_ms",
    "error_kind",
    "event",
    "exit_code",
    "headroom",
    "host_id",
    "http_status",
    "installation_id",
    "job_id",
    "label",
    "lock",
    "message",
    "mode",
    "os",
    "outcome",
    "pid",
    "policy_id",
    "policy_state",
    "reason",
    "retry_in_ms",
    "runner_id",
    "scope",
    "start_mode",
    "state",
    "target",
    "version",
];

/// Header and parameter names whose value is a credential.
///
/// Compared case-insensitively with `-` and `_` treated as the same character,
/// because the same header arrives as `Authorization`, `authorization`, and
/// `x_api_key` depending on who wrote the line.
const CREDENTIAL_KEYS: &[&str] = &[
    "access.token",
    "api.key",
    "apikey",
    "auth",
    "authorization",
    "client.secret",
    "cookie",
    "credential",
    "encoded.jit.config",
    "jit",
    "jit.config",
    "jitconfig",
    "password",
    "private.token",
    "proxy.authorization",
    "refresh.token",
    "secret",
    "set.cookie",
    "token",
    "www.authenticate",
    "x.api.key",
    "x.auth.token",
    "x.github.token",
    "x.hub.signature",
    "x.hub.signature.256",
];

/// Authentication scheme words. Whatever follows one of these is the
/// credential.
const SCHEME_WORDS: &[&str] = &["basic", "bearer", "digest", "negotiate", "token"];

/// Prefixes GitHub gives its credentials. Present as a belt on top of the
/// opaque-run rule below, because a short-lived or truncated token can be under
/// the length threshold while still being a live credential.
const TOKEN_PREFIXES: &[&str] = &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "gh_"];

/// How long an unbroken run of opaque characters has to be before it is assumed
/// to be a secret.
///
/// 40 rather than something shorter so that ordinary identifiers, hyphenated
/// words, and UUIDs (36 characters, and not secret) survive; short enough that
/// every GitHub credential format and every encoded JIT configuration is well
/// past it.
const OPAQUE_RUN_THRESHOLD: usize = 40;

/// Characters that make up base64, base64url, and hex.
fn is_opaque_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// Punctuation that may wrap a value without being part of it.
const WRAPPERS: &[char] = &[
    '"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',', ';', '.', '!', '?',
];

/// Punctuation that separates one key/value pair from the next *inside* a
/// single whitespace-delimited word.
///
/// [`redact_core`] judges a fragment by splitting it once, on the first `=` or
/// `:` it finds. That is enough for `key=value` and for a one-field object,
/// and it is why every shape this module was tested against put the credential
/// in the first pair. It is not enough for anything `serde_json::to_string`
/// actually emits: a struct with two fields becomes
/// `{"runner_id":42,"encoded_jit_config":"…"}`, where the only pair ever
/// examined is `runner_id`. Nesting is the same defect one level down, and a
/// form-encoded body is the same defect spelled with `&`.
///
/// So a word is cut on these before any of that runs, and each fragment is
/// judged on its own. The separators go back verbatim, because the structure
/// around a redaction is what keeps the line diagnosable.
const STRUCTURAL: &[char] = &[',', '{', '}', '[', ']', '&'];

/// Whether this sink will emit a field's value rather than replacing it.
#[must_use]
pub fn is_field_allowed(name: &str) -> bool {
    ALLOWED_FIELDS.binary_search(&name).is_ok()
}

/// Trims the punctuation a *key* can arrive wrapped in: [`WRAPPERS`], plus the
/// backslash.
///
/// The backslash is here rather than in [`WRAPPERS`] on purpose, and the
/// distinction is load-bearing in both directions.
///
/// It has to be trimmed somewhere. `tracing::error!(reason = ?err)` reaches
/// this module through `record_debug` and `format!("{:?}")`, and `Debug` on a
/// `String` escapes the quotes inside it — so an error whose `Debug` embeds an
/// HTTP body arrives with its keys spelled `\"password\"`. Trimming only
/// [`WRAPPERS`] leaves the backslash welded on, and `\"password\` is on no
/// list. That is `d2`'s shape: a secret-store failure carrying the body it was
/// handed.
///
/// It must not be trimmed unconditionally. [`split_wrappers`] runs before
/// [`looks_like_path`], so a `\` in [`WRAPPERS`] would strip the leading
/// `\\` that UNC detection keys on, and `\\server\share` would stop being
/// recognised as a path. A key is the one place a backslash can never be part
/// of the value, so it is the one place the trim is unconditional;
/// [`trim_start_wrappers`] takes the same backslash off a *value* only when it
/// is escaping punctuation.
fn trim_key(key: &str) -> &str {
    key.trim()
        .trim_matches(|c: char| c == '\\' || WRAPPERS.contains(&c))
}

fn normalise_key(key: &str) -> String {
    trim_key(key).to_ascii_lowercase().replace(['-', '_'], ".")
}

fn is_credential_key(key: &str) -> bool {
    let key = normalise_key(key);
    CREDENTIAL_KEYS.contains(&key.as_str())
}

fn is_scheme_word(word: &str) -> bool {
    SCHEME_WORDS.contains(&word.to_ascii_lowercase().as_str())
}

/// Scrubs a string of anything that looks like a credential, an encoded JIT
/// configuration, or a filesystem path.
///
/// Applied to every string this sink emits, including the ones whose field name
/// is on [`ALLOWED_FIELDS`]. Also public so that the TUI and the CLI can put a
/// value through the same rules before showing it, rather than inventing a
/// second, differently wrong set.
#[must_use]
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    // How many upcoming words to replace outright, because a credential key or
    // an authentication scheme word said the value comes next.
    let mut pending: u32 = 0;

    for chunk in text.split_inclusive(char::is_whitespace) {
        let (word, whitespace) = split_trailing_whitespace(chunk);

        if word.is_empty() {
            out.push_str(whitespace);
            continue;
        }

        if pending > 0 {
            pending -= 1;
            out.push_str(REDACTION);
            out.push_str(whitespace);
            // A header value ends at a comma or semicolon; anything after that
            // is the next header's name and is not a secret.
            if word.ends_with([',', ';']) {
                pending = 0;
            }
            continue;
        }

        let (rendered, follow_on) = redact_word(word);
        out.push_str(&rendered);
        out.push_str(whitespace);
        pending = follow_on;
    }

    out
}

/// Splits a chunk produced by `split_inclusive` into its word and the single
/// whitespace character that terminated it, if any.
fn split_trailing_whitespace(chunk: &str) -> (&str, &str) {
    match chunk.char_indices().next_back() {
        Some((index, last)) if last.is_whitespace() => chunk.split_at(index),
        _ => (chunk, ""),
    }
}

/// Splits a fragment into its leading wrapping punctuation, its core, and its
/// trailing wrapping punctuation.
///
/// Shared by [`redact_word`] and [`redact_core`], because both have to judge a
/// fragment on its core while emitting it with its punctuation intact.
///
/// [`WRAPPERS`], and an *escaped* quote as well. Escaped text is exactly what
/// a `Debug` rendering of a string is, and in it every quote arrives with a
/// backslash welded on — so a value spelled `\"ghu_…\"` is wrapped in the
/// same way `"ghu_…"` is, and none of the shape rules can see the token until
/// the wrapper comes off. Trimming the key alone is not enough: `runner_token`
/// is deliberately *not* on [`CREDENTIAL_KEYS`], because a name is not what
/// makes a value a secret, so that pair is caught by the token-prefix rule
/// reading its value or it is not caught at all.
fn split_wrappers(fragment: &str) -> (&str, &str, &str) {
    let leading = fragment.len() - trim_start_wrappers(fragment).len();
    let (prefix, rest) = fragment.split_at(leading);
    let core_len = trim_end_wrappers(rest).len();
    let (core, suffix) = rest.split_at(core_len);
    (prefix, core, suffix)
}

/// Trims wrapping punctuation from the front of a fragment.
///
/// A backslash counts as punctuation **only when it escapes punctuation**, and
/// that restriction is the whole of what keeps this safe. `\"value` is a
/// quoted value spelled the way an escaped rendering spells it, and the
/// backslash is not part of the value. `\\server\share` is a UNC path whose
/// leading backslashes escape nothing and *are* the value — trimming them is
/// exactly what would stop [`looks_like_path`] recognising it, and this runs
/// before [`looks_like_path`] does. `\\` is not a backslash-escaping-a-
/// wrapper, so the two cases separate cleanly.
fn trim_start_wrappers(fragment: &str) -> &str {
    let mut rest = fragment;
    loop {
        let trimmed = rest.trim_start_matches(WRAPPERS);
        let trimmed = match trimmed.strip_prefix('\\') {
            Some(after) if after.starts_with(WRAPPERS) => after,
            _ => trimmed,
        };
        if trimmed.len() == rest.len() {
            return rest;
        }
        rest = trimmed;
    }
}

/// Trims wrapping punctuation from the end of a fragment.
///
/// A trailing backslash goes with it, and needs no adjacency test: trimming
/// runs right to left, so a backslash that has reached the end is one whose
/// quote has already been taken off. A path that ends in a separator is still
/// a path without it.
fn trim_end_wrappers(fragment: &str) -> &str {
    let mut rest = fragment;
    loop {
        let trimmed = rest.trim_end_matches(WRAPPERS).trim_end_matches('\\');
        if trimmed.len() == rest.len() {
            return rest;
        }
        rest = trimmed;
    }
}

/// Redacts one whitespace-delimited word, and says how many following words the
/// word implicates.
fn redact_word(word: &str) -> (String, u32) {
    // Wrapping punctuation is kept so that JSON-ish and prose context survives
    // — `("ghu_…")` should become `("[redacted]")`, not `[redacted]`.
    let (prefix, core, suffix) = split_wrappers(word);

    if core.is_empty() {
        return (word.to_string(), 0);
    }

    // A bare credential key or scheme word: the value is the next word.
    //
    // The stem is unwrapped before it is judged: spaced JSON writes the key as
    // `"password":`, which leaves `password"` welded to a quote, and that is on
    // no list. A long value survived this anyway by way of the opaque-run rule,
    // so the gap only ever showed on a short one.
    let stem = core.trim_end_matches([':', '=']);
    if stem.len() < core.len() && is_credential_key(stem) {
        // Two, so that `Authorization: Bearer <token>` loses the scheme and the
        // token rather than only the scheme.
        return (word.to_string(), 2);
    }
    if is_scheme_word(core) {
        return (word.to_string(), 1);
    }

    (format!("{prefix}{}{suffix}", redact_core(core)), 0)
}

/// Redacts one word with its wrapping punctuation already removed.
fn redact_core(core: &str) -> String {
    // A URL survives, minus everything on it that carries a credential. The
    // scheme, host and path are what makes a log line diagnosable.
    if let Some((scheme, rest)) = core.split_once("://") {
        return redact_url(scheme, rest);
    }

    // A Windows drive path is `key:value`-shaped by accident, and
    // `looks_like_path` only recognises the drive letter at position zero.
    // Splitting such a path on its colon would hand the tail to a rule that
    // matches nothing, so it has to be judged whole, before the separators
    // get at it.
    if looks_like_path(core) {
        return PATH_REDACTION.to_string();
    }

    // A compact structure holds more than one key/value pair, and the rules
    // below examine exactly one of them: `split_once` stops at the first
    // separator it finds. So `{"encoded_jit_config":"…"}` was caught and
    // `{"runner_id":42,"encoded_jit_config":"…"}` was not — the two differ by
    // field order and by nothing else, and `serde_json::to_string` is what
    // chooses the order. Nesting was the same defect: the value recursion
    // below ends at `redact_value`, which is a leaf and never comes back
    // here, so an object inside an object went out whole. A form-encoded body
    // was the same defect again, with `&` as a separator nothing knew.
    //
    // Cutting on [`STRUCTURAL`] first turns all three into the shape the rules
    // already handle, and does it at any depth: the cut is flat, so
    // `{"a":{"b":{"token":"…"}}}` yields the same fragments a one-level object
    // would. A fragment contains no structural character by construction, so
    // this recurses exactly one level and cannot loop.
    if core.contains(STRUCTURAL) {
        let mut out = String::with_capacity(core.len());
        let mut rest = core;
        while let Some(index) = rest.find(STRUCTURAL) {
            let (fragment, tail) = rest.split_at(index);
            if !fragment.is_empty() {
                out.push_str(&redact_core(fragment));
            }
            // Every character in `STRUCTURAL` is ASCII, so the separator is
            // one byte and this cannot split a code point.
            out.push_str(&tail[..1]);
            rest = &tail[1..];
        }
        if !rest.is_empty() {
            out.push_str(&redact_core(rest));
        }
        return out;
    }

    // `key=value` and `key:value` in a single fragment.
    //
    // Pass one asks only whether either separator names a credential, and it
    // runs to completion before any value is inspected, because the *first*
    // separator in a fragment is not necessarily the structural one. A base64
    // payload carries `=` padding, and what follows that padding decides
    // whether one pass would have done.
    //
    // `{"encoded_jit_config":"eyJ…In0="}` on its own is *not* that case, and
    // this comment used to claim it was. Base64 padding is trailing-only, so
    // the `=` split yields an empty value and the `value.is_empty()` guard in
    // pass two already falls through to the `:`. The case that genuinely needs
    // two passes is a **multi-field** object, where the text after the padding
    // is not empty: `{"encoded_jit_config":"eyJ…In0=","runner_id":42}` is cut
    // on `,` above into a fragment still ending `…In0="`, so the `=` split
    // hands back a value of `"` — non-empty, inspected, found innocent, and
    // returned before the `:` that names the key is ever reached.
    //
    // Both halves are judged through `trim_key`: compact JSON welds a quote to
    // each, so the key arrives as `encoded_jit_config"`, and a `Debug`
    // rendering welds a backslash as well.
    for separator in ['=', ':'] {
        if let Some((key, _)) = core.split_once(separator)
            && is_credential_key(key)
        {
            return format!("{key}{separator}{REDACTION}");
        }
    }

    // Pass two: not a credential key, but the value may still be a path or a
    // token: `runtime=/var/lib/runner-manager/…`. Applied to `:` as well as
    // to `=`, because `:` is what compact JSON and a bare `key:value` use,
    // and recursing for `=` alone is what let an encoded JIT configuration
    // and a `runner_token:ghu_…` pair through verbatim.
    for separator in ['=', ':'] {
        if let Some((key, raw_value)) = core.split_once(separator) {
            let (lead, value, trail) = split_wrappers(raw_value);
            if value.is_empty() {
                continue;
            }
            let redacted = redact_value(value);
            // `as_sha256_digest` re-attaches its own `sha256:` label, so an
            // already-labelled digest would come back doubled as
            // `sha256:sha256:9f86d081884c…`. Dropping the redundant label
            // keeps the caller's own key and separator, and leaves the digest
            // truncated -- which the unrecursed `:` path never did, and which
            // is worth having, because an HMAC-SHA256 signature has exactly a
            // digest's shape and was previously printed in full.
            if trim_key(key).eq_ignore_ascii_case("sha256")
                && let Some(bare) = redacted.strip_prefix("sha256:")
            {
                return format!("{key}{separator}{lead}{bare}{trail}");
            }
            return format!("{key}{separator}{lead}{redacted}{trail}");
        }
    }

    redact_value(core)
}

/// Redacts the three places a URL can carry a credential, keeping the rest.
///
/// `scheme` is everything before `://` and `rest` everything after it.
///
/// The **userinfo** is the one this module used to miss, and it is not an
/// exotic shape: `https://x-access-token:ghu_…@github.com/owner/repo.git` is
/// the canonical token-authenticated git remote, so it is what `e2` and `e3`
/// will have in hand when a clone or a download fails and they log the error
/// they were given. The old `://` branch returned before the token-prefix and
/// opaque-run rules could run, so that URL came out intact.
///
/// A **fragment** is stripped for the same reason a query string is: an OAuth
/// implicit-flow response puts the token after the `#`, and the fragment is
/// never load-bearing for diagnosing an HTTP call.
fn redact_url(scheme: &str, rest: &str) -> String {
    // The authority runs to the first `/`, `?` or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);

    // `rsplit_once`, not `split_once`: a password may itself contain an `@`,
    // and the host is what follows the *last* one.
    let host = match authority.rsplit_once('@') {
        // Replaced rather than deleted. That the request carried credentials at
        // all is diagnostic — it is often the answer to "why did this 401?" —
        // and it is the credential, not its existence, that must not be here.
        Some((_userinfo, host)) => format!("{REDACTION}@{host}"),
        None => authority.to_string(),
    };

    // Whichever of `?` and `#` comes first ends the diagnosable part; anything
    // after it is replaced wholesale rather than parsed, because a token can be
    // in any parameter and this module does not guess which.
    match tail.find(['?', '#']) {
        Some(cut) => {
            let (path, query) = tail.split_at(cut);
            let separator = &query[..1];
            format!("{scheme}://{host}{path}{separator}{REDACTION}")
        }
        None => format!("{scheme}://{host}{tail}"),
    }
}

/// The shape rules, applied to a bare value.
fn redact_value(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if TOKEN_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return REDACTION.to_string();
    }

    if looks_like_path(value) {
        return PATH_REDACTION.to_string();
    }

    // A digest is not a secret, and `07-security.md` makes checksum
    // verification a security gate. The most useful thing `e2` can write when
    // that gate fails is expected-versus-actual, and until this carve-out
    // existed both sides came out as `[redacted]` — a gate that reports it
    // failed and refuses to say how.
    if let Some(digest) = as_sha256_digest(value) {
        return digest;
    }

    if looks_like_jwt(value) {
        return REDACTION.to_string();
    }

    if value.len() >= OPAQUE_RUN_THRESHOLD && value.chars().all(is_opaque_char) {
        return REDACTION.to_string();
    }

    value.to_string()
}

/// The length of a SHA-256 digest written as lowercase hex.
const SHA256_HEX_LEN: usize = 64;

/// How much of a digest is shown.
///
/// 12 is the short-digest convention git and the OCI tooling use: 48 bits, far
/// more than enough to tell an expected digest from the one that was actually
/// computed, which is the only comparison a checksum failure needs. Truncating
/// is also what makes this carve-out safe to have at all — a 64-character
/// lowercase hex run is *usually* a digest, but an HMAC-SHA256 signature has
/// the same shape, and 12 of its 64 characters are of no use to anybody.
const DIGEST_PREFIX_LEN: usize = 12;

/// Renders a value that is exactly a lowercase SHA-256 digest as a labelled
/// prefix, or `None` when it is not one.
///
/// Deliberately strict: exactly 64 characters, and lowercase only. An uppercase
/// or mixed-case run falls through to the opaque-run rule and is redacted,
/// because the narrower this exception is, the less there is to reason about.
fn as_sha256_digest(value: &str) -> Option<String> {
    let is_digest = value.len() == SHA256_HEX_LEN
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() && c.is_ascii_hexdigit());

    is_digest.then(|| format!("sha256:{}…", &value[..DIGEST_PREFIX_LEN]))
}

/// The most `.`-separated segments a JSON Web Token has: header, payload,
/// signature.
const JWT_SEGMENTS: usize = 3;

/// Whether a value is a JSON Web Token.
///
/// The opaque-run rule cannot see one. [`is_opaque_char`] excludes `.`, and a
/// JWT is base64url runs joined by two of them, so a 100-character credential
/// arrives as three runs that are each under the threshold and prints
/// verbatim. `Authorization: Bearer <jwt>` is caught by the scheme-word rule
/// and a credential-keyed one by the key rule, so this only ever bit a token
/// logged bare or under a name nobody listed — which is what a GitHub App
/// installation assertion is when it reaches a log at all.
///
/// Narrow deliberately, because the obvious fix is the wrong one: adding `.`
/// to [`is_opaque_char`] would swallow every long dotted word there is —
/// package names, dated filenames, dotted identifiers. A JWT header is
/// base64url of `{"alg":…`, which always begins `eyJ`, and that is a
/// discriminator ordinary text does not have.
fn looks_like_jwt(value: &str) -> bool {
    if value.len() < OPAQUE_RUN_THRESHOLD || !value.starts_with("eyJ") {
        return false;
    }

    let mut segments = 0usize;
    for segment in value.split('.') {
        segments += 1;
        if !segment.chars().all(is_opaque_char) {
            return false;
        }
    }

    // Two segments as well as three: an unsigned token has an empty signature,
    // and the trailing `.` that would have made the third is trimmed as
    // wrapping punctuation before this is reached.
    (2..=JWT_SEGMENTS).contains(&segments)
}

fn looks_like_path(value: &str) -> bool {
    let bytes = value.as_bytes();

    // `C:\Users\…` and `C:/Users/…`.
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }

    // `\\server\share\…`.
    if value.starts_with("\\\\") {
        return true;
    }

    // `~/…`.
    if value.starts_with("~/") || value.starts_with("~\\") {
        return true;
    }

    // `/var/lib/…`. Two segments required, so a lone `/` and a bare `/tmp`
    // stay readable; see the module documentation for why a URL path is caught
    // by this too.
    if let Some(rest) = value.strip_prefix('/') {
        return rest.contains('/') && !rest.is_empty();
    }

    false
}

// ---------------------------------------------------------------------------
// The tracing layer
// ---------------------------------------------------------------------------

/// The redacted fields recorded on a span, stashed in the span's extensions so
/// that an event inside the span can carry them.
#[derive(Debug, Clone)]
struct SpanFields(Map<String, Value>);

/// Collects a `tracing` record into JSON, applying the allowlist and the
/// scrubber as it goes.
#[derive(Debug, Default)]
struct RedactingVisitor {
    fields: Map<String, Value>,
}

impl RedactingVisitor {
    fn put_str(&mut self, name: &str, value: &str) {
        let rendered = if is_field_allowed(name) {
            redact(value)
        } else {
            REDACTION.to_string()
        };
        self.fields
            .insert(name.to_string(), Value::String(rendered));
    }

    fn put_value(&mut self, name: &str, value: Value) {
        if is_field_allowed(name) {
            self.fields.insert(name.to_string(), value);
        } else {
            // Numbers and booleans go the same way as strings. A credential is
            // never an `i64`, but the rule that makes this sink trustworthy is
            // that it has *no* exception for a name nobody listed.
            self.fields
                .insert(name.to_string(), Value::String(REDACTION.to_string()));
        }
    }
}

impl Visit for RedactingVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put_str(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // The event message arrives here, as `format_args!` output.
        self.put_str(field.name(), &format!("{value:?}"));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put_str(field.name(), &value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put_value(field.name(), Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put_value(field.name(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put_value(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put_value(field.name(), Value::from(value));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put_str(field.name(), &value.to_string());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put_str(field.name(), &value.to_string());
    }
}

/// A `tracing` layer that writes one redacted JSON object per event.
///
/// Written here rather than assembled from `tracing_subscriber::fmt` because
/// redaction has to happen *before* formatting, and a `tracing::Event`'s fields
/// cannot be rewritten for a downstream formatter to pick up. Owning the
/// formatting is what makes "unconditional" true: there is no path from an
/// event to the output that does not go through
/// [`RedactingVisitor`].
#[derive(Debug, Clone)]
pub struct RedactingLayer<W> {
    writer: W,
}

impl<W> RedactingLayer<W> {
    /// Wraps a writer factory — a file appender, a capture buffer, or
    /// `std::io::stderr`.
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<S, W> Layer<S> for RedactingLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut visitor = RedactingVisitor::default();
        attrs.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(visitor.fields));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        let mut visitor = RedactingVisitor::default();
        values.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(existing) = extensions.get_mut::<SpanFields>() {
                existing.0.extend(visitor.fields);
            } else {
                extensions.insert(SpanFields(visitor.fields));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = RedactingVisitor::default();
        event.record(&mut visitor);

        let mut record = Map::new();
        record.insert(
            "timestamp".to_string(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
        record.insert(
            "level".to_string(),
            Value::String(event.metadata().level().to_string()),
        );
        // Named `logger` and not `target`: `target` is also a domain field —
        // the repository or organization a policy points at — and two different
        // things under one key is how a diagnostic becomes a puzzle.
        record.insert(
            "logger".to_string(),
            Value::String(event.metadata().target().to_string()),
        );
        record.insert("fields".to_string(), Value::Object(visitor.fields));

        let spans: Vec<Value> = ctx
            .event_scope(event)
            .into_iter()
            .flat_map(tracing_subscriber::registry::Scope::from_root)
            .map(|span| {
                let mut entry = Map::new();
                entry.insert("name".to_string(), Value::String(span.name().to_string()));
                if let Some(fields) = span.extensions().get::<SpanFields>() {
                    entry.insert("fields".to_string(), Value::Object(fields.0.clone()));
                }
                Value::Object(entry)
            })
            .collect();
        if !spans.is_empty() {
            record.insert("spans".to_string(), Value::Array(spans));
        }

        let mut line = serde_json::to_string(&Value::Object(record)).unwrap_or_else(|_| {
            String::from(
                r#"{"level":"ERROR","fields":{"message":"a log record could not be encoded"}}"#,
            )
        });
        line.push('\n');

        // A failed write to the diagnostics file must not take the agent down,
        // and must not be reported through `tracing` either — that would
        // recurse straight back into this method.
        let mut writer = self.writer.make_writer();
        let _ = writer.write_all(line.as_bytes());
        let _ = writer.flush();
    }
}

// ---------------------------------------------------------------------------
// Installing the sink
// ---------------------------------------------------------------------------

/// The sink could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// The application-data directories could not be created.
    ///
    /// Carries a [`crate::paths::PathsError`] rather than a bare
    /// [`std::io::Error`] because [`install`] creates `logs/` through
    /// [`crate::paths::AppPaths::create_all`], which is what applies the `0700`
    /// restriction; the source therefore names whichever of the four
    /// directories actually failed, and that need not be `logs/`.
    #[error("cannot create the log directory {}: {source}", directory.display())]
    Directory {
        /// The diagnostics directory [`install`] was asked to write into.
        directory: PathBuf,
        /// The underlying error.
        #[source]
        source: crate::paths::PathsError,
    },

    /// A global subscriber was already installed.
    #[error("a tracing subscriber is already installed for this process: {message}")]
    AlreadyInstalled {
        /// What `tracing_subscriber` said.
        message: String,
    },
}

/// Keeps the background log-writing thread alive.
///
/// Dropping it flushes and stops that thread, so the value must be held for as
/// long as the program expects its diagnostics to be written. Losing it is a
/// silent, total loss of logs, which is why it is `#[must_use]`.
#[must_use = "dropping the guard stops the log writer and silently discards later diagnostics"]
#[derive(Debug)]
pub struct LoggingGuard {
    _worker: tracing_appender::non_blocking::WorkerGuard,
}

/// Installs the redacting sink as this process's global subscriber, writing
/// daily-rotating files into `logs/`.
///
/// `default_filter` applies when `RUST_LOG` is unset or unparseable.
///
/// # Errors
///
/// [`LoggingError::Directory`] and [`LoggingError::AlreadyInstalled`].
pub fn install(
    paths: &crate::paths::AppPaths,
    default_filter: &str,
) -> Result<LoggingGuard, LoggingError> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    // `AppPaths::create_all`, not `create_dir_all`. The claim `create_all`
    // documents — that a diagnostics file is not readable by other local
    // accounts — is only true if `logs/` is created at `0700`, and this is the
    // path a running daemon actually takes. Creating the directory here with a
    // bare `create_dir_all` left it at the umask default whenever `install`
    // won the race to create it, and `tracing_appender` then wrote 0644 files
    // into it: the invariant held in the test that asserts it and nowhere else.
    let directory = paths.logs_dir().to_path_buf();
    paths
        .create_all()
        .map_err(|source| LoggingError::Directory {
            directory: directory.clone(),
            source,
        })?;

    let appender = tracing_appender::rolling::daily(&directory, "runner-manager.log");
    let (writer, worker) = tracing_appender::non_blocking(appender);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));

    tracing_subscriber::registry()
        .with(filter)
        .with(RedactingLayer::new(writer))
        .try_init()
        .map_err(|error| LoggingError::AlreadyInstalled {
            message: error.to_string(),
        })?;

    Ok(LoggingGuard { _worker: worker })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::SubscriberExt as _;

    // -----------------------------------------------------------------------
    // Capturing what the sink actually wrote
    // -----------------------------------------------------------------------

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("not poisoned")).into_owned()
        }
    }

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("not poisoned").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = CaptureWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureWriter(Arc::clone(&self.0))
        }
    }

    /// A sink with the same plumbing and no redaction at all.
    ///
    /// Exists so that `the_scan_catches_a_sink_that_does_not_redact` can prove
    /// the secret-injection scan below is capable of failing. Without it, a scan
    /// that found nothing would be indistinguishable from a scan that looked
    /// nowhere.
    #[derive(Debug, Clone)]
    struct PassthroughLayer<W>(W);

    #[derive(Default)]
    struct PassthroughVisitor(Map<String, Value>);

    impl Visit for PassthroughVisitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0
                .insert(field.name().to_string(), Value::String(value.to_string()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.0.insert(
                field.name().to_string(),
                Value::String(format!("{value:?}")),
            );
        }
    }

    impl<S, W> Layer<S> for PassthroughLayer<W>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + 'static,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = PassthroughVisitor::default();
            event.record(&mut visitor);
            let mut line = serde_json::to_string(&Value::Object(visitor.0)).unwrap_or_default();
            line.push('\n');
            let _ = self.0.make_writer().write_all(line.as_bytes());
        }
    }

    // -----------------------------------------------------------------------
    // The secret-injection log scan (`07-security.md`, security gate)
    // -----------------------------------------------------------------------

    /// A user access token, in GitHub's user-to-server format.
    const USER_TOKEN: &str = "ghu_16C7e42F292c6912E7710c838347Ae178B4a";
    /// An installation-style token, to prove the prefix rule is not one-off.
    const SERVER_TOKEN: &str = "ghs_1CGGYnBAtn5ov3M0aTHhP7l3ZKuMhIB3pnPd";
    /// A fine-grained personal access token.
    const FINE_GRAINED: &str =
        "github_pat_11ABCDEFG0abcdefghijkl_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwv";
    /// Stands in for an encoded JIT configuration: base64, and long.
    const JIT_BLOB: &str = "eyJhZ2VudE5hbWUiOiJydW5uZXItbWFuYWdlciIsImVuY29kZWQiOiJhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz09In0=";
    /// A workspace path, which `07-security.md` also requires redacted.
    const WORKSPACE: &str = "/var/lib/runner-manager/runtime/9f2c/attempt-1";
    /// The same, on the platform the persona is least likely to be using but
    /// the CI matrix definitely is.
    const WINDOWS_WORKSPACE: &str = r"C:\Users\operator\AppData\Local\runner-manager\runtime\9f2c";
    /// A GitHub App installation assertion: a JSON Web Token.
    ///
    /// Its two `.` separators are the point. `is_opaque_char` excludes `.`, so
    /// the opaque-run rule sees three short runs rather than one long one, and
    /// every other secret here is caught by that rule when it stands alone.
    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
                       eyJpc3MiOiIxMjM0NTYiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDYwMH0.\
                       c2lnbmF0dXJlLXRoYXQtaXMtb3BhcXVlLWFuZC1sb25nLWVub3VnaC10by1tYXR0ZXI";

    /// An error whose `Debug` carries the HTTP body it was given.
    ///
    /// This is the shape `d2`'s secret store and `d3`'s installer will hand to
    /// `tracing::error!(reason = ?err)`, and it is not the same shape as any of
    /// the JSON above: `Debug` on a `String` escapes the quotes inside it, so
    /// the keys arrive spelled `\"password\"` rather than `"password"`.
    #[derive(Debug)]
    struct StoreError {
        body: String,
    }

    fn secrets() -> Vec<&'static str> {
        vec![
            USER_TOKEN,
            SERVER_TOKEN,
            FINE_GRAINED,
            JIT_BLOB,
            JWT,
            WORKSPACE,
            WINDOWS_WORKSPACE,
        ]
    }

    /// Routes every secret through `sink` in every shape a caller might use,
    /// and reports the first one that came out the other side.
    ///
    /// A helper returning `Result` rather than a test body, because the same
    /// injection has to be run against a deliberately non-redacting sink to
    /// show that it is capable of finding anything at all.
    fn scan_for_leaks<L>(layer: L, capture: &Capture) -> Result<String, String>
    where
        L: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
    {
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            for secret in secrets() {
                // 1. In the message body, which is the one field that must be
                //    allowed and therefore cannot be protected by the allowlist.
                tracing::info!("starting runner with {secret}");

                // 2. As a credential header in the message body, scheme and all.
                tracing::info!("request failed; Authorization: Bearer {secret}");
                tracing::warn!("retrying with x-api-key={secret}");

                // 3. In a field nobody listed — the case that must be safe with
                //    no edit to this file.
                tracing::info!(runner_token = %secret, "registered");

                // 4. In a field that *is* listed, which is where the allowlist
                //    alone would not save anything.
                tracing::info!(outcome = %secret, event = "started", "registered");
                tracing::info!(message = %secret, "ignored");

                // 5. Through `Debug` rather than `Display`.
                tracing::info!(?secret, "debug shaped");

                // 6. Embedded in a structured value rather than standing
                //    alone. Every shape above presents the secret as its
                //    own whitespace-delimited word, which is the one shape
                //    the opaque-run rule catches for free -- so the scan
                //    could pass while the sink leaked anything embedded.
                //    Compact JSON is what `serde_json::to_string` emits and
                //    what an HTTP error body arrives as, and it was emitted
                //    verbatim: `redact_core` recursed into the value for
                //    `=` only, and the JSON quote left the key spelled
                //    `encoded_jit_config"`, which is not on CREDENTIAL_KEYS.
                for key in ["encoded_jit_config", "runner_token", "pat"] {
                    tracing::error!("registration failed: {{\"{key}\":\"{secret}\"}}");
                    tracing::error!("registration failed: {{ \"{key}\": \"{secret}\" }}");
                    tracing::error!("registration failed: {key}:{secret}");
                }

                // 7. An `Authorization` header value, in the same three
                //    embedded shapes.
                tracing::error!("response: {{\"authorization\":\"Bearer {secret}\"}}");
                tracing::error!("response: {{ \"authorization\": \"Bearer {secret}\" }}");
                tracing::error!("response: authorization:Bearer {secret}");

                // 9. A compact object with **more than one field**, the
                //    credential key second. Shape 6 above differs from this by
                //    field order and by nothing else, and `serde_json::to_string`
                //    is what chooses the order -- so shape 6 could pass while an
                //    error body from a struct with two fields leaked. The rules
                //    split a word once, on the first separator they find, so
                //    only `runner_id` was ever examined.
                for key in ["encoded_jit_config", "runner_token", "access_token"] {
                    tracing::error!(
                        "registration failed: {{\"runner_id\":42,\"{key}\":\"{secret}\"}}"
                    );
                    tracing::error!(
                        "registration failed: {{\"status\":422,\"message\":\"bad\",\"{key}\":\"{secret}\"}}"
                    );
                    // The spaced spelling of the same thing, which was already
                    // safe -- by accident, because the value is its own word.
                    tracing::error!(
                        "registration failed: {{ \"runner_id\": 42, \"{key}\": \"{secret}\" }}"
                    );
                }

                // 10. Nested, one level and two. The value recursion goes to
                //     `redact_value`, which is a leaf and never re-enters
                //     `redact_core`, so an object inside an object was emitted
                //     whole.
                tracing::error!("response: {{\"body\":{{\"runner_token\":\"{secret}\"}}}}");
                tracing::error!(
                    "response: {{\"error\":{{\"status\":422,\"body\":{{\"encoded_jit_config\":\"{secret}\"}}}}}}"
                );

                // 11. A form-encoded body with the credential parameter second.
                //     `&` was not a separator this module knew, so the whole
                //     body was one word and only `scope` was ever judged.
                tracing::error!("token exchange failed: scope=repo&access_token={secret}");
                tracing::error!(
                    "token exchange failed: grant_type=refresh&refresh_token={secret}&scope=repo"
                );

                // 12. Backslash-escaped JSON, through `Debug` rather than
                //     `Display`. Shape 5 is also `Debug`, but it puts the
                //     secret on an *unlisted* field, which is dropped wholesale
                //     -- so the `Debug` lens and the compact-JSON lens were both
                //     here and had never been crossed. `reason` is allowed, so
                //     this one reaches the scrubber, with its keys spelled
                //     `\"runner_token\"`.
                let failure = StoreError {
                    body: format!("{{\"runner_token\":\"{secret}\"}}"),
                };
                tracing::error!(reason = ?failure, "the secret store rejected the request");

                // 8. Carried on a span rather than on the event.
                let span = tracing::info_span!("attempt", jit_config = %secret);
                let _entered = span.enter();
                tracing::info!(event = "inside_span", "in a span");
            }
        });

        let output = capture.text();
        for secret in secrets() {
            for needle in needles(secret) {
                if output.contains(&needle) {
                    return Err(format!(
                        "the sink emitted a secret verbatim: {secret}\n\
                         (found as: {needle})\n--- output ---\n{output}"
                    ));
                }
            }
        }
        Ok(output)
    }

    /// Every spelling a secret can have in the sink's output.
    ///
    /// The sink writes JSON, so a secret containing a character `serde_json`
    /// escapes never appears in the output as it was written. `WINDOWS_WORKSPACE`
    /// is a raw string with single backslashes and is emitted with doubled ones,
    /// so scanning for the literal could not have matched it — not even against
    /// `PassthroughLayer`, which redacts nothing at all. The path really is
    /// redacted, so this was a hole in the coverage rather than a leak, but a
    /// needle that cannot match is a check that cannot fail.
    fn needles(secret: &str) -> Vec<String> {
        // Strip the quotes `to_string` adds; what is left is the text exactly
        // as it appears inside a JSON string literal.
        let escape = |text: &str| {
            let json = serde_json::to_string(text).expect("a string is serialisable");
            json[1..json.len() - 1].to_string()
        };

        let once = escape(secret);
        // Twice, because a secret can be escaped twice on the way out, and
        // shape 12 is where that happens: `Debug` on a `String` escapes the
        // quotes *and* the backslashes inside it, and the sink then
        // JSON-encodes what `Debug` produced. A Windows path arrives in that
        // line with four backslashes where the secret has one, so the
        // once-escaped needle cannot match it there -- not even against
        // `PassthroughLayer`, which redacts nothing at all. That cell of the
        // matrix was a check incapable of failing, which is the same defect
        // this helper was written to fix one level down.
        let twice = escape(&once);

        let mut spellings = vec![secret.to_string(), once, twice];
        // Consecutive-only is enough: each level of escaping is a superset of
        // the last, so equal spellings are always adjacent.
        spellings.dedup();
        spellings
    }

    #[test]
    fn the_scan_looks_for_a_needle_that_can_actually_occur() {
        // Guards the helper above: if `needles` ever stops producing the
        // JSON-escaped spelling, the Windows workspace silently stops being
        // scanned for and every assertion about it becomes vacuous.
        let windows = needles(WINDOWS_WORKSPACE);
        assert_eq!(
            windows.len(),
            3,
            "a backslash path has three spellings, one per level of escaping it \
             can pass through on the way out: {windows:?}"
        );
        assert!(
            windows[1].contains(r"\\Users\\operator"),
            "the once-escaped spelling is what an ordinary JSON line contains: {windows:?}"
        );
        assert!(
            windows[2].contains(r"\\\\Users\\\\operator"),
            "the twice-escaped spelling is what a Debug rendering inside a JSON \
             line contains: {windows:?}"
        );

        // The third spelling is not hypothetical: it is exactly what the sink
        // writes for shape 12, and without it that cell of the scan was a
        // check that could not fail.
        let shape_twelve = serde_json::to_string(&Value::String(format!(
            "{:?}",
            StoreError {
                body: format!("{{\"runner_token\":\"{WINDOWS_WORKSPACE}\"}}"),
            }
        )))
        .expect("serialisable");
        assert!(
            shape_twelve.contains(&windows[2]),
            "the twice-escaped needle must be findable in what shape 12 emits: {shape_twelve}"
        );
        assert!(
            !shape_twelve.contains(&windows[1]),
            "and the once-escaped one must not be, or the gap was never there: {shape_twelve}"
        );

        // Confirms the premise: the raw spelling genuinely cannot occur in the
        // sink's output, which is why scanning only for it proved nothing.
        let rendered = serde_json::to_string(&Value::String(WINDOWS_WORKSPACE.to_string()))
            .expect("serialisable");
        assert!(
            !rendered.contains(WINDOWS_WORKSPACE),
            "if this ever contains the raw path, the original scan was fine after all: {rendered}"
        );
        assert!(rendered.contains(&windows[1]), "{rendered}");

        // A secret with nothing to escape has exactly one spelling.
        assert_eq!(needles(USER_TOKEN), vec![USER_TOKEN.to_string()]);
    }

    #[test]
    fn the_secret_injection_scan_finds_nothing() {
        let capture = Capture::default();
        let output = scan_for_leaks(RedactingLayer::new(capture.clone()), &capture)
            .unwrap_or_else(|complaint| panic!("{complaint}"));

        // Something must have been written, or "no secrets found" is trivially
        // true and means nothing.
        assert!(!output.trim().is_empty(), "the sink wrote nothing at all");
        assert!(
            output.contains(REDACTION),
            "nothing was redacted, so nothing was routed through the sink:\n{output}"
        );
    }

    #[test]
    fn the_scan_catches_a_sink_that_does_not_redact() {
        let capture = Capture::default();
        let complaint = scan_for_leaks(PassthroughLayer(capture.clone()), &capture)
            .expect_err("a sink with no redaction must be caught");
        assert!(
            complaint.contains("emitted a secret verbatim"),
            "the complaint must name the failure mode: {complaint}"
        );
    }

    // -----------------------------------------------------------------------
    // The allowlist
    // -----------------------------------------------------------------------

    fn emit(capture: &Capture, body: impl FnOnce()) -> String {
        let subscriber = tracing_subscriber::registry().with(RedactingLayer::new(capture.clone()));
        tracing::subscriber::with_default(subscriber, body);
        capture.text()
    }

    #[test]
    fn a_field_nobody_listed_is_redacted_by_default() {
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::info!(
                a_field_added_by_a_later_task = "supersecret-value",
                "an event"
            );
        });

        assert!(
            !output.contains("supersecret-value"),
            "an unlisted field leaked its value:\n{output}"
        );
        assert!(output.contains(REDACTION), "{output}");
        // The name survives: knowing the field was there is useful, and a field
        // name is not a credential.
        assert!(
            output.contains("a_field_added_by_a_later_task"),
            "the field name should be kept:\n{output}"
        );
    }

    #[test]
    fn an_unlisted_numeric_field_is_redacted_too() {
        // The rule has no exception for a type, because "a credential is never
        // an integer" is exactly the kind of reasoning that stops being true
        // once somebody logs an installation-scoped identifier they should not.
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::info!(unlisted_number = 8_675_309_u64, "an event");
        });
        assert!(!output.contains("8675309"), "{output}");
        assert!(output.contains(REDACTION), "{output}");
    }

    #[test]
    fn listed_fields_survive() {
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::info!(
                event = "reconciled",
                policy_id = "9f2c1a44-0000-4000-8000-000000000001",
                count = 3,
                outcome = "started",
                "reconciliation finished"
            );
        });

        for expected in [
            "reconciled",
            "9f2c1a44-0000-4000-8000-000000000001",
            "started",
            "reconciliation finished",
        ] {
            assert!(
                output.contains(expected),
                "{expected} missing from:\n{output}"
            );
        }
        assert!(output.contains("\"count\":3"), "{output}");
    }

    #[test]
    fn the_allowlist_is_sorted_and_has_no_duplicates() {
        // `is_field_allowed` uses a binary search, so an unsorted list would not
        // merely be untidy — it would silently start redacting fields that are
        // on it.
        let mut sorted = ALLOWED_FIELDS.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            ALLOWED_FIELDS,
            &sorted[..],
            "ALLOWED_FIELDS must stay sorted"
        );

        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted.len(), deduped.len(), "ALLOWED_FIELDS has duplicates");

        for name in ALLOWED_FIELDS {
            assert!(is_field_allowed(name), "{name} is listed but not allowed");
        }
        assert!(!is_field_allowed("authorization"));
        assert!(!is_field_allowed("runner_token"));
    }

    #[test]
    fn every_record_is_one_parseable_json_object_per_line() {
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::info!(event = "one", "first");
            tracing::warn!(event = "two", "second");
        });

        let lines: Vec<&str> = output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 2, "{output}");
        for line in lines {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("not JSON: {error}\n{line}"));
            assert!(value.get("timestamp").is_some(), "{line}");
            assert!(value.get("level").is_some(), "{line}");
            assert!(value.get("logger").is_some(), "{line}");
            assert!(value.get("fields").is_some(), "{line}");
        }
    }

    #[test]
    fn span_fields_are_redacted_and_carried() {
        let capture = Capture::default();
        let output = emit(&capture, || {
            let span = tracing::info_span!("attempt", attempt_id = "abc-123", jit = %JIT_BLOB);
            let _entered = span.enter();
            tracing::info!(event = "inside", "in the span");
        });

        assert!(output.contains("\"name\":\"attempt\""), "{output}");
        assert!(
            output.contains("abc-123"),
            "the listed span field survives:\n{output}"
        );
        assert!(!output.contains(JIT_BLOB), "a span field leaked:\n{output}");
    }

    /// Asserts that [`install`] created its directories the restrictive way.
    ///
    /// `install` used to call `std::fs::create_dir_all(logs_dir)` directly.
    /// That is invisible on Windows and *nearly* invisible on Unix — the
    /// directory exists either way, and `AppPaths::create_all`'s own test still
    /// passed, because it tests `create_all` rather than the path a running
    /// daemon actually takes. So this checks the two things that distinguish
    /// them:
    ///
    /// 1. **All four directories exist.** `create_dir_all(logs_dir)` makes
    ///    exactly one. This half runs on every platform, which matters because
    ///    Windows is the leg most likely to be run locally.
    /// 2. **On Unix the mode is `0700`.** This is the invariant `create_all`
    ///    documents — that a diagnostics file is not readable by other local
    ///    accounts — and `tracing_appender` writes 0644 files into whatever
    ///    directory it is given, so a `0755` `logs/` defeats it entirely.
    fn assert_install_created_restricted_directories(paths: &crate::paths::AppPaths) {
        for (purpose, path) in paths.all() {
            assert!(
                path.is_dir(),
                "install must create the {purpose} directory too: going through \
                 AppPaths::create_all is what applies the restriction, and creating only \
                 logs/ is the bug this asserts against ({})",
                path.display()
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                let mode = std::fs::metadata(path)
                    .expect("the directory exists")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    mode, 0o700,
                    "the {purpose} directory is mode {mode:04o}; a diagnostics file under a \
                     group- or world-readable directory is readable by other local accounts"
                );
            }
        }
    }

    /// The one test that exercises [`install`] rather than assembling a
    /// subscriber by hand: the rolling file appender, the non-blocking writer,
    /// and the guard that has to be held for any of it to reach disk.
    ///
    /// It installs a *global* subscriber, which a process can only do once, so
    /// it is the only test here that may. Everything else uses
    /// `with_default`, which is thread-local and does not conflict — including
    /// on threads that run after this one.
    #[test]
    #[serial_test::serial(global_subscriber)]
    fn install_writes_redacted_json_into_the_logs_directory() {
        // `install` honours `RUST_LOG`, and a developer who has set it to
        // something restrictive would otherwise see this fail for a reason that
        // has nothing to do with the code. CI sets no such variable.
        if std::env::var_os("RUST_LOG").is_some() {
            return;
        }

        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = crate::paths::AppPaths::rooted_at(root.path());

        let outcome = install(&paths, "trace");

        // Asserted before the early return below, because `install` creates the
        // directories before it touches the global subscriber: this holds
        // whether or not this test won the race to install one.
        assert_install_created_restricted_directories(&paths);

        let Ok(guard) = outcome else {
            // Another test binary in the same process already installed one.
            // Not this test's failure, and not worth making the suite
            // order-dependent over.
            return;
        };

        tracing::info!(event = "installed", runner_token = %USER_TOKEN, "hello from the sink");

        // Dropping the guard flushes and stops the background writer, which is
        // the documented way to be sure the line reached disk.
        drop(guard);

        let written: Vec<PathBuf> = std::fs::read_dir(paths.logs_dir())
            .expect("the log directory was created")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        assert_eq!(
            written.len(),
            1,
            "expected one rotating log file: {written:?}"
        );

        let contents = std::fs::read_to_string(&written[0]).expect("readable");
        assert!(contents.contains("hello from the sink"), "{contents}");
        assert!(
            !contents.contains(USER_TOKEN),
            "the file sink must redact exactly like the in-memory one:\n{contents}"
        );
        assert!(contents.contains(REDACTION), "{contents}");
        serde_json::from_str::<Value>(contents.lines().next().expect("a line"))
            .expect("each line is a JSON object");
    }

    // -----------------------------------------------------------------------
    // The scrubber, in isolation
    // -----------------------------------------------------------------------

    #[test]
    fn tokens_are_redacted_wherever_they_appear() {
        for token in [USER_TOKEN, SERVER_TOKEN, FINE_GRAINED] {
            for shape in [
                token.to_string(),
                format!("using {token} now"),
                format!("(\"{token}\")"),
                format!("token={token}"),
                format!("Authorization: Bearer {token}"),
                format!("authorization={token}"),
                // A URL's userinfo. This is the canonical token-authenticated
                // git remote, so it is what a clone or fetch error carries, and
                // it is the shape the `://` branch used to hand back verbatim.
                format!("https://x-access-token:{token}@github.com/owner/repo.git"),
                format!("fatal: could not read from https://{token}@github.com/o/r"),
                // Userinfo with no password half.
                format!("https://{token}@github.com/o/r.git"),
                // A fragment, which used to be stripped only when it was a
                // query string.
                format!("https://github.com/login/oauth#access_token={token}"),
                format!("https://github.com/x?a=1#token={token}"),
            ] {
                let redacted = redact(&shape);
                assert!(
                    !redacted.contains(token),
                    "{shape:?} survived redaction as {redacted:?}"
                );
            }
        }
    }

    #[test]
    fn a_url_keeps_what_diagnoses_it_and_loses_what_authenticates_it() {
        // The host and the path are the diagnosable part and must survive, or
        // nobody keeps this redaction.
        assert_eq!(
            redact(
                "https://x-access-token:ghu_16C7e42F292c6912E7710c838347Ae178B4a@github.com/owner/repo.git"
            ),
            format!("https://{REDACTION}@github.com/owner/repo.git")
        );
        assert_eq!(
            redact("https://user:hunter2@api.github.com/repos/o/r?page=2"),
            format!("https://{REDACTION}@api.github.com/repos/o/r?{REDACTION}")
        );
        // A password containing an `@`: the host is what follows the last one.
        assert_eq!(
            redact("https://user:p@ss@github.com/o/r"),
            format!("https://{REDACTION}@github.com/o/r")
        );
        // Userinfo on a bare authority, with no path at all.
        assert_eq!(
            redact("https://token@github.com"),
            format!("https://{REDACTION}@github.com")
        );
        // An `@` after the first `/` is part of the path, not userinfo.
        assert_eq!(
            redact("https://github.com/@owner/repo"),
            "https://github.com/@owner/repo"
        );
    }

    #[test]
    fn an_encoded_jit_configuration_is_redacted() {
        assert_eq!(redact(JIT_BLOB), REDACTION);
        let sentence = format!("handing off {JIT_BLOB} to the runner");
        let redacted = redact(&sentence);
        assert!(!redacted.contains(JIT_BLOB), "{redacted}");
        assert!(redacted.starts_with("handing off "), "{redacted}");
        assert!(redacted.ends_with(" to the runner"), "{redacted}");
    }

    #[test]
    fn a_secret_embedded_in_a_structured_value_is_redacted() {
        // Compact JSON is what `serde_json::to_string` emits and what an
        // HTTP error body arrives as; spaced JSON is the only shape that
        // used to be safe, and it was safe by accident -- the value is its
        // own word there, so the opaque-run rule caught it without the key
        // ever being recognised.
        for shape in [
            format!("{{\"encoded_jit_config\":\"{JIT_BLOB}\"}}"),
            format!("{{ \"encoded_jit_config\": \"{JIT_BLOB}\" }}"),
            format!("encoded_jit_config:{JIT_BLOB}"),
            format!("{{\"runner_token\":\"{USER_TOKEN}\"}}"),
            format!("runner_token:{USER_TOKEN}"),
            format!("pat:{USER_TOKEN}"),
            format!("{{\"authorization\":\"Bearer {USER_TOKEN}\"}}"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(JIT_BLOB) && !redacted.contains(USER_TOKEN),
                "leaked from {shape}:\n{redacted}"
            );
        }

        // A credential short enough to clear the opaque-run threshold and
        // without a GitHub prefix has nothing but the key to give it away,
        // so it leaked from the spaced shape too: `\"password\":` left the
        // key spelled `password\"`, which is on no list.
        for shape in [
            "{\"password\":\"hunter2\"}",
            "{ \"password\": \"hunter2\" }",
        ] {
            let redacted = redact(shape);
            assert!(
                !redacted.contains("hunter2"),
                "leaked from {shape}: {redacted}"
            );
        }

        // The neighbouring context still survives: this is a scrubber, not
        // a deleter.
        let body = format!("registration failed: {{\"encoded_jit_config\":\"{JIT_BLOB}\"}}");
        let redacted = redact(&body);
        assert!(redacted.starts_with("registration failed: "), "{redacted}");
        assert!(redacted.contains("encoded_jit_config"), "{redacted}");
    }

    #[test]
    fn a_credential_key_is_found_wherever_it_sits_in_a_compact_structure() {
        // Every shape the test above covers puts the credential in the
        // *first* key/value pair, and the rules split a word once, on the
        // first separator they find. So redaction was a function of field
        // order -- and `serde_json::to_string` is what decides field order for
        // any struct with more than one field, which is what an error body is.
        //
        // Nesting and a form-encoded body are the same defect wearing
        // different punctuation: the value recursion ends at `redact_value`,
        // which is a leaf, and `&` was not a separator at all.
        for shape in [
            // The credential key second, in a compact object.
            format!("{{\"runner_id\":42,\"encoded_jit_config\":\"{JIT_BLOB}\"}}"),
            format!("{{\"status\":422,\"message\":\"bad\",\"runner_token\":\"{USER_TOKEN}\"}}"),
            // Nested one level, and two.
            format!("{{\"body\":{{\"runner_token\":\"{USER_TOKEN}\"}}}}"),
            format!(
                "{{\"error\":{{\"status\":422,\"body\":{{\"encoded_jit_config\":\"{JIT_BLOB}\"}}}}}}"
            ),
            // An array of objects, which is what a list endpoint returns.
            format!("[{{\"id\":1}},{{\"access_token\":\"{USER_TOKEN}\"}}]"),
            // Form-encoded, credential second and in the middle.
            format!("scope=repo&access_token={USER_TOKEN}"),
            format!("grant_type=refresh&refresh_token={USER_TOKEN}&scope=repo"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(JIT_BLOB) && !redacted.contains(USER_TOKEN),
                "leaked from {shape}:\n{redacted}"
            );
            assert!(redacted.contains(REDACTION), "{shape} -> {redacted}");
        }

        // The pairs around it stay legible. A body whose every field came back
        // `[redacted]` diagnoses nothing, and is how a redaction gets turned
        // off rather than fixed.
        let redacted = redact(&format!(
            "failed: {{\"runner_id\":42,\"encoded_jit_config\":\"{JIT_BLOB}\"}}"
        ));
        assert!(redacted.starts_with("failed: "), "{redacted}");
        assert!(redacted.contains("\"runner_id\":42"), "{redacted}");
        assert!(redacted.contains("encoded_jit_config"), "{redacted}");

        // A credential short enough to clear the opaque-run threshold and
        // carrying no GitHub prefix has nothing but its key to give it away,
        // so it is the case the shape rules cannot rescue.
        for shape in [
            "{\"user\":\"operator\",\"password\":\"hunter2\"}",
            "{\"body\":{\"password\":\"hunter2\"}}",
            "user=operator&password=hunter2",
        ] {
            assert!(
                !redact(shape).contains("hunter2"),
                "leaked from {shape}: {}",
                redact(shape)
            );
        }

        // Ordinary punctuation still survives the cut, or the structure that
        // makes a log line readable is gone with the secret.
        assert_eq!(
            redact("desired 3, active 1, headroom 2"),
            "desired 3, active 1, headroom 2"
        );
        assert_eq!(
            redact("labels=[linux,x64,self-hosted]"),
            "labels=[linux,x64,self-hosted]"
        );
    }

    #[test]
    fn backslash_escaped_json_reaches_the_key_rules_and_the_value_rules() {
        // `tracing::error!(reason = ?err)` reaches this module through
        // `record_debug` and `format!("{:?}")`, and `Debug` on a `String`
        // escapes the quotes inside it. So an error whose `Debug` embeds an
        // HTTP body arrives with its keys spelled `\"password\"` -- and `\`
        // is not in `WRAPPERS`, so `trim_matches(WRAPPERS)` left it welded on
        // and no list contained the result. `reason` is on ALLOWED_FIELDS, so
        // this reaches the scrubber rather than being dropped.
        let failure = StoreError {
            body: "{\"password\":\"hunter2\"}".to_string(),
        };
        // The fixture carries the secret before anything has looked at it. A
        // premise, asserted rather than assumed: a fixture that quietly
        // stopped carrying one would make every assertion below vacuously
        // true.
        assert!(failure.body.contains("hunter2"), "{}", failure.body);
        let rendered = format!("{failure:?}");
        // The premise, asserted rather than assumed: `Debug` really does
        // produce the escaped spelling. If it ever stops, this test is
        // measuring something else.
        assert!(
            rendered.contains("\\\"password\\\""),
            "the premise is that Debug escapes the quotes: {rendered}"
        );
        assert!(
            !redact(&rendered).contains("hunter2"),
            "leaked: {}",
            redact(&rendered)
        );

        for shape in [
            "{\\\"password\\\":\\\"hunter2\\\"}",
            "Error { body: \"{\\\"access_token\\\":\\\"hunter2\\\"}\" }",
        ] {
            assert!(
                !redact(shape).contains("hunter2"),
                "leaked from {shape}: {}",
                redact(shape)
            );
        }

        // The escaped spelling of a long secret leaked too, and for the same
        // reason: the key was unrecognised, so nothing below it ever ran.
        let escaped = format!("{{\\\"encoded_jit_config\\\":\\\"{JIT_BLOB}\\\"}}");
        assert!(!redact(&escaped).contains(JIT_BLOB), "{}", redact(&escaped));

        // Trimming the key is only half of it, and it is the half that is
        // easy to mistake for the whole. `runner_token` is deliberately *not*
        // on CREDENTIAL_KEYS -- a field name is not what makes a value a
        // secret, and this module's own documentation says so -- so that pair
        // is caught by the token-prefix rule reading its *value*, or it is not
        // caught at all. The escaped quote hid the value from that rule
        // exactly as it hid the key from the key rules, and a key-only fix
        // leaves this one leaking through the sink.
        assert!(
            !is_credential_key("runner_token"),
            "the premise of this case is an unlisted key; once it is listed, \
             this stops exercising the value side at all"
        );
        let escaped_value = format!("{{\\\"runner_token\\\":\\\"{USER_TOKEN}\\\"}}");
        assert!(
            !redact(&escaped_value).contains(USER_TOKEN),
            "the value side leaked: {}",
            redact(&escaped_value)
        );

        // The trim is unconditional on a key and conditional on a value: a
        // backslash comes off a value only where it is escaping punctuation.
        // `split_wrappers` runs before `looks_like_path`, so putting `\` in
        // `WRAPPERS` would trim away the leading `\\` that UNC detection keys
        // on and turn a share path back into ordinary text.
        assert_eq!(redact(r"\\fileserver\share\jit"), PATH_REDACTION);
        assert_eq!(redact(r"\\?\C:\Users\operator\runtime"), PATH_REDACTION);
        // And the escaped spelling of a share path is still a share path:
        // `\\` escapes nothing, so it survives the trim that `\"` does not.
        assert_eq!(redact(r"\\\\fileserver\\share\\jit"), PATH_REDACTION);
        // A path ending in its own separator is still a path without it. The
        // separator is punctuation, so it is trimmed, judged, and put back.
        let trailing = redact("C:\\Users\\operator\\runtime\\");
        assert!(trailing.starts_with(PATH_REDACTION), "{trailing}");
        assert!(!trailing.contains("operator"), "{trailing}");
    }

    #[test]
    fn a_bare_jwt_is_redacted_despite_its_dots() {
        // `is_opaque_char` excludes `.`, so a JWT is three opaque runs rather
        // than one, each under the threshold, and a 100-character credential
        // printed verbatim. `Authorization: Bearer <jwt>` is caught by the
        // scheme rule and a credential-keyed one by the key rule, so this bit
        // only where a token stood alone or under a name nobody listed.
        assert!(
            JWT.len() > 100,
            "the premise is a long token: {}",
            JWT.len()
        );
        assert_eq!(redact(JWT), REDACTION);
        assert_eq!(
            redact(&format!("minted {JWT} for the installation")),
            format!("minted {REDACTION} for the installation")
        );
        // Sentence-final punctuation is trimmed as a wrapper first, so the
        // token is still recognised.
        assert!(!redact(&format!("minted {JWT}.")).contains(JWT));
        // Under a key nobody listed.
        assert!(!redact(&format!("assertion={JWT}")).contains(JWT));
        assert!(!redact(&format!("{{\"assertion\":\"{JWT}\"}}")).contains(JWT));

        // Narrow on purpose. Adding `.` to `is_opaque_char` is the obvious fix
        // and the wrong one: it swallows every long dotted word there is.
        for ordinary in [
            "com.example.runner.manager.platform.process.identity.token",
            "runner-manager.2026.08.21.log",
            "api.github.com",
            "9f2c1a44-0000-4000-8000-000000000001.attempt.json",
        ] {
            assert_eq!(redact(ordinary), ordinary, "over-redacted {ordinary}");
        }
    }

    #[test]
    fn the_sink_redacts_a_short_credential_that_only_its_key_gives_away() {
        // `scan_for_leaks` cannot carry this case. A credential short enough
        // to clear the opaque-run threshold and carrying no GitHub prefix is
        // indistinguishable from an ordinary word when it is logged bare, so
        // injecting it through shape 1 would demand a redaction no shape rule
        // can deliver. Here the key is always present, which is the situation
        // `d2`'s secret store is actually in -- and it is through the sink,
        // not through `redact` alone, because that distinction is why these
        // shapes survived a round.
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::error!("store rejected: {{\"user\":\"operator\",\"password\":\"hunter2\"}}");
            tracing::error!("store rejected: {{\"body\":{{\"password\":\"hunter2\"}}}}");
            tracing::error!("store rejected: user=operator&password=hunter2");
            let failure = StoreError {
                body: "{\"password\":\"hunter2\"}".to_string(),
            };
            tracing::error!(reason = ?failure, "store rejected the request");
        });

        assert!(
            !output.contains("hunter2"),
            "a short credential leaked through the sink:\n{output}"
        );
        assert!(output.contains(REDACTION), "{output}");
        // Four lines, or the sink was never reached and "no secret found" is
        // true of an empty string.
        assert_eq!(
            output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
            4,
            "{output}"
        );
    }

    #[test]
    fn paths_are_redacted_on_both_families() {
        assert_eq!(redact(WORKSPACE), PATH_REDACTION);
        assert_eq!(redact(WINDOWS_WORKSPACE), PATH_REDACTION);
        assert_eq!(redact("\\\\fileserver\\share\\jit"), PATH_REDACTION);
        assert_eq!(
            redact("~/Library/Application Support/x"),
            format!("{PATH_REDACTION} Support/x")
        );
        assert_eq!(
            redact("runtime=/var/lib/runner-manager/runtime"),
            format!("runtime={PATH_REDACTION}")
        );
    }

    #[test]
    fn a_url_survives_but_its_query_string_and_fragment_do_not() {
        assert_eq!(
            redact("GET https://api.github.com/repos/owner/repo/actions/runners"),
            "GET https://api.github.com/repos/owner/repo/actions/runners"
        );
        assert_eq!(
            redact("https://api.github.com/x?access_token=ghu_secret"),
            format!("https://api.github.com/x?{REDACTION}")
        );
        // A fragment carries a token in an OAuth implicit-flow response, and
        // is never needed to diagnose an HTTP call.
        assert_eq!(
            redact("https://api.github.com/x#access_token=ghu_secret"),
            format!("https://api.github.com/x#{REDACTION}")
        );
        // Whichever comes first ends the diagnosable part.
        assert_eq!(
            redact("https://api.github.com/x?page=2#access_token=ghu_secret"),
            format!("https://api.github.com/x?{REDACTION}")
        );
    }

    #[test]
    fn a_credential_header_loses_its_scheme_and_its_value() {
        assert_eq!(
            redact("Authorization: Bearer abc123"),
            format!("Authorization: {REDACTION} {REDACTION}")
        );
        assert_eq!(
            redact("Authorization: Bearer abc123, Accept: application/json"),
            // The comma ends the header value, so the next header's name is not
            // swallowed.
            format!("Authorization: {REDACTION} {REDACTION} Accept: application/json")
        );
        assert_eq!(
            redact("x-api-key=hunter2"),
            format!("x-api-key={REDACTION}")
        );
        assert_eq!(
            redact("Cookie: session=abc"),
            format!("Cookie: {REDACTION}")
        );

        // A webhook signature is not a credential the way a token is -- it is
        // derived, and it verifies rather than authenticates -- but it has a
        // SHA-256's exact shape, so the digest carve-out rendered it as a
        // labelled 12-character prefix rather than redacting it. Twelve hex
        // characters of an HMAC are of no use to anybody, which is why the
        // carve-out is safe in general; the header is on the list anyway,
        // because there is no diagnostic worth having in a signature and one
        // entry is cheaper than the argument.
        let hmac = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(
            redact(&format!("X-Hub-Signature-256: sha256={hmac}")),
            format!("X-Hub-Signature-256: {REDACTION}")
        );
        assert_eq!(
            redact(&format!("{{\"x-hub-signature-256\":\"sha256={hmac}\"}}")),
            format!("{{\"x-hub-signature-256\":{REDACTION}\"}}")
        );
        // The SHA-1 spelling GitHub still sends alongside it.
        assert_eq!(
            redact(&format!("X-Hub-Signature: sha1={hmac}")),
            format!("X-Hub-Signature: {REDACTION}")
        );
        // The carve-out itself is untouched: a bare digest still renders as a
        // prefix, because a checksum gate that cannot say which digest it got
        // is a gate nobody can act on.
        assert_eq!(redact(hmac), "sha256:9f86d081884c…");
    }

    #[test]
    fn ordinary_text_survives_intact() {
        // Redaction that eats the diagnostics is redaction nobody keeps. These
        // are the shapes this product's own log lines actually take.
        for text in [
            "reconciliation finished",
            "runner exited idle without work",
            "desired 3, active 1, headroom 2",
            "attempt 9f2c1a44-0000-4000-8000-000000000001 is busy",
            "http 403 after 2 retries",
            "windows/x64 is a documented pair",
        ] {
            assert_eq!(redact(text), text, "redaction damaged an ordinary message");
        }
    }

    /// A SHA-256 is 64 opaque characters and would otherwise be swallowed by
    /// the opaque-run rule. `07-security.md` makes checksum verification a
    /// security gate, and a gate that cannot say *which* digest it got is a
    /// gate nobody can act on, so a digest renders as a labelled prefix.
    #[test]
    fn a_digest_renders_as_a_prefix_rather_than_disappearing() {
        let digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

        assert_eq!(redact(digest), "sha256:9f86d081884c…");
        // The point of the change: expected-versus-actual stays legible.
        let other = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";
        assert_ne!(
            redact(digest),
            redact(other),
            "two digests must stay distinguishable"
        );

        // In the sentence shape `e2` will actually write.
        assert_eq!(
            redact(&format!("checksum mismatch: expected {digest} got {other}")),
            "checksum mismatch: expected sha256:9f86d081884c… got sha256:60303ae22b99…"
        );

        // A prefix a caller logged itself is below the threshold and untouched.
        assert_eq!(redact(&digest[..12]), digest[..12].to_string());

        // An already-labelled digest is labelled once, not twice, and is
        // truncated like a bare one.
        //
        // Before `redact_core` recursed into a `:` value this arrived at
        // `redact_value` whole, matched nothing there -- a `:` is not an
        // opaque character -- and was printed in full. Recursing hands
        // `as_sha256_digest` the digest on its own, which re-attaches its own
        // label, so the redundant one is dropped rather than doubled.
        //
        // The truncation is the part worth having: a 64-character lowercase
        // hex run is only *usually* a digest, an HMAC-SHA256 signature has
        // the same shape, and `sha256:<hmac>` used to be emitted whole.
        assert_eq!(redact(&format!("sha256:{digest}")), "sha256:9f86d081884c…");
        // The `=` spelling had the same doubling and is fixed with it; the
        // caller's own separator survives either way.
        assert_eq!(redact(&format!("sha256={digest}")), "sha256=9f86d081884c…");
    }

    #[test]
    fn the_digest_exception_is_exactly_sixty_four_lowercase_hex_and_nothing_else() {
        // The narrower this carve-out is, the less there is to reason about.
        // Anything that is not precisely a lowercase SHA-256 stays redacted by
        // the opaque-run rule.
        let digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

        assert_eq!(
            redact(&digest.to_ascii_uppercase()),
            REDACTION,
            "uppercase hex is not the shape this exception recognises"
        );
        assert_eq!(
            redact(&format!("{digest}0")),
            REDACTION,
            "65 characters is not a SHA-256"
        );
        // 64 characters of base64, which is what an encoded secret of that
        // length looks like: not hex, so not exempt.
        let base64ish = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvutsrqponmlkjihgfedcba98";
        assert_eq!(base64ish.len(), 64);
        assert_eq!(redact(base64ish), REDACTION);

        // And the JIT blob, which is the thing the opaque-run rule exists for,
        // must not have been weakened by any of this.
        assert_eq!(redact(JIT_BLOB), REDACTION);
    }

    #[test]
    fn a_uuid_survives() {
        // 36 characters, below the opaque-run threshold on purpose: every
        // identifier in this product's domain model is a UUID, and redacting
        // them would make the logs useless.
        let id = "9f2c1a44-0000-4000-8000-000000000001";
        assert_eq!(redact(id), id);
        assert!(id.len() < OPAQUE_RUN_THRESHOLD);
    }

    #[test]
    fn redaction_preserves_whitespace_and_line_structure() {
        let input = "line one\nAuthorization: Bearer x\nline three";
        let redacted = redact(input);
        assert_eq!(redacted.lines().count(), 3, "{redacted}");
        assert!(redacted.starts_with("line one\n"), "{redacted}");
        assert!(redacted.ends_with("\nline three"), "{redacted}");
    }
}
