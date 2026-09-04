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
//!   shape a clone or fetch failure arrives in. The path stays diagnosable but
//!   is not exempt: each segment goes through the same shape rules on its own,
//!   because a token in `…/raw/ghu_…/f` is a token, and the alternative was the
//!   one place the belt never ran. A 40-character git object name is opaque
//!   enough to go with it.
//! - A word ending in `:` or `=` whose stem is a credential header name causes
//!   the next two words to be redacted, so `Authorization: Bearer ghu_…` loses
//!   both the scheme and the token.
//!
//! A word is cut on structural punctuation — `,`, `;`, `{`, `}`, `[`, `]`,
//! `<`, `>` and `&` — before any of that runs, and each fragment is then judged
//! the way a whole word is: unwrapped, judged on its core, and re-emitted with
//! its punctuation put back. Without that cut only the *first* key/value pair
//! in a compact structure is ever examined, and redaction becomes a function of
//! field order: `{"encoded_jit_config":"…"}` was caught and
//! `{"runner_id":42,"encoded_jit_config":"…"}` was not, while
//! `serde_json::to_string` is what decides which of the two an error body is.
//! Nesting, a form-encoded body, a `;`-separated connection string and a plist
//! element are all that same defect in different punctuation. So is an array
//! element, one step further down — a fragment judged *with* its quote still
//! attached matches no shape rule at all, and an array element is the one
//! fragment that has no key of its own to give it away.
//!
//! Because the cut is flat, a credential's value does not have to be in the
//! same fragment as the key that names it — `{"password":["hunter2"]}`,
//! `{"password":{"v":"hunter2"}}` and a plist's
//! `<key>password</key><string>hunter2</string>` all put it one or more
//! fragments away — so a *carry* is threaded along the fragments to say that a
//! key is still waiting for its value, or that a quoted value was cut before
//! its closing quote. It steps over element names, because markup is not the
//! value a key named, and it stops at the punctuation that visibly closes the
//! value, because a redaction reported where no secret was is a false signal in
//! the one log a reader consults to find out whether anything leaked.
//!
//! A URL is cut out of the text around it rather than being allowed to own the
//! rest of the word. Its scheme is the run of scheme characters immediately
//! before the `://`, and it ends at the first character that cannot appear in a
//! URL — plus, *ahead of its query string only*, at a `;` or an `&`, which are
//! structural characters everywhere else and are query syntax after the `?`.
//! Everything on either side goes back through the rules. So
//! `{"documentation_url":"https://…","token":"ghu_…"}` — which is what a GitHub
//! REST error body looks like — keeps the URL and redacts the token, rather
//! than the URL swallowing the token, and
//! `Server=https://vault.local/api;Password=…` keeps the URL and redacts the
//! password rather than the URL swallowing the `;` that separates them.
//!
//! **The text after a URL is iterated over, not recursed into.** That is a
//! memory-safety property, not a style: recursing there made stack depth linear
//! in the length of the message, and ~86 KB of URL-carrying JSON exited
//! `STATUS_STACK_OVERFLOW`. A stack overflow is not catchable and takes the
//! process with it, so an attacker-influenceable error body could kill the
//! agent from inside its own log sink — and a sink that is not running redacts
//! nothing at all. For the same reason every search in `split_url` is bounded
//! by the URL's own end: a pass that never returns is as effective a denial as
//! one that overflows.
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
use std::path::{Path, PathBuf};

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
/// judged on its own, by [`redact_fragment`]. The separators go back verbatim,
/// because the structure around a redaction is what keeps the line diagnosable.
///
/// `;` is here for the reason `&` is: it separates the pairs of a Windows
/// connection string (`Server=host;Database=x;Password=…`), of a credential
/// string, and of a cookie header written without a space after the separator.
/// It was already in [`WRAPPERS`] — recognised as punctuation, and so never
/// used to cut — which left `Set-Cookie: theme=dark; session=…` safe only
/// because of the space. `d2` logs keychain, DPAPI and libsecret failures, and
/// that is the shape they arrive in.
///
/// `<` and `>` are here because [`split_wrappers`] strips only the *outermost*
/// pair, so `<string>ghu_…</string>` reached the rules as
/// `string>ghu_…</string`, which is on no list and matches no shape. `d3`'s
/// installers handle launchd plists, which is where that shape comes from.
const STRUCTURAL: &[char] = &[',', ';', '{', '}', '[', ']', '<', '>', '&'];

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

/// What a credential key left outstanding at the end of the text that named it.
///
/// The structural cut is flat and a credential's value does not have to be in
/// the same fragment as the key that names it, so something has to carry the
/// key across the cut. Nothing did, which is [`redact_core`]'s empty-value
/// case: the comment there claimed the value would be reached "in the next
/// fragment, where the structural cut reaches it", and no such thing happened.
///
/// The two variants are not the same claim, and collapsing them over-redacts:
///
/// - [`Carry::Expecting`] is *"a key named a value that has not appeared yet"*.
///   It has to step over markup, because `<key>password</key><string>…</string>`
///   puts `/key` and `string` between the key and its value.
/// - [`Carry::Unclosed`] is *"a quoted value was redacted and its closing quote
///   is not in this fragment"*, so the value continues past the cut. Inside an
///   open quote `<` and `>` are literal text rather than markup, so this one
///   must *not* step over anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Carry {
    /// Nothing outstanding.
    None,
    /// A credential key supplied no value of its own.
    Expecting,
    /// A redacted credential value was cut before its closing quote.
    Unclosed,
}

/// Whether wrapping punctuation closes the value it followed.
///
/// A quote closes a string and a bracket closes a structure, so either one
/// means the credential value ended here and a carry must stop. `,` and `;` are
/// on the list for the reason [`redact`] already stops its word-level follow-on
/// at them: they end a header value, and what comes after is the next header's
/// name.
///
/// `>` is deliberately absent. It closes a *tag*, not a value —
/// `<key>password</key>` ends in one with the credential's value still to come
/// — and treating it as a terminator is what would leave the multi-word plist
/// spelling leaking.
fn closes_a_value(wrappers: &str) -> bool {
    wrappers.contains(['"', '\'', '`', ',', ';', ']', '}', ')'])
}

/// Whether a value opened a quote that its own fragment did not close.
fn opens_an_unclosed_quote(lead: &str, trail: &str) -> bool {
    const QUOTES: [char; 3] = ['"', '\'', '`'];
    lead.contains(QUOTES) && !trail.contains(QUOTES)
}

/// Whether a fragment sits where an element *name* goes rather than where its
/// content does.
///
/// `<` and `>` are in [`STRUCTURAL`] because `<string>ghu_…</string>` reached
/// the rules as `string>ghu_…</string` and matched nothing. Having cut on them,
/// the loop knows which side of a tag it is on, and a [`Carry::Expecting`] must
/// not be spent on `/key` or `string` when the value it is waiting for is the
/// element's content. A tag name is still judged by every other rule — this
/// says only that it is not the value a credential key named.
fn is_tag_name(preceding: Option<char>, following: Option<char>) -> bool {
    preceding == Some('<') && following == Some('>')
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

    let (rendered, carry) = redact_core(core, suffix);

    // A value the word did not finish is the *next* word's problem, which is
    // the follow-on rule the word level already has, reached from one level
    // down. A pretty-printed plist is why it is needed: `<key>password</key>`
    // and `<string>hunter2</string>` are on separate lines, so the key and its
    // value are not even in the same word.
    //
    // The two carries ask for different amounts, for the same reason the stem
    // rule above asks for two words and not one:
    //
    // - [`Carry::Expecting`] means the value has not been seen *at all*, so it
    //   may be introduced by a word of its own — `<string>correct` and then
    //   `horse</string>`. Two, exactly as `Authorization: Bearer <token>` needs
    //   two.
    // - [`Carry::Unclosed`] means the value has already started and was cut, so
    //   only its remainder is outstanding. One.
    //
    // Trailing punctuation that closes the value withdraws the claim, for the
    // same reason pass one declines an empty value: `{"password":""}` names a
    // credential and supplies nothing, and redacting the next word there would
    // report a secret where none was.
    let follow_on = if closes_a_value(suffix) {
        0
    } else {
        match carry {
            Carry::None => 0,
            Carry::Unclosed => 1,
            Carry::Expecting => 2,
        }
    };
    (format!("{prefix}{rendered}{suffix}"), follow_on)
}

/// Redacts one fragment of a cut-up word, judging it on its core.
///
/// [`redact_core`] used to recurse on the *raw* fragment, and its terminal
/// fallback then handed that fragment to [`redact_value`] with its wrapping
/// punctuation still attached. A fragment carrying no `:` or `=` of its own —
/// which is exactly what an array element is — therefore reached the shape
/// rules as `"ghu_…`, where `starts_with("ghu_")` fails, [`is_opaque_char`]
/// fails on the quote, the `eyJ` test fails, and [`looks_like_path`] never gets
/// a clean look at `"C:\Users\…`.
///
/// That is the defect the structural cut was written to close, one step further
/// down: *"only the first key/value pair is ever examined"* became *"a value
/// with no key of its own is never examined"*. It survived a round because the
/// secret-injection scan had no array among its shapes, which is the same
/// lesson in a different place — a check that cannot fail proves nothing.
///
/// So a fragment is treated the way [`redact_word`] treats a word: split,
/// judge the core, put the punctuation back.
///
/// The *word-level* follow-on rule is still not repeated here, and the reason
/// stands: *"the value is the next word"* is a statement about whitespace, and
/// there is no next word inside a fragment. What that argument does not cover —
/// and what an earlier spelling of it wrongly took itself to have settled — is
/// the *fragment-level* claim: **the value is the next fragment**. That one is
/// a statement about the structural cut, it is true, and nothing implemented
/// it, which is why `{"password":["hunter2"]}` and
/// `<key>password</key><string>hunter2</string>` went out whole. [`Carry`] is
/// that claim, threaded through the loop in [`redact_core`].
///
/// `trailing` says this is the last fragment of its core, and it is what keeps
/// the carry from escaping a word it has already been spent inside: consuming
/// a claim in the middle of a core settles it, while consuming it at the end
/// leaves open the possibility that the value runs on into the next word.
fn redact_fragment(
    fragment: &str,
    carry: Carry,
    tag_name: bool,
    trailing: bool,
) -> (String, Carry) {
    let (prefix, core, suffix) = split_wrappers(fragment);
    if core.is_empty() {
        return (fragment.to_string(), carry);
    }

    let claimed = match carry {
        Carry::None => false,
        // Markup is not the value a credential key named.
        Carry::Expecting => !tag_name,
        // Inside an open quote there is no markup, only text.
        Carry::Unclosed => true,
    };

    if claimed {
        // Two different reasons to think the value has more to come, and one
        // answer: it is `Unclosed` from here, never the `Expecting` it may have
        // arrived as, because the value has now started.
        //
        // - `carry == Unclosed` — still inside an open quote, so the value runs
        //   into the next fragment as well.
        // - `trailing` — a claim spent on the *last* fragment of a core is one
        //   whose value reached the end of the word with nothing closing it, so
        //   it may continue into the next word.
        //   `<key>password</key><string>` + `correct horse</string>` is that
        //   shape.
        //
        // Anything else was spent in the middle of a core, where the value was
        // and is done — and punctuation that closes a string or a structure
        // settles it either way.
        let next = if !closes_a_value(suffix) && (carry == Carry::Unclosed || trailing) {
            Carry::Unclosed
        } else {
            Carry::None
        };
        return (format!("{prefix}{REDACTION}{suffix}"), next);
    }

    let (rendered, next) = redact_core(core, suffix);
    let next = if closes_a_value(suffix) {
        Carry::None
    } else if next == Carry::None {
        // **An unclaimed fragment preserves the claim rather than clearing
        // it.** This is the whole of what lets a plist work: `/key` and
        // `string` sit between `<key>password</key>` and the `<string>` content
        // that is the value, they are tag names so they do not spend the claim,
        // and a fragment that neither spends nor arms one must leave it exactly
        // as it found it. Overwriting with this fragment's own (empty) result
        // is how `<key>password</key><string>hunter2</string>` kept leaking
        // after the carry existed.
        carry
    } else {
        next
    };
    (format!("{prefix}{rendered}{suffix}"), next)
}

/// Redacts one word with its wrapping punctuation already removed, and reports
/// what it left outstanding for whatever follows it.
///
/// `closing` is the wrapping punctuation the caller stripped off the end of
/// this core. It is not emitted here — the caller puts it back — but the loop
/// below has to see it, because the character that follows the *last* fragment
/// is what says whether that fragment is an element name or an element's
/// content.
fn redact_core(core: &str, closing: &str) -> (String, Carry) {
    // A URL survives, minus everything on it that carries a credential. The
    // scheme, host and path are what makes a log line diagnosable.
    //
    // The URL is *cut out* of the text around it rather than being allowed to
    // own the rest of the fragment, and both sides of the cut come back through
    // here. [`split_url`] documents what the old unbounded `split_once("://")`
    // cost. This still runs ahead of the structural cut, because a query string
    // is `redact_url`'s to own: `?` and `#` are not structural characters, and
    // an OAuth implicit-flow response puts the token after one of them.
    //
    // **The tail is iterated, not recursed into, and that is a memory-safety
    // property rather than a matter of taste.** An earlier spelling called
    // `redact_core` on the remainder, and argued only that the recursion
    // *terminates*: every call is on a strictly shorter slice, which is true
    // and is not enough. Termination says nothing about **depth**, and depth
    // was linear in the length of the input — one frame per URL. A message of
    // ~2000 `{"url":"https://…"},` items, about 86 KB, exited
    // `0xc00000fd STATUS_STACK_OVERFLOW`.
    //
    // A stack overflow is not a `panic`: it is not catchable, it does not
    // unwind, and it takes the process with it. A large HTTP error body is
    // content an attacker can influence, so that was a way to kill the agent
    // from inside its own log sink — and a sink that is not running redacts
    // nothing at all, which is worse than any single leak.
    //
    // With the loop, every remaining re-entry is depth-bounded by construction
    // rather than by argument:
    //
    // - `prefix` holds everything before the *first* `://`, so it contains no
    //   `://` and cannot reach this branch again.
    // - `rest` is what is left when the loop finds no further `://`, for the
    //   same reason.
    // - the structural branch below calls [`redact_fragment`], whose fragments
    //   contain no structural character by construction and so cannot reach it
    //   again either.
    //
    // Three levels, whatever the input is. Anything added here that recurses on
    // a slice whose length is not bounded by a constant re-opens this.
    if let Some((prefix, scheme, url, remainder)) = split_url(core) {
        let mut out = String::with_capacity(core.len());
        if !prefix.is_empty() {
            out.push_str(&redact_core(prefix, "").0);
        }
        out.push_str(&redact_url(scheme, url));

        let mut rest = remainder;
        while let Some((prefix, scheme, url, remainder)) = split_url(rest) {
            if !prefix.is_empty() {
                out.push_str(&redact_core(prefix, "").0);
            }
            out.push_str(&redact_url(scheme, url));
            rest = remainder;
        }
        if !rest.is_empty() {
            out.push_str(&redact_core(rest, "").0);
        }

        // A URL is a complete value: it carries its own credentials in its own
        // places, and `redact_url` has already dealt with them. Nothing is
        // outstanding, which is also what keeps `{"token":"https://…"}` from
        // arming a claim against whatever follows the URL.
        return (out, Carry::None);
    }

    // A Windows drive path is `key:value`-shaped by accident, and
    // `looks_like_path` only recognises the drive letter at position zero.
    // Splitting such a path on its colon would hand the tail to a rule that
    // matches nothing, so it has to be judged whole, before the separators
    // get at it.
    if looks_like_path(core) {
        return (PATH_REDACTION.to_string(), Carry::None);
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
    // would.
    //
    // Each fragment goes through [`redact_fragment`] rather than straight back
    // in here, because a fragment carries its own wrapping punctuation and a
    // value judged with its quote attached matches nothing at all.
    //
    // The recursion terminates *and is depth-bounded*: a fragment contains no
    // structural character by construction, so `redact_fragment` cannot reach
    // this branch again, and the URL branch above iterates over its tail rather
    // than recursing into it. The loop here is a loop for the same reason — a
    // fragment per separator, at whatever length the input has.
    //
    // A [`Carry`] is threaded along it because the cut is flat and a
    // credential's value need not be in the same fragment as its key. Without
    // it the empty-value skip in pass one was a promise nothing kept: the value
    // was said to be reachable "in the next fragment", and no next fragment
    // ever heard about the key.
    if core.contains(STRUCTURAL) {
        let mut out = String::with_capacity(core.len());
        let mut carry = Carry::None;
        let mut rest = core;
        // The separator on each side of a fragment is what says whether it is
        // an element name or an element's content.
        let mut preceding: Option<char> = None;
        while let Some(index) = rest.find(STRUCTURAL) {
            let (fragment, tail) = rest.split_at(index);
            // Every character in `STRUCTURAL` is ASCII, so the separator is
            // one byte, this cannot split a code point, and the byte is the
            // whole character.
            let separator = char::from(tail.as_bytes()[0]);
            if !fragment.is_empty() {
                let (rendered, next) = redact_fragment(
                    fragment,
                    carry,
                    is_tag_name(preceding, Some(separator)),
                    false,
                );
                out.push_str(&rendered);
                carry = next;
            }
            out.push_str(&tail[..1]);
            preceding = Some(separator);
            rest = &tail[1..];
        }
        if !rest.is_empty() {
            // The last fragment's *following* character is the caller's closing
            // punctuation: in `<key>password</key>` the final `/key` is a tag
            // name only because the `>` that ends it was stripped as a wrapper
            // before this ran.
            let following = closing.chars().next();
            let (rendered, next) =
                redact_fragment(rest, carry, is_tag_name(preceding, following), true);
            out.push_str(&rendered);
            carry = next;
        }
        return (out, carry);
    }

    // `key=value` and `key:value` in a single fragment.
    //
    // Pass one asks only whether either separator names a credential, and it
    // runs to completion before any value is inspected, because the *first*
    // separator in a fragment is not necessarily the one that names the key.
    //
    // The witness is a webhook signature header in its compact-JSON spelling,
    // `{"x-hub-signature-256":"sha256=<hmac>"}`, and
    // `a_credential_header_loses_its_scheme_and_its_value` holds it. The `=`
    // comes first and names nothing, but what follows it is a whole HMAC —
    // *non-empty*, so a merged pass inspects that value, renders it as a
    // digest prefix, and returns without ever reaching the `:` that names
    // `x-hub-signature-256`. `{"password":"a=b"}` is the same witness with
    // nothing else going on: merged, it comes out whole.
    //
    // Two earlier spellings of this comment named
    // `{"encoded_jit_config":"eyJ…In0="}` and then
    // `{"encoded_jit_config":"eyJ…In0=","runner_id":42}`, and neither
    // demonstrates the invariant: base64 padding is trailing-only, so the `=`
    // split yields a value that `split_wrappers` trims to empty, and the
    // `value.is_empty()` guard in pass two falls through to the `:` anyway. A
    // comment naming a case that does not demonstrate its own invariant is how
    // the invariant gets deleted by the next person, so the witness above is
    // one that reds a named test when the two passes are merged.
    //
    // Both halves are judged through `trim_key`: compact JSON welds a quote to
    // each, so the key arrives as `encoded_jit_config"`, and a `Debug`
    // rendering welds a backslash as well.
    // Whether pass one saw a credential key and was given nothing to redact.
    let mut names_a_credential = false;

    for separator in ['=', ':'] {
        if let Some((key, raw_value)) = core.split_once(separator)
            && is_credential_key(key)
        {
            // The value's own wrapping punctuation goes back, exactly as pass
            // two puts it back. Dropping it emitted `{"password":[redacted]"}`
            // — an unbalanced quote in a line this module argues, correctly,
            // has to stay diagnosable, and a reader who cannot parse the line
            // cannot tell a redaction from a truncation.
            let (lead, value, trail) = split_wrappers(raw_value);

            // An empty value is nothing to redact, and pass two declines one
            // for the same reason. Claiming `[redacted]` here says a secret was
            // somewhere none was, which is a false signal in the one log a
            // reader consults to find out whether anything leaked.
            //
            // It is also load-bearing for the URL branch above, which sends
            // the text before a URL back through here: `{"token":"https://…"}`
            // leaves this pass a key of `token` and a value of nothing, and
            // redacting that emitted `token":"[redacted]https://…` — the URL
            // still standing behind the redaction meant to have replaced it.
            //
            // **What it is not is a reason to forget the key.** An earlier
            // spelling of this comment said the value would be found "in the
            // next fragment or the next word, where the structural cut and the
            // follow-on rule reach it", and half of that was false: the
            // follow-on rule does reach the next *word*, and nothing whatever
            // reached the next *fragment*, because `redact_fragment`
            // deliberately carries no follow-on. So `{"password":["hunter2"]}`,
            // `{"password":{"v":"hunter2"}}` and `Password=;hunter2` — a
            // credential key with its value one fragment away, which is what an
            // array, a nested object and an empty pair all are — went out
            // whole, with the key sitting in plain sight next to them.
            //
            // That is the failure this module warns about two comments down: a
            // comment naming a case that does not demonstrate its own
            // invariant. The claim is now true because [`Carry::Expecting`]
            // implements it, and `the_fragment_carry_stops_where_the_value_does`
            // holds both halves — that the claim is made, and that it is
            // withdrawn where the value visibly ended.
            if value.is_empty() {
                names_a_credential = true;
                continue;
            }

            // A quoted value whose closing quote is not in this fragment is a
            // value the cut ran through the middle of: `{"password":"p&ss"}`
            // reaches here as `password":"p`, and `ss` is the rest of the
            // secret. Adding `;`, `<` and `>` to `STRUCTURAL` this round made
            // three more characters able to do that, and punctuated passwords
            // are ordinary.
            let carry = if opens_an_unclosed_quote(lead, trail) {
                Carry::Unclosed
            } else {
                Carry::None
            };
            return (format!("{key}{separator}{lead}{REDACTION}{trail}"), carry);
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
                return (format!("{key}{separator}{lead}{bare}{trail}"), Carry::None);
            }
            return (
                format!("{key}{separator}{lead}{redacted}{trail}"),
                Carry::None,
            );
        }
    }

    // A credential key with no value at all — either `password:` with nothing
    // after it, or a bare `password` between a plist's tags. Both name a value
    // that is somewhere else, and the caller is the only one who can see where.
    let carry = if names_a_credential || is_credential_key(core) {
        Carry::Expecting
    } else {
        Carry::None
    };
    (redact_value(core), carry)
}

/// Characters a URL scheme is made of: RFC 3986 allows a letter followed by
/// letters, digits, `+`, `-` and `.`.
fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

/// Characters that cannot appear inside a URL, and therefore end one.
///
/// `\` is deliberately absent, even though it cannot appear in a URL either.
/// The shape it would have been there for is a `Debug`-escaped body, which
/// spells its quotes `\"` — and the quote already ends the URL. Making the
/// backslash a terminator as well costs a real redaction: a Windows path used
/// as a URL password, `https://x-access-token:C:\Users\…@github.com/o/r.git`,
/// would then end its URL at the first `\`, which puts the `@` that identifies
/// the userinfo *outside* the span, and [`redact_url`] echoes what it is given.
/// Measured: with `\` a terminator, that line emits the path verbatim; without
/// it, the userinfo is replaced as it should be.
fn is_url_terminator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | ',' | '{' | '}' | '[' | ']' | '<' | '>')
}

/// The same, plus the two [`STRUCTURAL`] characters that end a URL only *ahead
/// of its query string*.
///
/// [`STRUCTURAL`] has nine characters and [`is_url_terminator`] recognises seven
/// of them; `;` and `&` were missing. Because the URL branch runs ahead of the
/// structural cut, a URL earlier in a word made [`split_url`] swallow
/// everything to the next terminator — including the separator that would have
/// cut the word — and [`redact_url`]'s terminal arm echoes what it is given. So
/// `Server=https://vault.local/api;Password=hunter2` and
/// `cb=https://a.com/x&access_token=ghu_…` went out whole: the fix that bounds
/// a URL and the fix that cuts on `;` and `&` each worked alone and did not
/// compose.
///
/// **Adding them to [`is_url_terminator`] outright is the obvious fix and the
/// wrong one**, which is why there are two predicates rather than one extended
/// list. `&` is what separates the parameters *inside* a query string, and
/// [`redact_url`] replaces a query wholesale precisely because a token can be
/// in any parameter and this module does not guess which. Measured:
/// `https://a.com/cb?code=1&state=hunter2` goes from `?[redacted]` to
/// `?[redacted]&state=hunter2`. `;` is the same story — it is a legal query
/// separator too.
///
/// Ahead of the `?` there is no such conflict: a `;` or an `&` in an authority
/// or a path is not URL syntax this module needs to keep, and something else in
/// the word is much the likelier reading.
fn is_url_head_terminator(c: char) -> bool {
    is_url_terminator(c) || matches!(c, ';' | '&')
}

/// Finds the first URL in a fragment and cuts it out of the text around it.
///
/// Returns the text before the URL, its scheme, the URL itself with the `://`
/// removed, and the text after it — or `None` when the fragment holds no URL.
///
/// **Both bounds are the point.** `split_once("://")` treated *everything*
/// before the separator as the scheme and everything after it as the URL, and
/// the terminal arm of [`redact_url`] echoes both verbatim — so a single URL
/// anywhere in a word put the whole of the rest of that word beyond every rule
/// below it. `documentation_url` is in essentially every GitHub REST error
/// body, so that was *any* such body logged alongside a credential:
///
/// ```text
/// {"documentation_url":"https://docs.github.com/rest","token":"ghu_…"}
/// ```
///
/// came out intact. The reverse order leaked for the mirror reason —
/// everything before the `://` became the "scheme" — and a nested object behind
/// a URL was missed even when the URL's own userinfo was caught, because the
/// miss and the catch happened in the same call. The only thing that saved the
/// shape at all was a `?` or `#` *inside* the URL, which made [`redact_url`]
/// replace the tail.
///
/// An empty scheme run means the `://` is not introducing a URL, and the
/// fragment is left to the rules below rather than handed over as a URL with no
/// scheme.
fn split_url(fragment: &str) -> Option<(&str, &str, &str, &str)> {
    let separator = fragment.find("://")?;
    let before = &fragment[..separator];

    // Scheme characters are ASCII, so a byte count is a character boundary.
    let scheme_len = before
        .bytes()
        .rev()
        .take_while(|byte| is_scheme_byte(*byte))
        .count();
    if scheme_len == 0 {
        return None;
    }
    let (prefix, scheme) = before.split_at(before.len() - scheme_len);

    let after = &fragment[separator + "://".len()..];

    // Where the URL ends no matter what, and **the bound every other search
    // here is taken inside**. Searching the rest of the fragment first is a
    // correct answer computed quadratically: a body of *n* URLs would scan the
    // whole remaining text once per URL looking for a `?` that is not there,
    // which on the 860 KB regression case in
    // `a_large_message_does_not_overflow_the_stack` is 17 billion character
    // comparisons. That test is a guard against this module taking the process
    // down, and a redaction pass that never returns takes it down just as
    // effectively as an overflow does.
    let end = after.find(is_url_terminator).unwrap_or(after.len());
    let url = &after[..end];

    // The head is the authority and path — everything ahead of the first `?` or
    // `#`. Only there do `;` and `&` end the URL; inside a query string they
    // are query syntax, and the query is `redact_url`'s to replace wholesale.
    let query = url.find(['?', '#']).unwrap_or(url.len());
    let end = url[..query].find(is_url_head_terminator).unwrap_or(end);
    let (url, remainder) = after.split_at(end);

    Some((prefix, scheme, url, remainder))
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
            format!(
                "{scheme}://{host}{}{separator}{REDACTION}",
                redact_path(path)
            )
        }
        None => format!("{scheme}://{host}{}", redact_path(tail)),
    }
}

/// Applies the shape rules to a URL path, one segment at a time.
///
/// The path is the diagnosable part of a URL and stays that way: a segment is
/// judged on its own, and an ordinary one — `repos`, `owner`, `actions-runner-
/// linux-x64-2.330.0.tar.gz` — is not a secret and is not touched. What this
/// closes is that [`redact_url`] previously applied *no* rule to a path at all,
/// so `https://github.com/o/r/raw/ghu_…/f` was echoed whole while the identical
/// token one character to the left of the `/` would have been replaced. The
/// token-prefix rule is documented as a belt that catches a credential
/// *anywhere*, and a path was the one place it never ran.
///
/// Segment at a time rather than whole, because [`redact_value`] would
/// otherwise see the `/` and hand the whole path to [`looks_like_path`], which
/// is exactly the over-redaction the module documentation promises a full URL
/// escapes.
///
/// Worth knowing: [`OPAQUE_RUN_THRESHOLD`] is 40, and a git object name written
/// as hex is exactly 40 characters, so a `…/raw/<sha1>/f` URL loses its commit
/// to `[redacted]`. That is the module's standing trade — a less readable line
/// against a disclosed credential — and it is called out here because a commit
/// SHA is the one path segment somebody may miss.
fn redact_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        if !segment.is_empty() {
            out.push_str(&redact_value(segment));
        }
    }
    out
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

/// Whose diagnostics these are, and therefore which file they go in.
///
/// # Why the daemon does not share the operator's file
///
/// On the two Unixes a boot-mode registration runs the daemon as `root` while
/// the four application-data directories stay in the operator's profile —
/// `05-infrastructure.md` puts them there and `service install` records those
/// paths into the plist. So two accounts write into one `logs/` directory, and
/// the appender creates its file with the umask default, `0644`. Whichever
/// account opened today's file first owns it, and if that was `root` the
/// operator's own `runner-manager status` can no longer append to it.
///
/// That was not a degraded log. `tracing_appender::rolling::daily` **panics**
/// when it cannot open the file, so every CLI command on such a host died with
/// a backtrace before it did anything — reported on 0.1.17, on a host whose
/// daemon had rolled the file over at midnight as `root`:
///
/// ```text
/// thread 'main' panicked at rolling.rs:156:14:
/// initializing rolling file appender failed: InitError { context: "failed to
/// create log file", source: Os { code: 13, kind: PermissionDenied } }
/// ```
///
/// [`install`] no longer panics — see there — but not panicking would only have
/// turned a crash into an operator who never gets diagnostics again. The two
/// writers are separated instead, so neither can take the other's file: the
/// account that runs the daemon owns [`SERVICE_LOG_STEM`] and the operator owns
/// [`OPERATOR_LOG_STEM`], for as long as the registration lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogRole {
    /// A command the operator ran, or a daemon they started in the foreground.
    Operator,
    /// The daemon a service manager started, which on a boot-mode host is a
    /// different account from the operator's.
    Service,
}

/// The file stem [`LogRole::Operator`] writes.
pub const OPERATOR_LOG_STEM: &str = "runner-manager.log";
/// The file stem [`LogRole::Service`] writes, and what `service status`
/// reports as the daemon's log.
pub const SERVICE_LOG_STEM: &str = "runner-manager.service.log";

impl LogRole {
    /// The file stem this role writes, before the appender's date suffix.
    #[must_use]
    pub const fn file_stem(self) -> &'static str {
        match self {
            Self::Operator => OPERATOR_LOG_STEM,
            Self::Service => SERVICE_LOG_STEM,
        }
    }
}

impl fmt::Display for LogRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Operator => "operator",
            Self::Service => "service",
        })
    }
}

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

    /// No diagnostics file in `logs/` could be opened for appending.
    ///
    /// Both stems are named because [`install`] tries two — the role's own, and
    /// then one qualified by the account — and an operator who is told only
    /// about the second would go looking for a file this process never reached
    /// for first.
    #[error(
        "cannot open a diagnostics file in {}: neither {first_stem}.<date> ({first_source}) \
         nor {second_stem}.<date> ({second_source}) could be appended to",
        directory.display()
    )]
    Appender {
        /// The diagnostics directory.
        directory: PathBuf,
        /// The stem this role would ordinarily write.
        first_stem: String,
        /// Why that one could not be opened.
        first_source: String,
        /// The account-qualified stem tried after it.
        second_stem: String,
        /// Why that one could not be opened either.
        second_source: String,
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
/// `role` decides the file, for the reason [`LogRole`] gives. `default_filter`
/// applies when `RUST_LOG` is unset or unparseable.
///
/// # Errors
///
/// [`LoggingError::Directory`], [`LoggingError::Appender`] and
/// [`LoggingError::AlreadyInstalled`]. **None of them is fatal to the caller**,
/// and the CLI treats all three as a warning: a `host show` that refused to
/// print a capacity because a log file could not be opened would be a worse
/// failure than the one it was reporting.
pub fn install(
    paths: &crate::paths::AppPaths,
    role: LogRole,
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

    let appender = open_appender(&directory, role)?;
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

/// Opens today's diagnostics file, falling back to one only this account can
/// have created.
///
/// # Why there is a second attempt at all
///
/// [`LogRole`] keeps the daemon and the operator apart, which is enough on a
/// host where nothing else ever writes here. Two things still put a file the
/// caller cannot append to under the stem it wants:
///
/// 1. **A privileged command.** Signing in to the machine-scoped store is
///    `sudo runner-manager auth login`, and that run writes the *operator's*
///    stem as `root`. Every unprivileged command for the rest of that day then
///    finds a `root`-owned file under it.
/// 2. **A host upgraded into this change.** Files written before the roles were
///    split are all under [`OPERATOR_LOG_STEM`], and on a boot-mode host the
///    ones from the last few days belong to `root`.
///
/// Neither is worth losing diagnostics over, and neither can be repaired from
/// inside an unprivileged process — it may not chown the file, may not change
/// its mode, and must not delete an existing log. So it writes beside it, under
/// a stem carrying this account's identity, which no other account will choose.
///
/// The fallback is deliberately *not* the first choice. A file named after
/// whoever happened to open it first is a file an operator has to go looking
/// for; the plain stem stays the plain stem, and the qualified one appears only
/// on a host that has the collision.
fn open_appender(
    directory: &Path,
    role: LogRole,
) -> Result<tracing_appender::rolling::RollingFileAppender, LoggingError> {
    let stem = role.file_stem();
    let first = match build_appender(directory, stem) {
        Ok(appender) => return Ok(appender),
        Err(error) => error,
    };

    let qualified = account_qualified_stem(stem);
    match build_appender(directory, &qualified) {
        Ok(appender) => Ok(appender),
        Err(second) => Err(LoggingError::Appender {
            directory: directory.to_path_buf(),
            first_stem: stem.to_string(),
            first_source: first,
            second_stem: qualified,
            second_source: second,
        }),
    }
}

/// One attempt, through the constructor that **returns** its failure.
///
/// `tracing_appender::rolling::daily` is the same thing with an `.expect` on
/// the end, and that `.expect` is a panic in the middle of an operator's `status`
/// command. The whole reason this function exists is that the builder hands the
/// error back instead.
fn build_appender(
    directory: &Path,
    stem: &str,
) -> Result<tracing_appender::rolling::RollingFileAppender, String> {
    tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(stem)
        .build(directory)
        .map_err(|error| error.to_string())
}

/// `runner-manager.log` becomes `runner-manager.<account>.log`.
///
/// The stem carries its own `.log`, so the account goes before it rather than
/// after: the appender appends `.<date>`, and `runner-manager.log.uid-501` would
/// read as a rotated file rather than as another account's.
fn account_qualified_stem(stem: &str) -> String {
    let account = account_tag();
    match stem.rsplit_once('.') {
        Some((head, tail)) => format!("{head}.{account}.{tail}"),
        None => format!("{stem}.{account}"),
    }
}

/// Something stable, filename-safe, and different for every local account.
///
/// The numeric effective user id rather than a name: it needs no lookup, cannot
/// contain a path separator, and is the identity the filesystem actually
/// compared when it refused the open.
#[cfg(unix)]
fn account_tag() -> String {
    // SAFETY: `geteuid` takes no argument, touches no memory this process owns,
    // and is documented never to fail.
    let uid = unsafe { libc::geteuid() };
    format!("uid-{uid}")
}

/// As the Unix half, from the one identity Windows exposes without a lookup.
///
/// Sanitized rather than trusted: this becomes a file name, and `USERNAME` is
/// an ordinary environment variable that a caller may set to anything at all,
/// including something holding a path separator.
#[cfg(windows)]
fn account_tag() -> String {
    let raw = std::env::var("USERNAME").unwrap_or_default();
    let safe: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if safe.is_empty() {
        "other-account".to_string()
    } else {
        format!("user-{safe}")
    }
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

                // 13. A URL earlier in the same word. `redact_core` split on the
                //     first `://` and handed everything before it to
                //     `redact_url` as a "scheme" and everything after it as
                //     the URL -- and the terminal arm of `redact_url` echoes
                //     both verbatim. So one URL anywhere in a word put the
                //     whole of the rest of that word beyond every rule below.
                //     `documentation_url` is in essentially every GitHub REST
                //     error body, which makes that "any error body logged
                //     alongside a credential".
                tracing::error!(
                    "api failed: {{\"message\":\"Bad credentials\",\"documentation_url\":\"https://docs.github.com/rest\",\"token\":\"{secret}\"}}"
                );
                // The reverse order leaked for the mirror reason: everything
                // before the `://` became the scheme, and was echoed.
                tracing::error!(
                    "api failed: {{\"token\":\"{secret}\",\"documentation_url\":\"https://docs.github.com/rest\"}}"
                );
                // A nested object behind a URL, which is the shape a clone
                // failure arrives in.
                tracing::error!(
                    "clone failed: {{\"remote\":\"https://github.com/o/r.git\",\"body\":{{\"password\":\"{secret}\"}}}}"
                );

                // 14. A value with no key of its own: an array element. The
                //     structural cut recursed on the *raw* fragment, and the
                //     terminal fallback then handed it to `redact_value` with
                //     its quote still attached -- so `"ghu_…` failed
                //     `starts_with("ghu_")`, failed `is_opaque_char` on the
                //     quote, failed the `eyJ` test, and failed
                //     `looks_like_path`. This is shape 9's defect one step
                //     down: "only the first pair is examined" became "a value
                //     with no key of its own is never examined", and it
                //     survived because there was no array among the twelve
                //     shapes above.
                tracing::error!("registration failed: {{\"tokens\":[\"{secret}\",\"x\"]}}");
                tracing::error!("registration failed: {{\"tokens\":[\"x\",\"{secret}\"]}}");
                tracing::error!("registration failed: [\"x\",\"{secret}\"]");
                tracing::error!("registration failed: [{{\"id\":1}},[\"{secret}\"]]");
                let listed = StoreError {
                    body: format!("{{\"tokens\":[\"x\",\"{secret}\"]}}"),
                };
                tracing::error!(reason = ?listed, "the secret store rejected the list");

                // 15. `;` as the separator. It is in `WRAPPERS`, so it was
                //     recognised as punctuation, and it was not in
                //     `STRUCTURAL`, so it never cut a word. It is what
                //     separates the pairs of a Windows connection string, of a
                //     credential string, and of a cookie header written
                //     without a space -- `d2`'s territory exactly.
                tracing::error!("store rejected: Server=host;Database=x;Password={secret};");
                tracing::error!("store rejected: user=operator;password={secret}");
                tracing::error!("store rejected: theme=dark;session={secret}");

                // 16. Wrapped in an element rather than in a quote.
                //     `split_wrappers` strips only the *outermost* `<` and
                //     `>`, so `<string>…</string>` arrived as
                //     `string>…</string`, which matches no rule at all. `d3`'s
                //     installers handle launchd plists, which is where this
                //     shape comes from.
                tracing::error!("plist rejected: <string>{secret}</string>");
                tracing::error!("plist rejected: <key>token</key><string>{secret}</string>");

                // 17. A `;` or an `&` *after a URL in the same word*. This is
                //     shape 15 and shape 11 with one thing changed: a URL
                //     earlier in the word. `STRUCTURAL` has nine characters and
                //     `is_url_terminator` recognised seven of them -- `;` and
                //     `&` were missing -- and the URL branch runs *ahead* of
                //     the structural cut. So `split_url` swallowed everything
                //     to the next terminator, including the separator that
                //     would have cut the word, and `redact_url`'s terminal arm
                //     echoed it verbatim.
                //
                //     The L3 fix (bounding the URL) and the L1 fix (cutting on
                //     `;` and `&`) each work alone and did not compose: this
                //     commit added `;` to `STRUCTURAL` *for connection strings*
                //     while leaving the path a URL opens straight through it.
                //     A connection string whose `Server=` is a URL is exactly
                //     `d2`'s shape, and a systemd `Environment=` line is
                //     `d3`'s.
                tracing::error!(
                    "store rejected: Server=https://vault.local/api;Password={secret};"
                );
                tracing::error!("keychain error: url=https://kc.local;secret={secret}");
                tracing::error!("unit rejected: Environment=API=https://a.com/v1;TOKEN={secret}");
                tracing::error!("token exchange failed: cb=https://a.com/x&access_token={secret}");
                tracing::error!(
                    "dsn rejected: dsn=https://sentry.local/1;password={secret};user=x"
                );
                tracing::error!(
                    "callback failed: redirect=https://a.com/cb&state=1&access_token={secret}"
                );
                let routed = StoreError {
                    body: format!("Server=https://vault.local/api;Password={secret};"),
                };
                tracing::error!(reason = ?routed, "the secret store rejected the connection string");

                // 18. A credential key whose value is not in its own fragment.
                //     The empty-value skip is right, but its justification --
                //     "the value is in the next fragment, where the structural
                //     cut reaches it" -- was false: `redact_fragment` carried
                //     nothing across the cut, so nothing ever reached it. An
                //     array, a nested object, an empty pair and a plist
                //     key/value pair are four spellings of the same gap.
                tracing::error!("store rejected: {{\"password\":[\"{secret}\"]}}");
                tracing::error!("store rejected: {{\"password\":{{\"v\":\"{secret}\"}}}}");
                tracing::error!("store rejected: Password=;{secret}");
                tracing::error!("plist rejected: <key>password</key><string>{secret}</string>");

                // 19. A structural character *inside* a credential value. `,`
                //     and `&` could already split a secret; this commit added
                //     `;`, `<` and `>`, so each of those became a new character
                //     that can cut a punctuated password in half and leave the
                //     tail standing.
                tracing::error!("store rejected: {{\"password\":\"a<{secret}>b\"}}");
                tracing::error!("store rejected: {{\"password\":\"a&{secret},b\"}}");

                // 20. A secret in a URL *path*. `redact_url` applies no shape
                //     rule to the path at all, so a token that reaches one is
                //     echoed whole -- and the token-prefix rule is documented
                //     as a belt that catches a credential anywhere.
                //
                //     The two workspace paths are excluded, and the exclusion
                //     is a real limitation rather than a convenience. A path is
                //     judged one segment at a time, because judging the whole
                //     of a URL path with `looks_like_path` would redact every
                //     URL with two segments in it -- which is the
                //     over-redaction the module documentation explicitly
                //     promises a full URL escapes. A filesystem path pasted
                //     into a URL path is therefore indistinguishable from an
                //     ordinary deep URL path: `/var/lib/…` and `/repos/o/r/…`
                //     are the same shape, segment by segment. A *credential* in
                //     a path is caught, because a credential has a shape of its
                //     own; a path in a path is not.
                if !looks_like_path(secret) {
                    tracing::error!("download failed: https://github.com/o/r/raw/{secret}/f");
                    tracing::error!("download failed: https://github.com/o/r/raw/{secret}");
                }

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

        let outcome = install(&paths, LogRole::Operator, "trace");

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
    // Two accounts, one logs/ directory
    // -----------------------------------------------------------------------

    /// The daemon and the operator do not reach for the same file.
    ///
    /// Cheap, and it is the whole of the separation: everything else about
    /// [`LogRole`] follows from these two names being different.
    #[test]
    fn the_daemon_and_the_operator_write_different_files() {
        assert_ne!(
            LogRole::Service.file_stem(),
            LogRole::Operator.file_stem(),
            "a boot-mode daemon runs as another account and creates its file 0644; sharing a \
             stem hands whichever of them opened it first the day's file and locks the other out"
        );
        assert_eq!(LogRole::Operator.file_stem(), OPERATOR_LOG_STEM);
        assert_eq!(LogRole::Service.file_stem(), SERVICE_LOG_STEM);
    }

    /// A file this account may not append to is written *beside*, not panicked
    /// on.
    ///
    /// This is the reported 0.1.17 crash, reproduced at the mode that caused
    /// it. On the host it was ownership — `root` had rolled the file over at
    /// midnight — and an unprivileged test cannot make a `root`-owned file, so
    /// it makes an unwritable one instead: the appender's `OpenOptions` refuse
    /// both with the same `EACCES`, and refusing was what
    /// `tracing_appender::rolling::daily` turned into a panic.
    #[cfg(unix)]
    #[test]
    fn a_log_file_this_account_cannot_append_to_is_written_beside() {
        use std::os::unix::fs::PermissionsExt as _;

        // `root` is not subject to the mode bits, so it would sail through the
        // very open this test needs to fail.
        if account_tag() == "uid-0" {
            return;
        }

        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = crate::paths::AppPaths::rooted_at(root.path());
        paths
            .create_all()
            .expect("the four directories are created");

        // Every date the appender might choose, so the test cannot flake on a
        // run that straddles midnight UTC.
        let logs = paths.logs_dir().to_path_buf();
        let today = chrono::Utc::now();
        for date in [
            (today - chrono::Duration::days(1))
                .format("%Y-%m-%d")
                .to_string(),
            today.format("%Y-%m-%d").to_string(),
            (today + chrono::Duration::days(1))
                .format("%Y-%m-%d")
                .to_string(),
        ] {
            let taken = logs.join(format!("{OPERATOR_LOG_STEM}.{date}"));
            std::fs::write(&taken, b"another account's diagnostics").expect("writable");
            std::fs::set_permissions(&taken, std::fs::Permissions::from_mode(0o444))
                .expect("the mode is applied");
        }

        let mut appender = open_appender(&logs, LogRole::Operator)
            .expect("a diagnostics file is opened beside the one this account may not append to");
        appender
            .write_all(b"a line\n")
            .expect("the line is written");
        appender.flush().expect("the line is flushed");

        let qualified = account_qualified_stem(OPERATOR_LOG_STEM);
        let written: Vec<String> = std::fs::read_dir(&logs)
            .expect("the directory is readable")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            written.iter().any(|name| name.starts_with(&qualified)),
            "expected a file under {qualified:?} beside the unwritable ones, and found {written:?}"
        );
        for name in &written {
            if name.starts_with(&qualified) {
                continue;
            }
            assert_eq!(
                std::fs::read(logs.join(name)).expect("readable"),
                b"another account's diagnostics",
                "{name} belongs to another account and must not have been touched"
            );
        }
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
    fn a_url_does_not_make_the_rest_of_its_word_unredactable() {
        // `redact_core` split on the first `://` and handed *everything*
        // before it to `redact_url` as a scheme and everything after it as a
        // URL. The terminal arm of `redact_url` echoes both verbatim, so a
        // single URL anywhere in a word turned the whole of the rest of that
        // word into text no rule below could reach. The only thing that saved
        // the shape was a `?` or `#` inside the URL, which made `redact_url`
        // replace the tail.
        //
        // `documentation_url` is in essentially every GitHub REST error body,
        // so this was any such body logged alongside a credential.
        let body = format!(
            "{{\"message\":\"Bad credentials\",\"documentation_url\":\"https://docs.github.com/rest\",\"token\":\"{USER_TOKEN}\"}}"
        );
        let redacted = redact(&body);
        assert!(!redacted.contains(USER_TOKEN), "leaked: {redacted}");
        // The URL is the diagnosable part and must survive, or nobody keeps
        // this redaction.
        assert!(
            redacted.contains("https://docs.github.com/rest"),
            "the URL should survive: {redacted}"
        );

        // The mirror order: everything before the `://` became the "scheme".
        let reversed = format!(
            "{{\"token\":\"{USER_TOKEN}\",\"documentation_url\":\"https://docs.github.com/rest\"}}"
        );
        let redacted = redact(&reversed);
        assert!(!redacted.contains(USER_TOKEN), "leaked: {redacted}");

        // A nested object behind a URL was missed even when the URL's own
        // userinfo was caught, because the miss and the catch happened in the
        // same call.
        let clone = format!(
            "{{\"remote\":\"https://x-access-token:{USER_TOKEN}@github.com/o/r.git\",\"body\":{{\"password\":\"hunter2\"}}}}"
        );
        let redacted = redact(&clone);
        assert!(!redacted.contains(USER_TOKEN), "leaked: {redacted}");
        assert!(!redacted.contains("hunter2"), "leaked: {redacted}");
        assert!(
            redacted.contains("@github.com/o/r.git"),
            "the remote should stay diagnosable: {redacted}"
        );

        // A URL still owns its own query string, which is why the URL check
        // sits ahead of the structural cut: `?` and `#` are not structural
        // characters, and an OAuth response puts the token after one of them.
        assert_eq!(
            redact(&format!(
                "{{\"url\":\"https://api.github.com/x?token={USER_TOKEN}\"}}"
            )),
            format!("{{\"url\":\"https://api.github.com/x?{REDACTION}\"}}")
        );
        // And a URL standing on its own is untouched.
        assert_eq!(
            redact("GET https://api.github.com/repos/o/r/actions/runners"),
            "GET https://api.github.com/repos/o/r/actions/runners"
        );

        // A URL that is a credential key's *own* value keeps its scheme, host
        // and path like every other URL -- a URL is not a token, and this
        // module keeps exactly that much of one everywhere else. What must not
        // happen is the key's empty value being redacted on the way past,
        // which put the URL out behind a `[redacted]` that had replaced
        // nothing: `token=[redacted]https://evil.example/x`. Bounding the URL
        // is what created that shape, and pass one declining an empty value is
        // what closes it.
        assert_eq!(
            redact("token=https://evil.example/x"),
            "token=https://evil.example/x"
        );
        assert_eq!(
            redact("{\"token\":\"https://evil.example/x\"}"),
            "{\"token\":\"https://evil.example/x\"}"
        );
        // An empty credential value is nothing to redact wherever it sits, and
        // saying otherwise reports a secret in a place none was.
        assert_eq!(redact("{\"password\":\"\"}"), "{\"password\":\"\"}");
    }

    #[test]
    fn an_array_element_is_judged_without_the_quote_that_wraps_it() {
        // The structural cut recursed on the *raw* fragment, and the terminal
        // fallback then called `redact_value` with the wrappers still on. A
        // fragment carrying no `:` or `=` of its own -- which is exactly what
        // an array element is -- therefore reached the shape rules as
        // `"ghu_…`: `starts_with("ghu_")` fails, `is_opaque_char` fails on the
        // quote, `starts_with("eyJ")` fails, and `looks_like_path` never gets
        // a clean look at `"C:\Users\…`.
        //
        // This is the defect the structural cut was written to close, one step
        // further down: "only the first key/value pair is ever examined"
        // became "a value with no key of its own is never examined". It
        // survived a round because `scan_for_leaks` had no array among its
        // twelve shapes.
        for shape in [
            format!("{{\"tokens\":[\"{USER_TOKEN}\",\"x\"]}}"),
            format!("{{\"tokens\":[\"x\",\"{USER_TOKEN}\"]}}"),
            format!("[\"x\",\"{USER_TOKEN}\"]"),
            format!("[{{\"id\":1}},[\"{USER_TOKEN}\"]]"),
            // The `Debug`-escaped spelling of the same thing.
            format!("{{\\\"tokens\\\":[\\\"x\\\",\\\"{USER_TOKEN}\\\"]}}"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(USER_TOKEN),
                "leaked from {shape}: {redacted}"
            );
            assert!(redacted.contains(REDACTION), "{shape} -> {redacted}");
        }

        // Every other shape rule was reachable the same way.
        let jit = format!("{{\"items\":[\"{JIT_BLOB}\"]}}");
        assert!(!redact(&jit).contains(JIT_BLOB), "{}", redact(&jit));
        let assertions = format!("{{\"assertions\":[\"{JWT}\"]}}");
        assert!(
            !redact(&assertions).contains(JWT),
            "{}",
            redact(&assertions)
        );
        let opaque = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvut";
        assert!(opaque.len() > OPAQUE_RUN_THRESHOLD, "{}", opaque.len());
        let listed = format!("[\"x\",\"{opaque}\"]");
        assert!(!redact(&listed).contains(opaque), "{}", redact(&listed));

        // A path in an array. `07-security.md` requires paths redacted, and
        // only `looks_like_path` can see one -- with a clean look at the value
        // and not before.
        let roots = format!("{{\"roots\":[\"x\",\"{WINDOWS_WORKSPACE}\"]}}");
        let redacted = redact(&roots);
        assert!(!redacted.contains(WINDOWS_WORKSPACE), "leaked: {redacted}");
        assert!(redacted.contains(PATH_REDACTION), "{redacted}");

        // The array survives being scrubbed: this is a scrubber, not a
        // deleter.
        assert_eq!(
            redact("labels=[\"linux\",\"x64\"]"),
            "labels=[\"linux\",\"x64\"]"
        );
    }

    #[test]
    fn a_semicolon_cuts_a_word_the_way_a_comma_does() {
        // `;` was in `WRAPPERS` -- recognised as punctuation -- and not in
        // `STRUCTURAL`, so it never cut a word. It is the separator for a
        // Windows connection string, for a credential string, and for cookie
        // pairs written without a space, which is `d2`'s territory exactly.
        // `Set-Cookie: theme=dark; session=…` was safe only because of the
        // space after the `;`.
        for shape in [
            "store rejected: Server=host;Database=x;Password=hunter2;",
            "store rejected: user=operator;password=hunter2",
            "Server=host;Password=hunter2;Database=x",
        ] {
            let redacted = redact(shape);
            assert!(
                !redacted.contains("hunter2"),
                "leaked from {shape}: {redacted}"
            );
        }

        let cookies = format!("theme=dark;session={USER_TOKEN}");
        let redacted = redact(&cookies);
        assert!(!redacted.contains(USER_TOKEN), "leaked: {redacted}");

        // Separators go back verbatim, so ordinary prose is unaffected.
        assert_eq!(
            redact("started; then reconciled; then idled"),
            "started; then reconciled; then idled"
        );
        assert_eq!(
            redact("desired 3;active 1;headroom 2"),
            "desired 3;active 1;headroom 2"
        );
    }

    #[test]
    fn an_element_wrapped_value_is_redacted() {
        // `split_wrappers` strips only the *outermost* `<` and `>`, so
        // `<string>ghu_…</string>` arrived as `string>ghu_…</string`, which
        // matches no rule at all. `d3`'s installers handle launchd plists,
        // which is where this shape comes from; a systemd unit line is the
        // `key=value` spelling and was already covered.
        for shape in [
            format!("<string>{USER_TOKEN}</string>"),
            format!("<key>token</key><string>{USER_TOKEN}</string>"),
            format!("<dict><key>Token</key><string>{USER_TOKEN}</string></dict>"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(USER_TOKEN),
                "leaked from {shape}: {redacted}"
            );
            assert!(redacted.contains(REDACTION), "{shape} -> {redacted}");
        }

        // The element names survive: they are what says the line was about a
        // plist at all.
        let plist = format!("<key>token</key><string>{JIT_BLOB}</string>");
        let redacted = redact(&plist);
        assert!(!redacted.contains(JIT_BLOB), "leaked: {redacted}");
        assert!(redacted.contains("<key>token</key>"), "{redacted}");

        // An angle bracket in ordinary text is re-emitted verbatim.
        assert_eq!(redact("Custom<Io>"), "Custom<Io>");
    }

    #[test]
    fn a_redacted_value_keeps_the_punctuation_that_wrapped_it() {
        // Pass one returned `format!("{key}{separator}{REDACTION}")` and
        // dropped the value's trailing wrapper, so a redacted object came out
        // with an unbalanced quote: `{"password":[redacted]"}`. Pass two
        // already put `lead` and `trail` back.
        //
        // Worth fixing because this module argues, correctly, that the
        // structure around a redaction is what keeps a line diagnosable -- and
        // a reader who cannot parse the line cannot tell a redaction from a
        // truncation.
        assert_eq!(
            redact("{\"password\":\"hunter2\"}"),
            format!("{{\"password\":\"{REDACTION}\"}}")
        );
        assert_eq!(
            redact(&format!("{{\"access_token\":\"{USER_TOKEN}\"}}")),
            format!("{{\"access_token\":\"{REDACTION}\"}}")
        );
        assert_eq!(
            redact(&format!(
                "[{{\"id\":1}},{{\"access_token\":\"{USER_TOKEN}\"}}]"
            )),
            format!("[{{\"id\":1}},{{\"access_token\":\"{REDACTION}\"}}]")
        );
        // The `Debug`-escaped spelling keeps its escaped quotes.
        assert_eq!(
            redact("{\\\"password\\\":\\\"hunter2\\\"}"),
            format!("{{\\\"password\\\":\\\"{REDACTION}\\\"}}")
        );

        // The point of all of it: what the sink writes is still the JSON it
        // was handed, minus the secret.
        let line = redact(&format!(
            "{{\"runner_id\":42,\"access_token\":\"{USER_TOKEN}\"}}"
        ));
        serde_json::from_str::<Value>(&line)
            .unwrap_or_else(|error| panic!("a redacted body must still parse: {line} ({error})"));
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

            // A `;` or an `&` after a URL in the same word. The URL branch runs
            // ahead of the structural cut and `split_url` did not stop at
            // either character, so the separator that would have cut the word
            // was swallowed into the URL and echoed.
            tracing::error!("store rejected: Server=https://vault.local/api;Password=hunter2;");
            tracing::error!("keychain error: url=https://kc.local;password=hunter2");
            tracing::error!("unit rejected: Environment=API=https://a.com/v1;PASSWORD=hunter2");
            tracing::error!("token exchange failed: cb=https://a.com/x&password=hunter2");

            // A credential key whose value is in a *later* fragment. The
            // empty-value skip is right; the claim that the structural cut
            // reaches such a value was not, because nothing carried the key
            // across the cut.
            tracing::error!("store rejected: {{\"password\":[\"hunter2\"]}}");
            tracing::error!("store rejected: {{\"password\":{{\"v\":\"hunter2\"}}}}");
            tracing::error!("store rejected: Password=;hunter2");
            tracing::error!("plist rejected: <key>password</key><string>hunter2</string>");
            tracing::error!(
                "plist rejected: <dict><key>password</key><string>hunter2</string></dict>"
            );

            // A structural character inside the value. `,` and `&` could
            // already split a secret; this commit added `;`, `<` and `>`.
            //
            // The pieces are spelled so that none of them is a substring of
            // anything the line legitimately keeps -- `ss` would have "found" a
            // leak in the surviving key `password`, which is a check that fails
            // for the wrong reason and is no better than one that cannot fail.
            tracing::error!("store rejected: {{\"password\":\"qq<vv>xx\"}}");
            tracing::error!("store rejected: {{\"password\":\"j1&k2,m3\"}}");
            tracing::error!("store rejected: {{\"password\":\"n4;p5<q6>r7,t8\"}}");
        });

        assert!(
            !output.contains("hunter2"),
            "a short credential leaked through the sink:\n{output}"
        );
        // The punctuated passwords: every piece a structural character can cut
        // one into has to go, not just the piece that kept the key company.
        for piece in [
            "qq", "vv", "xx", "j1", "k2", "m3", "n4", "p5", "q6", "r7", "t8",
        ] {
            assert!(
                !output.contains(piece),
                "a structural character split a secret and the tail survived \
                 ({piece}):\n{output}"
            );
        }
        assert!(output.contains(REDACTION), "{output}");
        // Sixteen lines, or the sink was never reached and "no secret found" is
        // true of an empty string.
        assert_eq!(
            output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
            16,
            "{output}"
        );
    }

    /// The multi-word plist spelling, which is worse than the one-word one:
    /// the credential key and the value are in the same word, but the value
    /// itself is two words, so closing it needs the fragment carry to reach the
    /// word-level follow-on rule.
    #[test]
    fn a_credential_value_that_runs_past_its_own_word_is_still_redacted() {
        let capture = Capture::default();
        let output = emit(&capture, || {
            tracing::error!("plist rejected: <key>password</key><string>correct horse</string>");
            tracing::error!("plist rejected: <key>password</key> <string>correct horse</string>");
        });
        for piece in ["correct", "horse"] {
            assert!(
                !output.contains(piece),
                "a multi-word credential value leaked ({piece}):\n{output}"
            );
        }
    }

    /// The other half of the fragment carry: it must not swallow the ordinary,
    /// *closed* pairs sitting next to a credential.
    ///
    /// Every shape here is one the carry has an opportunity to over-redact —
    /// a closed empty value, a neighbouring key, the pairs of a connection
    /// string, and the element names of a plist. Redaction that eats the
    /// diagnostics is redaction nobody keeps, and a carry with no terminator
    /// is exactly how that happens.
    #[test]
    fn the_fragment_carry_stops_where_the_value_does() {
        for (input, expected) in [
            (
                "{\"password\":\"abc\",\"user\":\"bob\"}",
                format!("{{\"password\":\"{REDACTION}\",\"user\":\"bob\"}}"),
            ),
            (
                "Server=host;Password=hunter2;User=bob",
                format!("Server=host;Password={REDACTION};User=bob"),
            ),
            (
                "{\"password\":\"\",\"user\":\"bob\"}",
                "{\"password\":\"\",\"user\":\"bob\"}".to_string(),
            ),
            (
                "<dict><key>password</key><string>hunter2</string></dict>",
                format!("<dict><key>password</key><string>{REDACTION}</string></dict>"),
            ),
            (
                "{\"password\":\"qq<vv>xx\"}",
                format!("{{\"password\":\"{REDACTION}<{REDACTION}>{REDACTION}\"}}"),
            ),
        ] {
            assert_eq!(redact(input), expected, "from {input}");
        }

        // A closed value ends the claim, so the word after it is ordinary text.
        assert_eq!(
            redact("{\"password\":\"x\"} ok"),
            format!("{{\"password\":\"{REDACTION}\"}} ok")
        );
        assert_eq!(
            redact("Server=host;Password=hunter2; ok"),
            format!("Server=host;Password={REDACTION}; ok")
        );

        // `{"password":""} ok` is *not* on that list, and the reason is worth
        // recording rather than asserting away. `split_wrappers` strips the
        // empty value with the rest of the trailing punctuation, so the word
        // reaches `redact_word` as the core `password":` — a bare credential
        // key, which the stem rule has always read as "the value is the next
        // word". That rule predates the carry, is untouched by it, and fires
        // first; the empty-value skip below it never gets a look. So the `ok`
        // is redacted, exactly as it was before any of this.
        assert_eq!(
            redact("{\"password\":\"\"} ok"),
            format!("{{\"password\":\"\"}} {REDACTION}")
        );
        // What the empty-value skip does still guarantee is the thing it was
        // written for: no `[redacted]` is invented *inside* the pair itself.
        assert_eq!(redact("{\"password\":\"\"}"), "{\"password\":\"\"}");

        // Ordinary prose is untouched: the carry is only ever armed by a
        // credential key.
        assert_eq!(
            redact("started; then reconciled; then idled"),
            "started; then reconciled; then idled"
        );
        assert_eq!(redact("Custom<Io>"), "Custom<Io>");
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

    /// `;` and `&` end a URL, but only ahead of its query string.
    ///
    /// `STRUCTURAL` has nine characters and `is_url_terminator` recognised
    /// seven of them. Because the URL branch runs *ahead* of the structural
    /// cut, a URL earlier in a word made `split_url` swallow everything to the
    /// next terminator — including the `;` or `&` that would have cut the word
    /// — and `redact_url`'s terminal arm echoes what it is given. So the L3 fix
    /// (bounding a URL) and the L1 fix (cutting on `;` and `&`) did not
    /// compose, and this commit added `;` to `STRUCTURAL` for connection
    /// strings while leaving the path a URL opens straight through it.
    #[test]
    fn a_separator_after_a_url_still_cuts_the_word() {
        for shape in [
            format!("store rejected: Server=https://vault.local/api;Password={USER_TOKEN};"),
            format!("keychain error: url=https://kc.local;secret={USER_TOKEN}"),
            format!("unit rejected: Environment=API=https://a.com/v1;TOKEN={USER_TOKEN}"),
            format!("token exchange failed: cb=https://a.com/x&access_token={USER_TOKEN}"),
            format!("dsn rejected: dsn=https://sentry.local/1;password={USER_TOKEN};user=x"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(USER_TOKEN),
                "leaked from {shape}:\n{redacted}"
            );
        }

        // The URL itself still survives, or nobody keeps this redaction.
        assert_eq!(
            redact("store rejected: Server=https://vault.local/api;Password=hunter2;"),
            format!("store rejected: Server=https://vault.local/api;Password={REDACTION};")
        );

        // The obvious fix is the wrong one, and this is what it costs. Making
        // `;` and `&` terminators everywhere ends a URL *inside* its own query
        // string, and `redact_url` replaces a query wholesale precisely because
        // a token can be in any parameter and this module does not guess which:
        // `?[redacted]` would become `?[redacted]&state=hunter2`. So the cut is
        // restricted to the part of the URL ahead of the first `?` or `#`.
        assert_eq!(
            redact("https://a.com/cb?code=1&state=hunter2"),
            format!("https://a.com/cb?{REDACTION}")
        );
        assert_eq!(
            redact("https://a.com/cb#code=1&state=hunter2"),
            format!("https://a.com/cb#{REDACTION}")
        );
        assert_eq!(
            redact(&format!(
                "https://a.com/cb?a=1;b=2&access_token={USER_TOKEN}"
            )),
            format!("https://a.com/cb?{REDACTION}")
        );

        // And leaving `\` out of the terminators is still right: a Windows
        // path used as a URL password puts the `@` that identifies the
        // userinfo behind the first backslash, and `redact_url` echoes what it
        // is given.
        assert_eq!(
            redact(r"https://x-access-token:C:\Users\op\p@github.com/o/r.git"),
            format!("https://{REDACTION}@github.com/o/r.git")
        );
    }

    /// A secret in a URL *path* is echoed verbatim.
    ///
    /// `redact_url` applied no shape rule to the path at all. The design
    /// intends a path to be diagnosable — and it still is — but the
    /// token-prefix rule is documented as a belt that catches a credential
    /// *anywhere*, and a path was the one place it never ran.
    #[test]
    fn a_secret_in_a_url_path_is_redacted_and_the_rest_of_the_path_is_not() {
        for shape in [
            format!("https://github.com/o/r/raw/{USER_TOKEN}/f"),
            format!("https://api.github.com/{JIT_BLOB}"),
            format!("https://a.com/x/{JWT}?page=2"),
        ] {
            let redacted = redact(&shape);
            assert!(
                !redacted.contains(USER_TOKEN)
                    && !redacted.contains(JIT_BLOB)
                    && !redacted.contains(JWT),
                "leaked from {shape}:\n{redacted}"
            );
        }

        assert_eq!(
            redact(&format!("https://github.com/o/r/raw/{USER_TOKEN}/f")),
            format!("https://github.com/o/r/raw/{REDACTION}/f")
        );

        // The rest of the path is exactly as diagnosable as it was: a segment
        // is judged on its own, and an ordinary one is not a secret.
        for url in [
            "https://api.github.com/repos/owner/repo/actions/runners",
            "https://github.com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz",
            "https://github.com/o/r.git",
            "https://github.com/@owner/repo",
            "https://api.github.com/repos/o/r/actions/runners/42",
        ] {
            assert_eq!(redact(url), url, "over-redacted a diagnosable path: {url}");
        }
    }

    /// A large message must not take the process down.
    ///
    /// The URL branch recursed into `redact_core` on both sides of the cut. The
    /// termination argument was sound — every call is on a strictly shorter
    /// slice — and it was silent on *depth*, which was linear in the length of
    /// the input. A message of ~2000 URL-carrying items, about 86 KB, exited
    /// `0xc00000fd STATUS_STACK_OVERFLOW`.
    ///
    /// **A stack overflow is not catchable — it aborts the process.** A large
    /// HTTP error body is attacker-influenceable content, so this was a way to
    /// kill the agent from inside its own log sink, which is worse than any
    /// leak: a sink that is not running redacts nothing.
    ///
    /// Note what this test can and cannot do. An overflow aborts the test
    /// binary rather than failing an assertion, so the value of this test is
    /// that **the suite completes at all**; the assertions below only confirm
    /// it did the work rather than skipping it.
    #[test]
    fn a_large_message_does_not_overflow_the_stack() {
        // 20000 items is ~860 KB and an order of magnitude past the ~2000 that
        // was measured to abort. It is also what the commit *before* the URL
        // branch survived, because that branch returned without recursing --
        // so this is a regression guard with the margin the regression had.
        const ITEMS: usize = 20_000;
        let body = r#"{"url":"https://api.github.com/repos/o/r"},"#.repeat(ITEMS);
        assert!(body.len() > 800_000, "the premise is a large body");

        let redacted = redact(&body);
        assert!(
            redacted.contains("https://api.github.com/repos/o/r"),
            "the URLs are the diagnosable part and must survive"
        );

        // The same depth, reached through the structural cut and through a
        // credential value rather than through a bare URL.
        let nested = format!("{{\"error\":{{\"body\":{{\"list\":[{}]}}}}}}", body);
        assert!(!redact(&nested).is_empty());

        // A long run with no URL in it at all, so the structural loop is
        // exercised on its own.
        let flat = "{\"a\":1},".repeat(ITEMS);
        assert!(!redact(&flat).is_empty());

        // And one long unbroken URL, where the *path* loop is what iterates.
        let long_path = format!("https://a.com/{}", "seg/".repeat(ITEMS));
        assert!(!redact(&long_path).is_empty());
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
        // Pass one puts the value's wrapping quote back, so what comes out is
        // still the object that went in. It used to emit
        // `{"x-hub-signature-256":[redacted]"}` -- an unbalanced quote in a
        // line this module argues has to stay diagnosable.
        //
        // This case is also `redact_core`'s two-pass witness, and the comment
        // there names it: the `=` comes first and names nothing, but what
        // follows it is a whole HMAC -- non-empty -- so a merged pass inspects
        // that value and returns before ever reaching the `:` that names
        // `x-hub-signature-256`.
        assert_eq!(
            redact(&format!("{{\"x-hub-signature-256\":\"sha256={hmac}\"}}")),
            format!("{{\"x-hub-signature-256\":\"{REDACTION}\"}}")
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
