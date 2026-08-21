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
//!   treated as an opaque secret. A full SHA-256 digest is 64 hex characters
//!   and is therefore redacted even though it is not secret. Log a short
//!   prefix when a digest needs to be visible.
//! - A word ending in `:` or `=` whose stem is a credential header name causes
//!   the next two words to be redacted, so `Authorization: Bearer ghu_…` loses
//!   both the scheme and the token.
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

/// Whether this sink will emit a field's value rather than replacing it.
#[must_use]
pub fn is_field_allowed(name: &str) -> bool {
    ALLOWED_FIELDS.binary_search(&name).is_ok()
}

fn normalise_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace(['-', '_'], ".")
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

/// Redacts one whitespace-delimited word, and says how many following words the
/// word implicates.
fn redact_word(word: &str) -> (String, u32) {
    // Wrapping punctuation is kept so that JSON-ish and prose context survives
    // — `("ghu_…")` should become `("[redacted]")`, not `[redacted]`.
    let leading = word.len() - word.trim_start_matches(WRAPPERS).len();
    let (prefix, rest) = word.split_at(leading);
    let core_len = rest.trim_end_matches(WRAPPERS).len();
    let (core, suffix) = rest.split_at(core_len);

    if core.is_empty() {
        return (word.to_string(), 0);
    }

    // A bare credential key or scheme word: the value is the next word.
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
    // A URL survives, minus its query string. Query strings carry tokens; the
    // scheme, host and path are what makes a log line diagnosable.
    if core.contains("://") {
        return match core.split_once('?') {
            Some((base, _)) => format!("{base}?{REDACTION}"),
            None => core.to_string(),
        };
    }

    // `key=value` and `key:value` in a single word.
    for separator in ['=', ':'] {
        if let Some((key, value)) = core.split_once(separator) {
            if is_credential_key(key) {
                return format!("{key}{separator}{REDACTION}");
            }
            // Not a credential key, but the value may still be a path or a
            // token: `runtime=/var/lib/runner-manager/…`.
            if separator == '=' && !value.is_empty() {
                return format!("{key}={}", redact_value(value));
            }
        }
    }

    redact_value(core)
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

    if value.len() >= OPAQUE_RUN_THRESHOLD && value.chars().all(is_opaque_char) {
        return REDACTION.to_string();
    }

    value.to_string()
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
    /// The diagnostics directory could not be created.
    #[error("cannot create the log directory {}: {source}", directory.display())]
    Directory {
        /// The directory that could not be created.
        directory: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
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

    let directory = paths.logs_dir().to_path_buf();
    std::fs::create_dir_all(&directory).map_err(|source| LoggingError::Directory {
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

    fn secrets() -> Vec<&'static str> {
        vec![
            USER_TOKEN,
            SERVER_TOKEN,
            FINE_GRAINED,
            JIT_BLOB,
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

                // 6. Carried on a span rather than on the event.
                let span = tracing::info_span!("attempt", jit_config = %secret);
                let _entered = span.enter();
                tracing::info!(event = "inside_span", "in a span");
            }
        });

        let output = capture.text();
        for secret in secrets() {
            if output.contains(secret) {
                return Err(format!(
                    "the sink emitted a secret verbatim: {secret}\n--- output ---\n{output}"
                ));
            }
        }
        Ok(output)
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

        let Ok(guard) = install(&paths, "trace") else {
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
    fn an_encoded_jit_configuration_is_redacted() {
        assert_eq!(redact(JIT_BLOB), REDACTION);
        let sentence = format!("handing off {JIT_BLOB} to the runner");
        let redacted = redact(&sentence);
        assert!(!redacted.contains(JIT_BLOB), "{redacted}");
        assert!(redacted.starts_with("handing off "), "{redacted}");
        assert!(redacted.ends_with(" to the runner"), "{redacted}");
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
    fn a_url_survives_but_its_query_string_does_not() {
        assert_eq!(
            redact("GET https://api.github.com/repos/owner/repo/actions/runners"),
            "GET https://api.github.com/repos/owner/repo/actions/runners"
        );
        assert_eq!(
            redact("https://api.github.com/x?access_token=ghu_secret"),
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

    #[test]
    fn a_short_hex_digest_prefix_survives_while_a_full_one_does_not() {
        // Documented behaviour rather than an accident: a full SHA-256 is 64
        // opaque characters and is treated as a secret. `e2` should log a
        // prefix when it wants a digest to be visible.
        let digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(redact(digest), REDACTION);
        assert_eq!(redact(&digest[..12]), digest[..12].to_string());
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
