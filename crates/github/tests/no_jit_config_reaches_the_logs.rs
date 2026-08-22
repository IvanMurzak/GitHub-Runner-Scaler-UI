// owner: c4-demand-and-jit-gateway

//! The Definition of Done's log scan for the encoded just-in-time
//! configuration: drive a whole registration — the `201` and each of the three
//! failure statuses — through a capturing `tracing` subscriber, and fail if the
//! configuration appears anywhere in it.
//!
//! `c4`'s Definition of Done asks for the blob to be absent "from `Debug`
//! output, from `Display`, from any error value, from serialisation, and from a
//! log scan over the full request path". The first four are unit tests and a
//! `compile_fail` doctest in `src/jit.rs`, where the types are. This is the
//! fifth, and it is the only one that covers the *path* rather than the types:
//! a `tracing` field added to `RestJit` or to `AuthenticatedClient` that
//! rendered a response body would pass every one of the others.
//!
//! # Why this is a test binary and not a unit test
//!
//! It is `c2`'s reason, measured by `c2`, and it is not a matter of taste. From
//! `tests/no_secret_reaches_the_logs.rs`, which records the numbers:
//!
//! > `tracing::subscriber::with_default` installs a subscriber on the **calling
//! > thread**, while `tracing` caches each callsite's `Interest`
//! > **process-wide**. […] What collapses the capture is not *order*, it is
//! > **concurrency**: the interest cache is one global value shared by threads
//! > that do not share a subscriber, and other threads running through these
//! > callsites at the same time are what destroys it.
//!
//! The consequence there was a scan that reported `ok` while a real device code
//! leaked on the live path, under exactly the invocation CI uses
//! (`cargo test --workspace`, default parallelism). A test binary holding
//! **one** `#[test]` has no second thread to be poisoned by, which is why this
//! file holds one test and why the four checks it performs are one test's body
//! rather than four tests.
//!
//! Two defences are kept for the same reason `c2` keeps them:
//!
//! 1. [`LIBRARY_CALLSITES`] must appear in the capture. If the capture is ever
//!    blind again, this fails loudly instead of passing quietly.
//! 2. A positive control plants a leak of the shape the crate documentation
//!    names — a plain `String` field with a derived `Debug` — and requires the
//!    scan to catch it.
//!
//! # Why it re-declares its fixtures
//!
//! `crate::testing` is `#[cfg(test)]` and unreachable from an integration test;
//! `testkit` is reachable and supplies the clock. The rest is a few lines of
//! `wiremock` scaffolding, duplicated as the price of the isolation above. The
//! fixture constants are only ever compared against themselves within this file.

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use runner_manager_domain::model::ScaleTarget;
use runner_manager_github::{
    ApiRequest, AuthenticatedClient, Endpoints, UserAccessToken,
    jit::{JitGateway, JitRunnerRequest, RestJit},
    rest::CancelToken,
};
use runner_manager_testkit::clock::FakeClock;
use secrecy::SecretString;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Shaped like a real `ghu_` token, and unmistakably not one.
const FIXTURE_TOKEN: &str = "ghu_fixtureTOKENnotARealCredential00";

/// Shaped like a real encoded configuration — base64url of a JSON envelope, as
/// `v1` observed at 4,088 characters — and unmistakably not one. Its own
/// plaintext says what its appearance here would mean.
const FIXTURE_JIT_CONFIG: &str = concat!(
    "eyJmaXh0dXJlIjoibm90LWEtcmVhbC1qaXQtY29uZmlndXJhdGlvbiIsIm5vdGUiOiJpZi",
    "B0aGlzIHN0cmluZyBhcHBlYXJzIGluIGEgbG9nIHRoZSByZWRhY3Rpb24gZmFpbGVkIn0"
);

/// A prefix of the fixture, so that a *truncated* leak is caught too.
///
/// A field that rendered the first forty bytes of the response body would slip
/// past a whole-string search while disclosing most of a credential.
const FIXTURE_JIT_PREFIX: &str = "eyJmaXh0dXJlIjoibm90LWEtcmVhbC1qaXQ";

/// Message fragments from library callsites this flow is *known* to reach.
///
/// Their absence does not mean "no secret leaked"; it means the capture saw
/// nothing worth scanning, which is the failure this list exists to make loud.
const LIBRARY_CALLSITES: &[&str] = &[
    // AuthenticatedClient::send_raw, on every round trip
    "github api request",
    // RestJit::generate_jit_config, on the 201
    "registered a just-in-time runner",
];

#[test]
fn no_jit_config_reaches_the_logs() {
    let sink = CaptureLog::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime, so the thread-local subscriber applies throughout");

    tracing::subscriber::with_default(sink.subscriber(), || {
        runtime.block_on(drive_a_registration_and_each_failure());
    });

    let logs = sink.contents();

    // -- the capture is not blind ------------------------------------------
    //
    // Everything below is already true of a capture containing nothing.
    assert!(!logs.is_empty(), "the subscriber captured nothing to scan");
    for expected in LIBRARY_CALLSITES {
        assert!(
            logs.contains(expected),
            "the capture is blind to library callsites; this scan proves nothing:\n{logs}"
        );
    }

    // -- the configuration is not in it ------------------------------------
    assert!(
        !logs.contains(FIXTURE_JIT_CONFIG),
        "the encoded JIT configuration reached the logs:\n{logs}"
    );
    assert!(
        !logs.contains(FIXTURE_JIT_PREFIX),
        "a prefix of the encoded JIT configuration reached the logs, which discloses \
         most of a credential while passing a whole-string search:\n{logs}"
    );
    assert!(
        !logs.contains(FIXTURE_TOKEN),
        "the user access token reached the logs:\n{logs}"
    );
    assert!(
        !logs.to_ascii_lowercase().contains("bearer "),
        "an Authorization header value reached the logs:\n{logs}"
    );

    // -- and the diagnostics that are *supposed* to survive did -------------
    //
    // A scan satisfied by logging nothing at all is a scan that would be
    // satisfied by deleting the logging, and an agent with no diagnostics is
    // not the outcome this control is for.
    assert!(
        logs.contains("runner_group_id"),
        "the runner group is not a secret and is the field an operator needs when a \
         later registration is refused for it:\n{logs}"
    );
    assert!(
        logs.contains("config_bytes"),
        "the configuration's *length* is what distinguishes a truncated handoff from a \
         redacted one, and it is not the secret:\n{logs}"
    );

    // -- and the scan can actually see a leak ------------------------------
    the_scan_catches_a_plain_string_field_rendered_through_a_derived_debug();
}

async fn drive_a_registration_and_each_failure() {
    let target = ScaleTarget::repository("octo/dashboard").expect("a valid owner/repo");
    let request = JitRunnerRequest::new("rm-home-win-x64-0001", 3, ["rm-home-win-x64"]);

    // -- the 201, which is the only response that carries the secret --------
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(RestJit::path(&target)))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "runner": {
                "id": 73,
                "name": "rm-home-win-x64-0001",
                "os": "windows",
                "status": "offline",
                "busy": false,
                "runner_group_id": 3,
                "labels": [{ "id": 1, "name": "rm-home-win-x64", "type": "read-only" }]
            },
            "encoded_jit_config": FIXTURE_JIT_CONFIG
        })))
        .mount(&server)
        .await;

    let client = Arc::new(client_for(&server));
    let gateway = RestJit::new(Arc::clone(&client));

    // The request itself, rendered through `Debug`, because `ApiRequest` is the
    // one type in the crate that carries a POST body and its `Debug` is what
    // keeps that body out of a log.
    let api_request = ApiRequest::post_json(RestJit::path(&target), &json!({"probe": true}))
        .expect("a serialisable probe body");
    tracing::info!(?api_request, "an api request, rendered through Debug");

    let registration = gateway
        .generate_jit_config(&target, &request, &CancelToken::new())
        .await
        .expect("a 201");

    // Forcing each secret-bearing value through `Debug` and `Display` inside the
    // capture is what makes this scan bite: a `#[derive(Debug)]` added to any of
    // them later fails here rather than in production.
    tracing::info!(?registration, "a registration, rendered through Debug");
    tracing::info!(config = ?registration.config(), "the configuration, through Debug");
    tracing::info!(config = %registration.config(), "the configuration, through Display");
    tracing::info!(?gateway, "the gateway, rendered through Debug");
    tracing::info!(?client, "the authenticated client, rendered through Debug");

    // -- and each failure, whose error values must be clean too -------------
    //
    // Each response carries an `encoded_jit_config` key it has no business
    // carrying. GitHub does not send one on a failure; the point is that an
    // error variant which ever rendered a response *body* would be caught here.
    for status in [403_u16, 404, 422] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(RestJit::path(&target)))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "message": "Resource not accessible by integration",
                "encoded_jit_config": FIXTURE_JIT_CONFIG
            })))
            .mount(&server)
            .await;

        let gateway = RestJit::new(Arc::new(client_for(&server)));
        let error = gateway
            .generate_jit_config(&target, &request, &CancelToken::new())
            .await
            .expect_err("a failure status");
        tracing::info!(%error, ?error, "a registration failure, through Display and Debug");
        tracing::info!(
            action = error.operator_action(),
            "the operator action, which is prose and must stay renderable"
        );
    }
}

fn client_for(server: &MockServer) -> AuthenticatedClient {
    AuthenticatedClient::new(
        Endpoints::for_test_server(&server.uri()).expect("a valid test base"),
        UserAccessToken::new(SecretString::from(FIXTURE_TOKEN)),
        Arc::new(FakeClock::default()),
    )
    .expect("the HTTP client builds")
}

/// The positive control: a leak of the exact shape the crate documentation
/// names, proven to be caught.
///
/// `lib.rs`'s crate documentation says every secret-bearing type wraps its
/// secret *and* hand-writes `Debug`, "because a `#[derive(Debug)]` added later
/// to a struct with a plain `String` field is precisely how this control is
/// lost". Without this, "the scan would catch a derive" is an assertion about
/// the scan rather than a property of it — and `c2`'s own history is that a
/// version of this claim was false for months.
fn the_scan_catches_a_plain_string_field_rendered_through_a_derived_debug() {
    /// Exactly the mistake the crate documentation warns about.
    #[derive(Debug)]
    struct RegistrationWithADerivedDebug {
        #[allow(dead_code)]
        encoded_jit_config: String,
    }

    let sink = CaptureLog::default();
    tracing::subscriber::with_default(sink.subscriber(), || {
        let leaky = RegistrationWithADerivedDebug {
            encoded_jit_config: FIXTURE_JIT_CONFIG.to_string(),
        };
        tracing::info!(
            ?leaky,
            "a plain String field rendered through a derived Debug"
        );
    });

    let contents = sink.contents();
    assert!(
        contents.contains(FIXTURE_JIT_CONFIG),
        "the scan cannot see a plain-String secret rendered through a derived Debug, so \
         every negative assertion above is worthless:\n{contents}"
    );
    assert!(
        contents.contains(FIXTURE_JIT_PREFIX),
        "and the prefix search, which is what catches a truncating leak, is equally \
         worthless if it cannot see this:\n{contents}"
    );
}

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// Everything a `tracing` subscriber saw, as one flat string to scan.
///
/// Hand-written because `tracing-subscriber` is not a dependency of this crate
/// and `a1` owns every manifest — needing one would have been a reason to stop
/// and report, not to edit a `Cargo.toml`. It records every event's target,
/// message and fields, and every span's name and fields, which is the whole
/// surface a secret could reach a log through.
#[derive(Clone, Default)]
struct CaptureLog(Arc<Mutex<String>>);

impl CaptureLog {
    fn contents(&self) -> String {
        self.0.lock().expect("log lock poisoned").clone()
    }

    fn subscriber(&self) -> CaptureSubscriber {
        CaptureSubscriber {
            sink: self.clone(),
            next_span: AtomicU64::new(1),
        }
    }
}

struct CaptureSubscriber {
    sink: CaptureLog,
    next_span: AtomicU64,
}

impl CaptureSubscriber {
    fn write(&self, prefix: &str, metadata: &tracing::Metadata<'_>, record: impl Fn(&mut Sink)) {
        let mut buffer = self.sink.0.lock().expect("log lock poisoned");
        buffer.push_str(prefix);
        buffer.push(' ');
        buffer.push_str(metadata.target());
        buffer.push(' ');
        buffer.push_str(metadata.name());
        let mut sink = Sink(&mut buffer);
        record(&mut sink);
        buffer.push('\n');
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.write("SPAN", span.metadata(), |sink| span.record(sink));
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst))
    }

    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut buffer = self.sink.0.lock().expect("log lock poisoned");
        buffer.push_str("RECORD");
        let mut sink = Sink(&mut buffer);
        values.record(&mut sink);
        buffer.push('\n');
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        self.write("EVENT", event.metadata(), |sink| event.record(sink));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct Sink<'a>(&'a mut String);

impl tracing::field::Visit for Sink<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        use fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use fmt::Write;
        let _ = write!(self.0, " {}={value}", field.name());
    }
}
