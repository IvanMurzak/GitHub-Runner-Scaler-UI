// owner: c2-device-flow-auth

//! The Definition of Done's log scan: drive a whole login and an authenticated
//! round trip through a capturing `tracing` subscriber, and fail if the device
//! code, the user access token, or an `Authorization` header value appears.
//!
//! # Why this is a test binary and not a unit test
//!
//! It used to be `lib.rs`'s `tests::no_secret_reaches_the_logs`, and in that
//! position **it did not work**. A reviewer replaced the `user_code` field of
//! the `device login started` event with the raw device code — a real leak, on
//! the real path — and the suite reported `35 passed`, with this very test
//! printing `ok`. The same leak was caught immediately under `--test-threads=1`
//! or `--exact`. `.github/workflows/ci.yml` runs `cargo test --workspace`, which
//! is the mode where it passed.
//!
//! # The mechanism, corrected
//!
//! `tracing::subscriber::with_default` installs a subscriber on the **calling
//! thread**, while `tracing` caches each callsite's `Interest` **process-wide**.
//! That much is right, and it is the whole of the hazard. What this file used to
//! say next was not: that whichever unit test reached a logging callsite first
//! registered it `Interest::never()` *permanently*, for the rest of the process.
//!
//! It does not survive contact with `tracing-core`. `Dispatch::new` — which
//! `with_default` calls to wrap a subscriber — calls `callsite::register_dispatch`,
//! whose last act is `CALLSITES.rebuild_interest(..)`: it walks **every**
//! registered callsite and recomputes its interest against the dispatchers now
//! present (`tracing-core-0.1.36`, `callsite.rs`). Installing a subscriber
//! un-disables the callsites that were disabled before it existed. A first
//! registration is not permanent, and cannot be.
//!
//! The measurement says the same thing, and says it louder. Driving this flow
//! from inside the unit-test binary, under `--test-threads=1`, with the probe
//! ordered **last** so that all fifty-nine other tests have already executed
//! every logging callsite in `lib.rs` and `device_flow.rs` with no subscriber
//! installed:
//!
//! | how the suite was run | events the scan captured |
//! |---|---|
//! | `--lib --test-threads=1` | **67** |
//! | `--lib`, default parallelism | **0** |
//! | `--workspace`, default parallelism | **1** |
//!
//! If first registration were permanent, the first row would read `0` — every
//! callsite had already been touched, subscriber-less, before the probe ran. It
//! reads 67. What collapses the capture is not *order*, it is **concurrency**:
//! the interest cache is one global value shared by threads that do not share a
//! subscriber, and other threads running through these callsites at the same
//! time are what destroys it.
//!
//! The consequence for the original failure is unchanged. The scan captured
//! nothing but the three `tracing::info!` events it emitted itself — so
//! `assert!(!logs.is_empty())` passed, and `logs.contains(FIXTURE_USER_CODE)`
//! passed too, because the test's own `?auth` event renders
//! `DeviceAuthorization`. What looked like a scan over a whole login was three
//! `Debug` impls being re-checked, which
//! `no_type_in_this_crate_renders_a_secret_through_debug` already covers
//! directly.
//!
//! # Why a separate binary is still the fix
//!
//! A test binary is one process, and this file holds exactly **one** `#[test]`,
//! so there is no second thread to run a callsite concurrently with the capture.
//! The conclusion is the same one the old paragraph reached; it now rests on the
//! reason that is actually true, which matters because the two readings disagree
//! about the remedy. Under the permanent-first-registration story, nothing short
//! of process isolation could ever help and `--test-threads=1` would be useless;
//! under the concurrency story, serialisation *does* restore the capture — the
//! 67 above is exactly that — and process isolation is chosen because it does
//! not depend on how anyone invokes `cargo test`. `.github/workflows/ci.yml`
//! runs `cargo test --workspace`, the 1-event row.
//!
//! `serial_test` was considered and is not enough. It serialises the tests that
//! opt in, so it would work only for as long as every future unit test in this
//! crate remembered to, and a scan that silently proves nothing is worse than no
//! scan at all. Two defences are kept for the same reason:
//!
//! 1. [`the four callsite markers`](LIBRARY_CALLSITES) must appear in the
//!    capture. If the capture is ever blind again, this fails loudly instead of
//!    passing quietly.
//! 2. A positive control at the end plants a real leak of the shape this
//!    crate's own documentation names as the hazard — `#[derive(Debug)]` on a
//!    struct with a plain `String` field — and requires the scan to catch it.
//!
//! # Why it re-declares its fixtures
//!
//! `crate::testing` is `#[cfg(test)]` and unreachable from here; `testkit` is
//! reachable and supplies the clock. The rest is a few lines of `wiremock`
//! scaffolding, and duplicating them is the price of the isolation above. The
//! fixture constants are only ever compared against themselves within this
//! file, so there is nothing here that can drift out of step with `lib.rs`.

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use runner_manager_github::{
    ApiRequest, AppRegistration, AuthenticatedClient, Endpoints, Sleeper, device_flow::DeviceFlow,
};
use runner_manager_testkit::clock::FakeClock;
use serde_json::json;
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

/// Shaped like a real `ghu_` token, and unmistakably not one.
const FIXTURE_TOKEN: &str = "ghu_fixtureTOKENnotARealCredential00";
/// Shaped like a real device code, and unmistakably not one.
const FIXTURE_DEVICE_CODE: &str = "fixture-device-code-0e37a9c1b4d84f2a";
/// The example user code from RFC 8628.
const FIXTURE_USER_CODE: &str = "WDJB-MJHT";

/// Message fragments from library callsites the scanned flow is *known* to
/// reach — one from each of the four modules' worth of logging the flow drives.
///
/// Their absence does not mean "no secret leaked"; it means the capture saw
/// nothing worth scanning, which is the failure this list exists to make loud.
const LIBRARY_CALLSITES: &[&str] = &[
    // device_flow::start
    "device login started",
    // device_flow::poll_once_from, on approval
    "device login approved",
    // AuthenticatedClient::send_raw, on every round trip
    "github api request",
    // AuthenticatedClient::revalidate, after the 401
    "re-validated the stored credential",
];

#[test]
fn no_secret_reaches_the_logs() {
    let sink = CaptureLog::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime, so the thread-local subscriber applies throughout");

    tracing::subscriber::with_default(sink.subscriber(), || {
        runtime.block_on(drive_a_whole_login_and_an_authenticated_round_trip());
    });

    let logs = sink.contents();

    // -- the capture is not blind ------------------------------------------
    //
    // This block is the finding. Everything below it was already true of a
    // capture containing three events and no library logging at all.
    assert!(!logs.is_empty(), "the subscriber captured nothing to scan");
    for expected in LIBRARY_CALLSITES {
        assert!(
            logs.contains(expected),
            "the capture is blind to library callsites; this scan proves nothing:\n{logs}"
        );
    }

    // -- nothing secret is in it -------------------------------------------
    assert!(
        !logs.contains(FIXTURE_TOKEN),
        "the user access token reached the logs:\n{logs}"
    );
    assert!(
        !logs.contains(FIXTURE_DEVICE_CODE),
        "the device code reached the logs:\n{logs}"
    );
    assert!(
        !logs.to_ascii_lowercase().contains("bearer "),
        "an Authorization header value reached the logs:\n{logs}"
    );
    assert!(
        logs.contains(FIXTURE_USER_CODE),
        "the user code is displayed by design and only during login, so the flow must \
         still surface it:\n{logs}"
    );

    // -- and the scan can actually see a leak ------------------------------
    the_scan_catches_a_plain_string_field_rendered_through_a_derived_debug();
}

async fn drive_a_whole_login_and_an_authenticated_round_trip() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": FIXTURE_DEVICE_CODE,
            "user_code": FIXTURE_USER_CODE,
            "verification_uri": format!("{}/login/device", server.uri()),
            "expires_in": 900,
            "interval": 5
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(Script::new(vec![
            ResponseTemplate::new(200).set_body_json(json!({"error": "authorization_pending"})),
            ResponseTemplate::new(200).set_body_json(
                json!({"access_token": FIXTURE_TOKEN, "token_type": "bearer", "scope": ""}),
            ),
        ]))
        .mount(&server)
        .await;
    // A 401 first, so the re-validation path and its logging are in the scan.
    Mock::given(method("GET"))
        .and(path("/orgs/acme/actions/runners"))
        .respond_with(Script::new(vec![
            ResponseTemplate::new(401).set_body_json(json!({"message": "Bad credentials"})),
            ResponseTemplate::new(200).set_body_json(json!({"total_count": 0})),
        ]))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/installations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_count": 1,
            "installations": [{
                "id": 11,
                "account": { "login": "IvanMurzak", "type": "User" },
                "repository_selection": "selected",
                "permissions": { "administration": "write" }
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/installations/11/repositories"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({ "total_count": 1, "repositories": [{ "full_name": "a/b" }] }),
            ),
        )
        .mount(&server)
        .await;

    let app = AppRegistration::new("Iv23liTESTCLIENTID", "runner-manager").unwrap();
    let endpoints = Endpoints::for_test_server(&server.uri()).unwrap();

    let flow = DeviceFlow::new(app.clone(), endpoints.clone()).unwrap();
    let auth = flow.start().await.expect("device authorization");
    // Forcing each secret-bearing type through `Debug` is what makes this scan
    // bite: a `#[derive(Debug)]` added to any of them later fails here rather
    // than in production.
    tracing::info!(?auth, "device authorization, rendered through Debug");

    let token = flow
        .complete(&auth, &ImmediateSleeper)
        .await
        .expect("approved");
    tracing::info!(?token, "user access token, rendered through Debug");

    let client =
        AuthenticatedClient::new(endpoints, token.clone(), Arc::new(FakeClock::default())).unwrap();
    tracing::info!(?client, "authenticated client, rendered through Debug");

    client
        .send(&ApiRequest::get("/orgs/acme/actions/runners"))
        .await
        .expect("401 then retry");
    client
        .discover_installations(&app)
        .await
        .expect("discovery");
}

/// The positive control: a leak of the exact shape this crate's documentation
/// names, proven to be caught.
///
/// `lib.rs`'s crate doc says every secret-bearing type wraps its secret in
/// `SecretString` *and* hand-writes `Debug`, "because a `#[derive(Debug)]` added
/// later to a struct with a plain `String` field is precisely how this control
/// is lost". A reviewer tested that claim by replacing `UserAccessToken`'s
/// hand-written `Debug` with a derive — and the scan still passed, because
/// `SecretString`'s *own* `Debug` renders `[REDACTED]`. So the redaction was
/// coming from `secrecy`, and the named hazard — a plain `String` field, which
/// `secrecy` cannot help with — was never tested at all.
///
/// This plants one and requires the scan to see it. Without this, "the scan
/// would catch a derive" is an assertion about the scan rather than a property
/// of it.
fn the_scan_catches_a_plain_string_field_rendered_through_a_derived_debug() {
    const CANARY: &str = "ghu_canaryTOKENthatMUSTbeSEENbyTHIScheck";

    /// Exactly the mistake the crate documentation warns about: a secret held as
    /// a plain `String`, with `Debug` derived rather than written.
    #[derive(Debug)]
    struct CredentialWithADerivedDebug {
        #[allow(dead_code)]
        token: String,
    }

    let sink = CaptureLog::default();
    tracing::subscriber::with_default(sink.subscriber(), || {
        let leaky = CredentialWithADerivedDebug {
            token: CANARY.to_string(),
        };
        tracing::info!(
            ?leaky,
            "a plain String field rendered through a derived Debug"
        );
    });

    assert!(
        sink.contents().contains(CANARY),
        "the scan cannot see a plain-String secret rendered through a derived Debug, so \
         it could not have caught the hazard `lib.rs`'s crate documentation names — every \
         negative assertion above is worthless:\n{}",
        sink.contents()
    );
}

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// A sleeper that returns at once, so a fifteen-minute poll budget costs
/// nothing. This test asserts on redaction, not on timing.
#[derive(Debug)]
struct ImmediateSleeper;

#[async_trait::async_trait]
impl Sleeper for ImmediateSleeper {
    async fn sleep(&self, _: Duration) {}
}

/// Answers from a fixed script, one entry per call, repeating the last.
struct Script {
    responses: Vec<ResponseTemplate>,
    calls: AtomicUsize,
}

impl Script {
    fn new(responses: Vec<ResponseTemplate>) -> Self {
        assert!(
            !responses.is_empty(),
            "a script needs at least one response"
        );
        Self {
            responses,
            calls: AtomicUsize::new(0),
        }
    }
}

impl Respond for Script {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let i = self.calls.fetch_add(1, Ordering::SeqCst);
        self.responses[i.min(self.responses.len() - 1)].clone()
    }
}

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
