//! A fake GitHub for the GitHub App and the reconciliation sweep: JWTs are
//! verified against the App's real public key, installation tokens are
//! minted and checked, and the queue listings answer `304` to a matching
//! `If-None-Match`, as `api.github.com` does.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use runner_manager_coordinator::github_app::{AppKey, GithubApp};
use runner_manager_coordinator::registry::{Outbound, Registry};
use runner_manager_coordinator::sweep::{SweepConfig, Sweeper, WakeLog};
use runner_manager_coordinator_protocol::{Hello, PROTOCOL_VERSION, Profile, Target, TargetScope};
use runner_manager_domain::model::SystemClock;
use runner_manager_github::Endpoints;
use secrecy::SecretString;
use serde_json::json;
use tokio::sync::mpsc;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Match, Mock, MockServer, Request, Respond, ResponseTemplate};

pub const APP_ID: u64 = 4242;
pub const INSTALLATION: u64 = 77;
/// Shaped like an installation token, and unmistakably not one.
pub const TOKEN_ONE: &str = "ghs_fixtureINSTALLATIONtokenONE000000";
pub const TOKEN_TWO: &str = "ghs_fixtureINSTALLATIONtokenTWO000000";

/// The App's key pair: the PEM the coordinator is configured with, and the
/// public half the fake checks JWTs against.
pub struct AppKeys {
    pub pem: SecretString,
    /// The base64 body of the PEM, for log scans.
    pub pem_body: String,
    public: Vec<u8>,
}

pub fn app_keys() -> AppKeys {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("key");
    let body = STANDARD.encode(key.as_der().expect("der").as_ref());
    AppKeys {
        pem: SecretString::from(format!(
            "-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
        )),
        pem_body: body,
        public: key.public_key().as_ref().to_vec(),
    }
}

/// Matches a request carrying a JWT this App signed, issued for [`APP_ID`].
struct SignedByTheApp(Vec<u8>);

impl Match for SignedByTheApp {
    fn matches(&self, request: &Request) -> bool {
        let Some(jwt) = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        let parts: Vec<&str> = jwt.split('.').collect();
        let [head, claims, signature] = parts.as_slice() else {
            return false;
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        let verified = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.0)
            .verify(format!("{head}.{claims}").as_bytes(), &signature)
            .is_ok();
        let issuer = URL_SAFE_NO_PAD
            .decode(claims)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|claims| claims["iss"].as_str() == Some(APP_ID.to_string().as_str()));
        verified && issuer
    }
}

/// Answers in order, repeating the last.
pub struct Script {
    responses: Vec<ResponseTemplate>,
    next: AtomicUsize,
}

impl Script {
    pub fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self {
            responses,
            next: AtomicUsize::new(0),
        }
    }
}

impl Respond for Script {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let at = self.next.fetch_add(1, Ordering::SeqCst);
        self.responses[at.min(self.responses.len() - 1)].clone()
    }
}

fn token(value: &str, lifetime: Duration) -> ResponseTemplate {
    let expires = chrono::Utc::now() + chrono::TimeDelta::from_std(lifetime).expect("delta");
    ResponseTemplate::new(201).set_body_json(json!({
        "token": value,
        "expires_at": expires.to_rfc3339(),
        "permissions": { "actions": "read", "metadata": "read" }
    }))
}

/// A listing with an `ETag`, and a `304` for a request that sends it back.
async fn conditional(
    server: &MockServer,
    at: &str,
    status: Option<&str>,
    etag: &str,
    body: serde_json::Value,
) {
    let quoted = format!("W/\"{etag}\"");
    let mut not_modified = Mock::given(method("GET"))
        .and(path(at))
        .and(header("if-none-match", quoted.as_str()));
    let mut full = Mock::given(method("GET")).and(path(at));
    if let Some(status) = status {
        not_modified = not_modified.and(query_param("status", status));
        full = full.and(query_param("status", status));
    }
    not_modified
        .respond_with(ResponseTemplate::new(304).insert_header("etag", quoted.as_str()))
        .with_priority(1)
        .mount(server)
        .await;
    full.respond_with(
        ResponseTemplate::new(200)
            .insert_header("etag", quoted.as_str())
            .set_body_json(body),
    )
    .with_priority(5)
    .mount(server)
    .await;
}

/// The App installed on all of `octo`'s repositories, one of which has a
/// queued run holding one queued job for `self-hosted, linux`. Tokens last
/// `lifetime`; the first is [`TOKEN_ONE`], every later one [`TOKEN_TWO`].
pub async fn fake_github(keys: &AppKeys, lifetime: Duration) -> MockServer {
    let server = MockServer::start().await;
    let signed = || SignedByTheApp(keys.public.clone());
    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .and(signed())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": INSTALLATION,
            "account": { "login": "octo", "type": "Organization" },
            "repository_selection": "all"
        }])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION}/access_tokens"
        )))
        .and(signed())
        .respond_with(Script::new(vec![
            token(TOKEN_ONE, lifetime),
            token(TOKEN_TWO, lifetime),
        ]))
        .mount(&server)
        .await;
    for value in [TOKEN_ONE, TOKEN_TWO] {
        Mock::given(method("GET"))
            .and(path("/installation/repositories"))
            .and(header("authorization", format!("Bearer {value}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total_count": 1,
                "repositories": [{ "full_name": "octo/app" }]
            })))
            .mount(&server)
            .await;
    }
    server
}

/// The queue of `octo/app`: one queued run holding one queued linux job.
pub async fn queue(server: &MockServer) {
    conditional(
        server,
        "/repos/octo/app/actions/runs",
        Some("queued"),
        "queued-1",
        json!({ "total_count": 1, "workflow_runs": [{ "id": 11 }] }),
    )
    .await;
    conditional(
        server,
        "/repos/octo/app/actions/runs",
        Some("in_progress"),
        "progress-1",
        json!({ "total_count": 0, "workflow_runs": [] }),
    )
    .await;
    conditional(
        server,
        "/repos/octo/app/actions/runs/11/jobs",
        None,
        "jobs-1",
        json!({ "total_count": 1, "jobs": [
            { "id": 5, "status": "queued", "labels": ["self-hosted", "linux"] }
        ] }),
    )
    .await;
}

pub fn app(keys: &AppKeys, server: &MockServer) -> GithubApp {
    GithubApp::new(
        AppKey::from_pem(APP_ID, &keys.pem).expect("key"),
        Endpoints::for_test_server(&server.uri()).expect("endpoints"),
        Arc::new(SystemClock),
    )
    .expect("app")
}

/// A version-2 host serving the organization `octo` with a linux profile.
pub fn host(registry: &Registry) -> mpsc::Receiver<Outbound> {
    let (tx, rx) = mpsc::channel(64);
    let connection = registry.register("h1", PROTOCOL_VERSION, tx);
    registry.set_hello(
        "h1",
        connection,
        Hello {
            protocol_version: PROTOCOL_VERSION,
            host_id: "h1".into(),
            os: "linux".into(),
            arch: "x64".into(),
            cores: 8,
            ram_bytes: None,
            disk_free_bytes: None,
            targets: vec![Target {
                scope: TargetScope::Org,
                name: "octo".into(),
                profiles: vec![Profile {
                    name: "default".into(),
                    labels: vec!["self-hosted".into(), "linux".into()],
                    enabled: true,
                }],
            }],
        },
    );
    rx
}

pub fn sweeper(app: GithubApp, registry: &Arc<Registry>) -> Sweeper {
    Sweeper::new(
        SweepConfig {
            interval: Duration::from_secs(30),
        },
        Box::new(app),
        Arc::clone(registry),
        Arc::new(WakeLog::default()),
    )
}

/// Requests the fake received for `at`, and how many carried
/// `If-None-Match`.
pub async fn requests_to(server: &MockServer, at: &str) -> (usize, usize) {
    let received = server.received_requests().await.unwrap_or_default();
    let matching: Vec<&Request> = received.iter().filter(|r| r.url.path() == at).collect();
    let conditional = matching
        .iter()
        .filter(|r| r.headers.contains_key("if-none-match"))
        .count();
    (matching.len(), conditional)
}

pub async fn bearer_tokens(server: &MockServer, at: &str) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == at)
        .filter_map(|r| {
            r.headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.trim_start_matches("Bearer ").to_string())
        })
        .collect()
}
