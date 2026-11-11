//! The web dashboard end to end: GitHub sign-in against a fake GitHub, the
//! allowlist, the session cookie, sign-out, and the API it guards.

use std::sync::Arc;

use hmac::{Hmac, KeyInit as _, Mac as _};
use runner_manager_coordinator::dashboard::auth::AuthConfig;
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::store::Store;
use secrecy::SecretString;
use sha2::Sha256;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET: &str = "a-webhook-secret-for-tests";
/// Shaped like a user token, and unmistakably not one.
const ACCESS_TOKEN: &str = "gho_fixtureUSERtoken0000000000000000";

struct Coordinator {
    base: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start(dashboard: Option<AuthConfig>) -> Coordinator {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mut config = Config::new(base.clone(), SecretString::from(SECRET));
    config.dashboard = dashboard;
    let state = AppState::new(config, Store::open_in_memory().expect("store"));
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(listener, Arc::clone(&state), async {
        let _ = stopped.await;
    }));
    Coordinator {
        base,
        _shutdown: shutdown,
    }
}

fn auth(github: &MockServer) -> AuthConfig {
    AuthConfig {
        client_id: "Iv1.client".into(),
        client_secret: SecretString::from("a-client-secret"),
        allowed_logins: vec!["IvanMurzak".into()],
        web_base: github.uri(),
        api_base: github.uri(),
    }
}

/// A GitHub that trades `code` for a token and says the token is `login`.
async fn github_for(login: &str) -> MockServer {
    let github = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(body_partial_json(serde_json::json!({
            "client_id": "Iv1.client",
            "client_secret": "a-client-secret",
            "code": "the-code",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"access_token": ACCESS_TOKEN, "token_type": "bearer"}),
        ))
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header(
            "authorization",
            format!("Bearer {ACCESS_TOKEN}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "login": login,
            "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
        })))
        .mount(&github)
        .await;
    github
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client")
}

fn cookie_value(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, value)| *key == name && !value.is_empty())
        .map(|(_, value)| value.to_owned())
}

/// Goes through GitHub's sign-in and returns where it lands and the session
/// cookie, if one was set.
async fn sign_in(coordinator: &Coordinator) -> (String, Option<String>) {
    let http = client();
    let login = http
        .get(format!("{}/auth/login", coordinator.base))
        .send()
        .await
        .expect("login");
    assert!(login.status().is_redirection());
    let to = login.headers()["location"]
        .to_str()
        .expect("location")
        .to_owned();
    let state = url::Url::parse(&to)
        .expect("url")
        .query_pairs()
        .find(|(key, _)| key == "state")
        .expect("a state")
        .1
        .into_owned();
    let cookie = cookie_value(&login, "rm_oauth_state").expect("the state cookie");
    assert_eq!(cookie, state);
    let back = http
        .get(format!(
            "{}/auth/callback?code=the-code&state={state}",
            coordinator.base
        ))
        .header("cookie", format!("rm_oauth_state={cookie}"))
        .send()
        .await
        .expect("callback");
    assert!(back.status().is_redirection());
    (
        back.headers()["location"]
            .to_str()
            .expect("location")
            .to_owned(),
        cookie_value(&back, "rm_session"),
    )
}

async fn get(coordinator: &Coordinator, route: &str, session: Option<&str>) -> reqwest::Response {
    let mut request = client().get(format!("{}{route}", coordinator.base));
    if let Some(session) = session {
        request = request.header("cookie", format!("rm_session={session}"));
    }
    request.send().await.expect("sent")
}

#[tokio::test]
async fn an_allowed_login_signs_in_and_sees_the_queue() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;

    let page = get(&coordinator, "/", None).await;
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"]
        .to_str()
        .expect("csp");
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"));
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    assert_eq!(
        get(&coordinator, "/assets/app.js", None).await.status(),
        200
    );
    assert_eq!(
        get(&coordinator, "/api/overview", None).await.status(),
        401,
        "nothing without a session"
    );

    let (landing, session) = sign_in(&coordinator).await;
    assert_eq!(landing, "/");
    let session = session.expect("a session cookie");

    let me: serde_json::Value = get(&coordinator, "/api/session", Some(&session))
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(me["login"], "ivanmurzak");

    let body = serde_json::json!({
        "action": "queued",
        "workflow_job": {"id": 41, "run_id": 7, "name": "build",
                         "labels": ["self-hosted", "linux"],
                         "created_at": "2026-11-10T10:00:00Z"},
        "repository": {"full_name": "IvanMurzak/app"},
    })
    .to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
    mac.update(body.as_bytes());
    let delivered = client()
        .post(format!("{}/webhook", coordinator.base))
        .header("x-github-event", "workflow_job")
        .header("x-github-delivery", "72d3162e-cc78-11e3-81ab-4c9367dc0958")
        .header(
            "x-hub-signature-256",
            format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
        )
        .body(body)
        .send()
        .await
        .expect("webhook");
    assert_eq!(delivered.status(), 200);

    let overview: serde_json::Value = get(&coordinator, "/api/overview", Some(&session))
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(overview["summary"]["jobs_queued"], 1);
    assert_eq!(overview["queue"][0]["repository"], "IvanMurzak/app");
    assert_eq!(overview["queue"][0]["run_id"], 7);
    assert_eq!(overview["version"], env!("CARGO_PKG_VERSION"));

    let metrics = get(&coordinator, "/api/metrics?range=1h", Some(&session)).await;
    assert_eq!(metrics.status(), 200);
    let metrics: serde_json::Value = metrics.json().await.expect("json");
    assert_eq!(metrics["t"].as_array().expect("t").len(), 60);
    assert_eq!(
        get(&coordinator, "/api/metrics?range=2y", Some(&session))
            .await
            .status(),
        400
    );

    // Sign-out: refused from another origin, done from this one.
    let foreign = client()
        .post(format!("{}/auth/logout", coordinator.base))
        .header("cookie", format!("rm_session={session}"))
        .header("origin", "https://evil.example")
        .send()
        .await
        .expect("sent");
    assert_eq!(foreign.status(), 403);
    let out = client()
        .post(format!("{}/auth/logout", coordinator.base))
        .header("cookie", format!("rm_session={session}"))
        .header("origin", coordinator.base.as_str())
        .send()
        .await
        .expect("sent");
    assert_eq!(out.status(), 204);
    assert_eq!(
        get(&coordinator, "/api/session", Some(&session))
            .await
            .status(),
        401
    );
}

#[tokio::test]
async fn a_login_off_the_allowlist_gets_no_session() {
    let github = github_for("someone-else").await;
    let coordinator = start(Some(auth(&github))).await;
    let (landing, session) = sign_in(&coordinator).await;
    assert_eq!(landing, "/?denied=1");
    assert_eq!(session, None);
}

#[tokio::test]
async fn a_callback_with_a_state_it_was_not_given_is_refused() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let back = client()
        .get(format!(
            "{}/auth/callback?code=the-code&state=forged",
            coordinator.base
        ))
        .header("cookie", "rm_oauth_state=another")
        .send()
        .await
        .expect("callback");
    assert_eq!(back.headers()["location"], "/?error=1");
    assert_eq!(cookie_value(&back, "rm_session"), None);
    assert!(
        github
            .received_requests()
            .await
            .expect("recorded")
            .is_empty(),
        "GitHub is never asked"
    );
}

#[tokio::test]
async fn without_sign_in_settings_there_is_no_dashboard() {
    let coordinator = start(None).await;
    for route in ["/", "/assets/app.js", "/auth/login", "/api/overview"] {
        assert_eq!(
            get(&coordinator, route, None).await.status(),
            404,
            "{route}"
        );
    }
    assert_eq!(get(&coordinator, "/healthz", None).await.status(), 200);
}
