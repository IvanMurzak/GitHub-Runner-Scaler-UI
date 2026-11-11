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
    start_with_status(
        dashboard,
        std::path::PathBuf::from("/nonexistent/status.json"),
    )
    .await
}

async fn start_with_status(
    dashboard: Option<AuthConfig>,
    update_status: std::path::PathBuf,
) -> Coordinator {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mut config = Config::new(base.clone(), SecretString::from(SECRET));
    config.dashboard = dashboard;
    config.update_status = update_status;
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
    sign_in_from(coordinator, "/auth/login").await
}

/// [`sign_in`], starting at `login` (`/auth/login?next=...`).
async fn sign_in_from(coordinator: &Coordinator, login: &str) -> (String, Option<String>) {
    let http = client();
    let login = http
        .get(format!("{}{login}", coordinator.base))
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
        .header(
            "cookie",
            match cookie_value(&login, "rm_oauth_next") {
                Some(next) => format!("rm_oauth_state={cookie}; rm_oauth_next={next}"),
                None => format!("rm_oauth_state={cookie}"),
            },
        )
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

    // Queued a minute ago by the real clock: the dashboard forgets a job
    // queued for a day, so a fixed date would drop out of the queue a day on.
    let created_at = (chrono::Utc::now() - chrono::TimeDelta::minutes(1)).to_rfc3339();
    let body = serde_json::json!({
        "action": "queued",
        "workflow_job": {"id": 41, "run_id": 7, "name": "build",
                         "labels": ["self-hosted", "linux"],
                         "created_at": created_at},
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

#[tokio::test]
async fn the_updaters_status_reaches_the_overview() {
    let github = github_for("ivanmurzak").await;
    let directory = tempfile::tempdir().expect("dir");
    let status = directory.path().join("status.json");
    std::fs::write(
        &status,
        r#"{"state":"rolled_back","current":"0.4.57","previous":null,"latest":"0.4.58",
            "checked_at":1794349000,"changed_at":null,"message":"0.4.58 did not come up"}"#,
    )
    .expect("written");
    let coordinator = start_with_status(Some(auth(&github)), status).await;
    let (_, session) = sign_in(&coordinator).await;
    let overview: serde_json::Value = get(&coordinator, "/api/overview", session.as_deref())
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(overview["update"]["state"], "rolled_back");
    assert_eq!(overview["update"]["latest"], "0.4.58");
}

// ---------------------------------------------------------------------------
// The CLI's sign-in
// ---------------------------------------------------------------------------

async fn cli_start(coordinator: &Coordinator) -> serde_json::Value {
    let started = client()
        .post(format!("{}/auth/cli/start", coordinator.base))
        .send()
        .await
        .expect("sent");
    assert_eq!(started.status(), 200);
    started.json().await.expect("json")
}

async fn cli_poll(coordinator: &Coordinator, device_code: &str) -> (u16, serde_json::Value) {
    let polled = client()
        .post(format!("{}/auth/cli/poll", coordinator.base))
        .json(&serde_json::json!({ "device_code": device_code }))
        .send()
        .await
        .expect("sent");
    let status = polled.status().as_u16();
    (status, polled.json().await.unwrap_or_default())
}

/// Answers a sign-in as a browser would: a form, with `cookie` and `origin`.
async fn cli_answer(
    coordinator: &Coordinator,
    code: &str,
    decision: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    bearer: Option<&str>,
) -> reqwest::Response {
    let mut request = client()
        .post(format!("{}/auth/cli/approve", coordinator.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("code={code}&decision={decision}"));
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("rm_session={cookie}"));
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    request.send().await.expect("sent")
}

async fn bearer_get(coordinator: &Coordinator, route: &str, token: &str) -> reqwest::Response {
    client()
        .get(format!("{}{route}", coordinator.base))
        .bearer_auth(token)
        .send()
        .await
        .expect("sent")
}

/// Signs the CLI in end to end and returns its token.
async fn cli_token(coordinator: &Coordinator, session: &str) -> String {
    let started = cli_start(coordinator).await;
    let code = started["user_code"].as_str().expect("code");
    let answered = cli_answer(
        coordinator,
        code,
        "approve",
        Some(session),
        Some(&coordinator.base),
        None,
    )
    .await;
    assert_eq!(answered.status(), 200);
    let (status, body) = cli_poll(coordinator, started["device_code"].as_str().expect("dc")).await;
    assert_eq!(status, 200, "{body}");
    body["token"].as_str().expect("token").to_owned()
}

#[tokio::test]
async fn the_cli_signs_in_through_a_browser_session_and_calls_the_api_with_its_token() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;

    let started = cli_start(&coordinator).await;
    let device_code = started["device_code"].as_str().expect("device code");
    let code = started["user_code"].as_str().expect("user code");
    assert_eq!(device_code.len(), 64);
    assert_eq!(code.len(), 9);
    assert_eq!(&code[4..5], "-");
    assert_eq!(
        started["verification_url"],
        format!("{}/auth/cli?code={code}", coordinator.base)
    );
    assert_eq!(started["interval_secs"], 3);
    assert_eq!(started["expires_in_secs"], 600);
    assert_eq!(
        cli_poll(&coordinator, device_code).await,
        (428, serde_json::json!({"status": "pending"}))
    );

    // Signed out, the page sends the browser to GitHub and back to it.
    let page = get(&coordinator, &format!("/auth/cli?code={code}"), None).await;
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["referrer-policy"], "same-origin");
    assert!(
        page.headers()["content-security-policy"]
            .to_str()
            .expect("csp")
            .contains("script-src 'self'")
    );
    let text = page.text().await.expect("text");
    let next = format!("/auth/login?next=%2Fauth%2Fcli%3Fcode%3D{code}");
    assert!(text.contains(&next), "{text}");
    let (landing, session) = sign_in_from(&coordinator, &next).await;
    assert_eq!(landing, format!("/auth/cli?code={code}"));
    let session = session.expect("a session cookie");

    // Signed in, it asks.
    let page = get(&coordinator, &landing, Some(&session)).await;
    assert_eq!(page.status(), 200);
    let text = page.text().await.expect("text");
    assert!(text.contains("as <strong>ivanmurzak</strong>?"), "{text}");
    assert!(text.contains(code));
    assert!(text.contains("action=\"/auth/cli/approve\""));
    assert!(!text.contains("<script") && !text.contains("style="));
    assert_eq!(
        get(&coordinator, "/assets/cli.css", None).await.status(),
        200
    );

    let approved = cli_answer(
        &coordinator,
        code,
        "approve",
        Some(&session),
        Some(&coordinator.base),
        None,
    )
    .await;
    assert_eq!(approved.status(), 200);
    let (status, body) = cli_poll(&coordinator, device_code).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["login"], "ivanmurzak");
    let token = body["token"].as_str().expect("token").to_owned();
    assert_eq!(token.len(), 64);
    assert_eq!(
        cli_poll(&coordinator, device_code).await.0,
        410,
        "the token is handed out once"
    );

    let overview = bearer_get(&coordinator, "/api/overview", &token).await;
    assert_eq!(overview.status(), 200);
    let me: serde_json::Value = bearer_get(&coordinator, "/api/session", &token)
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(me["login"], "ivanmurzak");

    // A bearer change needs no origin; the same with the cookie does.
    let by_token = client()
        .post(format!("{}/api/hosts/nobody/command", coordinator.base))
        .bearer_auth(&token)
        .json(&serde_json::json!({"argv": ["repo", "list"]}))
        .send()
        .await
        .expect("sent");
    assert_eq!(
        by_token.status(),
        503,
        "past the origin check: not connected"
    );
    let by_cookie = client()
        .post(format!("{}/api/hosts/nobody/command", coordinator.base))
        .header("cookie", format!("rm_session={session}"))
        .json(&serde_json::json!({"argv": ["repo", "list"]}))
        .send()
        .await
        .expect("sent");
    assert_eq!(by_cookie.status(), 403);

    // Kinds do not mix: the token is no cookie, the cookie no token.
    assert_eq!(
        get(&coordinator, "/api/overview", Some(&token))
            .await
            .status(),
        401
    );
    assert_eq!(
        bearer_get(&coordinator, "/api/overview", &session)
            .await
            .status(),
        401
    );

    // Signing the CLI out ends its token.
    let out = client()
        .post(format!("{}/auth/cli/logout", coordinator.base))
        .bearer_auth(&token)
        .send()
        .await
        .expect("sent");
    assert_eq!(out.status(), 204);
    assert_eq!(
        bearer_get(&coordinator, "/api/overview", &token)
            .await
            .status(),
        401
    );
}

#[tokio::test]
async fn a_denied_cli_sign_in_gets_no_token() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let (_, session) = sign_in(&coordinator).await;
    let session = session.expect("session");
    let started = cli_start(&coordinator).await;
    let code = started["user_code"].as_str().expect("code");
    let denied = cli_answer(
        &coordinator,
        code,
        "deny",
        Some(&session),
        Some(&coordinator.base),
        None,
    )
    .await;
    assert_eq!(denied.status(), 200);
    let device_code = started["device_code"].as_str().expect("dc");
    assert_eq!(
        cli_poll(&coordinator, device_code).await,
        (403, serde_json::json!({"status": "denied"}))
    );
    assert_eq!(cli_poll(&coordinator, device_code).await.0, 410);
    // Answered: it cannot be approved after all.
    let late = cli_answer(
        &coordinator,
        code,
        "approve",
        Some(&session),
        Some(&coordinator.base),
        None,
    )
    .await;
    assert_eq!(late.status(), 410);
}

#[tokio::test]
async fn an_unknown_or_malformed_cli_code_is_gone() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let (_, session) = sign_in(&coordinator).await;
    let session = session.expect("session");
    assert_eq!(
        cli_poll(&coordinator, &"0".repeat(64)).await,
        (410, serde_json::json!({"status": "expired"}))
    );
    assert_eq!(cli_poll(&coordinator, "short").await.0, 410);
    assert_eq!(
        get(&coordinator, "/auth/cli?code=BCDF-GHJK", Some(&session))
            .await
            .status(),
        410
    );
    assert_eq!(
        get(&coordinator, "/auth/cli?code=<script>", Some(&session))
            .await
            .status(),
        400
    );
    let answered = cli_answer(
        &coordinator,
        "BCDF-GHJK",
        "approve",
        Some(&session),
        Some(&coordinator.base),
        None,
    )
    .await;
    assert_eq!(answered.status(), 410);
    // `next` goes nowhere but the CLI page or the dashboard.
    let login = client()
        .get(format!(
            "{}/auth/login?next=https%3A%2F%2Fevil.example%2F",
            coordinator.base
        ))
        .send()
        .await
        .expect("sent");
    assert_eq!(cookie_value(&login, "rm_oauth_next"), None);
}

#[tokio::test]
async fn a_cli_token_cannot_approve_a_sign_in() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let (_, session) = sign_in(&coordinator).await;
    let token = cli_token(&coordinator, &session.expect("session")).await;

    let started = cli_start(&coordinator).await;
    let code = started["user_code"].as_str().expect("code");
    let answered = cli_answer(
        &coordinator,
        code,
        "approve",
        None,
        Some(&coordinator.base),
        Some(&token),
    )
    .await;
    assert_eq!(answered.status(), 401);
    assert_eq!(
        cli_poll(&coordinator, started["device_code"].as_str().expect("dc"))
            .await
            .0,
        428,
        "still waiting"
    );
}

#[tokio::test]
async fn a_cross_origin_approval_is_refused() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let (_, session) = sign_in(&coordinator).await;
    let session = session.expect("session");
    let started = cli_start(&coordinator).await;
    let code = started["user_code"].as_str().expect("code");
    for origin in [Some("https://evil.example"), Some("null"), None] {
        let answered =
            cli_answer(&coordinator, code, "approve", Some(&session), origin, None).await;
        assert_eq!(answered.status(), 403, "{origin:?}");
    }
    assert_eq!(
        cli_poll(&coordinator, started["device_code"].as_str().expect("dc"))
            .await
            .0,
        428
    );
}

#[tokio::test]
async fn cli_sign_ins_are_rate_limited_per_address() {
    let github = github_for("ivanmurzak").await;
    let coordinator = start(Some(auth(&github))).await;
    let mut statuses = Vec::new();
    for _ in 0..25 {
        statuses.push(
            client()
                .post(format!("{}/auth/cli/start", coordinator.base))
                .send()
                .await
                .expect("sent")
                .status()
                .as_u16(),
        );
    }
    assert_eq!(statuses.first(), Some(&200));
    assert_eq!(statuses.last(), Some(&429));
}
