//! The reconciliation sweep against a fake GitHub: the App's JWT, its
//! installation tokens and their renewal, conditional listings, rate limits,
//! and the wakes that come out.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    INSTALLATION, TOKEN_ONE, TOKEN_TWO, app, app_keys, bearer_tokens, fake_github, host, queue,
    requests_to, sweeper,
};
use runner_manager_coordinator::registry::{Outbound, Registry};
use runner_manager_coordinator_protocol::{ServerMessage, TargetScope, WakeReason};
use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

fn messages(rx: &mut tokio::sync::mpsc::Receiver<Outbound>) -> Vec<ServerMessage> {
    let mut out = Vec::new();
    while let Ok(Outbound::Send(message)) = rx.try_recv() {
        out.push(message);
    }
    out
}

#[tokio::test]
async fn the_sweep_authenticates_as_the_app_and_wakes_for_a_queued_job_once() {
    let keys = app_keys();
    let server = fake_github(&keys, Duration::from_secs(3600)).await;
    queue(&server).await;
    let registry = Arc::new(Registry::default());
    let mut rx = host(&registry);
    let mut sweeper = sweeper(app(&keys, &server), &registry);

    let first = sweeper.sweep_once().await;
    assert_eq!(first.repositories, 1);
    assert_eq!(first.queued, 1);
    assert_eq!(first.wakes, 1);
    let sent = messages(&mut rx);
    let Some(ServerMessage::HelloAck(ack)) = sent
        .iter()
        .rev()
        .find(|message| matches!(message, ServerMessage::HelloAck(_)))
    else {
        panic!("the coverage was published: {sent:?}");
    };
    assert_eq!(ack.reconcile_interval_secs, Some(30));
    assert_eq!(ack.covered.len(), 1);
    assert_eq!(ack.covered[0].scope, TargetScope::Org);
    let wakes: Vec<_> = sent
        .iter()
        .filter_map(|message| match message {
            ServerMessage::Wake(wake) => Some(wake),
            _ => None,
        })
        .collect();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes[0].repository, "octo/app");
    assert_eq!(wakes[0].reason, WakeReason::Reconcile);

    // The queue was read with the installation token, never the JWT.
    let used = bearer_tokens(&server, "/repos/octo/app/actions/runs").await;
    assert!(!used.is_empty() && used.iter().all(|token| token == TOKEN_ONE));

    // Unchanged listings: every request conditional, every answer a 304,
    // and the job, already woken within the interval, is not woken again.
    let second = sweeper.sweep_once().await;
    assert_eq!(second.queued, 1);
    assert_eq!(second.already_woken, 1);
    assert_eq!(second.wakes, 0);
    assert!(messages(&mut rx).is_empty());
    let (runs, conditional_runs) = requests_to(&server, "/repos/octo/app/actions/runs").await;
    assert_eq!(
        (runs, conditional_runs),
        (4, 2),
        "two listings, twice; the second time conditional"
    );
    let (jobs, conditional_jobs) =
        requests_to(&server, "/repos/octo/app/actions/runs/11/jobs").await;
    assert_eq!((jobs, conditional_jobs), (2, 1));
    // One token was enough for an hour-long lifetime.
    let (minted, _) = requests_to(
        &server,
        &format!("/app/installations/{INSTALLATION}/access_tokens"),
    )
    .await;
    assert_eq!(minted, 1);
}

#[tokio::test]
async fn a_token_close_to_expiry_is_replaced_before_it_is_used_again() {
    let keys = app_keys();
    // Five minutes: inside the ten-minute renewal window from the start.
    let server = fake_github(&keys, Duration::from_secs(5 * 60)).await;
    queue(&server).await;
    let registry = Arc::new(Registry::default());
    let _rx = host(&registry);
    let mut sweeper = sweeper(app(&keys, &server), &registry);

    sweeper.sweep_once().await;
    sweeper.sweep_once().await;
    let (minted, _) = requests_to(
        &server,
        &format!("/app/installations/{INSTALLATION}/access_tokens"),
    )
    .await;
    assert!(minted >= 2, "renewed: {minted}");
    let used = bearer_tokens(&server, "/repos/octo/app/actions/runs").await;
    assert_eq!(used.first().map(String::as_str), Some(TOKEN_ONE));
    assert_eq!(
        used.last().map(String::as_str),
        Some(TOKEN_TWO),
        "the renewed token is the one in use"
    );
}

#[tokio::test]
async fn a_rate_limited_installation_is_left_alone_until_github_says_so() {
    let keys = app_keys();
    let server = fake_github(&keys, Duration::from_secs(3600)).await;
    let reset = chrono::Utc::now().timestamp() + 3600;
    Mock::given(method("GET"))
        .and(path("/repos/octo/app/actions/runs"))
        .and(query_param("status", "queued"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-limit", "5000")
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("x-ratelimit-reset", reset.to_string().as_str())
                .set_body_json(json!({ "message": "API rate limit exceeded for installation." })),
        )
        .mount(&server)
        .await;
    let registry = Arc::new(Registry::default());
    let mut rx = host(&registry);
    let mut sweeper = sweeper(app(&keys, &server), &registry);

    let first = sweeper.sweep_once().await;
    assert_eq!(first.rate_limited, 1);
    assert_eq!(first.wakes, 0);
    let second = sweeper.sweep_once().await;
    assert_eq!(second.rate_limited, 1, "still inside GitHub's wait");
    let (runs, _) = requests_to(&server, "/repos/octo/app/actions/runs").await;
    assert_eq!(runs, 1, "no request is sent while GitHub asked to wait");
    assert!(
        messages(&mut rx)
            .iter()
            .all(|message| !matches!(message, ServerMessage::Wake(_)))
    );
}
