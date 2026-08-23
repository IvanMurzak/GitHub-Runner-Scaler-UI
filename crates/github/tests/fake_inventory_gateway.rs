// owner: c3-rest-inventory-gateway

//! The fake gateway, exercised from outside the crate that defines it.
//!
//! `c3`'s Definition of Done requires that
//! `crates/testkit/src/github.rs` "offers a fake gateway with programmable
//! pagination, rate limits, revoked-token `401`, and lockout `403`, and is used
//! by at least one test outside this crate". Groups E, F and G are the real
//! consumers and none of them exists yet, so this file stands in for them: it is
//! written the way `e1`, `f1` and `g2` will be written, and it fails if the fake
//! stops being able to carry that weight.
//!
//! # Why this is an integration test and not a unit one
//!
//! `runner-manager-testkit` depends on `runner-manager-github`, so a **unit**
//! test inside `crates/github/src/` that used the fake would link a second
//! instance of this library and the two instances' types would not unify —
//! `InventoryGateway` implemented for the fake would not be the
//! `InventoryGateway` the unit test names. Under `tests/` the library is
//! compiled once and both sides link the same instance, which is the whole
//! reason this file is here rather than beside the code it exercises.
//!
//! `crates/github/src/rest.rs`'s own unit tests use `wiremock` and real HTTP,
//! and prove a different thing: that the wire is read correctly. This file
//! proves that a consumer can be written against the seam at all.

use std::{sync::Arc, time::Duration};

use runner_manager_domain::model::{Arch, Org, Os, OwnerRepo, RefreshInterval, ScaleTarget};
use runner_manager_github::rest::{
    ActivityScope, Admission, BudgetProjection, CancelToken, InventoryGateway, RateLimitKind,
    RefreshCoalescer, RefreshState, TargetCost,
};
use runner_manager_testkit::{
    clock::FakeClock,
    github::{
        FakeCall, FakeFailure, FakeGithub, download, download_without_checksum, runner, runners,
    },
};

fn repo() -> OwnerRepo {
    OwnerRepo::parse("octo/dashboard").expect("a valid owner/repo")
}

fn other_repo() -> OwnerRepo {
    OwnerRepo::parse("octo/api").expect("a valid owner/repo")
}

fn org() -> Org {
    Org::new("octo-org").expect("a valid organization login")
}

fn org_target() -> ScaleTarget {
    ScaleTarget::Organization(org())
}

fn org_scope() -> ActivityScope {
    ActivityScope::organization(org(), [repo(), other_repo()])
}

/// The shape every consumer of this seam will have: one refresh, summarised into
/// a state a screen can render.
///
/// Taking `&dyn InventoryGateway` rather than a generic is deliberate — it is
/// the assertion that the trait is object-safe, which is what lets `e1` hold one
/// gateway behind an `Arc` and `g2` render whatever it produces.
async fn refresh_once(gateway: &dyn InventoryGateway, scope: &ActivityScope) -> RefreshState {
    RefreshState::from_result(gateway.snapshot(scope, &CancelToken::new()).await)
}

/// A consumer receives a complete multi-page inventory, and can see what it
/// cost.
#[tokio::test]
async fn a_consumer_receives_a_complete_multi_page_inventory() {
    let target = org_target();
    let gateway = FakeGithub::new()
        .with_page_size(50)
        .with_runners(target.clone(), runners(210))
        .with_in_progress(repo(), 3)
        .with_in_progress(other_repo(), 4);

    let state = refresh_once(&gateway, &org_scope()).await;
    let snapshot = state.snapshot().expect("ready");

    assert_eq!(snapshot.runners.len(), 210);
    assert_eq!(
        snapshot.runners.pages(),
        5,
        "210 runners at 50 a page is five pages, and a consumer that assumed one \
         would be reading 50 of them"
    );
    assert!(!snapshot.runners.truncated());
    assert_eq!(snapshot.activity.total(), 7);
    assert_eq!(
        gateway.requests_issued(),
        7,
        "five inventory pages plus one runs request per installed repository"
    );
    assert_eq!(
        gateway.calls(),
        vec![
            FakeCall::ListRunners(target.clone()),
            FakeCall::InProgressActivity(target),
        ]
    );
}

/// The two aggregates stay distinct across the seam, which is the property `g2`
/// renders and therefore the one a fake most needs to preserve.
#[tokio::test]
async fn the_busy_runner_count_and_the_in_progress_count_stay_distinct() {
    let target = ScaleTarget::Repository(repo());
    let gateway = FakeGithub::new()
        .with_runners(
            target.clone(),
            vec![
                runner(1, "rm-home-win-x64-1").busy().build(),
                runner(2, "rm-home-win-x64-2").build(),
                runner(3, "legacy").offline().build(),
            ],
        )
        .with_in_progress(repo(), 11);

    let scope = ActivityScope::repository(repo());
    let snapshot = refresh_once(&gateway, &scope)
        .await
        .snapshot()
        .expect("ready")
        .clone();

    assert_eq!(snapshot.runners.len(), 3);
    assert_eq!(snapshot.runners.busy_count(), 1);
    assert_eq!(snapshot.runners.online_count(), 2);
    assert_eq!(snapshot.activity.total(), 11);
}

/// Each programmed failure reaches a consumer as its own state. `f1` reports
/// four authentication outcomes separately and cannot do that if the fake
/// collapses them.
#[tokio::test]
async fn every_programmed_failure_arrives_as_its_own_state() {
    let gateway = FakeGithub::new();
    let scope = ActivityScope::repository(repo());

    gateway.fail_next(FakeFailure::secondary_rate_limit(45));
    let state = refresh_once(&gateway, &scope).await;
    let RefreshState::RateLimited(limit) = state else {
        panic!("expected a rate-limited state, got {state:?}");
    };
    assert_eq!(limit.kind, RateLimitKind::Secondary);
    assert_eq!(limit.retry_after, Some(Duration::from_secs(45)));
    assert_eq!(
        RefreshState::RateLimited(limit).retry_delay(gateway.now()),
        Some(Duration::from_secs(45)),
        "a rate limit lengthens the refresh delay; that is the number it lengthens by"
    );

    gateway.fail_next(FakeFailure::primary_rate_limit(
        u64::try_from(gateway.now().timestamp()).expect("a positive instant") + 600,
    ));
    let state = refresh_once(&gateway, &scope).await;
    let RefreshState::RateLimited(limit) = state else {
        panic!("expected a rate-limited state, got {state:?}");
    };
    assert_eq!(limit.kind, RateLimitKind::Primary);
    assert_eq!(limit.remaining, Some(0));

    gateway.fail_next(FakeFailure::RevokedToken);
    assert_eq!(
        refresh_once(&gateway, &scope).await,
        RefreshState::Unauthorized,
        "a revoked token is terminal until `auth login`, and must not read as \
         something to wait for"
    );

    gateway.fail_next(FakeFailure::AuthenticationLockout {
        retry_after_secs: 60,
    });
    assert_eq!(
        refresh_once(&gateway, &scope).await,
        RefreshState::LockedOut {
            retry_after: Duration::from_secs(60)
        },
        "the lockout is the opposite advice from a revoked token: wait, and do \
         not re-authenticate"
    );

    gateway.fail_next(FakeFailure::Forbidden {
        message: Some("Resource not accessible by integration".to_string()),
    });
    let state = refresh_once(&gateway, &scope).await;
    assert!(
        matches!(&state, RefreshState::Forbidden { message }
            if message.as_deref() == Some("Resource not accessible by integration")),
        "{state:?}"
    );
    assert_eq!(state.retry_delay(gateway.now()), None);

    gateway.fail_next(FakeFailure::not_found());
    assert!(matches!(
        refresh_once(&gateway, &scope).await,
        RefreshState::Failed {
            status: Some(404),
            ..
        }
    ));

    // The queue is empty again, so the gateway answers normally.
    assert!(refresh_once(&gateway, &scope).await.is_ready());
}

/// A latched failure persists, which is the shape of a revoked token or an
/// exhausted quota. A queued one does not.
#[tokio::test]
async fn a_latched_failure_persists_and_a_queued_one_does_not() {
    let gateway = FakeGithub::new();
    let scope = ActivityScope::repository(repo());

    gateway.fail_always(FakeFailure::RevokedToken);
    for _ in 0..3 {
        assert_eq!(
            refresh_once(&gateway, &scope).await,
            RefreshState::Unauthorized,
            "a revoked token does not clear because one request went by"
        );
    }

    gateway.recover();
    assert!(refresh_once(&gateway, &scope).await.is_ready());
}

/// Cancellation reaches the fake too, so a consumer's cancellation path is
/// reachable without a network.
#[tokio::test]
async fn a_cancelled_token_stops_the_fake_as_well() {
    let gateway = FakeGithub::new();
    let scope = ActivityScope::repository(repo());
    let cancel = CancelToken::new();
    cancel.cancel();

    let error = gateway
        .snapshot(&scope, &cancel)
        .await
        .expect_err("the token is cancelled");
    assert!(error.is_cancelled(), "{error}");
    assert_eq!(
        gateway.requests_issued(),
        0,
        "a cancelled refresh spends nothing"
    );
    assert_eq!(RefreshState::from_error(&error), RefreshState::Cancelled);
}

/// The coalescer is a gateway-agnostic primitive, so a consumer can use it over
/// the fake exactly as it will over the real one.
#[tokio::test]
async fn a_manual_refresh_coalesces_over_the_fake_too() {
    let gateway = Arc::new(
        FakeGithub::new()
            .with_runners(ScaleTarget::Repository(repo()), runners(2))
            .with_in_progress(repo(), 1),
    );
    let coalescer: Arc<RefreshCoalescer<RefreshState>> = Arc::new(RefreshCoalescer::new());
    let scope = ActivityScope::repository(repo());

    let refresh = || {
        let gateway = gateway.clone();
        let coalescer = coalescer.clone();
        let scope = scope.clone();
        async move {
            coalescer
                .refresh(|| async { refresh_once(gateway.as_ref(), &scope).await })
                .await
        }
    };

    let (scheduled, manual) = tokio::join!(refresh(), refresh());
    assert_eq!(scheduled, manual);
    assert_eq!(coalescer.performed() + coalescer.joined(), 2);
    assert!(scheduled.is_ready(), "{scheduled}");
}

/// `f1`'s `host show` and `f2`'s `org add`, written against the fake's scope.
#[test]
fn a_consumer_projects_the_budget_from_the_scope_it_will_actually_poll() {
    let default =
        RefreshInterval::from_secs(RefreshInterval::DEFAULT_SECS).expect("the documented default");

    // One organization reaching two repositories.
    let cost = TargetCost::from_activity_scope(&org_scope());
    assert_eq!(cost.installed_repositories(), 2);
    assert_eq!(cost.requests_per_hour(default), 420);

    let projection = BudgetProjection::new(default, [cost]);
    assert_eq!(projection.requests_per_hour(), 420);
    assert_eq!(projection.headroom(), 2_080);
    assert!(!projection.exceeds_allowance());
    assert_eq!(
        BudgetProjection::max_repository_targets(default, TargetCost::repository()),
        10,
        "the figure `host show` prints"
    );

    // And the refusal `org add` has to print.
    let refusal = projection.admit(TargetCost::organization(12));
    assert!(matches!(refusal, Admission::Refused { .. }));
    let message = refusal.to_string();
    assert!(
        message.contains("installed on 12 of its repositories"),
        "{message}"
    );
}

/// `e2`'s two paths, both reachable from the fake: a published digest, and the
/// absent one it must fail closed on.
#[tokio::test]
async fn runner_download_metadata_carries_an_absent_checksum_as_absent() {
    let target = ScaleTarget::Repository(repo());
    let gateway = FakeGithub::new().with_downloads(vec![
        download("win", "x64"),
        download_without_checksum("linux", "arm64"),
    ]);

    let downloads = gateway
        .runner_downloads(&target, &CancelToken::new())
        .await
        .expect("readable");

    let windows = downloads
        .select(Os::Windows, Arch::X64)
        .expect("a published Windows package");
    assert_eq!(windows.sha256_checksum().map(str::len), Some(64));

    let linux = downloads
        .select(Os::Linux, Arch::Arm64)
        .expect("a published Linux package");
    assert_eq!(
        linux.sha256_checksum(),
        None,
        "`e2` fails closed here and needs a fixture that can reach the branch"
    );

    assert_eq!(
        downloads.select(Os::MacOs, Arch::Arm64),
        None,
        "an unpublished pair is refused rather than substituted"
    );
}

/// The fake's clock is the test's, so a consumer's time-dependent branches are
/// decidable rather than raced.
#[tokio::test]
async fn the_fake_stamps_snapshots_from_a_clock_the_test_controls() {
    let clock = Arc::new(FakeClock::at_epoch_secs(1_787_270_400));
    let gateway = FakeGithub::new().with_clock(clock.clone());
    let scope = ActivityScope::repository(repo());

    let first = refresh_once(&gateway, &scope).await;
    let first_at = first.snapshot().expect("ready").observed_at;

    clock.advance_secs(60);
    let second = refresh_once(&gateway, &scope).await;
    let second_at = second.snapshot().expect("ready").observed_at;

    assert_eq!((second_at - first_at).num_seconds(), 60);
}
