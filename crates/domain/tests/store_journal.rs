// owner: b2-sqlite-persistence

//! The half of `b2`'s Definition of Done that needs `testkit`.
//!
//! **Why this directory exists.** `crates/domain` dev-depends on
//! `runner-manager-testkit`, which depends on `runner-manager-domain` in turn.
//! Cargo permits that cycle, but building the domain's **unit-test** target
//! compiles a second instance of the domain library for `testkit` to link
//! against, and the two instances' types do not unify — a `FakeClock` or a
//! `fixtures::attempt()` used from `crates/domain/src/*.rs` fails with `E0308:
//! there are multiple different versions of crate runner_manager_domain`. An
//! **integration** test here does not hit that: the domain is compiled once and
//! this file and `testkit` link the same instance.
//!
//! So the split between `store.rs`'s unit tests and this file is mechanical, not
//! editorial. Mechanics that need no fixture — migrations, the column/field
//! mapping, hand-corrupted rows — stay there, next to the code. Everything that
//! needs a real domain object built through `testkit`, a fake clock, or a second
//! process's view of the same file is here.

use std::fs;
use std::num::NonZeroU16;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use runner_manager_domain::attempt::{
    AttemptOutcome, AttemptState, FailureReason, GithubRunnerObservation, PersistedAttempt,
    RecoveryDecision, RecoveryObservation, RecoveryTimeouts, RunnerAttempt, active_count,
    recovery_decision,
};
use runner_manager_domain::model::{
    Arch, AttemptId, CachePolicy, Clock, Elapsed, Host, HostId, Os, PolicyId, StartMode,
    TargetScope,
};
use runner_manager_domain::policy::{PolicyState, ScalePolicy};
use runner_manager_domain::store::{SCHEMA_VERSION, SqliteStore, Store};
use runner_manager_testkit::clock::FakeClock;
use runner_manager_testkit::fixtures;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn database(dir: &Path) -> std::path::PathBuf {
    dir.join("runner-manager.sqlite3")
}

/// Write everything, then abandon the connection the way a killed process does.
///
/// `std::mem::forget` skips `Drop`, so `sqlite3_close` is never called, no
/// checkpoint runs and the write-ahead log is left for the next opener to
/// recover from. That is a materially stronger simulation of process death than
/// dropping the store: a clean drop closes the database and checkpoints it, so a
/// reopen afterwards proves only that SQLite can read a file it shut down
/// tidily.
fn abandon(store: SqliteStore) {
    std::mem::forget(store);
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn a_host_round_trips_byte_identically_in_every_configuration() {
    let store = SqliteStore::open_in_memory().expect("in-memory");

    for os in Os::ALL {
        for arch in Arch::ALL {
            for mode in [StartMode::Boot, StartMode::Login] {
                let host = fixtures::host()
                    .id(HostId::from_u128(
                        u128::from(os as u8) * 100 + u128::from(arch as u8) * 10 + mode as u128,
                    ))
                    .os(os)
                    .architecture(arch)
                    .start_mode(mode)
                    .capacity(4)
                    .refresh_secs(30)
                    .build();
                store.put_host(&host).expect("stored");
                let back = store.host(host.id).expect("loads").expect("present");
                assert_eq!(back, host, "{os}/{arch}/{mode} did not round-trip");
            }
        }
    }

    assert_eq!(store.hosts().expect("loads").len(), 3 * 3 * 2);
}

#[test]
fn both_scale_target_variants_and_both_policy_modes_round_trip_byte_identically() {
    // `04-subsystem-contracts.md`: repository and organization targets "differ
    // only in which GitHub endpoints and which App permission the gateway uses",
    // and D19's two modes are an enforced invariant. Storage must not be the
    // place either distinction quietly changes.
    let store = SqliteStore::open_in_memory().expect("in-memory");

    let cases: Vec<(&str, ScalePolicy)> = vec![
        (
            "an autoscale repository policy",
            fixtures::policy()
                .id(PolicyId::from_u128(1))
                .repository("IvanMurzak/GitHub-Runner-Scaler-UI")
                .active()
                .build(),
        ),
        (
            "an autoscale organization policy",
            fixtures::policy()
                .id(PolicyId::from_u128(2))
                .organization("tap-top-fun")
                .active()
                .build(),
        ),
        (
            "a monitor-only repository policy",
            fixtures::policy()
                .id(PolicyId::from_u128(3))
                .repository("o/r")
                .monitor_only()
                .active()
                .build(),
        ),
        (
            "a monitor-only organization policy",
            fixtures::policy()
                .id(PolicyId::from_u128(4))
                .organization("some-org")
                .monitor_only()
                .build(),
        ),
        (
            "a pending policy with extra routing labels and a non-default cache policy",
            {
                let mut policy = fixtures::policy()
                    .id(PolicyId::from_u128(5))
                    .autoscale("home-win", 3)
                    .cache_policy(CachePolicy::DiscardRunnerPackage)
                    .installation_id(9_876_543_210)
                    .build();
                policy
                    .add_routing_label(fixtures::label("gpu"))
                    .expect("autoscale");
                policy
                    .add_routing_label(fixtures::label("cuda-12"))
                    .expect("autoscale");
                policy
            },
        ),
        ("a policy that reached repair_required", {
            let mut policy = fixtures::policy().id(PolicyId::from_u128(6)).build();
            policy.repair_required().expect("pending policies may");
            policy
        }),
        ("a policy that drained to disabled", {
            let mut policy = fixtures::policy()
                .id(PolicyId::from_u128(7))
                .active()
                .build();
            policy.request_disable().expect("active policies drain");
            policy.drain_completed(0).expect("no runners remain");
            policy
        }),
        ("a policy whose authentication failed", {
            let mut policy = fixtures::policy()
                .id(PolicyId::from_u128(8))
                .active()
                .build();
            policy.authentication_failed().expect("any state may");
            policy
        }),
    ];

    for (label, policy) in &cases {
        store
            .insert_policy(policy)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let back = store
            .policy(policy.id)
            .unwrap_or_else(|e| panic!("{label}: {e}"))
            .unwrap_or_else(|| panic!("{label}: not present after insert"));
        assert_eq!(&back, policy, "{label} did not round-trip");
    }

    // Every distinguishing property survived, not merely the equality check.
    let loaded = store.policies().expect("loads");
    assert_eq!(loaded.len(), cases.len());
    assert_eq!(
        loaded.iter().filter(|p| p.owns_runners()).count(),
        6,
        "the monitor-only/autoscale split must survive storage"
    );
    assert_eq!(
        loaded
            .iter()
            .filter(|p| p.target.scope() == TargetScope::Organization)
            .count(),
        2,
        "the repository/organization split must survive storage"
    );
    assert!(
        loaded
            .iter()
            .any(|p| p.state() == PolicyState::RepairRequired),
        "a repair_required policy must be loadable, which is this task's Goal"
    );
}

#[test]
fn every_attempt_state_round_trips_byte_identically() {
    let store = SqliteStore::open_in_memory().expect("in-memory");
    let clock = FakeClock::default();

    for (index, state) in AttemptState::ALL.into_iter().enumerate() {
        let attempt = fixtures::attempt()
            .id(AttemptId::from_u128(0x100 + index as u128))
            .state(state)
            .github_runner_id(73)
            .process_id(4_242)
            .entered_state_at(clock.now() + Elapsed::seconds(index as i64))
            .build();
        store.record_attempt(&attempt).expect("journalled");
        let back = store
            .attempt(attempt.id)
            .expect("loads")
            .expect("present after a write");
        assert_eq!(back, attempt, "{state} did not round-trip");
        assert_eq!(back.state(), state);
        assert_eq!(back.outcome().is_some(), state.is_terminal());
    }

    let all = store.attempts().expect("loads");
    assert_eq!(all.len(), AttemptState::ALL.len());
    assert_eq!(
        active_count(&all),
        5,
        "exactly the five non-terminal states hold a host capacity slot; if \
         storage changed that, the reconciliation formula would silently starve \
         or oversubscribe the host"
    );

    // The surplus exit and a failure are terminal in the same way and must stay
    // distinguishable in the journal, not only on screen (`g2`).
    let idle_exit = fixtures::idle_exit_attempt();
    let failed = fixtures::failed_attempt();
    let mut renamed = Vec::new();
    for (index, attempt) in [idle_exit, failed].into_iter().enumerate() {
        let moved = RunnerAttempt::from_persisted(PersistedAttempt {
            id: AttemptId::from_u128(0x200 + index as u128),
            ..attempt.to_persisted()
        })
        .expect("a legal attempt");
        store.record_attempt(&moved).expect("journalled");
        renamed.push(moved);
    }
    let a = store
        .attempt(renamed[0].id)
        .expect("loads")
        .expect("present");
    let b = store
        .attempt(renamed[1].id)
        .expect("loads")
        .expect("present");
    assert!(a.outcome().expect("terminal").is_idle_exit());
    assert!(!a.outcome().expect("terminal").is_failure());
    assert!(b.outcome().expect("terminal").is_failure());
    assert_ne!(a.outcome(), b.outcome());
}

#[test]
fn a_failure_reason_round_trips_including_the_open_ended_one() {
    let store = SqliteStore::open_in_memory().expect("in-memory");
    let reasons = [
        FailureReason::JitRequestFailed,
        FailureReason::JitExpired,
        FailureReason::RunnerPackageUnverified,
        FailureReason::RunnerVersionRejected,
        FailureReason::ProcessStartFailed,
        FailureReason::ProcessExitedUnexpectedly,
        // `e3` writes this one to the journal after reading its own
        // terminate-intent back, so its snake_case serde name is on a real
        // persistence path and belongs here. This list is hand-maintained and
        // nothing binds it to `FailureReason::ALL`, which is why
        // `RegistrationTimedOut` is absent from it -- an omission that predates
        // this variant and is left alone rather than tidied in passing.
        FailureReason::TerminatedAfterRegistrationTimeout,
        FailureReason::Other("the runner package cache was pruned mid-start".to_string()),
    ];

    for (index, reason) in reasons.into_iter().enumerate() {
        let attempt = fixtures::attempt()
            .id(AttemptId::from_u128(0x300 + index as u128))
            .state(AttemptState::Failed)
            .outcome(AttemptOutcome::failed(reason))
            .build();
        store.record_attempt(&attempt).expect("journalled");
        assert_eq!(
            store.attempt(attempt.id).expect("loads").expect("present"),
            attempt
        );
    }
}

// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------

#[test]
fn the_journal_survives_process_death_and_yields_the_same_attempts() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = database(dir.path());
    let clock = FakeClock::default();

    let written: Vec<RunnerAttempt> = AttemptState::ALL
        .into_iter()
        .enumerate()
        .map(|(index, state)| {
            fixtures::attempt()
                .id(AttemptId::from_u128(0x100 + index as u128))
                .state(state)
                .process_id(1_000 + index as u32)
                .entered_state_at(clock.now() + Elapsed::seconds(index as i64))
                .build()
        })
        .collect();

    let host = fixtures::host().build();
    let mut policy = fixtures::policy().build();
    policy.repair_required().expect("pending policies may");

    let (mode, wal) = {
        let store = SqliteStore::open(&path).expect("a fresh database opens");
        store.put_host(&host).expect("stored");
        store.insert_policy(&policy).expect("stored");
        for attempt in &written {
            store.record_attempt(attempt).expect("journalled");
        }
        let observed = (
            store.journal_mode().to_string(),
            store.readers_do_not_block_writers(),
        );
        abandon(store);
        observed
    };

    // The store *asks* for WAL and now reports what it got, so this asks too.
    // Asserting the `-wal` file unconditionally failed on a healthy build
    // wherever WAL is unavailable -- no shared-memory support, as on a
    // network-mounted application data directory -- with nothing to say that
    // the mode, rather than the durability, was what had changed. Everything
    // below holds in either mode and is the actual point of the test; this pair
    // of assertions is the part that is about WAL specifically.
    //
    // Nothing reopens the database here. A second `SqliteStore` would close
    // cleanly at the end of its statement, and a clean close checkpoints the
    // write-ahead log away -- which is precisely the file being asserted on.
    // What this first assertion checks is the letter case, and it now says so.
    // It used to read `assert_eq!(wal, mode == "wal")` under a message about
    // `readers_do_not_block_writers` agreeing with the reported mode -- but that
    // method *is* `journal_mode().eq_ignore_ascii_case("wal")`, so the two sides
    // could only ever have differed on case. Agreement is worth pinning too, and
    // that is the next assertion, which reads a second source rather than the
    // same fact twice.
    //
    // **What the case pin protects is the tests, not production.** Both
    // production comparisons fold case -- `store.rs`'s WAL warning at open, and
    // `readers_do_not_block_writers` -- so a `WAL` from some future SQLite would
    // not change the agent's behaviour by one branch. The literal comparisons
    // are both in `store.rs`'s own test module: `assert_eq!(memory.
    // journal_mode(), "memory")` and `matches!(mode, "wal" | "delete")`. Those
    // are what a change of case would red, and they would red loudly rather than
    // silently, which is the outcome to want. Below in *this* file `mode` is
    // only interpolated into failure messages, so nothing here compares it at
    // all.
    //
    // So this is a canary on an assumption the suite is built on, not a guard on
    // a live code path -- worth keeping, worth not overstating.
    assert_eq!(
        mode,
        mode.to_ascii_lowercase(),
        "SQLite reports the mode lowercased, and `store.rs`'s tests compare it \
         literally, so a change of case here would red them somewhere less \
         obvious than this"
    );
    assert_eq!(
        path.with_extension("sqlite3-wal").exists(),
        wal,
        "in {mode} mode a write-ahead log beside the database is {}",
        if wal {
            "required: without it the reopen below proves nothing about \
             recovering from an unclean stop"
        } else {
            "impossible, so one on disk means the mode was misreported"
        }
    );

    let reopened = SqliteStore::open(&path).expect("a killed process leaves a readable database");
    assert_eq!(reopened.schema_version(), SCHEMA_VERSION);
    assert_eq!(
        reopened.attempts().expect("loads"),
        {
            let mut sorted = written.clone();
            sorted.sort_by_key(|a| (a.created_at, a.id.to_string()));
            sorted
        },
        "the same attempts, in the same states"
    );
    assert_eq!(reopened.host(host.id).expect("loads"), Some(host));

    // The Goal, stated as a test: a `repair_required` policy survives a restart
    // and still yields an explicit repair instruction rather than a silent
    // destructive retry.
    let recovered = reopened.policy(policy.id).expect("loads").expect("present");
    assert_eq!(recovered.state(), PolicyState::RepairRequired);
    assert!(!recovered.may_start_runners());
    assert!(
        !recovered.can_activate(),
        "`repair_required` has no edge back to `active`, so a restart must not \
         quietly re-arm the policy; the operator has to be told"
    );
}

#[test]
fn a_reloaded_journal_drives_the_same_recovery_decisions_as_the_live_one() {
    // The journal is the input to `e3`'s startup recovery, so what matters is
    // not only that the rows come back but that the decisions taken from them do
    // not change. Time enters only through the fake clock.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = database(dir.path());
    let clock = FakeClock::default();
    let timeouts = RecoveryTimeouts::provisional();

    // `entered_state_at` is deliberately **not** `created_at`. The two used to
    // be the same instant -- `fixtures::created_at()` is exactly what
    // `FakeClock::default().now()` returns -- and with them equal, a storage
    // layer that wrote `created_at` into `last_state_change_at` was
    // unobservable here: every elapsed-time assertion below landed on the same
    // branch either way. Confirmed by mutating the store: that transposition
    // passed this test while two others failed it.
    //
    // So both attempts are allocated at T0 and enter the state they are in a
    // full idle timeout later, and the clock is advanced to match. The
    // transposition now moves `last_state_change_at` *earlier* by exactly one
    // timeout, which is enough to push the first assertion below onto the wrong
    // branch.
    let allocated_at = clock.now();
    // Named for the column rather than for `idle`: `busy` below is built from
    // the same instant, and calling it `entered_idle_at` there said something
    // that was not true of it.
    let entered_state_at = allocated_at + timeouts.idle;
    let idle = fixtures::attempt()
        .id(AttemptId::from_u128(0x401))
        .state(AttemptState::Idle)
        .github_runner_id(73)
        .process_id(4_242)
        .created_at(allocated_at)
        .entered_state_at(entered_state_at)
        .build();
    let busy = fixtures::attempt()
        .id(AttemptId::from_u128(0x402))
        .state(AttemptState::Busy)
        .github_runner_id(74)
        .process_id(4_243)
        .created_at(allocated_at)
        .entered_state_at(entered_state_at)
        .build();
    // Both attempts, not just the one the assertions below happen to read
    // first: `busy` is reloaded and decided on too, so it needs the same two
    // columns to be distinguishable.
    for attempt in [&idle, &busy] {
        assert_ne!(
            attempt.created_at,
            attempt.last_state_change_at(),
            "if these are equal, nothing below can tell the two columns apart"
        );
    }

    // Now is the moment the runner entered `idle`, so no time has yet elapsed
    // *in that state* -- while a whole idle timeout has elapsed since
    // allocation. That gap is the discriminator.
    clock.advance(timeouts.idle);

    {
        let store = SqliteStore::open(&path).expect("opens");
        store.record_attempt(&idle).expect("journalled");
        store.record_attempt(&busy).expect("journalled");
        abandon(store);
    }

    let reopened = SqliteStore::open(&path).expect("opens");
    let loaded = reopened.attempts().expect("loads");
    assert_eq!(loaded, vec![idle.clone(), busy.clone()]);

    let vanished = RecoveryObservation {
        process_alive: false,
        github: GithubRunnerObservation::NotRegistered,
    };
    let offline = RecoveryObservation {
        process_alive: false,
        github: GithubRunnerObservation::Unreachable,
    };

    // Before the idle timeout the disappearance is a crash; after it, it is
    // flow 2.7's surplus runner. The reloaded attempt must land on the same side
    // of that line as the in-memory one, which is only true if
    // `last_state_change_at` survived storage as itself.
    assert_eq!(
        recovery_decision(&loaded[0], vanished, timeouts, &clock),
        recovery_decision(&idle, vanished, timeouts, &clock)
    );
    assert!(
        matches!(
            recovery_decision(&loaded[0], vanished, timeouts, &clock),
            RecoveryDecision::Conclude(outcome) if outcome.is_failure()
        ),
        "no time has passed in `idle`, so this is a crash -- and this is the \
         discriminating assertion: had storage written `created_at` into \
         `last_state_change_at`, a whole idle timeout would appear to have \
         elapsed and this would report the benign surplus exit instead"
    );

    clock.advance(timeouts.idle);
    assert!(
        matches!(
            recovery_decision(&loaded[0], vanished, timeouts, &clock),
            RecoveryDecision::Conclude(outcome) if outcome.is_idle_exit()
        ),
        "and once the timeout really has elapsed in `idle`, it is flow 2.7's \
         surplus runner"
    );

    // And an outage decides nothing destructive, reloaded or not.
    for attempt in &loaded {
        assert_eq!(
            recovery_decision(attempt, offline, timeouts, &clock),
            RecoveryDecision::Defer
        );
    }
}

// ---------------------------------------------------------------------------
// Optimistic concurrency, with real concurrent writers
// ---------------------------------------------------------------------------

#[test]
fn two_concurrent_writers_race_and_exactly_one_wins() {
    // Two *separate connections* to one file, in two threads, each holding a
    // policy it read at the same revision. This is the TUI-versus-CLI case the
    // revision token exists for, and it is asserted against a real race rather
    // than by reasoning about the transaction.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = database(dir.path());
    let policy = fixtures::policy().build();
    let policy_id = policy.id;

    {
        let seed = SqliteStore::open(&path).expect("opens");
        seed.insert_policy(&policy).expect("stored");
        drop(seed);
    }

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for ceiling in [5u16, 9u16] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let store = SqliteStore::open(&path).expect("opens");
            let mut mine = store.policy(policy_id).expect("loads").expect("present");
            let read_at = mine.revision();
            mine.set_max_capacity(NonZeroU16::new(ceiling).expect("non-zero"))
                .expect("autoscale");
            // Both have read before either writes; the barrier is what makes
            // that true rather than probable.
            barrier.wait();
            (ceiling, store.update_policy(&mine, read_at))
        }));
    }

    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("neither writer panicked"))
        .collect();

    let winners: Vec<u16> = outcomes
        .iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(ceiling, _)| *ceiling)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent write may land; got {outcomes:?}"
    );
    for (ceiling, result) in &outcomes {
        if let Err(error) = result {
            assert!(
                error.is_conflict(),
                "the loser must be told it lost a race, not handed an I/O error: \
                 ceiling {ceiling} got {error:?}"
            );
        }
    }

    let stored = SqliteStore::open(&path).expect("opens");
    let final_policy = stored.policy(policy_id).expect("loads").expect("present");
    assert_eq!(
        final_policy.max_capacity().expect("autoscale").get(),
        winners[0],
        "the winner's value is what is stored; the loser wrote nothing"
    );
    assert_eq!(
        final_policy.revision(),
        1,
        "one write happened, so the token advanced exactly once"
    );
}

// ---------------------------------------------------------------------------
// The security gate
// ---------------------------------------------------------------------------

/// Prefixes GitHub uses for the credential classes this product could plausibly
/// hold, plus the two header shapes a leaked request would carry.
const TOKEN_PREFIXES: &[&str] = &[
    "ghu_",
    "gho_",
    "ghp_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "Bearer ",
    "Authorization",
];

/// Every token-shaped thing in `haystack`: a known prefix, or a run of at least
/// forty hexadecimal characters, which is the shape of a classic personal access
/// token and of the encoded blobs this product must never store.
fn token_shaped(haystack: &str) -> Vec<String> {
    let mut found: Vec<String> = TOKEN_PREFIXES
        .iter()
        .filter(|prefix| haystack.contains(**prefix))
        .map(|prefix| (*prefix).to_string())
        .collect();

    let mut run = 0usize;
    for ch in haystack.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run == 40 {
                found.push("a 40-character hexadecimal run".to_string());
            }
        } else {
            run = 0;
        }
    }
    found
}

#[test]
fn the_token_scanner_can_actually_fail() {
    // A scan that cannot fail proves nothing about the database it passes over.
    // This is the positive control for the one below.
    assert!(token_shaped("nothing to see here").is_empty());
    assert!(!token_shaped("ghu_16C7e42F292c6912E7710c838347Ae178B4a").is_empty());
    assert!(!token_shaped("Authorization: token abc").is_empty());
    assert!(!token_shaped(&"a".repeat(40)).is_empty());
    assert!(
        token_shaped(&"a".repeat(39)).is_empty(),
        "the hexadecimal run threshold must be an edge, not an approximation"
    );

    // And it finds a planted secret in a real database and its dump, which is
    // what makes the clean result in the next test meaningful. `runtime_path`,
    // `display_name` and `FailureReason::Other` are the three free-form strings
    // a caller could put one in; the schema cannot stop that, so the scan is
    // what would catch it.
    let store = SqliteStore::open_in_memory().expect("in-memory");
    let planted = "ghu_16C7e42F292c6912E7710c838347Ae178B4a";
    let leaky = fixtures::attempt()
        .id(AttemptId::from_u128(0x501))
        .state(AttemptState::Failed)
        .outcome(AttemptOutcome::failed(FailureReason::Other(format!(
            "start failed with {planted}"
        ))))
        .build();
    store.record_attempt(&leaky).expect("journalled");
    assert!(
        !token_shaped(&store.dump_text().expect("dumpable")).is_empty(),
        "if this passes, the scan in the next test is vacuous"
    );
}

#[test]
fn no_fixture_database_or_its_dump_holds_a_token_shaped_value() {
    // `05-infrastructure.md` puts the user access token in the machine-scoped
    // secret store and the encoded JIT configuration in a restrictive temporary
    // file. The check that SQLite holds neither is this one: a fully populated
    // database, every file it left on disk, and its own dump.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = database(dir.path());
    let clock = FakeClock::default();

    let dump = {
        let store = SqliteStore::open(&path).expect("opens");

        store.put_host(&fixtures::host().build()).expect("stored");
        store
            .put_host(
                &Host::new(
                    HostId::from_u128(0x0000_0002),
                    "build-mini",
                    Os::MacOs,
                    Arch::Arm64,
                    NonZeroU16::new(1).expect("non-zero"),
                    clock.now(),
                )
                .expect("valid"),
            )
            .expect("stored");

        for (index, policy) in [
            fixtures::policy()
                .id(PolicyId::from_u128(1))
                .active()
                .build(),
            fixtures::policy()
                .id(PolicyId::from_u128(2))
                .organization("tap-top-fun")
                .active()
                .build(),
            fixtures::policy()
                .id(PolicyId::from_u128(3))
                .monitor_only()
                .build(),
        ]
        .into_iter()
        .enumerate()
        {
            store
                .insert_policy(&policy)
                .unwrap_or_else(|e| panic!("policy {index}: {e}"));
        }

        for (index, state) in AttemptState::ALL.into_iter().enumerate() {
            let attempt = fixtures::attempt()
                .id(AttemptId::from_u128(0x600 + index as u128))
                .state(state)
                .github_runner_id(73)
                .process_id(4_242)
                .entered_state_at(clock.now())
                .build();
            store.record_attempt(&attempt).expect("journalled");
        }

        let dump = store.dump_text().expect("dumpable");
        // A clean close checkpoints the write-ahead log into the main file, so
        // the scan below sees everything that was written rather than only what
        // had been checkpointed.
        drop(store);
        dump
    };

    let offenders = token_shaped(&dump);
    assert!(
        offenders.is_empty(),
        "the dump of a fully populated database holds token-shaped values: \
         {offenders:?}"
    );

    let mut scanned = 0usize;
    for entry in fs::read_dir(dir.path()).expect("the directory is readable") {
        let entry = entry.expect("a readable entry");
        let bytes = fs::read(entry.path()).expect("a readable file");
        let text = String::from_utf8_lossy(&bytes);
        let offenders = token_shaped(&text);
        assert!(
            offenders.is_empty(),
            "{:?} holds token-shaped values: {offenders:?}",
            entry.file_name()
        );
        scanned += 1;
    }
    assert!(
        scanned > 0,
        "the scan must have read at least the database file, or it proved nothing"
    );
}
