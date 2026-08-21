// owner: b1-domain-core

//! A clock the test drives.
//!
//! `b1`'s Definition of Done requires that "recovery decisions are tested
//! against the fake clock with no real time dependency". That is not a style
//! preference: every timeout in this product — the JIT handoff window, the
//! startup deadline, the idle timeout that separates a surplus runner from a
//! crashed one — is minutes long. Tested against the system clock those
//! decisions are either untested or slow, and a suite that sleeps is a suite
//! that eventually flakes on a loaded CI runner.
//!
//! [`FakeClock`] implements `runner_manager_domain::model::Clock`, which is the
//! only source of "now" any domain decision has. Substituting it is therefore
//! total: there is no second path to the wall clock for a domain function to
//! take.

use std::sync::Mutex;

use runner_manager_domain::model::{Clock, Elapsed, Timestamp};

/// The instant [`FakeClock::default`] starts at: 2026-08-21T00:00:00Z, the date
/// this taskflow's decisions were locked.
pub const DEFAULT_EPOCH_SECS: i64 = 1_787_270_400;

/// A clock that only moves when a test moves it.
///
/// Shared by `&`: the domain takes `&dyn Clock`, and the interior [`Mutex`] means
/// a test can advance time while the value under test still holds a reference.
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<Timestamp>,
}

impl FakeClock {
    /// A clock stopped at `now`.
    #[must_use]
    pub fn at(now: Timestamp) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    /// A clock stopped at a Unix timestamp.
    ///
    /// # Panics
    /// If `secs` is not a representable instant.
    #[must_use]
    pub fn at_epoch_secs(secs: i64) -> Self {
        Self::at(timestamp(secs))
    }

    /// Stop the clock at a new instant. Moving backwards is allowed — a test of
    /// clock skew is a legitimate thing to write.
    ///
    /// # Panics
    /// If a previous holder panicked while the lock was held.
    pub fn set(&self, now: Timestamp) {
        *self.now.lock().expect("FakeClock lock poisoned") = now;
    }

    /// Move the clock forward (or back, for a negative delta).
    ///
    /// # Panics
    /// If a previous holder panicked while the lock was held.
    pub fn advance(&self, delta: Elapsed) {
        let mut now = self.now.lock().expect("FakeClock lock poisoned");
        *now += delta;
    }

    /// [`FakeClock::advance`] in whole seconds, which is what most timeouts here
    /// are expressed in.
    pub fn advance_secs(&self, secs: i64) {
        self.advance(Elapsed::seconds(secs));
    }

    /// [`FakeClock::advance`] in whole minutes.
    pub fn advance_minutes(&self, minutes: i64) {
        self.advance(Elapsed::minutes(minutes));
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::at_epoch_secs(DEFAULT_EPOCH_SECS)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        *self.now.lock().expect("FakeClock lock poisoned")
    }
}

/// A [`Timestamp`] from a Unix timestamp, for fixtures that need a specific
/// instant rather than a clock.
///
/// # Panics
/// If `secs` is not a representable instant.
#[must_use]
pub fn timestamp(secs: i64) -> Timestamp {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| panic!("{secs} is not a representable UTC timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_moves_only_when_the_test_moves_it() {
        let clock = FakeClock::at_epoch_secs(1_000);
        assert_eq!(clock.now(), timestamp(1_000));
        assert_eq!(
            clock.now(),
            timestamp(1_000),
            "reading the clock must not advance it"
        );

        clock.advance_secs(30);
        assert_eq!(clock.now(), timestamp(1_030));

        clock.advance_minutes(2);
        assert_eq!(clock.now(), timestamp(1_150));

        clock.advance_secs(-150);
        assert_eq!(clock.now(), timestamp(1_000), "backwards is allowed too");

        clock.set(timestamp(9_999));
        assert_eq!(clock.now(), timestamp(9_999));
    }

    #[test]
    fn the_clock_is_usable_as_the_domain_port_through_a_shared_reference() {
        let clock = FakeClock::at_epoch_secs(0);
        let port: &dyn Clock = &clock;
        assert_eq!(port.now(), timestamp(0));

        // The point of the interior mutex: a test can advance time while the
        // value under test still holds its reference.
        clock.advance_secs(5);
        assert_eq!(port.now(), timestamp(5));
    }

    #[test]
    fn the_default_epoch_is_the_date_this_taskflow_was_locked() {
        let clock = FakeClock::default();
        assert_eq!(
            clock.now().to_rfc3339(),
            "2026-08-21T00:00:00+00:00",
            "fixtures should be reproducible and dated, not `now`"
        );
    }
}

/// The domain's recovery decisions, driven end to end by [`FakeClock`].
///
/// `b1`'s Definition of Done requires that "recovery decisions are tested against
/// the fake clock with no real time dependency". These tests live in `testkit`
/// rather than in `crates/domain/src/attempt.rs` for a mechanical reason worth
/// recording, because `b2` will meet it too:
///
/// `testkit` depends on `runner-manager-domain`, and `runner-manager-domain`
/// dev-depends on `testkit`. Cargo permits that cycle, but when it builds the
/// **unit-test** target of `domain` it compiles a *second* instance of the domain
/// library for `testkit` to link against. The two instances have distinct types,
/// so a unit test inside `domain` that passes a `FakeClock` to
/// `domain::attempt::recovery_decision` fails to compile with "there are multiple
/// different versions of crate `runner_manager_domain` in the dependency graph".
///
/// An *integration* test under `crates/domain/tests/` does not hit this — there
/// `domain` is compiled once and both the test and `testkit` link the same
/// instance. `b1` owns no file there, so these tests are here instead; they
/// exercise exactly the same functions across the same crate boundary that `e1`
/// and `e3` will.
#[cfg(test)]
mod domain_recovery_tests {
    use super::*;
    use runner_manager_domain::attempt::{
        AttemptOutcome, AttemptState, FailureReason, GithubRunnerObservation, OwnershipError,
        RecoveryDecision, RecoveryObservation, RecoveryTimeouts, authorize, recovery_decision,
    };

    use crate::fixtures;

    #[test]
    fn the_idle_timeout_decision_moves_only_when_the_fake_clock_moves() {
        let timeouts = RecoveryTimeouts::new(
            Elapsed::seconds(60),
            Elapsed::seconds(120),
            Elapsed::minutes(5),
        );
        let clock = FakeClock::default();
        let attempt = fixtures::attempt()
            .state(AttemptState::Idle)
            .github_runner_id(73)
            .process_id(4242)
            .entered_state_at(clock.now())
            .build();
        let vanished = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::NotRegistered,
        };

        // No time has passed: the runner did not sit out its idle timeout, so its
        // disappearance is a crash.
        assert_eq!(
            recovery_decision(&attempt, vanished, timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            ))
        );

        clock.advance(Elapsed::minutes(5) - Elapsed::seconds(1));
        assert_eq!(
            recovery_decision(&attempt, vanished, timeouts, &clock),
            RecoveryDecision::Conclude(AttemptOutcome::failed(
                FailureReason::ProcessExitedUnexpectedly
            )),
            "one second short of the timeout is still short of it"
        );

        clock.advance_secs(1);
        let decision = recovery_decision(&attempt, vanished, timeouts, &clock);
        assert_eq!(
            decision,
            RecoveryDecision::Conclude(AttemptOutcome::ExitedIdleWithoutWork),
            "at the idle timeout this is flow 2.7's surplus runner, not a fault"
        );

        let RecoveryDecision::Conclude(outcome) = decision else {
            unreachable!("asserted just above")
        };
        assert!(outcome.is_idle_exit());
        assert!(
            !outcome.is_failure(),
            "`g2` reads this flag to decide whether to alarm an operator"
        );
    }

    #[test]
    fn the_whole_recovery_surface_runs_with_no_reference_to_real_time() {
        // Every state, driven from one controlled instant. `FakeClock` starts at a
        // fixed 2026-08-21 and never advances on its own, so any branch that
        // consulted the system clock would compare a 2026 timestamp against the
        // real present and answer differently.
        let clock = FakeClock::default();
        assert_eq!(clock.now(), timestamp(DEFAULT_EPOCH_SECS));

        let timeouts = RecoveryTimeouts::provisional();
        let alive = RecoveryObservation {
            process_alive: true,
            github: GithubRunnerObservation::NotRegistered,
        };
        let offline = RecoveryObservation {
            process_alive: false,
            github: GithubRunnerObservation::Unreachable,
        };

        for state in AttemptState::ALL {
            let attempt = fixtures::attempt()
                .state(state)
                .entered_state_at(clock.now())
                .build();

            let decision = recovery_decision(&attempt, alive, timeouts, &clock);
            match state {
                AttemptState::Cleaned => assert_eq!(decision, RecoveryDecision::Nothing),
                s if s.is_terminal() => assert_eq!(decision, RecoveryDecision::Clean, "{state}"),
                _ => assert_eq!(decision, RecoveryDecision::Adopt, "{state}"),
            }

            // While GitHub is unreachable, nothing non-terminal is decided: an
            // outage must not conclude and clean a runner that is still running.
            if !state.is_terminal() {
                assert_eq!(
                    recovery_decision(&attempt, offline, timeouts, &clock),
                    RecoveryDecision::Defer,
                    "{state}"
                );
            }
        }

        assert_eq!(
            clock.now(),
            timestamp(DEFAULT_EPOCH_SECS),
            "no decision may advance the clock"
        );
    }

    #[test]
    fn a_fixture_attempt_from_another_host_is_rejected() {
        let ours = fixtures::policy().host(fixtures::HOST_ID).build();
        let theirs = fixtures::policy()
            .id(fixtures::POLICY_ID)
            .host(fixtures::OTHER_HOST_ID)
            .build();
        let attempt = fixtures::attempt().policy_id(fixtures::POLICY_ID).build();

        assert!(authorize(fixtures::HOST_ID, &ours, &attempt).is_ok());
        assert!(matches!(
            authorize(fixtures::HOST_ID, &theirs, &attempt),
            Err(OwnershipError::ForeignHost { .. })
        ));
    }
}
