//! Fail-closed decision model for managed-WSL recovery.
//!
//! An unreachable guest is not evidence that it is idle.  This module keeps
//! the destructive decision separate from probing so every missing or stale
//! fact has one conservative answer and can be property-tested without WSL.

use std::time::Duration;

/// Evidence collected by the Windows-side supervisor for one distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvidence {
    pub consecutive_probe_failures: u8,
    pub failure_span: Option<Duration>,
    pub failure_is_recoverable: bool,
    pub drain_generation: u64,
    pub acknowledged_generation: Option<u64>,
    pub heartbeat_age: Option<Duration>,
    pub local_active_attempts: Option<u32>,
    pub consecutive_zero_attempt_heartbeats: u8,
    pub managed_busy_runners: Option<u32>,
    pub managed_online_registrations: Option<u32>,
    pub consecutive_zero_inventory_reads: u8,
    pub unmanaged_runner_services: Option<u32>,
    pub task_is_product_owned: bool,
    pub distribution_is_wsl2: bool,
    pub inventory_authorized: bool,
    pub recovery_fence_held: bool,
    pub circuit_open: bool,
}

/// The only outcomes the watchdog may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    Observe,
    RequestDrain,
    TerminateNamed,
    Blocked(&'static str),
}

pub const FAILURE_THRESHOLD: u8 = 3;
pub const MINIMUM_FAILURE_SPAN: Duration = Duration::from_secs(5 * 60);
pub const MAX_HEARTBEAT_AGE: Duration = Duration::from_secs(30);

/// Decide without optimistic defaults. `TerminateNamed` means every required
/// proof is present, current and mutually consistent; `None` always blocks.
#[must_use]
pub fn decide(evidence: &RecoveryEvidence) -> RecoveryDecision {
    if evidence.circuit_open {
        return RecoveryDecision::Blocked("the recovery circuit is open");
    }
    if evidence.consecutive_probe_failures < FAILURE_THRESHOLD {
        return RecoveryDecision::Observe;
    }
    if !evidence.failure_is_recoverable {
        return RecoveryDecision::Blocked("the failure is not a recoverable WSL transport failure");
    }
    let Some(failure_span) = evidence.failure_span else {
        return RecoveryDecision::Blocked("the probe failure window is unknown");
    };
    if failure_span < MINIMUM_FAILURE_SPAN {
        return RecoveryDecision::Observe;
    }
    if !evidence.task_is_product_owned {
        return RecoveryDecision::Blocked("the lifecycle task is not product-owned");
    }
    if !evidence.distribution_is_wsl2 {
        return RecoveryDecision::Blocked("the distribution is not verified as WSL2");
    }
    if !evidence.inventory_authorized {
        return RecoveryDecision::Blocked("GitHub runner inventory is not authorized");
    }
    if !evidence.recovery_fence_held {
        return RecoveryDecision::Blocked("the recovery fence is not held");
    }
    let Some(unmanaged) = evidence.unmanaged_runner_services else {
        return RecoveryDecision::Blocked("the unmanaged-runner audit is unknown");
    };
    if unmanaged != 0 {
        return RecoveryDecision::Blocked("an unmanaged runner service exists");
    }
    let Some(age) = evidence.heartbeat_age else {
        return RecoveryDecision::Blocked("the guest heartbeat is missing");
    };
    if age > MAX_HEARTBEAT_AGE {
        return RecoveryDecision::Blocked("the guest heartbeat is stale");
    }
    if evidence.acknowledged_generation != Some(evidence.drain_generation) {
        return RecoveryDecision::RequestDrain;
    }
    match evidence.local_active_attempts {
        Some(0) => {}
        Some(_) => return RecoveryDecision::Blocked("the guest owns an active attempt"),
        None => return RecoveryDecision::Blocked("the guest attempt count is unknown"),
    }
    if evidence.consecutive_zero_attempt_heartbeats < 2 {
        return RecoveryDecision::Blocked("idle guest state has not been confirmed twice");
    }
    match (
        evidence.managed_busy_runners,
        evidence.managed_online_registrations,
    ) {
        (Some(0), Some(0)) if evidence.consecutive_zero_inventory_reads >= 2 => {
            RecoveryDecision::TerminateNamed
        }
        (Some(0), Some(0)) => {
            RecoveryDecision::Blocked("empty GitHub inventory has not been confirmed twice")
        }
        (Some(busy), _) if busy != 0 => {
            RecoveryDecision::Blocked("GitHub reports a busy managed runner")
        }
        (None, _) | (_, None) => {
            RecoveryDecision::Blocked("the GitHub runner inventory is unknown")
        }
        _ => RecoveryDecision::Blocked("GitHub reports an online managed runner"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle() -> RecoveryEvidence {
        RecoveryEvidence {
            consecutive_probe_failures: 3,
            failure_span: Some(Duration::from_secs(5 * 60)),
            failure_is_recoverable: true,
            drain_generation: 7,
            acknowledged_generation: Some(7),
            heartbeat_age: Some(Duration::from_secs(2)),
            local_active_attempts: Some(0),
            consecutive_zero_attempt_heartbeats: 2,
            managed_busy_runners: Some(0),
            managed_online_registrations: Some(0),
            consecutive_zero_inventory_reads: 2,
            unmanaged_runner_services: Some(0),
            task_is_product_owned: true,
            distribution_is_wsl2: true,
            inventory_authorized: true,
            recovery_fence_held: true,
            circuit_open: false,
        }
    }

    #[test]
    fn only_a_complete_idle_proof_allows_named_termination() {
        assert_eq!(decide(&idle()), RecoveryDecision::TerminateNamed);
    }

    #[test]
    fn every_unknown_safety_fact_blocks() {
        let mutations: [fn(&mut RecoveryEvidence); 6] = [
            |e| e.failure_span = None,
            |e| e.heartbeat_age = None,
            |e| e.local_active_attempts = None,
            |e| e.managed_busy_runners = None,
            |e| e.managed_online_registrations = None,
            |e| e.unmanaged_runner_services = None,
        ];
        for mutate in mutations {
            let mut evidence = idle();
            mutate(&mut evidence);
            assert!(matches!(decide(&evidence), RecoveryDecision::Blocked(_)));
        }
    }

    #[test]
    fn work_or_an_unmanaged_runner_blocks_recovery() {
        for mutate in [
            |e: &mut RecoveryEvidence| e.local_active_attempts = Some(1),
            |e: &mut RecoveryEvidence| e.managed_busy_runners = Some(1),
            |e: &mut RecoveryEvidence| e.unmanaged_runner_services = Some(1),
        ] {
            let mut evidence = idle();
            mutate(&mut evidence);
            assert!(matches!(decide(&evidence), RecoveryDecision::Blocked(_)));
        }
    }

    #[test]
    fn a_matching_drain_ack_is_mandatory() {
        let mut evidence = idle();
        evidence.acknowledged_generation = Some(6);
        assert_eq!(decide(&evidence), RecoveryDecision::RequestDrain);
    }

    #[test]
    fn recovery_requires_a_classified_five_minute_failure_and_two_idle_observations() {
        for mutate in [
            |e: &mut RecoveryEvidence| e.failure_is_recoverable = false,
            |e: &mut RecoveryEvidence| e.failure_span = Some(Duration::from_secs(299)),
            |e: &mut RecoveryEvidence| e.consecutive_zero_attempt_heartbeats = 1,
            |e: &mut RecoveryEvidence| e.consecutive_zero_inventory_reads = 1,
            |e: &mut RecoveryEvidence| e.recovery_fence_held = false,
        ] {
            let mut evidence = idle();
            mutate(&mut evidence);
            assert_ne!(decide(&evidence), RecoveryDecision::TerminateNamed);
        }
    }
}
