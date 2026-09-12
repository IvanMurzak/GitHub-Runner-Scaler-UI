//! Windows-side watchdog for managed WSL runner hosts.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use runner_manager_github::rest::{CancelToken, InventoryGateway};
use runner_manager_platform::paths::AppPaths;
use runner_manager_platform::wsl::WslHost;
use runner_manager_platform::wsl::fence::{
    DrainRequest, FenceClaim, FenceOwnerKind, GuestHeartbeat, RecoveryPhase, RecoveryStatus,
    SCHEMA_VERSION, clear_recovery, recovery_root,
};
use runner_manager_platform::wsl::probe::LinuxCommand;
use runner_manager_platform::wsl::record::WslProviderRecord;
use runner_manager_platform::wsl::recovery::{RecoveryDecision, RecoveryEvidence, decide};
use runner_manager_platform::wsl::task::LifecycleTaskIdentity;

const WATCH_INTERVAL: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const CIRCUIT_WINDOW: Duration = Duration::from_secs(60 * 60);
const CIRCUIT_LIMIT: usize = 3;

#[derive(Debug, Default)]
struct Tracker {
    failures: u8,
    first_failure: Option<Instant>,
    generation: Option<u64>,
    fence_held: bool,
    last_heartbeat: Option<DateTime<Utc>>,
    zero_heartbeats: u8,
    zero_inventory_reads: u8,
    recovery_attempts: VecDeque<Instant>,
    last_recovered_at: Option<DateTime<Utc>>,
}

/// Runs for the daemon lifetime. Off Windows it performs no probes at all.
pub async fn maintain(paths: AppPaths, inventory: Arc<dyn InventoryGateway>) {
    if !cfg!(windows) {
        std::future::pending::<()>().await;
        return;
    }
    let mut trackers = HashMap::<String, Tracker>::new();
    loop {
        match WslProviderRecord::all(&paths) {
            Ok(records) => {
                for record in records {
                    let tracker = trackers.entry(record.distribution.clone()).or_default();
                    observe(&paths, &record, tracker, inventory.as_ref()).await;
                }
            }
            Err(_) => tracing::warn!(
                reason = "wsl_provider_records_unreadable",
                "managed WSL recovery cannot enumerate providers"
            ),
        }
        tokio::time::sleep(WATCH_INTERVAL).await;
    }
}

async fn observe(
    paths: &AppPaths,
    record: &WslProviderRecord,
    tracker: &mut Tracker,
    inventory: &dyn InventoryGateway,
) {
    let Ok(root) = recovery_root(paths, &record.distribution) else {
        return;
    };
    let host = match WslHost::on_this_host("managed WSL recovery") {
        Ok(host) => host,
        Err(_) => return,
    };
    let identity = match LifecycleTaskIdentity::for_distribution(&record.distribution) {
        Ok(identity) => identity,
        Err(_) => return,
    };
    let task_owned = host
        .tasks()
        .query(&identity)
        .ok()
        .flatten()
        .is_some_and(|task| task.is_product_owned() && task.enabled());
    let distribution_is_wsl2 = host
        .invoker()
        .list()
        .ok()
        .and_then(|table| {
            table
                .exactly(&record.distribution)
                .ok()
                .map(|entry| entry.wsl_version() == 2)
        })
        .unwrap_or(false);
    let probe = host
        .invoker()
        .exec(LinuxCommand::new(&record.distribution, "/bin/true").with_timeout(PROBE_TIMEOUT));
    let healthy = probe.as_ref().is_ok_and(|output| output.success());

    if healthy {
        if let Some(generation) = tracker.generation.take() {
            let _ = clear_recovery(&root, generation);
        }
        tracker.failures = 0;
        tracker.first_failure = None;
        tracker.fence_held = false;
        tracker.zero_heartbeats = 0;
        tracker.zero_inventory_reads = 0;
        publish(&root, tracker, RecoveryPhase::Healthy, None);
        return;
    }

    tracker.failures = tracker.failures.saturating_add(1);
    let first = *tracker.first_failure.get_or_insert_with(Instant::now);
    let generation = *tracker.generation.get_or_insert_with(generation_now);
    let request = DrainRequest::new(generation, Utc::now());
    if request.write(&root).is_err() {
        publish(
            &root,
            tracker,
            RecoveryPhase::RecoveryBlocked,
            Some("the drain request cannot be written"),
        );
        return;
    }

    if !tracker.fence_held {
        match FenceClaim::try_claim(&root, FenceOwnerKind::WindowsRecovery, Some(generation)) {
            Ok(Some(claim)) => {
                claim.make_durable();
                tracker.fence_held = true;
            }
            Ok(None) => {
                tracker.fence_held = FenceClaim::owner(&root)
                    .ok()
                    .flatten()
                    .is_some_and(|owner| {
                        owner.kind == FenceOwnerKind::WindowsRecovery
                            && owner.generation == Some(generation)
                    });
            }
            Err(_) => {}
        }
    }

    let heartbeat = GuestHeartbeat::read(&root).ok().flatten();
    update_zero_heartbeats(tracker, heartbeat.as_ref(), generation);
    let (busy, online, authorized) = match heartbeat.as_ref() {
        Some(heartbeat) => match github_inventory(heartbeat, inventory).await {
            Some((busy, online)) => {
                if busy == 0 && online == 0 {
                    tracker.zero_inventory_reads = tracker.zero_inventory_reads.saturating_add(1);
                } else {
                    tracker.zero_inventory_reads = 0;
                }
                (Some(busy), Some(online), true)
            }
            None => {
                tracker.zero_inventory_reads = 0;
                (None, None, false)
            }
        },
        None => (None, None, false),
    };
    let now = Utc::now();
    let heartbeat_age = heartbeat
        .as_ref()
        .and_then(|heartbeat| (now - heartbeat.observed_at).to_std().ok());
    expire_circuit(tracker);
    let evidence = RecoveryEvidence {
        consecutive_probe_failures: tracker.failures,
        failure_span: Some(first.elapsed()),
        failure_is_recoverable: true,
        drain_generation: generation,
        acknowledged_generation: heartbeat
            .as_ref()
            .and_then(|heartbeat| heartbeat.acknowledged_generation),
        heartbeat_age,
        local_active_attempts: heartbeat
            .as_ref()
            .and_then(|heartbeat| heartbeat.local_active_attempts),
        consecutive_zero_attempt_heartbeats: tracker.zero_heartbeats,
        managed_busy_runners: busy,
        managed_online_registrations: online,
        consecutive_zero_inventory_reads: tracker.zero_inventory_reads,
        unmanaged_runner_services: heartbeat
            .as_ref()
            .and_then(|heartbeat| heartbeat.unmanaged_runner_services),
        task_is_product_owned: task_owned,
        distribution_is_wsl2,
        inventory_authorized: authorized,
        recovery_fence_held: tracker.fence_held,
        circuit_open: tracker.recovery_attempts.len() >= CIRCUIT_LIMIT,
    };

    match decide(&evidence) {
        RecoveryDecision::Observe => publish(
            &root,
            tracker,
            RecoveryPhase::Degraded,
            Some("waiting for the bounded failure threshold"),
        ),
        RecoveryDecision::RequestDrain => publish(
            &root,
            tracker,
            RecoveryPhase::Draining,
            Some("waiting for the guest drain acknowledgement"),
        ),
        RecoveryDecision::Blocked(reason) => {
            publish(&root, tracker, RecoveryPhase::RecoveryBlocked, Some(reason))
        }
        RecoveryDecision::TerminateNamed => {
            publish(&root, tracker, RecoveryPhase::Recovering, None);
            tracker.recovery_attempts.push_back(Instant::now());
            if recover_named(&host, &record.distribution, &identity).await {
                let _ = clear_recovery(&root, generation);
                tracker.failures = 0;
                tracker.first_failure = None;
                tracker.generation = None;
                tracker.fence_held = false;
                tracker.zero_heartbeats = 0;
                tracker.zero_inventory_reads = 0;
                tracker.last_recovered_at = Some(Utc::now());
                publish(&root, tracker, RecoveryPhase::Healthy, None);
            } else {
                publish(
                    &root,
                    tracker,
                    RecoveryPhase::Backoff,
                    Some("the named distribution did not become healthy after recovery"),
                );
            }
        }
    }
}

fn update_zero_heartbeats(
    tracker: &mut Tracker,
    heartbeat: Option<&GuestHeartbeat>,
    generation: u64,
) {
    let Some(heartbeat) = heartbeat else {
        tracker.zero_heartbeats = 0;
        return;
    };
    if tracker.last_heartbeat == Some(heartbeat.observed_at) {
        return;
    }
    tracker.last_heartbeat = Some(heartbeat.observed_at);
    tracker.zero_heartbeats = if heartbeat.acknowledged_generation == Some(generation)
        && heartbeat.local_active_attempts == Some(0)
    {
        tracker.zero_heartbeats.saturating_add(1)
    } else {
        0
    };
}

async fn github_inventory(
    heartbeat: &GuestHeartbeat,
    inventory: &dyn InventoryGateway,
) -> Option<(u32, u32)> {
    let mut busy = 0_u32;
    let mut online = 0_u32;
    for target in &heartbeat.managed_targets {
        let runners = inventory
            .list_runners(target, &CancelToken::new())
            .await
            .ok()?;
        if runners.truncated() || runners.missing().is_some() {
            return None;
        }
        for runner in runners
            .runners()
            .iter()
            .filter(|runner| runner.name.starts_with("runner-manager-"))
        {
            busy = busy.saturating_add(u32::from(runner.busy));
            online = online.saturating_add(u32::from(runner.status.is_online()));
        }
    }
    Some((busy, online))
}

async fn recover_named(
    host: &WslHost,
    distribution: &str,
    identity: &LifecycleTaskIdentity,
) -> bool {
    if host.invoker().terminate_named(distribution).is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = host.tasks().start(identity);
    for delay in [2_u64, 4, 8, 16, 30, 30] {
        tokio::time::sleep(Duration::from_secs(delay)).await;
        if host
            .invoker()
            .exec(LinuxCommand::new(distribution, "/bin/true").with_timeout(PROBE_TIMEOUT))
            .is_ok_and(|output| output.success())
        {
            return true;
        }
    }
    false
}

fn generation_now() -> u64 {
    u64::try_from(Utc::now().timestamp_millis())
        .unwrap_or(1)
        .max(1)
}

fn expire_circuit(tracker: &mut Tracker) {
    while tracker
        .recovery_attempts
        .front()
        .is_some_and(|attempt| attempt.elapsed() > CIRCUIT_WINDOW)
    {
        tracker.recovery_attempts.pop_front();
    }
}

fn publish(root: &Path, tracker: &Tracker, phase: RecoveryPhase, reason: Option<&str>) {
    let _ = RecoveryStatus {
        schema_version: SCHEMA_VERSION,
        observed_at: Utc::now(),
        phase,
        consecutive_probe_failures: tracker.failures,
        reason: reason.map(str::to_string),
        last_recovered_at: tracker.last_recovered_at,
    }
    .write(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heartbeat(
        observed_at: DateTime<Utc>,
        generation: Option<u64>,
        active: u32,
    ) -> GuestHeartbeat {
        GuestHeartbeat {
            schema_version: SCHEMA_VERSION,
            observed_at,
            acknowledged_generation: generation,
            local_active_attempts: Some(active),
            managed_targets: Vec::new(),
            unmanaged_runner_services: Some(0),
        }
    }

    #[test]
    fn only_distinct_idle_heartbeats_for_the_current_drain_are_counted() {
        let mut tracker = Tracker::default();
        let first_at = Utc::now();
        let before_drain = heartbeat(first_at, None, 0);
        update_zero_heartbeats(&mut tracker, Some(&before_drain), 7);
        assert_eq!(tracker.zero_heartbeats, 0);

        let first = heartbeat(first_at + chrono::Duration::seconds(1), Some(7), 0);
        update_zero_heartbeats(&mut tracker, Some(&first), 7);
        update_zero_heartbeats(&mut tracker, Some(&first), 7);
        assert_eq!(tracker.zero_heartbeats, 1);

        let second = heartbeat(first_at + chrono::Duration::seconds(2), Some(7), 0);
        update_zero_heartbeats(&mut tracker, Some(&second), 7);
        assert_eq!(tracker.zero_heartbeats, 2);
    }

    #[test]
    fn active_work_or_another_generation_resets_the_idle_proof() {
        let mut tracker = Tracker::default();
        let now = Utc::now();
        update_zero_heartbeats(&mut tracker, Some(&heartbeat(now, Some(9), 0)), 9);
        update_zero_heartbeats(
            &mut tracker,
            Some(&heartbeat(now + chrono::Duration::seconds(1), Some(9), 1)),
            9,
        );
        assert_eq!(tracker.zero_heartbeats, 0);
        update_zero_heartbeats(
            &mut tracker,
            Some(&heartbeat(now + chrono::Duration::seconds(2), Some(8), 0)),
            9,
        );
        assert_eq!(tracker.zero_heartbeats, 0);
    }
}
