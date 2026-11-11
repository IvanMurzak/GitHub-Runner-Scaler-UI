//! What the dashboard shows of the jobs: the queued ones, the running ones and
//! the last ones to finish, as GitHub's `workflow_job` webhooks describe them,
//! and which host each runner belongs to, as the hosts' `attempt_started`
//! reports say.
//!
//! Only jobs for self-hosted runners are kept: a repository's jobs on GitHub's
//! own runners are not this fleet's work. Everything is in memory; after a
//! restart the lists fill again from the next webhooks.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde::Serialize;

use crate::stats::JobTimes;
use crate::webhook::WorkflowJobEvent;

/// The most finished jobs kept.
const RECENT: usize = 50;
/// The most jobs tracked at once; the oldest go first beyond it.
const MAX_JOBS: usize = 2000;
/// The most runner names remembered with their host.
const MAX_RUNNERS: usize = 4000;
/// A queued job no webhook moved on in this long is forgotten (a lost
/// `completed`), as is a running one in [`RUNNING_FOR`].
const QUEUED_FOR: i64 = 24 * 60 * 60;
const RUNNING_FOR: i64 = 3 * 24 * 60 * 60;

/// A job in the queue or running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveJob {
    pub id: u64,
    pub run_id: u64,
    pub repository: String,
    pub name: Option<String>,
    pub labels: Vec<String>,
    /// Unix seconds.
    pub queued_at: i64,
    pub started_at: Option<i64>,
    pub runner_name: Option<String>,
}

/// A job that finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FinishedJob {
    pub id: u64,
    pub run_id: u64,
    pub repository: String,
    pub name: Option<String>,
    pub runner_name: Option<String>,
    pub conclusion: Option<String>,
    pub completed_at: i64,
    pub duration_secs: Option<i64>,
    pub queued_secs: Option<i64>,
}

#[derive(Debug, Default)]
struct Inner {
    jobs: HashMap<u64, ActiveJob>,
    recent: VecDeque<FinishedJob>,
    /// Runner name to host id, and the order they came in.
    runners: HashMap<String, String>,
    runner_order: VecDeque<String>,
}

/// The dashboard's view of the jobs.
#[derive(Debug, Default)]
pub struct Activity {
    inner: Mutex<Inner>,
}

/// What [`Activity::snapshot`] hands the dashboard.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Oldest first.
    pub queued: Vec<ActiveJob>,
    /// Longest running first.
    pub running: Vec<ActiveJob>,
    /// Newest first.
    pub recent: Vec<FinishedJob>,
}

/// Whether a job asked for a self-hosted runner: `self-hosted`, or a shared
/// pool label (`rm-pool-...`), which only this fleet answers.
fn self_hosted(labels: &[String]) -> bool {
    labels.iter().any(|label| {
        label.eq_ignore_ascii_case("self-hosted")
            || runner_manager_domain::policy::in_pool_namespace(label)
    })
}

/// Runner names compare without case, as placement's do.
fn runner_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

impl Activity {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A `workflow_job` webhook arrived at `now` (Unix seconds); `times` are
    /// its timestamps as the statistics read them.
    pub fn job_event(&self, event: &WorkflowJobEvent, times: &JobTimes, now: i64) {
        let job = &event.workflow_job;
        if !self_hosted(&job.labels) {
            return;
        }
        let unix = |at: Option<chrono::DateTime<chrono::Utc>>| at.map(|at| at.timestamp());
        let mut inner = self.lock();
        match event.action.as_str() {
            action @ ("queued" | "waiting" | "in_progress") => {
                let entry = inner.jobs.entry(job.id).or_insert_with(|| ActiveJob {
                    id: job.id,
                    run_id: job.run_id,
                    repository: event.repository.full_name.clone(),
                    name: job.name.clone(),
                    labels: job.labels.clone(),
                    queued_at: unix(times.created_at).unwrap_or(now),
                    started_at: None,
                    runner_name: None,
                });
                if action == "in_progress" {
                    entry.started_at = unix(times.started_at).or(Some(now));
                    entry.runner_name.clone_from(&job.runner_name);
                    if job.name.is_some() {
                        entry.name.clone_from(&job.name);
                    }
                }
            }
            "completed" => {
                inner.jobs.remove(&job.id);
                // A job cancelled before any runner took it never ran.
                let ran = job.runner_name.is_some();
                let seconds = |secs: Option<u64>| secs.and_then(|secs| i64::try_from(secs).ok());
                inner.recent.push_front(FinishedJob {
                    id: job.id,
                    run_id: job.run_id,
                    repository: event.repository.full_name.clone(),
                    name: job.name.clone(),
                    runner_name: job.runner_name.clone(),
                    conclusion: job.conclusion.clone(),
                    completed_at: unix(times.completed_at).unwrap_or(now),
                    duration_secs: seconds(times.run_secs()).filter(|_| ran),
                    queued_secs: seconds(times.queue_wait_secs()).filter(|_| ran),
                });
                inner.recent.truncate(RECENT);
            }
            _ => {}
        }
        if inner.jobs.len() > MAX_JOBS {
            let mut oldest: Vec<(i64, u64)> = inner
                .jobs
                .values()
                .map(|job| (job.queued_at, job.id))
                .collect();
            oldest.sort_unstable();
            let excess = inner.jobs.len() - MAX_JOBS;
            for (_, id) in oldest.into_iter().take(excess) {
                inner.jobs.remove(&id);
            }
        }
    }

    /// A host said one of its runners took a job.
    pub fn runner_started(&self, host_id: &str, runner_name: &str) {
        let mut inner = self.lock();
        let key = runner_key(runner_name);
        if inner
            .runners
            .insert(key.clone(), host_id.to_owned())
            .is_none()
        {
            inner.runner_order.push_back(key);
            while inner.runner_order.len() > MAX_RUNNERS {
                if let Some(old) = inner.runner_order.pop_front() {
                    inner.runners.remove(&old);
                }
            }
        }
    }

    /// The host a runner belongs to, when its host said.
    #[must_use]
    pub fn host_of(&self, runner_name: &str) -> Option<String> {
        self.lock().runners.get(&runner_key(runner_name)).cloned()
    }

    /// How many jobs are queued and running now.
    pub fn counts(&self, now: i64) -> (usize, usize) {
        let mut inner = self.lock();
        Self::forget_stale(&mut inner, now);
        let running = inner
            .jobs
            .values()
            .filter(|job| job.started_at.is_some())
            .count();
        (inner.jobs.len() - running, running)
    }

    fn forget_stale(inner: &mut Inner, now: i64) {
        inner.jobs.retain(|_, job| match job.started_at {
            Some(started) => now - started < RUNNING_FOR,
            None => now - job.queued_at < QUEUED_FOR,
        });
    }

    /// The jobs now, forgetting the ones no webhook moved on for too long.
    pub fn snapshot(&self, now: i64) -> Snapshot {
        let mut inner = self.lock();
        Self::forget_stale(&mut inner, now);
        let (mut running, mut queued): (Vec<ActiveJob>, Vec<ActiveJob>) = inner
            .jobs
            .values()
            .cloned()
            .partition(|job| job.started_at.is_some());
        queued.sort_by_key(|job| (job.queued_at, job.id));
        running.sort_by_key(|job| (job.started_at, job.id));
        Snapshot {
            queued,
            running,
            recent: inner.recent.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str, id: u64, labels: &[&str], runner: Option<&str>) -> WorkflowJobEvent {
        serde_json::from_value(serde_json::json!({
            "action": action,
            "workflow_job": {
                "id": id, "run_id": 9, "name": "build",
                "labels": labels,
                "runner_name": runner,
                "created_at": "2026-11-10T10:00:00Z",
                "started_at": if action == "queued" { serde_json::Value::Null } else { "2026-11-10T10:00:05Z".into() },
                "completed_at": if action == "completed" { "2026-11-10T10:01:05Z".into() } else { serde_json::Value::Null },
                "conclusion": if action == "completed" { "success".into() } else { serde_json::Value::Null },
            },
            "repository": {"full_name": "IvanMurzak/app"}
        }))
        .expect("an event")
    }

    fn feed(activity: &Activity, event: &WorkflowJobEvent, now: i64) {
        let job = &event.workflow_job;
        let times = JobTimes::parse(
            job.created_at.as_deref(),
            job.started_at.as_deref(),
            job.completed_at.as_deref(),
        );
        activity.job_event(event, &times, now);
    }

    #[test]
    fn a_job_moves_from_the_queue_to_running_to_recent() {
        let activity = Activity::default();
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-10T10:00:30Z")
            .unwrap()
            .timestamp();
        feed(
            &activity,
            &event("queued", 1, &["self-hosted", "linux"], None),
            now,
        );
        feed(
            &activity,
            &event("queued", 2, &["ubuntu-latest"], None),
            now,
        );
        let snapshot = activity.snapshot(now);
        assert_eq!(
            snapshot.queued.len(),
            1,
            "GitHub's own runners are not shown"
        );
        feed(
            &activity,
            &event("in_progress", 1, &["self-hosted", "linux"], Some("rm-a")),
            now,
        );
        activity.runner_started("host-1", "RM-A");
        let snapshot = activity.snapshot(now);
        assert!(snapshot.queued.is_empty());
        assert_eq!(snapshot.running[0].runner_name.as_deref(), Some("rm-a"));
        assert_eq!(activity.host_of("rm-a").as_deref(), Some("host-1"));
        feed(
            &activity,
            &event("completed", 1, &["self-hosted", "linux"], Some("rm-a")),
            now,
        );
        let snapshot = activity.snapshot(now);
        assert!(snapshot.running.is_empty());
        assert_eq!(snapshot.recent[0].duration_secs, Some(60));
        assert_eq!(snapshot.recent[0].queued_secs, Some(5));
        assert_eq!(activity.counts(now), (0, 0));
    }

    #[test]
    fn a_job_no_webhook_finished_is_forgotten() {
        let activity = Activity::default();
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-10T10:00:30Z")
            .unwrap()
            .timestamp();
        feed(
            &activity,
            &event("queued", 1, &["rm-pool-linux"], None),
            now,
        );
        assert_eq!(activity.snapshot(now).queued.len(), 1);
        assert!(activity.snapshot(now + QUEUED_FOR).queued.is_empty());
    }
}
