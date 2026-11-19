//! What placement did lately, for the dashboard's Balancing screen: the last
//! decisions, with every candidate's score parts and why each other connected
//! host was passed over, and what became of their launches.
//!
//! In memory only and bounded ([`KEEP_DECISIONS`], [`KEEP_EVENTS`]): a restart
//! starts it empty. Decisions and events share one rising sequence, the
//! cursor a page reads from ([`PlacementLog::since`]).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::HostScore;
use serde::Serialize;

/// Decisions kept.
pub const KEEP_DECISIONS: usize = 200;
/// Lease events kept.
pub const KEEP_EVENTS: usize = 500;
/// A queue left unplaced for the same reasons is recorded again only after
/// this: placement retries every few seconds.
const REPEAT_EVERY: Duration = Duration::from_secs(60);

/// Why a connected host was not scored for a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterReason {
    /// No enabled pool profile of its serves the queue (or it is not in
    /// launch mode for that repository).
    NoCandidate,
    /// Its doctor says unfit, or it drains (see `detail`).
    UnfitOrDraining,
    /// Its slots are taken, by its last heartbeat and the launches sent since.
    NoFreeSlot,
    /// Asked already in this round and it refused or did not answer (see
    /// `detail`).
    Tried,
}

/// One host passed over before scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Filtered {
    pub host_id: String,
    pub reason: FilterReason,
    /// `unfit` or `draining`; for `tried`, the refusal (`max_capacity`, ...)
    /// or `unanswered`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// For `no_free_slot`: its slots by its last heartbeat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_slots: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_slots: Option<u32>,
}

impl Filtered {
    #[must_use]
    pub fn new(host_id: &str, reason: FilterReason) -> Self {
        Self {
            host_id: host_id.to_owned(),
            reason,
            detail: None,
            busy_slots: None,
            free_slots: None,
        }
    }

    #[must_use]
    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_owned());
        self
    }
}

/// One scored host: its score parts and what they were computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LoggedScore {
    #[serde(flatten)]
    pub score: HostScore,
    /// A warm workspace for the repository.
    pub warm: bool,
    pub ram_bytes: Option<u64>,
    pub free_ram_bytes: Option<u64>,
    /// What its launches still to come hold of its free memory.
    pub reserved_bytes: u64,
    /// What a new job could count on (free less reserved, capped by its
    /// memory less every launch whose job has not ended).
    pub available_bytes: Option<u64>,
    pub busy_slots: u32,
    pub free_slots: u32,
    pub cores: u32,
    /// Idle cores, in thousandths, by its last heartbeat.
    pub idle_millicores: u64,
}

/// One placement decision for a pool queue.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LoggedDecision {
    /// Its place in the sequence.
    pub id: u64,
    /// Unix milliseconds.
    pub at_ms: i64,
    pub repository: String,
    /// The queue's required labels, comma-separated.
    pub labels: String,
    /// The job the launch names (the queue's lowest id), when one is known.
    pub job_id: Option<u64>,
    /// The job names queued in it, as far as webhooks named them.
    pub jobs: Vec<String>,
    pub queued: u32,
    /// Open leases of the queue before this one.
    pub leases: u32,
    pub estimate_bytes: u64,
    /// `job`, `repository` or `default`.
    pub estimate_source: String,
    /// `weighted`, or `stage3` without statistics to weigh.
    pub method: String,
    /// The heaviest measured demand of another queue short of runners: what
    /// `bigfit` spares a host for.
    pub heavier_bytes: Option<u64>,
    /// The most idle cores among the contenders, in thousandths.
    pub most_idle_millicores: u64,
    /// Every scored host, best first; one that does not fit (`fits: false`)
    /// was passed over for memory (`no_memory_fit`).
    pub scores: Vec<LoggedScore>,
    /// The host offered the launch, if any.
    pub chosen: Option<String>,
    /// Every other connected host, and why.
    pub filtered: Vec<Filtered>,
    /// Why nothing was offered: `no_candidate`, `unfit_or_draining`,
    /// `no_free_slot`, `no_memory_fit`, `refused` or `unanswered`.
    pub reason: Option<String>,
    /// For `refused`: the last host's reason.
    pub refusal: Option<String>,
}

/// What happened to a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Offered,
    Accepted,
    Refused,
    Unanswered,
    /// Its runner took a job.
    Claimed,
    /// Its runner's attempt ended.
    Finished,
    /// Its job left the queue first, or another runner took it.
    Cancelled,
    /// It outlived its lifetime.
    Expired,
}

/// One launch event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoggedEvent {
    pub seq: u64,
    pub at_ms: i64,
    pub kind: EventKind,
    pub lease_id: String,
    pub host_id: String,
    /// The decision that offered it, while that is remembered.
    pub decision: Option<u64>,
    pub repository: Option<String>,
    /// For `refused`: the host's reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For `finished`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
}

impl LoggedEvent {
    #[must_use]
    pub fn new(kind: EventKind, lease_id: &str, host_id: &str) -> Self {
        Self {
            seq: 0,
            at_ms: 0,
            kind,
            lease_id: lease_id.to_owned(),
            host_id: host_id.to_owned(),
            decision: None,
            repository: None,
            reason: None,
            duration_secs: None,
            peak_rss_bytes: None,
        }
    }
}

/// Totals since the coordinator started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub decisions: u64,
    pub offered: u64,
    pub accepted: u64,
    pub refused: u64,
    pub unanswered: u64,
    pub claimed: u64,
    pub finished: u64,
    pub cancelled: u64,
    pub expired: u64,
}

impl Counters {
    fn count(&mut self, kind: EventKind) {
        let counter = match kind {
            EventKind::Offered => &mut self.offered,
            EventKind::Accepted => &mut self.accepted,
            EventKind::Refused => &mut self.refused,
            EventKind::Unanswered => &mut self.unanswered,
            EventKind::Claimed => &mut self.claimed,
            EventKind::Finished => &mut self.finished,
            EventKind::Cancelled => &mut self.cancelled,
            EventKind::Expired => &mut self.expired,
        };
        *counter += 1;
    }
}

/// What a page asked for: everything after its cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LogPage {
    /// The newest sequence number: the next page's cursor.
    pub cursor: u64,
    /// The cursor asked for is ahead of the log (it restarted): everything
    /// kept is sent again.
    pub reset: bool,
    pub decisions: Vec<LoggedDecision>,
    pub events: Vec<LoggedEvent>,
    pub counters: Counters,
}

/// The last decisions and launch events, bounded.
#[derive(Debug, Default)]
pub struct PlacementLog {
    last: u64,
    decisions: VecDeque<LoggedDecision>,
    events: VecDeque<LoggedEvent>,
    counters: Counters,
    /// When each queue was last recorded unplaced, and why.
    unplaced: HashMap<(String, String), (Instant, String)>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// What makes two unplaced decisions of a queue the same.
fn signature(decision: &LoggedDecision) -> String {
    let mut parts: Vec<String> = decision
        .filtered
        .iter()
        .map(|filtered| format!("{}:{:?}", filtered.host_id, filtered.reason))
        .chain(
            decision
                .scores
                .iter()
                .map(|score| format!("{}:{}", score.score.host_id, score.score.fits)),
        )
        .collect();
    parts.sort();
    format!(
        "{}|{}|{}",
        decision.reason.as_deref().unwrap_or_default(),
        decision.refusal.as_deref().unwrap_or_default(),
        parts.join(",")
    )
}

impl PlacementLog {
    /// Records `decision` and returns its id; `None` when it repeats the
    /// queue's last unplaced decision within a minute.
    pub fn decided(&mut self, mut decision: LoggedDecision, now: Instant) -> Option<u64> {
        let queue = (decision.repository.clone(), decision.labels.clone());
        if decision.chosen.is_none() {
            let signature = signature(&decision);
            self.unplaced
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < REPEAT_EVERY);
            if self
                .unplaced
                .get(&queue)
                .is_some_and(|(_, last)| *last == signature)
            {
                return None;
            }
            self.unplaced.insert(queue, (now, signature));
        } else {
            self.unplaced.remove(&queue);
        }
        self.last += 1;
        decision.id = self.last;
        decision.at_ms = now_ms();
        self.decisions.push_back(decision);
        while self.decisions.len() > KEEP_DECISIONS {
            self.decisions.pop_front();
        }
        self.counters.decisions += 1;
        Some(self.last)
    }

    /// Records a launch event; its decision is looked up by its lease when
    /// not given.
    pub fn event(&mut self, mut event: LoggedEvent) {
        if (event.decision.is_none() || event.repository.is_none())
            && let Some(offered) = self.offered(&event.lease_id)
        {
            event.decision = event.decision.or(offered.decision);
            event.repository = event.repository.or_else(|| offered.repository.clone());
        }
        self.last += 1;
        event.seq = self.last;
        event.at_ms = now_ms();
        self.counters.count(event.kind);
        self.events.push_back(event);
        while self.events.len() > KEEP_EVENTS {
            self.events.pop_front();
        }
    }

    /// The `offered` event of `lease_id`, while kept.
    fn offered(&self, lease_id: &str) -> Option<&LoggedEvent> {
        self.events
            .iter()
            .rev()
            .find(|event| event.lease_id == lease_id && event.kind == EventKind::Offered)
    }

    /// Whether `lease_id` was offered by a decision still kept.
    #[must_use]
    pub fn knows(&self, lease_id: &str) -> bool {
        self.offered(lease_id).is_some()
    }

    /// Everything after `cursor`, or everything kept when `cursor` is ahead
    /// of the log.
    #[must_use]
    pub fn since(&self, cursor: u64) -> LogPage {
        let reset = cursor > self.last;
        let after = if reset { 0 } else { cursor };
        LogPage {
            cursor: self.last,
            reset,
            decisions: self
                .decisions
                .iter()
                .filter(|decision| decision.id > after)
                .cloned()
                .collect(),
            events: self
                .events
                .iter()
                .filter(|event| event.seq > after)
                .cloned()
                .collect(),
            counters: self.counters,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(repository: &str, chosen: Option<&str>) -> LoggedDecision {
        LoggedDecision {
            repository: repository.to_owned(),
            labels: "rm-pool-linux".to_owned(),
            chosen: chosen.map(str::to_owned),
            reason: chosen.is_none().then(|| "no_free_slot".to_owned()),
            filtered: vec![Filtered::new("a", FilterReason::NoFreeSlot)],
            ..LoggedDecision::default()
        }
    }

    #[test]
    fn decisions_and_events_are_bounded_and_keep_the_newest() {
        let mut log = PlacementLog::default();
        let now = Instant::now();
        for index in 0..KEEP_DECISIONS + 25 {
            log.decided(decision(&format!("o/r{index}"), Some("a")), now);
        }
        for index in 0..KEEP_EVENTS + 40 {
            log.event(LoggedEvent::new(
                EventKind::Offered,
                &format!("l{index}"),
                "a",
            ));
        }
        let page = log.since(0);
        assert_eq!(page.decisions.len(), KEEP_DECISIONS);
        assert_eq!(page.events.len(), KEEP_EVENTS);
        assert_eq!(
            page.decisions.last().unwrap().repository,
            format!("o/r{}", KEEP_DECISIONS + 24)
        );
        assert_eq!(
            page.events.last().unwrap().lease_id,
            format!("l{}", KEEP_EVENTS + 39)
        );
        assert_eq!(page.counters.decisions, (KEEP_DECISIONS + 25) as u64);
        assert_eq!(page.counters.offered, (KEEP_EVENTS + 40) as u64);
        assert_eq!(page.cursor, (KEEP_DECISIONS + 25 + KEEP_EVENTS + 40) as u64);
    }

    #[test]
    fn a_cursor_returns_only_what_came_after_it() {
        let mut log = PlacementLog::default();
        let now = Instant::now();
        let first = log.decided(decision("o/a", Some("a")), now).unwrap();
        let cursor = log.since(0).cursor;
        assert_eq!(cursor, first);
        log.event(LoggedEvent::new(EventKind::Offered, "l1", "a"));
        let second = log.decided(decision("o/b", Some("b")), now).unwrap();
        let page = log.since(cursor);
        assert!(!page.reset);
        assert_eq!(
            page.decisions.iter().map(|d| d.id).collect::<Vec<_>>(),
            [second]
        );
        assert_eq!(page.events.len(), 1);
        assert!(log.since(page.cursor).decisions.is_empty());
        // A cursor from before a restart is ahead of the log: all again.
        let page = log.since(page.cursor + 100);
        assert!(page.reset);
        assert_eq!(page.decisions.len(), 2);
    }

    #[test]
    fn a_repeated_unplaced_decision_is_recorded_once_a_minute() {
        let mut log = PlacementLog::default();
        let now = Instant::now();
        assert!(log.decided(decision("o/a", None), now).is_some());
        assert!(
            log.decided(decision("o/a", None), now + Duration::from_secs(5))
                .is_none()
        );
        // Another reason is news.
        let mut other = decision("o/a", None);
        other.filtered[0].reason = FilterReason::UnfitOrDraining;
        assert!(log.decided(other, now + Duration::from_secs(6)).is_some());
        assert!(
            log.decided(decision("o/a", None), now + Duration::from_secs(7))
                .is_some()
        );
        assert!(
            log.decided(decision("o/a", None), now + Duration::from_secs(70))
                .is_some()
        );
    }

    #[test]
    fn events_inherit_the_decision_of_their_offer() {
        let mut log = PlacementLog::default();
        let mut offered = LoggedEvent::new(EventKind::Offered, "l1", "a");
        offered.decision = Some(7);
        offered.repository = Some("o/a".to_owned());
        log.event(offered);
        log.event(LoggedEvent::new(EventKind::Accepted, "l1", "a"));
        let page = log.since(0);
        assert_eq!(page.events[1].decision, Some(7));
        assert_eq!(page.events[1].repository.as_deref(), Some("o/a"));
        assert!(log.knows("l1"));
        assert!(!log.knows("l2"));
    }
}
