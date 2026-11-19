//! What placement did lately, for the dashboard's Balancing screen: the last
//! decisions, with every candidate's score parts and why each other connected
//! host was passed over, and what became of their launches.
//!
//! In memory only and bounded ([`KEEP_DECISIONS`], [`KEEP_EVENTS`]): a restart
//! starts it empty, under a new [`LogPage::epoch`]. Decisions and events share
//! one rising sequence, the cursor a page reads from ([`PlacementLog::since`]).
//!
//! A decision that offers a launch is held until the host answers, then
//! recorded with its `offered` event and the answer, in that order. A round
//! that repeats the queue's last refused one (same host, same reason, same
//! field) within a minute is not recorded again, nor is a queue left unplaced
//! for the same reasons: placement retries every few seconds.
//!
//! It has its own lock, taken after the placement state's when both are.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::HostScore;
use serde::Serialize;

/// Decisions kept.
pub const KEEP_DECISIONS: usize = 200;
/// Lease events kept.
pub const KEEP_EVENTS: usize = 500;
/// A queue left unplaced, or refused by the same host, for the same reasons is
/// recorded again only after this: placement retries every few seconds.
const REPEAT_EVERY: Duration = Duration::from_secs(60);
/// A launch whose answer never came is forgotten after this.
const HOLD_AT_MOST: Duration = Duration::from_secs(5 * 60);

/// Why a connected host was not scored for a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterReason {
    /// No enabled pool profile of its serves the queue (or it is not in
    /// launch mode for that repository).
    NoCandidate,
    /// Connected, but has not said hello or sent a heartbeat yet.
    NotReady,
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
    /// Closed without an answer from its runner: its host went away or
    /// reconnected, or its heartbeat no longer lists it.
    Lost,
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
    pub lost: u64,
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
            EventKind::Lost => &mut self.lost,
        };
        *counter += 1;
    }
}

/// What a page asked for: everything after its cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LogPage {
    /// This log's identity: a new one each time the coordinator starts, so a
    /// page holding a cursor of another knows to read everything again.
    pub epoch: String,
    /// The newest sequence number: the next page's cursor.
    pub cursor: u64,
    /// The cursor asked for is ahead of the log (it restarted) or older than
    /// what it still keeps: everything kept is sent, to replace what the page
    /// has.
    pub reset: bool,
    pub decisions: Vec<LoggedDecision>,
    pub events: Vec<LoggedEvent>,
    pub counters: Counters,
}

/// A decision waiting for its launch's answer.
#[derive(Debug)]
struct Held {
    decision: LoggedDecision,
    offered: LoggedEvent,
    since: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    last: u64,
    decisions: VecDeque<LoggedDecision>,
    events: VecDeque<LoggedEvent>,
    counters: Counters,
    /// When each queue was last recorded unplaced, and why.
    unplaced: HashMap<(String, String), (Instant, String)>,
    /// When each queue's launch was last recorded refused or unanswered, and
    /// what that round looked like.
    refused: HashMap<(String, String), (Instant, String)>,
    /// Launches offered and not answered yet, by lease.
    held: HashMap<String, Held>,
}

/// The last decisions and launch events, bounded, behind their own lock.
#[derive(Debug)]
pub struct PlacementLog {
    epoch: String,
    inner: Mutex<Inner>,
}

impl Default for PlacementLog {
    fn default() -> Self {
        Self {
            epoch: uuid::Uuid::new_v4().simple().to_string(),
            inner: Mutex::new(Inner::default()),
        }
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// What makes two rounds of a queue the same: its outcome and its field.
fn signature(decision: &LoggedDecision, outcome: &str) -> String {
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
        "{outcome}|{}|{}|{}|{}",
        decision.chosen.as_deref().unwrap_or_default(),
        decision.reason.as_deref().unwrap_or_default(),
        decision.refusal.as_deref().unwrap_or_default(),
        parts.join(",")
    )
}

/// Whether `signature` repeats what `seen` holds for `queue` within a minute;
/// otherwise it is noted as the queue's last.
fn repeats(
    seen: &mut HashMap<(String, String), (Instant, String)>,
    queue: (String, String),
    signature: String,
    now: Instant,
) -> bool {
    seen.retain(|_, (at, _)| now.saturating_duration_since(*at) < REPEAT_EVERY);
    if seen.get(&queue).is_some_and(|(_, last)| *last == signature) {
        return true;
    }
    seen.insert(queue, (now, signature));
    false
}

impl Inner {
    fn push_decision(&mut self, mut decision: LoggedDecision) -> u64 {
        self.last += 1;
        decision.id = self.last;
        self.decisions.push_back(decision);
        while self.decisions.len() > KEEP_DECISIONS {
            self.decisions.pop_front();
        }
        self.last
    }

    fn push_event(&mut self, mut event: LoggedEvent) {
        self.last += 1;
        event.seq = self.last;
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

    /// `held`'s launch was answered by `outcome`: the decision, its offer and
    /// the answer are recorded, unless the round repeats the queue's last
    /// refused one.
    fn settle(&mut self, held: Held, mut outcome: LoggedEvent, now: Instant) {
        let Held {
            decision,
            mut offered,
            ..
        } = held;
        let queue = (decision.repository.clone(), decision.labels.clone());
        if outcome.kind == EventKind::Accepted {
            self.refused.remove(&queue);
            self.unplaced.remove(&queue);
        } else {
            let answer = format!(
                "{:?}:{}",
                outcome.kind,
                outcome.reason.as_deref().unwrap_or_default()
            );
            if repeats(&mut self.refused, queue, signature(&decision, &answer), now) {
                return;
            }
        }
        let id = self.push_decision(decision);
        offered.decision = Some(id);
        outcome.decision = Some(id);
        outcome.repository.clone_from(&offered.repository);
        self.push_event(offered);
        self.push_event(outcome);
    }
}

impl PlacementLog {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a decision that offered nothing and returns its id; `None`
    /// when it repeats the queue's last unplaced decision within a minute.
    pub fn decided(&self, mut decision: LoggedDecision, now: Instant) -> Option<u64> {
        let mut inner = self.inner();
        inner.counters.decisions += 1;
        let queue = (decision.repository.clone(), decision.labels.clone());
        if repeats(
            &mut inner.unplaced,
            queue,
            signature(&decision, "unplaced"),
            now,
        ) {
            return None;
        }
        decision.at_ms = now_ms();
        Some(inner.push_decision(decision))
    }

    /// Holds a decision that offered `lease_id` to `host_id` until its answer
    /// ([`Self::event`]).
    pub fn offering(
        &self,
        mut decision: LoggedDecision,
        lease_id: &str,
        host_id: &str,
        now: Instant,
    ) {
        let mut inner = self.inner();
        inner.counters.decisions += 1;
        inner.counters.count(EventKind::Offered);
        inner
            .held
            .retain(|_, held| now.saturating_duration_since(held.since) < HOLD_AT_MOST);
        decision.at_ms = now_ms();
        let mut offered = LoggedEvent::new(EventKind::Offered, lease_id, host_id);
        offered.repository = Some(decision.repository.clone());
        offered.at_ms = decision.at_ms;
        inner.held.insert(
            lease_id.to_owned(),
            Held {
                decision,
                offered,
                since: now,
            },
        );
    }

    /// Records a launch event; its decision is looked up by its lease. The
    /// first answer to a held launch records that launch's decision first.
    pub fn event(&self, mut event: LoggedEvent, now: Instant) {
        let mut inner = self.inner();
        event.at_ms = now_ms();
        inner.counters.count(event.kind);
        if let Some(held) = inner.held.remove(&event.lease_id) {
            inner.settle(held, event, now);
            return;
        }
        if let Some(offered) = inner.offered(&event.lease_id) {
            event.decision = offered.decision;
            event.repository = event.repository.or_else(|| offered.repository.clone());
        }
        inner.push_event(event);
    }

    /// Whether `lease_id` was offered by a decision this log holds.
    #[must_use]
    pub fn knows(&self, lease_id: &str) -> bool {
        let inner = self.inner();
        inner.held.contains_key(lease_id) || inner.offered(lease_id).is_some()
    }

    /// Everything after `cursor`; everything kept when `cursor` is ahead of
    /// the log or older than what it keeps.
    #[must_use]
    pub fn since(&self, cursor: u64) -> LogPage {
        let inner = self.inner();
        let oldest = inner
            .decisions
            .front()
            .map(|decision| decision.id)
            .into_iter()
            .chain(inner.events.front().map(|event| event.seq))
            .min();
        // Something after the cursor was dropped already.
        let gap = cursor > 0 && oldest.is_some_and(|oldest| cursor + 1 < oldest);
        let reset = cursor > inner.last || gap;
        let after = if reset { 0 } else { cursor };
        LogPage {
            epoch: self.epoch.clone(),
            cursor: inner.last,
            reset,
            decisions: inner
                .decisions
                .iter()
                .filter(|decision| decision.id > after)
                .cloned()
                .collect(),
            events: inner
                .events
                .iter()
                .filter(|event| event.seq > after)
                .cloned()
                .collect(),
            counters: inner.counters,
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

    fn refused(lease: &str, host: &str, reason: &str) -> LoggedEvent {
        let mut event = LoggedEvent::new(EventKind::Refused, lease, host);
        event.reason = Some(reason.to_owned());
        event
    }

    #[test]
    fn decisions_and_events_are_bounded_and_keep_the_newest() {
        let log = PlacementLog::default();
        let now = Instant::now();
        for index in 0..KEEP_DECISIONS + 25 {
            log.decided(decision(&format!("o/r{index}"), None), now);
        }
        for index in 0..KEEP_EVENTS + 40 {
            log.event(
                LoggedEvent::new(EventKind::Claimed, &format!("l{index}"), "a"),
                now,
            );
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
        assert_eq!(page.counters.claimed, (KEEP_EVENTS + 40) as u64);
        assert_eq!(page.cursor, (KEEP_DECISIONS + 25 + KEEP_EVENTS + 40) as u64);
        // A cursor older than what is kept missed something: all again.
        assert!(log.since(1).reset);
        assert!(!log.since(page.cursor).reset);
    }

    #[test]
    fn a_cursor_returns_only_what_came_after_it() {
        let log = PlacementLog::default();
        let now = Instant::now();
        let first = log.decided(decision("o/a", None), now).unwrap();
        let cursor = log.since(0).cursor;
        assert_eq!(cursor, first);
        log.event(LoggedEvent::new(EventKind::Claimed, "l1", "a"), now);
        let second = log.decided(decision("o/b", None), now).unwrap();
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
        // Each log is told apart from the one before a restart.
        assert_ne!(log.since(0).epoch, PlacementLog::default().since(0).epoch);
    }

    #[test]
    fn a_repeated_unplaced_decision_is_recorded_once_a_minute() {
        let log = PlacementLog::default();
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
    fn a_launch_is_recorded_with_its_answer_and_a_repeated_refusal_once_a_minute() {
        let log = PlacementLog::default();
        let now = Instant::now();
        log.offering(decision("o/a", Some("h")), "l1", "h", now);
        assert!(log.knows("l1"));
        assert!(log.since(0).decisions.is_empty(), "held until answered");
        log.event(refused("l1", "h", "max_capacity"), now);
        let page = log.since(0);
        let id = page.decisions[0].id;
        let kinds: Vec<(EventKind, Option<u64>)> =
            page.events.iter().map(|e| (e.kind, e.decision)).collect();
        assert_eq!(
            kinds,
            [
                (EventKind::Offered, Some(id)),
                (EventKind::Refused, Some(id))
            ]
        );
        // The same round again: nothing new is recorded, though counted.
        log.offering(
            decision("o/a", Some("h")),
            "l2",
            "h",
            now + Duration::from_secs(5),
        );
        log.event(
            refused("l2", "h", "max_capacity"),
            now + Duration::from_secs(5),
        );
        let again = log.since(page.cursor);
        assert!(again.decisions.is_empty() && again.events.is_empty());
        assert_eq!(again.counters.refused, 2);
        // Accepted is always news, and later events find their decision.
        log.offering(
            decision("o/a", Some("h")),
            "l3",
            "h",
            now + Duration::from_secs(6),
        );
        log.event(
            LoggedEvent::new(EventKind::Accepted, "l3", "h"),
            now + Duration::from_secs(6),
        );
        log.event(
            LoggedEvent::new(EventKind::Claimed, "l3", "h"),
            now + Duration::from_secs(7),
        );
        let accepted = log.since(page.cursor);
        let id = accepted.decisions[0].id;
        assert!(accepted.events.iter().all(|e| e.decision == Some(id)));
        assert_eq!(
            accepted.events.last().unwrap().repository.as_deref(),
            Some("o/a")
        );
    }
}
