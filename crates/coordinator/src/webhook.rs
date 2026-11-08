//! GitHub's side: signature verification, delivery de-duplication, and the
//! one event stage 1 acts on.

use std::collections::{HashSet, VecDeque};

use hmac::{Hmac, KeyInit as _, Mac as _};
use runner_manager_domain::model::Label;
use runner_manager_domain::policy::RunsOn;
use serde::Deserialize;
use sha2::Sha256;

/// The largest webhook body accepted. `workflow_job` payloads are tens of
/// kilobytes; GitHub caps any payload at 25 MB, which nothing here needs.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// How many recent delivery ids are remembered.
pub const DELIVERY_MEMORY: usize = 10_000;

/// Whether `header` (`X-Hub-Signature-256`) is the HMAC-SHA256 of `body`
/// under `secret`. The comparison is constant-time (`Mac::verify_slice`).
#[must_use]
pub fn signature_valid(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    let Some(expected) = header
        .and_then(|value| value.trim().strip_prefix("sha256="))
        .and_then(|hex_text| hex::decode(hex_text).ok())
    else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// GitHub's delivery GUID, checked to be something safe to keep and log.
#[must_use]
pub fn valid_delivery_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Recently seen `X-GitHub-Delivery` ids, bounded.
///
/// GitHub redelivers on a timeout and an operator can redeliver by hand; a
/// repeat is acknowledged and otherwise ignored. In memory: after a restart a
/// repeat costs at most one extra wake, which a host absorbs.
#[derive(Debug)]
pub struct DeliveryLog {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl DeliveryLog {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Records `id`; `false` when it was already recorded.
    pub fn first_time(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return false;
        }
        if self.order.len() == self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(id.to_string());
        self.order.push_back(id.to_string());
        true
    }
}

/// The parts of a `workflow_job` event stage 1 reads.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowJobEvent {
    pub action: String,
    pub workflow_job: WorkflowJob,
    pub repository: Repository,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowJob {
    pub id: u64,
    pub run_id: u64,
    #[serde(default)]
    pub labels: Vec<String>,
    /// The job's name, matrix values expanded: `build (ubuntu, 3.12)`.
    #[serde(default)]
    pub name: Option<String>,
    /// The runner that took the job (`in_progress`, `completed`).
    #[serde(default)]
    pub runner_name: Option<String>,
    /// RFC 3339 times, kept as text: one GitHub writes in an unexpected form
    /// costs that figure in the statistics, never the event.
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    /// `null` until `completed`.
    #[serde(default)]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    pub full_name: String,
}

/// The `action` of a `workflow_job` event, as a closed set for logging.
#[must_use]
pub fn action_name(action: &str) -> &'static str {
    match action {
        "queued" => "queued",
        "waiting" => "waiting",
        "in_progress" => "in_progress",
        "completed" => "completed",
        _ => "other",
    }
}

/// Whether a profile registered with `profile` labels can take a job that
/// asked for `job` labels.
///
/// The same rule the host applies to its own demand (`RoutingLabels::matches`
/// over `RunsOn::required_labels`): every label the job requires must be one
/// of the profile's, compared case-insensitively. A job whose labels cannot
/// be resolved (an expression, no labels at all) matches nothing.
#[must_use]
pub fn labels_cover(profile: &[String], job: &[String]) -> bool {
    required_labels(job).is_some_and(|required| profile_covers(profile, &required))
}

/// The labels a job labelled `job` requires, or `None` when they cannot be
/// resolved (an expression, no labels at all).
#[must_use]
pub fn required_labels(job: &[String]) -> Option<Vec<Label>> {
    RunsOn::from_job_labels(job.iter().cloned())
        .required_labels()
        .ok()
}

/// Whether a profile registered with `profile` labels has every label in
/// `required`.
#[must_use]
pub fn profile_covers(profile: &[String], required: &[Label]) -> bool {
    let offered: Vec<Label> = profile
        .iter()
        .filter_map(|label| Label::new(label).ok())
        .collect();
    required.iter().all(|label| offered.contains(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"It's a Secret to Everybody";
    const BODY: &[u8] = b"Hello, World!";
    /// GitHub's documented test vector for exactly this secret and body.
    const GITHUB_VECTOR: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    #[test]
    fn githubs_documented_signature_verifies() {
        assert!(signature_valid(SECRET, BODY, Some(GITHUB_VECTOR)));
    }

    #[test]
    fn a_wrong_missing_or_malformed_signature_is_refused() {
        assert!(!signature_valid(
            b"another secret",
            BODY,
            Some(GITHUB_VECTOR)
        ));
        assert!(!signature_valid(
            SECRET,
            b"Hello, World?",
            Some(GITHUB_VECTOR)
        ));
        assert!(!signature_valid(SECRET, BODY, None));
        assert!(!signature_valid(SECRET, BODY, Some("")));
        assert!(!signature_valid(
            SECRET,
            BODY,
            Some(GITHUB_VECTOR.trim_start_matches("sha256="))
        ));
        assert!(!signature_valid(SECRET, BODY, Some("sha256=zz")));
        assert!(!signature_valid(SECRET, BODY, Some("sha1=757107ea")));
        // A truncated MAC is not a shorter valid one.
        assert!(!signature_valid(SECRET, BODY, Some(&GITHUB_VECTOR[..40])));
    }

    #[test]
    fn a_delivery_is_acted_on_once_and_memory_is_bounded() {
        let mut log = DeliveryLog::new(2);
        assert!(log.first_time("a"));
        assert!(!log.first_time("a"));
        assert!(log.first_time("b"));
        assert!(log.first_time("c"));
        // `a` was evicted to make room, `c` was not.
        assert!(log.first_time("a"));
        assert!(!log.first_time("c"));
        assert!(log.seen.len() <= 2);
    }

    #[test]
    fn delivery_ids_must_look_like_guids() {
        assert!(valid_delivery_id("72d3162e-cc78-11e3-81ab-4c9367dc0958"));
        assert!(!valid_delivery_id(""));
        assert!(!valid_delivery_id("a b"));
        assert!(!valid_delivery_id(&"a".repeat(65)));
    }

    fn strings(labels: &[&str]) -> Vec<String> {
        labels.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_profile_covers_a_job_when_it_has_every_required_label() {
        let profile = strings(&["rm-home-linux-x64", "self-hosted", "Linux", "X64"]);
        assert!(labels_cover(&profile, &strings(&["self-hosted", "linux"])));
        assert!(labels_cover(&profile, &strings(&["RM-HOME-LINUX-X64"])));
        assert!(labels_cover(
            &profile,
            &strings(&["self-hosted", "", "x64"])
        ));
        assert!(!labels_cover(&profile, &strings(&["self-hosted", "gpu"])));
        assert!(!labels_cover(&profile, &strings(&["ubuntu-latest"])));
        // Unresolvable: no labels, or an expression.
        assert!(!labels_cover(&profile, &[]));
        assert!(!labels_cover(&profile, &strings(&["${{ matrix.os }}"])));
    }

    #[test]
    fn a_workflow_job_event_parses_from_githubs_shape() {
        let body = r#"{"action":"queued","workflow_job":{"id":7,"run_id":9,
            "labels":["self-hosted","linux"],"name":"build"},
            "repository":{"full_name":"octo/app","private":true},"sender":{}}"#;
        let event: WorkflowJobEvent = serde_json::from_str(body).expect("parses");
        assert_eq!(event.action, "queued");
        assert_eq!(
            event.workflow_job.labels,
            strings(&["self-hosted", "linux"])
        );
        assert_eq!(event.repository.full_name, "octo/app");
        assert_eq!(event.workflow_job.name.as_deref(), Some("build"));
        assert_eq!(event.workflow_job.runner_name, None);
        let taken = r#"{"action":"in_progress","workflow_job":{"id":7,"run_id":9,
            "labels":["rm-pool-linux"],"name":"build (linux, 3.12)","workflow_name":"CI",
            "runner_name":"runner-manager-abc","runner_id":3,
            "created_at":"2026-11-07T10:00:00Z","started_at":"2026-11-07T10:00:04Z",
            "completed_at":null},
            "repository":{"full_name":"octo/app"}}"#;
        let event: WorkflowJobEvent = serde_json::from_str(taken).expect("parses");
        assert_eq!(
            event.workflow_job.started_at.as_deref(),
            Some("2026-11-07T10:00:04Z")
        );
        assert_eq!(event.workflow_job.completed_at, None);
        assert_eq!(
            event.workflow_job.runner_name.as_deref(),
            Some("runner-manager-abc")
        );
        assert_eq!(action_name("in_progress"), "in_progress");
        assert_eq!(action_name("<script>"), "other");
    }
}
