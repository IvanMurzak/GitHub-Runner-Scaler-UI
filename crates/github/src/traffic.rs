// owner: c2-authenticated-client (traffic accounting)

//! What this host actually spends against GitHub's rate limits, measured.
//!
//! The budget model in [`crate::rest`] *projects* a cost from a table of
//! request counts. This module *measures* one: every response the shared
//! [`crate::AuthenticatedClient`] receives is counted here by class, and the
//! rate-limit headers GitHub attaches to it are kept.
//!
//! # Why the classes are full, not-modified, and failed
//!
//! GitHub's own words, from "Best practices for using the REST API"
//! (<https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests-if-appropriate>):
//!
//! > Making a conditional request does not count against your primary rate
//! > limit if a `304` response is returned and the request was made while
//! > correctly authorized with an `Authorization` header.
//!
//! So a `304` is free against the hourly quota and a `200` is not. That is the
//! whole reason [`crate::demand`] sends `If-None-Match`, and the reason this
//! module counts the two apart: the share of `304`s is the number that says
//! whether conditional polling is paying off. Errors are counted separately
//! because they do count against the quota and are not data.
//!
//! # The headers describe the ACCOUNT, not this machine
//!
//! "Primary rate limits for GitHub App user access tokens … are dictated by the
//! primary rate limits for the authenticated user. This rate limit is combined
//! with any requests that another GitHub App or OAuth app makes on that user's
//! behalf and any requests that the user makes with a personal access token"
//! (<https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#primary-rate-limit-for-github-app-installations>).
//!
//! Every host signed in as the same person therefore draws from **one** bucket,
//! and so does that person's `gh` CLI. `x-ratelimit-remaining` on any response
//! is the bucket's level, whoever drained it — which is exactly why it is the
//! right input for slowing down: this machine cannot count the other machines'
//! requests, but it can see what they left.
//!
//! # The secondary limit has no header until it is exceeded
//!
//! "No more than 900 points per minute are allowed for REST API endpoints", and
//! a `GET` costs one point
//! (<https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api#about-secondary-rate-limits>).
//! GitHub does not say a `304` is exempt from that limit, so this module
//! assumes it is not: every request is a point. The secondary headroom shown
//! to an operator is therefore this host's busiest minute against
//! [`SECONDARY_POINTS_PER_MINUTE`], stated as one host's share of a limit the
//! other hosts on the account share too.

use std::sync::Mutex;
use std::time::Duration;

use reqwest::StatusCode;
use runner_manager_domain::model::Timestamp;
use serde::{Deserialize, Serialize};

use crate::HeaderMap;

/// GitHub's documented REST secondary limit, in points per minute.
///
/// A `GET` is one point, so for this product — which only polls with `GET` —
/// it is also a request count.
pub const SECONDARY_POINTS_PER_MINUTE: u32 = 900;

/// Below this share of the hourly quota left, polling stretches.
///
/// One fifth: 1,000 of 5,000. Chosen so that a host noticing it still has
/// enough budget to keep polling at its *active* interval for the rest of the
/// hour, while giving the fleet's interactive users (`gh`, other apps on the
/// same account) room.
pub const LOW_PRIMARY_REMAINING_PERCENT: u64 = 20;

/// Below this share, polling stretches further.
///
/// One twentieth: 250 of 5,000. At that level a single busy repository's job
/// listings can drain the rest of the bucket, and an exhausted bucket stops
/// every host on the account, not just this one.
pub const CRITICAL_PRIMARY_REMAINING_PERCENT: u64 = 5;

const _: () = assert!(
    CRITICAL_PRIMARY_REMAINING_PERCENT < LOW_PRIMARY_REMAINING_PERCENT,
    "the critical threshold must sit below the low one"
);

/// How many minutes of history are kept.
const WINDOW_MINUTES: usize = 60;

/// What GitHub said about the account's hourly quota on one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitSnapshot {
    /// `x-ratelimit-limit`.
    pub limit: u64,
    /// `x-ratelimit-remaining`.
    pub remaining: u64,
    /// `x-ratelimit-used`, when sent.
    pub used: Option<u64>,
    /// `x-ratelimit-reset`, a Unix timestamp in seconds.
    pub reset_unix_secs: u64,
    /// When this host read it.
    pub observed_at: Timestamp,
}

impl RateLimitSnapshot {
    /// The `core` quota's state from a response's headers, or `None` when the
    /// response did not carry all three of limit, remaining and reset, or
    /// described a different resource (`search`, `graphql`, …), whose bucket
    /// is not the one demand polling spends.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap, now: Timestamp) -> Option<Self> {
        let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
        if text("x-ratelimit-resource").is_some_and(|r| !r.trim().eq_ignore_ascii_case("core")) {
            return None;
        }
        let number = |name: &str| text(name).and_then(|v| v.trim().parse::<u64>().ok());
        Some(Self {
            limit: number("x-ratelimit-limit")?,
            remaining: number("x-ratelimit-remaining")?,
            used: number("x-ratelimit-used"),
            reset_unix_secs: number("x-ratelimit-reset")?,
            observed_at: now,
        })
    }

    /// How long until the quota resets, zero once it has.
    #[must_use]
    pub fn reset_in(&self, now: Timestamp) -> Duration {
        let reset = i64::try_from(self.reset_unix_secs).unwrap_or(i64::MAX);
        u64::try_from(reset.saturating_sub(now.timestamp()))
            .map_or(Duration::ZERO, Duration::from_secs)
    }

    /// How hard this reading says to slow down.
    ///
    /// A reading whose reset has passed says nothing about the current window,
    /// so it is [`PrimaryPressure::Normal`] however low it was.
    #[must_use]
    pub fn pressure(&self, now: Timestamp) -> PrimaryPressure {
        if self.limit == 0 || self.reset_in(now).is_zero() {
            return PrimaryPressure::Normal;
        }
        let percent = self.remaining.saturating_mul(100) / self.limit;
        if percent < CRITICAL_PRIMARY_REMAINING_PERCENT {
            PrimaryPressure::Critical
        } else if percent < LOW_PRIMARY_REMAINING_PERCENT {
            PrimaryPressure::Low
        } else {
            PrimaryPressure::Normal
        }
    }
}

/// How much of the shared hourly quota is left, as a decision input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryPressure {
    /// At least [`LOW_PRIMARY_REMAINING_PERCENT`] left.
    Normal,
    /// Under [`LOW_PRIMARY_REMAINING_PERCENT`].
    Low,
    /// Under [`CRITICAL_PRIMARY_REMAINING_PERCENT`].
    Critical,
}

impl PrimaryPressure {
    /// How many times the active interval a poll should wait at this level.
    #[must_use]
    pub const fn stretch_factor(self) -> u32 {
        match self {
            Self::Normal => 1,
            Self::Low => 2,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Minute {
    /// Minutes since the Unix epoch this bucket counts, so a bucket left over
    /// from an hour ago is recognised as stale rather than added in.
    epoch_minute: i64,
    full: u32,
    not_modified: u32,
    failed: u32,
}

impl Minute {
    const fn total(&self) -> u32 {
        self.full
            .saturating_add(self.not_modified)
            .saturating_add(self.failed)
    }
}

#[derive(Debug)]
struct Inner {
    minutes: [Minute; WINDOW_MINUTES],
    first_seen: Option<Timestamp>,
    latest: Option<RateLimitSnapshot>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            minutes: [Minute::default(); WINDOW_MINUTES],
            first_seen: None,
            latest: None,
        }
    }
}

/// Every response one client received, by class and by minute, for the last
/// hour, plus the newest rate-limit reading.
#[derive(Debug, Default)]
pub struct ApiTraffic {
    inner: Mutex<Inner>,
}

impl ApiTraffic {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one response.
    pub fn record(&self, status: StatusCode, headers: &HeaderMap, now: Timestamp) {
        let snapshot = RateLimitSnapshot::from_headers(headers, now);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.first_seen.get_or_insert(now);
        let epoch_minute = now.timestamp().div_euclid(60);
        let slot = usize::try_from(epoch_minute.rem_euclid(WINDOW_MINUTES as i64)).unwrap_or(0);
        let bucket = &mut inner.minutes[slot];
        if bucket.epoch_minute != epoch_minute {
            *bucket = Minute {
                epoch_minute,
                ..Minute::default()
            };
        }
        if status == StatusCode::NOT_MODIFIED {
            bucket.not_modified = bucket.not_modified.saturating_add(1);
        } else if status.is_success() {
            bucket.full = bucket.full.saturating_add(1);
        } else {
            bucket.failed = bucket.failed.saturating_add(1);
        }
        if let Some(snapshot) = snapshot {
            inner.latest = Some(snapshot);
        }
    }

    /// The newest `core` rate-limit reading, from any response.
    #[must_use]
    pub fn latest_rate_limit(&self) -> Option<RateLimitSnapshot> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latest
    }

    /// The last hour, summed.
    #[must_use]
    pub fn summary(&self, now: Timestamp) -> TrafficSummary {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = now.timestamp().div_euclid(60);
        let mut summary = TrafficSummary {
            observed_minutes: 0,
            full: 0,
            not_modified: 0,
            failed: 0,
            peak_requests_per_minute: 0,
            rate_limit: inner.latest,
        };
        for minute in &inner.minutes {
            // Strictly inside the last hour, the current minute included.
            if minute.epoch_minute > current - WINDOW_MINUTES as i64
                && minute.epoch_minute <= current
            {
                summary.full = summary.full.saturating_add(minute.full);
                summary.not_modified = summary.not_modified.saturating_add(minute.not_modified);
                summary.failed = summary.failed.saturating_add(minute.failed);
                summary.peak_requests_per_minute =
                    summary.peak_requests_per_minute.max(minute.total());
            }
        }
        summary.observed_minutes = inner.first_seen.map_or(0, |first| {
            let minutes = current - first.timestamp().div_euclid(60) + 1;
            u32::try_from(minutes.clamp(0, WINDOW_MINUTES as i64)).unwrap_or(0)
        });
        summary
    }
}

/// One host's measured traffic over (up to) the last hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSummary {
    /// How many minutes the counts below cover: the time since the first
    /// response, capped at sixty. Under sixty, the counts are not yet an
    /// hourly rate.
    pub observed_minutes: u32,
    /// `2xx` responses: data, and charged against the primary limit.
    pub full: u32,
    /// `304` responses: free against the primary limit.
    pub not_modified: u32,
    /// Everything else. Charged, and not data.
    pub failed: u32,
    /// The most requests of any one minute, every class counted: the number
    /// to hold against [`SECONDARY_POINTS_PER_MINUTE`].
    pub peak_requests_per_minute: u32,
    /// The newest reading of the account's hourly quota.
    pub rate_limit: Option<RateLimitSnapshot>,
}

impl TrafficSummary {
    /// Every response counted.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.full
            .saturating_add(self.not_modified)
            .saturating_add(self.failed)
    }

    /// The share of responses that were `304`, in whole percent, or `None`
    /// before any response.
    #[must_use]
    pub fn not_modified_percent(&self) -> Option<u32> {
        let total = self.total();
        (total > 0).then(|| {
            u32::try_from(u64::from(self.not_modified) * 100 / u64::from(total)).unwrap_or(100)
        })
    }

    /// `count` over the observed minutes, scaled to an hour.
    #[must_use]
    pub fn per_hour(&self, count: u32) -> u32 {
        if self.observed_minutes == 0 {
            return 0;
        }
        u32::try_from(u64::from(count) * 60 / u64::from(self.observed_minutes)).unwrap_or(u32::MAX)
    }
}

/// `requests_per_minute` as a share of [`SECONDARY_POINTS_PER_MINUTE`], in
/// whole percent: a `GET` is one point.
#[must_use]
pub const fn secondary_share_percent(requests_per_minute: u32) -> u32 {
    requests_per_minute.saturating_mul(100) / SECONDARY_POINTS_PER_MINUTE
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use reqwest::header::HeaderValue;

    fn at(secs: i64) -> Timestamp {
        chrono::Utc
            .timestamp_opt(secs, 0)
            .single()
            .expect("a valid instant")
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).expect("a header value"));
        }
        map
    }

    fn quota(remaining: u64, reset: u64) -> HeaderMap {
        headers(&[
            ("x-ratelimit-limit", "5000"),
            ("x-ratelimit-remaining", &remaining.to_string()),
            ("x-ratelimit-used", &(5000 - remaining).to_string()),
            ("x-ratelimit-reset", &reset.to_string()),
            ("x-ratelimit-resource", "core"),
        ])
    }

    #[test]
    fn a_304_is_counted_apart_from_a_200_and_from_a_failure() {
        let traffic = ApiTraffic::new();
        let now = at(1_000_000);
        traffic.record(StatusCode::OK, &HeaderMap::new(), now);
        traffic.record(StatusCode::NOT_MODIFIED, &HeaderMap::new(), now);
        traffic.record(StatusCode::NOT_MODIFIED, &HeaderMap::new(), now);
        traffic.record(StatusCode::NOT_FOUND, &HeaderMap::new(), now);
        let summary = traffic.summary(now);
        assert_eq!(
            (summary.full, summary.not_modified, summary.failed),
            (1, 2, 1)
        );
        assert_eq!(
            summary.full + summary.failed,
            2,
            "a 304 is not charged; a 404 is"
        );
        assert_eq!(summary.not_modified_percent(), Some(50));
        assert_eq!(summary.peak_requests_per_minute, 4);
    }

    #[test]
    fn counts_older_than_an_hour_fall_out_of_the_window() {
        let traffic = ApiTraffic::new();
        traffic.record(StatusCode::OK, &HeaderMap::new(), at(0));
        // Same ring slot, one hour later: the old count must not be added in.
        traffic.record(StatusCode::NOT_MODIFIED, &HeaderMap::new(), at(3_600));
        let summary = traffic.summary(at(3_600));
        assert_eq!((summary.full, summary.not_modified), (0, 1));
        assert_eq!(summary.observed_minutes, 60);
        assert_eq!(traffic.summary(at(3_600 + 3_600)).total(), 0);
    }

    #[test]
    fn per_hour_scales_a_short_observation_to_an_hourly_rate() {
        let traffic = ApiTraffic::new();
        for second in 0..10 {
            traffic.record(StatusCode::OK, &HeaderMap::new(), at(60 * second));
        }
        let summary = traffic.summary(at(60 * 9));
        assert_eq!(summary.observed_minutes, 10);
        assert_eq!(summary.per_hour(summary.full), 60);
    }

    #[test]
    fn the_newest_core_reading_is_kept_and_another_resource_is_ignored() {
        let traffic = ApiTraffic::new();
        traffic.record(StatusCode::OK, &quota(4_000, 5_000), at(10));
        let mut search = quota(1, 5_000);
        search.insert("x-ratelimit-resource", HeaderValue::from_static("search"));
        traffic.record(StatusCode::OK, &search, at(11));
        let latest = traffic.latest_rate_limit().expect("a reading");
        assert_eq!(latest.remaining, 4_000);
        assert_eq!(latest.used, Some(1_000));
    }

    #[test]
    fn pressure_follows_the_documented_thresholds_and_expires_at_reset() {
        let now = at(1_000);
        let reading = |remaining| {
            RateLimitSnapshot::from_headers(&quota(remaining, 4_600), now).expect("a reading")
        };
        assert_eq!(reading(1_000).pressure(now), PrimaryPressure::Normal);
        assert_eq!(reading(999).pressure(now), PrimaryPressure::Low);
        assert_eq!(reading(250).pressure(now), PrimaryPressure::Low);
        assert_eq!(reading(249).pressure(now), PrimaryPressure::Critical);
        assert_eq!(reading(0).reset_in(now), Duration::from_secs(3_600));
        assert_eq!(
            reading(0).pressure(at(4_600)),
            PrimaryPressure::Normal,
            "a reading from a window that has reset says nothing about the new one"
        );
    }

    #[test]
    fn the_secondary_share_is_the_busiest_minute_against_nine_hundred() {
        let traffic = ApiTraffic::new();
        for _ in 0..90 {
            traffic.record(StatusCode::NOT_MODIFIED, &HeaderMap::new(), at(120));
        }
        traffic.record(StatusCode::OK, &HeaderMap::new(), at(180));
        assert_eq!(
            secondary_share_percent(traffic.summary(at(180)).peak_requests_per_minute),
            10
        );
    }
}
