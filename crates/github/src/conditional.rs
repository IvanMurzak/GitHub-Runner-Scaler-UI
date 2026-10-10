// owner: c4-demand-and-jit-gateway (conditional polling)

//! Conditional `GET`s: ask GitHub whether a listing changed before paying for
//! it again.
//!
//! # Why
//!
//! A demand poll re-reads the same few listings every interval, and on an
//! idle host they are the same bytes every time. GitHub's REST documentation
//! ("Best practices for using the REST API", *Use conditional requests if
//! appropriate*,
//! <https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests-if-appropriate>):
//!
//! > Most endpoints return an `etag` header, and many endpoints return a
//! > `last-modified` header. You can use the values of these headers to make
//! > conditional `GET` requests. … If the data has not changed, you will
//! > receive a `304 Not Modified` response.
//! >
//! > Making a conditional request does not count against your primary rate
//! > limit if a `304` response is returned and the request was made while
//! > correctly authorized with an `Authorization` header.
//!
//! So [`ConditionalCache`] keeps each listing's validators and body, sends the
//! validators back, and on `304` hands the caller the body it already has. The
//! caller cannot tell the two apart except through [`Fetched::not_modified`],
//! which is the point: parsing is unchanged, and an idle poll costs nothing
//! against the hourly quota.
//!
//! # What was measured before this was relied on
//!
//! Against `api.github.com`, with `gh api -i`, read-only:
//!
//! * `GET /repos/{o}/{r}/actions/runs?status=queued|in_progress&per_page=100`,
//!   `GET …/actions/runs/{id}/jobs?filter=latest&per_page=100` and
//!   `GET /repos/{o}/{r}/actions/runners?per_page=100` each return a **weak**
//!   `ETag` (`W/"…"`) and `Cache-Control: private, max-age=60`.
//! * For an unchanged listing the `ETag` is stable. Five listings were asked
//!   twelve times, ten seconds apart: an idle repository's queued and
//!   in-progress runs, a queued-runs listing holding two stuck runs, one of
//!   those runs' jobs, and a repository's runners. All sixty answers were
//!   `304`, one distinct `ETag` per listing.
//! * A listing that is changing is not: while CI ran, the jobs of an
//!   in-progress run changed on 11 of 18 polls ten seconds apart, and the
//!   in-progress runs listing on 1 of 18. That is why an active target keeps
//!   the longer active interval.
//! * A `304` carries the account's `x-ratelimit-*` headers, and twenty `304`s
//!   in a row left `x-ratelimit-used` unchanged apart from other clients'
//!   traffic on the same account — consistent with the documented exemption.
//! * The `ETag` differs between credentials for the same listing (the
//!   response varies on `Authorization`), so it is cached per client and is
//!   never shared between machines. After a token renewal the first poll of
//!   each listing may be a full `200`; that is one request per listing per
//!   eight hours.
//!
//! # Bounded
//!
//! A job listing's URL names a run id, so a busy repository mints new keys all
//! day. Entries unused for [`IDLE_ENTRY_TTL`] are dropped, and the map never
//! holds more than [`MAX_ENTRIES`].

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner_manager_domain::model::{Clock, Timestamp};

use crate::{ApiRequest, ApiResponse, AuthenticatedClient, GithubError, Validators};

/// How long an entry nobody asked for is kept.
///
/// Longer than any wait the schedule produces in practice: the 15-minute
/// ceilings on the offline and rate-limit back-offs, and the active interval
/// stretched four times under a critically low quota up to a 30-minute
/// active interval. An entry evicted by a long wait costs one charged `200`
/// on the next poll, which is exactly the wrong moment when the quota is low.
pub const IDLE_ENTRY_TTL: Duration = Duration::from_secs(2 * 60 * 60);

/// The most entries kept. A ceiling against a pathological number of runs,
/// not a size anyone should reach: ten repositories with a handful of active
/// runs each use a few dozen.
pub const MAX_ENTRIES: usize = 1_024;

struct Entry {
    validators: Validators,
    /// Shared, so answering a `304` hands out a reference rather than a copy
    /// of a body that may be a hundred workflow runs long.
    response: Arc<ApiResponse>,
    last_used: Timestamp,
}

/// One response, and whether GitHub said it was unchanged.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The full response: freshly received, or the cached copy GitHub said is
    /// still current. Never a bodiless `304`.
    pub response: Arc<ApiResponse>,
    /// `true` when GitHub answered `304` and `response` is the cached copy.
    pub not_modified: bool,
}

/// Validators and bodies of the listings one client polls.
pub struct ConditionalCache {
    clock: Arc<dyn Clock>,
    entries: Mutex<HashMap<String, Entry>>,
}

impl fmt::Debug for ConditionalCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bodies may be large and are nobody's business in a log; the count is
        // what a reader of a `Debug` dump needs.
        f.debug_struct("ConditionalCache")
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

impl ConditionalCache {
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// How many listings are cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `request`, sent conditionally when a previous answer to it is cached.
    ///
    /// # Errors
    /// Whatever [`AuthenticatedClient::send`] fails with.
    pub async fn send(
        &self,
        client: &AuthenticatedClient,
        request: &ApiRequest,
    ) -> Result<Fetched, GithubError> {
        let key = request.cache_key();
        let validators = self.lock().get(&key).map(|entry| entry.validators.clone());
        let sent = match validators.clone() {
            Some(validators) => request.clone().conditional(validators),
            None => request.clone(),
        };
        let response = client.send(&sent).await?;
        let now = self.clock.now();

        if response.is_not_modified() {
            let cached = self.cached_for(&key, validators.as_ref(), now);
            if let Some(response) = cached {
                return Ok(Fetched {
                    response,
                    not_modified: true,
                });
            }
            // The entry was evicted or replaced between the lookup and the
            // answer, so the body GitHub says is current is gone. Ask again
            // without validators: one charged request, instead of a bodiless
            // or wrong reply.
            let response = Arc::new(client.send(request).await?);
            self.store(key, &response, now);
            return Ok(Fetched {
                response,
                not_modified: false,
            });
        }

        let response = Arc::new(response);
        self.store(key, &response, now);
        Ok(Fetched {
            response,
            not_modified: false,
        })
    }

    /// The cached body a `304` to `sent` vouches for, if it is still the one
    /// cached.
    ///
    /// Only the body the validators we SENT describe. Another request for
    /// this key may have stored a different answer meanwhile, and a `304`
    /// vouches for ours, not for whatever is cached now.
    fn cached_for(
        &self,
        key: &str,
        sent: Option<&Validators>,
        now: Timestamp,
    ) -> Option<Arc<ApiResponse>> {
        self.lock()
            .get_mut(key)
            .filter(|entry| Some(&entry.validators) == sent)
            .map(|entry| {
                entry.last_used = now;
                Arc::clone(&entry.response)
            })
    }

    fn store(&self, key: String, response: &Arc<ApiResponse>, now: Timestamp) {
        let validators = Validators::of(response);
        let mut entries = self.lock();
        if validators.is_empty() {
            // Nothing to send back next time, so nothing worth keeping; and an
            // entry for this key from an earlier answer is now stale.
            entries.remove(&key);
            return;
        }
        entries.insert(
            key,
            Entry {
                validators,
                response: Arc::clone(response),
                last_used: now,
            },
        );
        if entries.len() > MAX_ENTRIES {
            retain_recent(&mut entries, now);
        }
        while entries.len() > MAX_ENTRIES {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&oldest);
        }
    }

    /// Drop every entry unused for [`IDLE_ENTRY_TTL`].
    pub fn evict_idle(&self) {
        let now = self.clock.now();
        retain_recent(&mut self.lock(), now);
    }
}

/// Keep only the entries used within [`IDLE_ENTRY_TTL`] of `now`.
fn retain_recent(entries: &mut HashMap<String, Entry>, now: Timestamp) {
    let idle = chrono::TimeDelta::from_std(IDLE_ENTRY_TTL).unwrap_or(chrono::TimeDelta::MAX);
    entries.retain(|_, entry| now.signed_duration_since(entry.last_used) < idle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FIXTURE_TOKEN, TestClock};
    use crate::{Endpoints, UserAccessToken};
    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ETAG: &str = r#"W/"6042c04e7d4294834a2b329b7cb11869""#;

    fn client(server: &MockServer, clock: Arc<TestClock>) -> AuthenticatedClient {
        let endpoints = Endpoints::for_test_server(&server.uri()).expect("a test server base");
        let token = UserAccessToken::from_stored(SecretString::from(FIXTURE_TOKEN));
        AuthenticatedClient::new(endpoints, token, clock).expect("a client over the test server")
    }

    fn listing() -> ApiRequest {
        ApiRequest::get("/repos/octo/dashboard/actions/runs")
            .query("status", "queued")
            .query("per_page", 100)
    }

    /// The first answer is a `200` with an `ETag`; every request that sends the
    /// tag back gets a bodiless `304`. Mounted most-specific first: wiremock
    /// answers with the first mock whose matchers all pass.
    async fn mount_unchanged_listing(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/repos/octo/dashboard/actions/runs"))
            .and(header("if-none-match", ETAG))
            .respond_with(ResponseTemplate::new(304).insert_header("etag", ETAG))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/dashboard/actions/runs"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", ETAG)
                    .set_body_json(body),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_304_hands_back_the_cached_body_and_says_it_was_unchanged() {
        let server = MockServer::start().await;
        let body = json!({ "total_count": 1, "workflow_runs": [ { "id": 7 } ] });
        mount_unchanged_listing(&server, body.clone()).await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(clock);

        let first = cache
            .send(&client, &listing())
            .await
            .expect("a first answer");
        assert!(
            !first.not_modified,
            "nothing was cached, so nothing was asked conditionally"
        );
        let second = cache
            .send(&client, &listing())
            .await
            .expect("a second answer");
        assert!(
            second.not_modified,
            "the tag was sent back and GitHub said unchanged"
        );
        assert_eq!(
            second
                .response
                .json::<serde_json::Value>()
                .expect("the cached JSON"),
            body,
            "a 304 has no body; the caller must get the one it already paid for"
        );
        assert_eq!(second.response.status(), reqwest::StatusCode::OK);

        let received = server.received_requests().await.expect("recorded requests");
        assert_eq!(received.len(), 2);
        assert!(received[0].headers.get("if-none-match").is_none());
        assert_eq!(
            received[1]
                .headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok()),
            Some(ETAG),
            "the weak tag goes back verbatim, `W/` prefix and all"
        );
        let traffic = client.traffic().summary(client.clock.now());
        assert_eq!((traffic.full, traffic.not_modified), (1, 1));
    }

    #[tokio::test]
    async fn a_changed_listing_replaces_the_cached_body() {
        let server = MockServer::start().await;
        // The server has moved on: a conditional request gets a new body and
        // a new tag, and the next request must send the new tag.
        Mock::given(method("GET"))
            .and(header("if-none-match", ETAG))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", r#"W/"second""#)
                    .set_body_json(json!({ "total_count": 0, "workflow_runs": [] })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(header("if-none-match", r#"W/"second""#))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", ETAG)
                    .set_body_json(json!({ "total_count": 1, "workflow_runs": [ { "id": 7 } ] })),
            )
            .mount(&server)
            .await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(clock);

        let _ = cache
            .send(&client, &listing())
            .await
            .expect("the first answer");
        let changed = cache
            .send(&client, &listing())
            .await
            .expect("the changed answer");
        assert!(!changed.not_modified);
        assert_eq!(
            changed.response.json::<serde_json::Value>().expect("JSON")["total_count"],
            0
        );
        let unchanged = cache
            .send(&client, &listing())
            .await
            .expect("the third answer");
        assert!(unchanged.not_modified, "the new tag was the one sent back");
        assert_eq!(
            unchanged
                .response
                .json::<serde_json::Value>()
                .expect("JSON")["total_count"],
            0,
            "the cached body is the newest one, not the first"
        );
    }

    #[tokio::test]
    async fn last_modified_is_sent_back_as_if_modified_since() {
        let server = MockServer::start().await;
        let stamp = "Wed, 07 Oct 2026 15:06:57 GMT";
        // A closure rather than `header(..)`: wiremock splits a header value on
        // commas, and every HTTP-date has one.
        Mock::given(method("GET"))
            .and(move |request: &wiremock::Request| {
                request
                    .headers
                    .get("if-modified-since")
                    .and_then(|v| v.to_str().ok())
                    == Some(stamp)
            })
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("last-modified", stamp)
                    .set_body_json(json!({ "total_count": 0, "workflow_runs": [] })),
            )
            .mount(&server)
            .await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(clock);

        let _ = cache
            .send(&client, &listing())
            .await
            .expect("the first answer");
        let second = cache
            .send(&client, &listing())
            .await
            .expect("the second answer");
        assert!(second.not_modified);
    }

    #[tokio::test]
    async fn a_response_without_validators_is_never_asked_conditionally() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "total_count": 0, "workflow_runs": [] })),
            )
            .mount(&server)
            .await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(clock);

        for _ in 0..3 {
            let fetched = cache.send(&client, &listing()).await.expect("an answer");
            assert!(!fetched.not_modified);
        }
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn a_304_nobody_asked_for_is_still_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        let client = client(&server, Arc::new(TestClock::default()));

        let error = client
            .send(&listing())
            .await
            .expect_err("an unconditional request has no cached body for a 304 to mean");
        assert!(
            matches!(error, GithubError::Status { status: 304, .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_304_vouches_only_for_the_body_its_validators_describe() {
        let server = MockServer::start().await;
        mount_unchanged_listing(&server, json!({ "total_count": 0, "workflow_runs": [] })).await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let _ = cache.send(&client, &listing()).await.expect("an answer");
        let key = listing().cache_key();
        let ours = Validators {
            etag: Some(ETAG.to_string()),
            last_modified: None,
        };
        let theirs = Validators {
            etag: Some(r#"W/"stored-by-a-request-that-finished-later""#.to_string()),
            last_modified: None,
        };

        assert!(cache.cached_for(&key, Some(&ours), clock.now()).is_some());
        assert!(
            cache.cached_for(&key, Some(&theirs), clock.now()).is_none(),
            "a 304 to other validators must not hand out the body cached now"
        );
        assert!(cache.cached_for(&key, None, clock.now()).is_none());
    }

    #[tokio::test]
    async fn idle_entries_are_evicted() {
        let server = MockServer::start().await;
        mount_unchanged_listing(&server, json!({ "total_count": 0, "workflow_runs": [] })).await;
        let clock = Arc::new(TestClock::default());
        let client = client(&server, Arc::clone(&clock));
        let cache = ConditionalCache::new(Arc::clone(&clock) as Arc<dyn Clock>);

        let _ = cache.send(&client, &listing()).await.expect("an answer");
        assert_eq!(cache.len(), 1);
        clock.advance_secs(i64::try_from(IDLE_ENTRY_TTL.as_secs()).expect("fits") - 1);
        cache.evict_idle();
        assert_eq!(cache.len(), 1, "not yet idle long enough");
        clock.advance_secs(1);
        cache.evict_idle();
        assert!(cache.is_empty());
    }
}
