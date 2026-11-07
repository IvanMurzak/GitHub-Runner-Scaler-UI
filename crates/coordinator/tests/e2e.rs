//! The coordinator in-process, driven by a fake host over a real socket:
//! invite → enroll → connect → challenge → hello → signed webhook → wake.
//!
//! The fake host speaks either version: version 1 is a stage-1 host, which
//! must keep working against this coordinator unchanged.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::{SinkExt as _, StreamExt as _};
use hmac::{Hmac, KeyInit as _, Mac as _};
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::store::Store;
use runner_manager_coordinator_protocol::{
    CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_VERSION, EnrollRequest, EnrollResponse, Hello, HelloAck,
    HostMessage, HostSigningKey, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, Profile, ServerMessage,
    SessionPurpose, Target, TargetScope, Wake, WakeReason, decode_nonce, encode_public_key,
    sign_challenge, signing_key_from_seed,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message;

const SECRET: &str = "a-webhook-secret-for-tests";

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Coordinator {
    base: String,
    state: Arc<AppState>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> Coordinator {
    start_with(Store::open_in_memory().expect("store")).await
}

async fn start_with(store: Store) -> Coordinator {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mut config = Config::new(base.clone(), SecretString::from(SECRET));
    config.revocation_check = Duration::from_millis(100);
    let state = AppState::new(config, store);
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(listener, Arc::clone(&state), async {
        let _ = stopped.await;
    }));
    Coordinator {
        base,
        state,
        _shutdown: shutdown,
    }
}

impl Coordinator {
    fn invite(&self, name: &str) -> String {
        self.state
            .store
            .lock()
            .expect("store")
            .create_invite(name, Duration::from_secs(900), Utc::now())
            .expect("invite")
            .code
            .expose_secret()
            .to_string()
    }

    async fn enroll(&self, code: &str, key: &HostSigningKey) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/enroll", self.base))
            .json(&EnrollRequest {
                // Enrollment is unchanged since version 1, and sent as 1.
                protocol_version: MIN_PROTOCOL_VERSION,
                code: code.to_string(),
                hostname: "test-box".into(),
                public_key: encode_public_key(&key.verifying_key()),
            })
            .send()
            .await
            .expect("sent")
    }

    async fn webhook(&self, event: &str, delivery: &str, body: &str, sign: bool) -> u16 {
        let mut request = reqwest::Client::new()
            .post(format!("{}/webhook", self.base))
            .header("x-github-event", event)
            .header("x-github-delivery", delivery)
            .body(body.to_string());
        if sign {
            let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
            mac.update(body.as_bytes());
            request = request.header(
                "x-hub-signature-256",
                format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
            );
        }
        request.send().await.expect("sent").status().as_u16()
    }

    async fn connect(&self, host_id: &str, key: &HostSigningKey) -> Socket {
        self.connect_at(PROTOCOL_VERSION, host_id, key).await
    }

    /// Connects as a host speaking `version`; a version-1 host checks the
    /// challenge the way stage 1 did.
    async fn connect_at(&self, version: u32, host_id: &str, key: &HostSigningKey) -> Socket {
        self.connect_for(version, host_id, key, None).await
    }

    /// Connects for `purpose` (a version-4 query session, or the link).
    async fn connect_for(
        &self,
        version: u32,
        host_id: &str,
        key: &HostSigningKey,
        purpose: Option<SessionPurpose>,
    ) -> Socket {
        let url = self.base.replacen("http://", "ws://", 1) + "/connect";
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connected");
        let ServerMessage::Challenge {
            protocol_version,
            nonce,
            max_protocol_version,
        } = next(&mut socket).await
        else {
            panic!("the first message is a challenge");
        };
        assert_eq!(protocol_version, 1, "what a stage-1 host requires");
        assert_eq!(max_protocol_version, Some(PROTOCOL_VERSION));
        let nonce = decode_nonce(&nonce).expect("nonce");
        let auth = HostMessage::Auth {
            protocol_version: version,
            host_id: host_id.to_string(),
            signature: sign_challenge(key, &nonce, &self.base),
            purpose,
        };
        socket
            .send(Message::Text(auth.encode().into()))
            .await
            .expect("sent");
        socket
    }
}

async fn next(socket: &mut Socket) -> ServerMessage {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a message in time")
            .expect("open")
            .expect("readable");
        if let Message::Text(text) = frame {
            return ServerMessage::decode(&text).expect("decodes");
        }
    }
}

/// The close code the server ended the connection with.
async fn closed_with(socket: &mut Socket) -> Option<u16> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("closed in time")
        {
            Some(Ok(Message::Close(frame))) => return frame.map(|f| u16::from(f.code)),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return None,
        }
    }
}

fn hello(version: u32, host_id: &str) -> HostMessage {
    HostMessage::Hello(Hello {
        protocol_version: version,
        host_id: host_id.to_string(),
        os: "linux".into(),
        arch: "x64".into(),
        cores: 8,
        ram_bytes: Some(1 << 34),
        disk_free_bytes: None,
        targets: vec![Target {
            scope: TargetScope::Org,
            name: "octo".into(),
            profiles: vec![Profile {
                name: "default".into(),
                labels: vec!["self-hosted".into(), "linux".into()],
                enabled: true,
                warm: false,
            }],
        }],
    })
}

fn queued(repository: &str, labels: &[&str]) -> String {
    serde_json::json!({
        "action": "queued",
        "workflow_job": {"id": 1, "run_id": 2, "labels": labels},
        "repository": {"full_name": repository},
    })
    .to_string()
}

async fn enrolled(coordinator: &Coordinator, name: &str, seed: u8) -> (String, HostSigningKey) {
    let key = signing_key_from_seed(&[seed; 32]);
    let response = coordinator.enroll(&coordinator.invite(name), &key).await;
    assert_eq!(response.status(), 200);
    let enrolled: EnrollResponse = response.json().await.expect("json");
    assert_eq!(enrolled.name, name);
    (enrolled.host_id, key)
}

async fn wait_for_hello(coordinator: &Coordinator) {
    for _ in 0..100 {
        if coordinator
            .state
            .registry
            .connected()
            .iter()
            .any(|host| host.hello.is_some())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the hello never arrived");
}

#[tokio::test]
async fn a_version_two_host_is_told_its_coverage_and_woken() {
    let coordinator = start().await;
    let (host_id, key) = enrolled(&coordinator, "linux-new", 7).await;
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome {
            protocol_version: PROTOCOL_VERSION,
            ..
        }
    ));
    socket
        .send(Message::Text(
            hello(PROTOCOL_VERSION, &host_id).encode().into(),
        ))
        .await
        .expect("hello");
    // No GitHub App here: no sweep, so nothing is covered.
    assert_eq!(
        next(&mut socket).await,
        ServerMessage::HelloAck(HelloAck::default())
    );
    let body = queued("octo/app", &["self-hosted", "linux"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "n-1", &body, true)
            .await,
        200
    );
    assert!(matches!(next(&mut socket).await, ServerMessage::Wake(_)));

    // A hello at a version other than the negotiated one is refused.
    socket
        .send(Message::Text(hello(1, &host_id).encode().into()))
        .await
        .expect("hello");
    assert_eq!(
        closed_with(&mut socket).await,
        Some(CLOSE_UNSUPPORTED_VERSION)
    );
    let mut socket = coordinator
        .connect_at(PROTOCOL_VERSION + 1, &host_id, &key)
        .await;
    assert_eq!(
        closed_with(&mut socket).await,
        Some(CLOSE_UNSUPPORTED_VERSION)
    );
}

/// A stage-1 host against this coordinator: version 1 throughout, no
/// `hello_ack`, and wakes exactly as before.
#[tokio::test]
async fn a_queued_job_wakes_the_enrolled_host_that_serves_it() {
    let coordinator = start().await;
    assert_eq!(
        reqwest::get(format!("{}/healthz", coordinator.base))
            .await
            .expect("health")
            .status(),
        200
    );
    let (host_id, key) = enrolled(&coordinator, "linux-big", 1).await;
    let mut socket = coordinator.connect_at(1, &host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome {
            protocol_version: 1,
            ..
        }
    ));
    socket
        .send(Message::Text(hello(1, &host_id).encode().into()))
        .await
        .expect("hello");
    wait_for_hello(&coordinator).await;

    // Unsigned: a bare 401, and nothing is woken.
    let body = queued("octo/app", &["self-hosted", "Linux"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-0", &body, false)
            .await,
        401
    );
    assert_eq!(coordinator.webhook("ping", "d-ping", "{}", true).await, 200);
    // A job no profile here can take wakes nobody.
    let windows = queued("octo/app", &["windows"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-win", &windows, true)
            .await,
        200
    );
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-1", &body, true)
            .await,
        200
    );
    let ServerMessage::Wake(wake) = next(&mut socket).await else {
        panic!("a wake");
    };
    assert_eq!(
        wake,
        Wake {
            target: runner_manager_coordinator_protocol::TargetRef {
                scope: TargetScope::Org,
                name: "octo".into()
            },
            repository: "octo/app".into(),
            reason: WakeReason::JobQueued,
            delivery_id: "d-1".into(),
        }
    );
    // The same delivery again is acknowledged and not acted on.
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-1", &body, true)
            .await,
        200
    );
    assert_eq!(
        coordinator
            .webhook("workflow_job", "d-2", &body, true)
            .await,
        200
    );
    let ServerMessage::Wake(second) = next(&mut socket).await else {
        panic!("a wake");
    };
    assert_eq!(second.delivery_id, "d-2", "d-1's repeat produced no wake");
}

#[tokio::test]
async fn an_enrollment_code_works_once() {
    let coordinator = start().await;
    let code = coordinator.invite("mac");
    let key = signing_key_from_seed(&[2; 32]);
    assert_eq!(coordinator.enroll(&code, &key).await.status(), 200);
    assert_eq!(coordinator.enroll(&code, &key).await.status(), 401);
    assert_eq!(coordinator.enroll("rmc_nope", &key).await.status(), 401);
}

#[tokio::test]
async fn a_wrong_key_an_unknown_host_and_a_revoked_host_are_refused() {
    let coordinator = start().await;
    let (host_id, key) = enrolled(&coordinator, "win", 3).await;

    let impostor = signing_key_from_seed(&[4; 32]);
    let mut socket = coordinator.connect(&host_id, &impostor).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));

    let mut socket = coordinator.connect("no-such-host", &key).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));

    // Connected, then revoked in-process: the link is cut at once.
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome { .. }
    ));
    coordinator.state.revoke("win").expect("revoked");
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
}

/// `hosts revoke` is another process writing the same database: the server
/// notices the commit and closes the host's live connection within a second.
#[tokio::test]
async fn a_revocation_by_the_admin_cli_closes_the_connection_within_a_second() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("coordinator.db");
    let coordinator = start_with(Store::open(&path).expect("store")).await;
    let (host_id, key) = enrolled(&coordinator, "mac", 9).await;
    let mut socket = coordinator.connect(&host_id, &key).await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome { .. }
    ));
    socket
        .send(Message::Text(
            hello(PROTOCOL_VERSION, &host_id).encode().into(),
        ))
        .await
        .expect("hello");
    wait_for_hello(&coordinator).await;

    // What `runner-manager-coordinator hosts revoke mac` does: its own
    // connection to the file.
    let admin = Store::open(&path).expect("admin store");
    let revoked_at = std::time::Instant::now();
    admin.revoke("mac", Utc::now()).expect("revoked");
    let code = loop {
        match tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("closed in time")
        {
            Some(Ok(Message::Close(frame))) => break frame.map(|f| u16::from(f.code)),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => break None,
        }
    };
    assert_eq!(code, Some(CLOSE_UNAUTHORIZED));
    assert!(
        revoked_at.elapsed() < Duration::from_secs(1),
        "closed {:?} after the revocation",
        revoked_at.elapsed()
    );
}

/// A queued pool job over real sockets: the version-3 host in launch mode is
/// sent one `launch` and no wake; the version-2 host serving the same label
/// is woken as before.
#[tokio::test]
async fn a_pool_job_launches_on_one_version_three_host_and_wakes_a_version_two_one() {
    use runner_manager_coordinator::registry::Coverage;
    use runner_manager_coordinator_protocol::{Heartbeat, LaunchAck};

    let coordinator = start().await;
    coordinator.state.registry.set_coverage(Coverage {
        interval: Some(Duration::from_secs(120)),
        repositories: std::collections::BTreeSet::new(),
        accounts: std::collections::BTreeSet::from(["octo".to_string()]),
    });
    let pool_hello = |version: u32, host_id: &str| {
        let HostMessage::Hello(mut hello) = hello(version, host_id) else {
            unreachable!()
        };
        hello.targets[0].profiles[0]
            .labels
            .push("rm-pool-linux".into());
        HostMessage::Hello(hello)
    };
    let mut hosts = Vec::new();
    for (name, seed, version) in [("new", 11, PROTOCOL_VERSION), ("old", 12, 2)] {
        let (host_id, key) = enrolled(&coordinator, name, seed).await;
        let mut socket = coordinator.connect_at(version, &host_id, &key).await;
        assert!(matches!(
            next(&mut socket).await,
            ServerMessage::Welcome { .. }
        ));
        for message in [
            pool_hello(version, &host_id),
            HostMessage::Heartbeat(Heartbeat {
                free_slots: 2,
                ..Heartbeat::default()
            }),
        ] {
            socket
                .send(Message::Text(message.encode().into()))
                .await
                .expect("sent");
        }
        assert!(matches!(
            next(&mut socket).await,
            ServerMessage::HelloAck(_)
        ));
        hosts.push(socket);
    }
    // Both heartbeats are in before the job is queued.
    for _ in 0..100 {
        if coordinator
            .state
            .registry
            .connected()
            .iter()
            .all(|host| host.heartbeat.is_some())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let body = queued("octo/app", &["rm-pool-linux"]);
    assert_eq!(
        coordinator
            .webhook("workflow_job", "pool-1", &body, true)
            .await,
        200
    );
    let ServerMessage::Launch(launch) = next(&mut hosts[0]).await else {
        panic!("the version-3 host is sent a launch, not a wake");
    };
    assert_eq!(launch.profile, "default");
    assert_eq!(launch.job_key, "octo/app#1");
    hosts[0]
        .send(Message::Text(
            HostMessage::LaunchAck(LaunchAck::accepted(&launch.lease_id))
                .encode()
                .into(),
        ))
        .await
        .expect("ack");
    assert!(matches!(next(&mut hosts[1]).await, ServerMessage::Wake(_)));
    let key = runner_manager_coordinator::placement::JobKey::new(
        "octo/app",
        &[runner_manager_domain::model::Label::new("rm-pool-linux").expect("label")],
    );
    for _ in 0..100 {
        if coordinator.state.placement.counts(&key) == (1, 1) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the accepted launch was not recorded as a lease");
}

fn job_event(action: &str, job_id: u64, runner: Option<&str>) -> String {
    serde_json::json!({
        "action": action,
        "workflow_job": {
            "id": job_id, "run_id": 2, "labels": ["self-hosted", "linux"],
            "name": "build (linux, 3.12)", "workflow_name": "CI",
            "runner_name": runner,
        },
        "repository": {"full_name": "Octo/App"},
    })
    .to_string()
}

async fn send(socket: &mut Socket, message: &HostMessage) {
    socket
        .send(Message::Text(message.encode().into()))
        .await
        .expect("sent");
}

/// A query session: authenticated, answered once, and the host's link
/// stays up beside it.
async fn query_stats(
    coordinator: &Coordinator,
    host_id: &str,
    key: &HostSigningKey,
) -> runner_manager_coordinator_protocol::StatsReport {
    let mut query = coordinator
        .connect_for(PROTOCOL_VERSION, host_id, key, Some(SessionPurpose::Query))
        .await;
    assert!(matches!(
        next(&mut query).await,
        ServerMessage::Welcome { .. }
    ));
    send(&mut query, &HostMessage::StatsRequest).await;
    let ServerMessage::Stats(report) = next(&mut query).await else {
        panic!("the statistics");
    };
    assert_eq!(closed_with(&mut query).await, Some(1000));
    report
}

/// Stage 4 end to end: the webhook names the job a runner took, the host
/// reports what the attempt used, and a query session reads the result
/// while the host's link stays connected. A version-3 host's report (no
/// usage) still counts its duration.
#[tokio::test]
async fn a_measured_attempt_becomes_a_job_sample_read_over_an_authenticated_query() {
    use runner_manager_coordinator_protocol::{
        AttemptFinished, AttemptOutcomeKind, AttemptUsage, STATS_VERSION,
    };

    let coordinator = start().await;
    let (new_id, new_key) = enrolled(&coordinator, "linux", 21).await;
    let (old_id, old_key) = enrolled(&coordinator, "older", 22).await;
    let mut link = coordinator.connect(&new_id, &new_key).await;
    assert!(matches!(
        next(&mut link).await,
        ServerMessage::Welcome {
            protocol_version: STATS_VERSION,
            ..
        }
    ));
    send(&mut link, &hello(PROTOCOL_VERSION, &new_id)).await;
    let mut old = coordinator.connect_at(3, &old_id, &old_key).await;
    assert!(matches!(
        next(&mut old).await,
        ServerMessage::Welcome {
            protocol_version: 3,
            ..
        }
    ));
    send(&mut old, &hello(3, &old_id)).await;

    // Queued, then taken by each host's runner (the webhook names it).
    assert_eq!(
        coordinator
            .webhook("workflow_job", "s-1", &job_event("queued", 5, None), true)
            .await,
        200
    );
    for (delivery, job, runner) in [
        ("s-2", 5, "runner-manager-new"),
        ("s-3", 6, "runner-manager-old"),
    ] {
        assert_eq!(
            coordinator
                .webhook(
                    "workflow_job",
                    delivery,
                    &job_event("in_progress", job, Some(runner)),
                    true
                )
                .await,
            200
        );
    }
    let finished = |runner: &str, usage| {
        HostMessage::AttemptFinished(AttemptFinished {
            lease_id: None,
            runner_name: runner.into(),
            outcome: AttemptOutcomeKind::CompletedJob,
            duration_secs: Some(300),
            usage,
        })
    };
    send(
        &mut link,
        &finished(
            "runner-manager-new",
            Some(AttemptUsage {
                peak_rss_bytes: 3 << 30,
                cpu_avg_millicores: 2500,
                cpu_peak_millicores: 7000,
                samples: 150,
            }),
        ),
    )
    .await;
    send(&mut old, &finished("runner-manager-old", None)).await;

    let mut report = None;
    for _ in 0..100 {
        let read = query_stats(&coordinator, &new_id, &new_key).await;
        if read.jobs.first().is_some_and(|job| job.samples == 2) {
            report = Some(read);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let report = report.expect("both samples recorded");
    let job = &report.jobs[0];
    assert_eq!(job.job_key, "octo/app/CI/build (linux, 3.12)");
    assert_eq!(job.p90_peak_rss_bytes, Some(3 << 30));
    assert_eq!(job.p50_duration_secs, Some(300));
    assert_eq!(report.wakes, 2, "the queued job woke both hosts");
    let names: Vec<Option<&str>> = report
        .hosts
        .iter()
        .map(|h| h.host_name.as_deref())
        .collect();
    assert!(
        names.contains(&Some("linux")) && names.contains(&Some("older")),
        "{names:?}"
    );

    // The query did not take the host's link over.
    assert!(
        coordinator.state.registry.host_ids().contains(&new_id),
        "the link is still registered"
    );
    send(
        &mut link,
        &HostMessage::Heartbeat(runner_manager_coordinator_protocol::Heartbeat::default()),
    )
    .await;
    assert_eq!(
        coordinator
            .webhook("workflow_job", "s-4", &job_event("queued", 7, None), true)
            .await,
        200
    );
    loop {
        if let ServerMessage::Wake(wake) = next(&mut link).await
            && wake.delivery_id == "s-4"
        {
            break;
        }
    }
}

/// The statistics are behind the same signed challenge as the link: a wrong
/// key, an unknown or revoked host, and a version-3 query get nothing.
#[tokio::test]
async fn statistics_over_the_link_require_an_authenticated_version_four_host() {
    let coordinator = start().await;
    let (host_id, key) = enrolled(&coordinator, "mac", 23).await;
    let impostor = signing_key_from_seed(&[24; 32]);
    for (id, signer) in [(host_id.as_str(), &impostor), ("no-such-host", &key)] {
        let mut socket = coordinator
            .connect_for(PROTOCOL_VERSION, id, signer, Some(SessionPurpose::Query))
            .await;
        // Nothing but the close: no welcome, no statistics.
        assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
    }
    let mut socket = coordinator
        .connect_for(3, &host_id, &key, Some(SessionPurpose::Query))
        .await;
    assert_eq!(
        closed_with(&mut socket).await,
        Some(CLOSE_UNSUPPORTED_VERSION)
    );
    // Anything but a stats request on a query session closes it.
    let mut socket = coordinator
        .connect_for(
            PROTOCOL_VERSION,
            &host_id,
            &key,
            Some(SessionPurpose::Query),
        )
        .await;
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Welcome { .. }
    ));
    send(&mut socket, &hello(PROTOCOL_VERSION, &host_id)).await;
    assert_eq!(closed_with(&mut socket).await, Some(1008));
    assert!(
        coordinator.state.registry.host_ids().is_empty(),
        "never registered"
    );

    let report = query_stats(&coordinator, &host_id, &key).await;
    assert!(report.jobs.is_empty());
    coordinator.state.revoke("mac").expect("revoked");
    let mut socket = coordinator
        .connect_for(
            PROTOCOL_VERSION,
            &host_id,
            &key,
            Some(SessionPurpose::Query),
        )
        .await;
    assert_eq!(closed_with(&mut socket).await, Some(CLOSE_UNAUTHORIZED));
}
