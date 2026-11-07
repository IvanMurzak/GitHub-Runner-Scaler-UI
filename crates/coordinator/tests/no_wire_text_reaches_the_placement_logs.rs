//! Placement logs identifiers and counts only: drive a whole placement
//! (a refusal, a silent host, an acceptance, a claim, a surplus cancel, an
//! expiry), weighed by job statistics (stage 4: a job identified by its
//! webhook, a measured attempt, a scored decision), through a capturing
//! subscriber at TRACE, and scan it for the repository, the labels, the
//! workflow and job names and the runner name, which came off the wire.
//!
//! Its own binary for the reason `no_secret_reaches_the_logs.rs` gives.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runner_manager_coordinator::placement::Placement;
use runner_manager_coordinator::registry::{Coverage, Outbound, Registry};
use runner_manager_coordinator::stats::{JobIdentity, Statistics, StatsConfig};
use runner_manager_coordinator::store::Store;
use runner_manager_coordinator_protocol::{
    AttemptFinished, AttemptOutcomeKind, AttemptStarted, AttemptUsage, Heartbeat, Hello,
    LAUNCH_VERSION, LaunchAck, Profile, RefusalReason, ServerMessage, Target, TargetRef,
    TargetScope,
};
use runner_manager_domain::model::Label;

const REPOSITORY: &str = "secretive-owner/hush-hush-repo";
const POOL: &str = "rm-pool-linux";
const EXTRA: &str = "very-private-label";
const RUNNER: &str = "runner-manager-wire-runner-name";
const WORKFLOW: &str = "Confidential Release Pipeline";
const JOB: &str = "sign-with-hsm (prod, eu)";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn connect(registry: &Registry, id: &str, ram: u64) -> tokio::sync::mpsc::Receiver<Outbound> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let connection = registry.register(id, LAUNCH_VERSION, tx);
    registry.set_hello(
        id,
        connection,
        Hello {
            protocol_version: LAUNCH_VERSION,
            host_id: id.into(),
            os: "linux".into(),
            arch: "x64".into(),
            cores: 4,
            ram_bytes: None,
            disk_free_bytes: None,
            targets: vec![Target {
                scope: TargetScope::Repo,
                name: REPOSITORY.into(),
                profiles: vec![Profile {
                    name: "pool".into(),
                    labels: vec![POOL.into(), EXTRA.into()],
                    enabled: true,
                    warm: false,
                }],
            }],
        },
    );
    registry.set_heartbeat(
        id,
        connection,
        Heartbeat {
            free_slots: 2,
            free_ram_bytes: Some(ram),
            ..Heartbeat::default()
        },
    );
    rx
}

#[test]
fn no_wire_text_reaches_the_placement_logs() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let registry = Arc::new(Registry::default());
            registry.set_coverage(Coverage {
                interval: Some(Duration::from_secs(120)),
                repositories: BTreeSet::from([REPOSITORY.to_string()]),
                accounts: BTreeSet::new(),
            });
            let stats = Arc::new(Statistics::load(
                Arc::new(Mutex::new(Store::open_in_memory().expect("store"))),
                StatsConfig::default(),
            ));
            let identity = JobIdentity::new(REPOSITORY, Some(WORKFLOW), Some(JOB)).expect("named");
            stats.job_identified(RUNNER, identity.clone());
            stats.attempt_finished(
                "accepts",
                &AttemptFinished {
                    lease_id: None,
                    runner_name: RUNNER.into(),
                    outcome: AttemptOutcomeKind::CompletedJob,
                    duration_secs: Some(60),
                    usage: Some(AttemptUsage {
                        peak_rss_bytes: 1 << 30,
                        samples: 5,
                        ..AttemptUsage::default()
                    }),
                }, None);
            let placement = Arc::new(
                Placement::with_timings(
                    Arc::clone(&registry),
                    Duration::from_millis(100),
                    Duration::from_secs(60),
                )
                .with_statistics(Arc::clone(&stats)),
            );
            let mut refuses = connect(&registry, "refuses", 64 << 30);
            let _silent = connect(&registry, "silent", 32 << 30);
            let mut accepts = connect(&registry, "accepts", 8 << 30);
            let answering = {
                let placement = Arc::clone(&placement);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            message = refuses.recv() => match message {
                                Some(Outbound::Send(ServerMessage::Launch(launch))) => {
                                    placement.acknowledged(
                                        "refuses",
                                        LaunchAck::refused(&launch.lease_id, RefusalReason::MaxCapacity),
                                    );
                                }
                                Some(_) => {}
                                None => break,
                            },
                            message = accepts.recv() => match message {
                                Some(Outbound::Send(ServerMessage::Launch(launch))) => {
                                    placement.acknowledged("accepts", LaunchAck::accepted(&launch.lease_id));
                                }
                                Some(_) => {}
                                None => break,
                            },
                        }
                    }
                })
            };
            let required = vec![
                Label::new(POOL).expect("label"),
                Label::new(EXTRA).expect("label"),
            ];
            let key = placement
                .queued_job(REPOSITORY, &required, 1, Some(identity.key()))
                .expect("pool job");
            placement.queued_job(REPOSITORY, &required, 2, Some(identity.key()));
            let report = placement.rebalance(&key).await;
            assert_eq!(report.accepted, 2, "{report:?}");
            placement.attempt_started(
                "accepts",
                &AttemptStarted {
                    lease_id: Some("not-a-lease".into()),
                    runner_name: RUNNER.into(),
                    target: TargetRef {
                        scope: TargetScope::Repo,
                        name: REPOSITORY.into(),
                    },
                    profile: "pool".into(),
                },
            );
            placement.dequeued(REPOSITORY, &required, 1);
            assert_eq!(placement.rebalance(&key).await.cancelled, 1);
            placement.expire(Instant::now() + Duration::from_secs(120));
            answering.abort();
        });
    });

    let logs = String::from_utf8(capture.0.lock().expect("capture").clone()).expect("utf-8");
    for expected in [
        "a host refused a launch",
        "did not answer a launch in time",
        "a host accepted a launch",
        "a launch was cancelled",
        "placement leases expired",
        "a job sample was recorded",
        "a pool queue was weighed",
        "placement score",
    ] {
        assert!(logs.contains(expected), "missing `{expected}`:\n{logs}");
    }
    for wire in [
        REPOSITORY,
        "hush-hush",
        EXTRA,
        RUNNER,
        WORKFLOW,
        "Confidential",
        JOB,
        "sign-with-hsm",
    ] {
        assert!(!logs.contains(wire), "`{wire}` reached the logs:\n{logs}");
    }
}
