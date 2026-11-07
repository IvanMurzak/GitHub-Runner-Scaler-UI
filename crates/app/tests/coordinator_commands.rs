// owner: coordinator-stage1
//
// `coordinator join | status | leave | stats` through the real binary, against
// a real coordinator started in this process on loopback.
//
// The secret scan mirrors `no_secret_reaches_command_output.rs`: the host's
// private key and the one-time invite code must appear in no command's stdout
// or stderr and in no log file, and the scan is shown to find them when they
// are planted, so "nothing found" cannot mean "nothing looked at".

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::store::Store;
use runner_manager_platform::secrets::{
    PlatformSecretStore, SecretItem, SecretScope, SecretStore as _,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;
use support::{Outcome, run, runner_manager};

/// A coordinator on loopback, served from its own thread.
struct Coordinator {
    base: String,
    state: Arc<AppState>,
}

fn coordinator() -> Coordinator {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let state = AppState::new(
        Config::new(
            base.clone(),
            SecretString::from("a-webhook-secret-for-tests"),
        ),
        Store::open_in_memory().expect("store"),
    );
    let served = Arc::clone(&state);
    std::thread::spawn(move || runtime.block_on(serve(listener, served, std::future::pending())));
    Coordinator { base, state }
}

impl Coordinator {
    fn invite(&self) -> String {
        self.state
            .store
            .lock()
            .expect("store")
            .create_invite("box", Duration::from_secs(900), Utc::now())
            .expect("invite")
            .code
            .expose_secret()
            .to_string()
    }
}

fn command(data: &Path, arguments: &[&str]) -> Outcome {
    let mut command = runner_manager(data);
    command.args(arguments);
    run(command)
}

/// The key the binary stored, read back the way the daemon reads it. A fresh
/// data root has no recorded start mode, and the default (`boot`) is the
/// machine-scoped store.
fn stored_key(data: &Path) -> Option<String> {
    PlatformSecretStore::rooted_at(SecretScope::Machine, data)
        .expect("store")
        .for_item(SecretItem::CoordinatorKey)
        .load()
        .expect("readable")
        .map(|key| key.expose_secret().to_string())
}

fn logs(data: &Path) -> String {
    let mut text = String::new();
    for entry in walk(data) {
        if entry.extension().is_some_and(|ext| ext == "log") {
            text.push_str(&std::fs::read_to_string(&entry).unwrap_or_default());
        }
    }
    text
}

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// Every needle found in `corpus`, by name.
fn leaks(corpus: &str, needles: &[(&str, &str)]) -> Vec<String> {
    needles
        .iter()
        .filter(|(_, needle)| !needle.is_empty() && corpus.contains(needle))
        .map(|(name, _)| (*name).to_string())
        .collect()
}

#[test]
fn join_status_and_leave_round_trip_and_no_secret_reaches_their_output() {
    let coordinator = coordinator();
    let data = tempfile::tempdir().expect("data root");
    let data = data.path();
    let mut corpus = String::new();
    let mut record = |outcome: &Outcome| {
        corpus.push_str(&outcome.stdout);
        corpus.push_str(&outcome.stderr);
    };

    let before = command(data, &["coordinator", "status", "--json"]);
    record(&before);
    assert_eq!(before.code, 0, "{}", before.stderr);
    let document: Value = serde_json::from_str(&before.stdout).expect("json");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["configured"], false);
    assert_eq!(document["link"], "not_configured");

    let code = coordinator.invite();
    let joined = command(
        data,
        &["coordinator", "join", &coordinator.base, "--code", &code],
    );
    record(&joined);
    assert_eq!(joined.code, 0, "{}", joined.stderr);
    assert!(
        joined
            .stdout
            .contains(&format!("joined {} as box", coordinator.base)),
        "{}",
        joined.stdout
    );
    let key = stored_key(data).expect("the private key is in the secret store");

    // The coordinator holds the matching public key, and only that.
    let hosts = coordinator
        .state
        .store
        .lock()
        .expect("store")
        .hosts()
        .expect("hosts");
    assert_eq!(hosts.len(), 1);
    let public = runner_manager_coordinator_protocol::encode_public_key(
        &runner_manager_coordinator_protocol::decode_signing_key(&key)
            .expect("a key")
            .verifying_key(),
    );
    assert_eq!(hosts[0].public_key, public);

    let again = command(
        data,
        &["coordinator", "join", &coordinator.base, "--code", &code],
    );
    record(&again);
    assert_eq!(
        again.code, 11,
        "a second join is a conflict: {}",
        again.stderr
    );

    let status = command(data, &["coordinator", "status", "--json"]);
    record(&status);
    let document: Value = serde_json::from_str(&status.stdout).expect("json");
    assert_eq!(document["configured"], true);
    assert_eq!(document["host_id"], Value::from(hosts[0].id.clone()));
    assert_eq!(document["link"], "unknown", "no service is running here");
    let human = command(data, &["coordinator", "status"]);
    record(&human);
    assert!(
        human.stdout.contains("Coordinator: joined"),
        "{}",
        human.stdout
    );
    let whole = command(data, &["status", "--json"]);
    record(&whole);
    let whole: Value = serde_json::from_str(&whole.stdout).expect("json");
    assert_eq!(whole["coordinator"]["configured"], true);

    let left = command(data, &["coordinator", "leave"]);
    record(&left);
    assert_eq!(left.code, 0, "{}", left.stderr);
    assert!(left.stdout.contains("hosts revoke"), "{}", left.stdout);
    assert_eq!(stored_key(data), None, "leave removes the key");
    let after = command(data, &["coordinator", "status"]);
    record(&after);
    assert!(after.stdout.contains("not configured"), "{}", after.stdout);

    corpus.push_str(&logs(data));
    let needles = [
        ("private key", key.as_str()),
        ("invite code", code.as_str()),
    ];
    assert_eq!(
        leaks(&corpus, &needles),
        Vec::<String>::new(),
        "a secret reached command output or a log"
    );
    // The control: the same scan over a corpus that does contain them.
    assert_eq!(
        leaks(&format!("{corpus}{key} {code}"), &needles),
        ["private key", "invite code"]
    );
}

#[test]
fn a_refused_code_and_an_insecure_url_change_nothing() {
    let coordinator = coordinator();
    let data = tempfile::tempdir().expect("data root");
    let data = data.path();

    let refused = command(
        data,
        &[
            "coordinator",
            "join",
            &coordinator.base,
            "--code",
            "rmc_not-a-code",
        ],
    );
    assert_eq!(refused.code, 9, "{}", refused.stderr);
    assert!(
        refused.stderr.contains("unknown, already used, or expired"),
        "{}",
        refused.stderr
    );
    assert_eq!(stored_key(data), None);

    let insecure = command(
        data,
        &[
            "coordinator",
            "join",
            "http://runners.example.com",
            "--code",
            "x",
        ],
    );
    assert_eq!(insecure.code, 9, "{}", insecure.stderr);

    let unreachable = command(
        data,
        &["coordinator", "join", "http://127.0.0.1:1", "--code", "x"],
    );
    assert_eq!(unreachable.code, 26, "{}", unreachable.stderr);

    let status = command(data, &["coordinator", "status", "--json"]);
    let document: Value = serde_json::from_str(&status.stdout).expect("json");
    assert_eq!(document["configured"], false);
    assert!(
        coordinator
            .state
            .store
            .lock()
            .expect("store")
            .hosts()
            .expect("hosts")
            .is_empty()
    );

    let leave = command(data, &["coordinator", "leave"]);
    assert_eq!(leave.code, 0, "leaving when not joined is not an error");
}

#[test]
fn stats_are_read_over_the_hosts_signed_link_and_need_a_join() {
    let coordinator = coordinator();
    let data = tempfile::tempdir().expect("data root");
    let data = data.path();

    let unjoined = command(data, &["coordinator", "stats"]);
    assert_eq!(unjoined.code, 10, "not joined: {}", unjoined.stderr);
    assert!(
        unjoined.stderr.contains("coordinator join"),
        "{}",
        unjoined.stderr
    );

    let code = coordinator.invite();
    let joined = command(
        data,
        &["coordinator", "join", &coordinator.base, "--code", &code],
    );
    assert_eq!(joined.code, 0, "{}", joined.stderr);
    let key = stored_key(data).expect("the private key");

    let text = command(data, &["coordinator", "stats"]);
    assert_eq!(text.code, 0, "{}", text.stderr);
    assert!(text.stdout.contains("Job statistics"), "{}", text.stdout);
    assert!(
        text.stdout.contains("No job has been measured yet."),
        "{}",
        text.stdout
    );
    let json = command(data, &["coordinator", "stats", "--json"]);
    assert_eq!(json.code, 0, "{}", json.stderr);
    let document: Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["samples_per_job"], 30);
    assert_eq!(document["jobs"], Value::Array(Vec::new()));

    // Revoked at the coordinator: the signed query is refused.
    coordinator.state.revoke("box").expect("revoked");
    let refused = command(data, &["coordinator", "stats"]);
    assert_eq!(refused.code, 26, "{}", refused.stderr);
    assert!(
        refused.stderr.contains("refused this host's key"),
        "{}",
        refused.stderr
    );

    let mut corpus = String::new();
    for outcome in [&unjoined, &text, &json, &refused] {
        corpus.push_str(&outcome.stdout);
        corpus.push_str(&outcome.stderr);
    }
    corpus.push_str(&logs(data));
    assert_eq!(
        leaks(
            &corpus,
            &[
                ("private key", key.as_str()),
                ("invite code", code.as_str())
            ]
        ),
        Vec::<String>::new()
    );
}
