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
use runner_manager_coordinator::dashboard::auth::{self, AuthConfig};
use runner_manager_coordinator::registry::Outbound;
use runner_manager_coordinator::server::{AppState, Config, serve};
use runner_manager_coordinator::store::Store;
use runner_manager_coordinator::store::{DashboardSession, SessionKind};
use runner_manager_domain::coordinator_protocol::{
    CommandResult, Hello, RunCommand, ServerMessage, encode_public_key, signing_key_from_seed,
};
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
    coordinator_with(None)
}

/// A coordinator whose dashboard sign-in is configured for `ivanmurzak`.
/// GitHub itself is never asked: sessions are made in its store.
fn coordinator_with_dashboard() -> Coordinator {
    coordinator_with(Some(AuthConfig {
        client_id: "Iv1.client".into(),
        client_secret: SecretString::from("a-client-secret"),
        allowed_logins: vec!["IvanMurzak".into()],
        web_base: "http://127.0.0.1:9".into(),
        api_base: "http://127.0.0.1:9".into(),
    }))
}

fn coordinator_with(dashboard: Option<AuthConfig>) -> Coordinator {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let mut config = Config::new(
        base.clone(),
        SecretString::from("a-webhook-secret-for-tests"),
    );
    config.dashboard = dashboard;
    let state = AppState::new(config, Store::open_in_memory().expect("store"));
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
    let public = runner_manager_domain::coordinator_protocol::encode_public_key(
        &runner_manager_domain::coordinator_protocol::decode_signing_key(&key)
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
    assert_eq!(document["schema_version"], 4);
    assert_eq!(document["samples_per_job"], 30);
    assert_eq!(document["p90_queue_wait_secs"], Value::Null);
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

#[test]
fn remote_changes_are_off_until_the_operator_allows_them_here() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let say = |choice: &str| -> Outcome {
        run({
            let mut command = runner_manager(data_dir.path());
            command.args(["coordinator", "remote-changes", choice]);
            command
        })
    };
    let status = say("status");
    assert_eq!(status.code, 0, "{}", status.both());
    assert!(status.stdout.contains("not allowed"), "{}", status.stdout);
    let allowed = say("allow");
    assert_eq!(allowed.code, 0, "{}", allowed.both());
    assert!(say("status").stdout.contains("allowed"));
    assert!(!say("status").stdout.contains("not allowed"));
    assert_eq!(say("deny").code, 0);
    assert!(say("status").stdout.contains("not allowed"));
    assert_ne!(say("maybe").code, 0, "an unknown choice is refused");
}

// ---------------------------------------------------------------------------
// coordinator login | logout | hosts, and --host remote:NAME
// ---------------------------------------------------------------------------

impl Coordinator {
    /// A session of `kind` for `ivanmurzak`, made in the store; its token.
    fn session(&self, kind: SessionKind) -> String {
        let token = auth::token();
        let now = Utc::now().timestamp();
        self.state
            .store
            .lock()
            .expect("store")
            .create_session(
                &auth::token_hash(&token),
                &DashboardSession {
                    login: "ivanmurzak".into(),
                    avatar_url: None,
                },
                kind,
                now,
                now + 3600,
            )
            .expect("session");
        token
    }

    /// An enrolled host named `name`, connected at `version` when given,
    /// answering each command with `answer`. Its id.
    fn host(
        &self,
        name: &str,
        seed: u8,
        version: Option<u32>,
        answer: impl Fn(&RunCommand) -> CommandResult + Send + 'static,
    ) -> String {
        let id = {
            let mut store = self.state.store.lock().expect("store");
            let code = store
                .create_invite(name, Duration::from_secs(900), Utc::now())
                .expect("invite")
                .code
                .expose_secret()
                .to_string();
            let key = signing_key_from_seed(&[seed; 32]);
            store
                .enroll(
                    &code,
                    name,
                    &encode_public_key(&key.verifying_key()),
                    Utc::now(),
                )
                .expect("enrolled")
                .id
        };
        let Some(version) = version else {
            return id;
        };
        let (sender, mut receiver) = tokio::sync::mpsc::channel(16);
        let registry = &self.state.registry;
        let connection = registry.register(&id, version, sender);
        registry.set_hello(
            &id,
            connection,
            Hello {
                protocol_version: version,
                host_id: id.clone(),
                os: "linux".into(),
                arch: "x64".into(),
                cores: 8,
                ram_bytes: None,
                disk_free_bytes: None,
                targets: Vec::new(),
                remote_changes: false,
            },
        );
        let state = Arc::clone(&self.state);
        std::thread::spawn(move || {
            while let Some(message) = receiver.blocking_recv() {
                if let Outbound::Send(ServerMessage::RunCommand(command)) = message {
                    state.remote.complete(answer(&command));
                }
            }
        });
        id
    }
}

/// Signs `data`'s account in to `coordinator` the way `login` leaves it.
fn signed_in(data: &Path, coordinator: &Coordinator, token: &str) {
    PlatformSecretStore::rooted_at(SecretScope::User, data)
        .expect("store")
        .for_item(SecretItem::CoordinatorCliSession)
        .store(&SecretString::from(
            serde_json::json!({
                "schema_version": 1,
                "url": coordinator.base,
                "login": "ivanmurzak",
                "token": token,
            })
            .to_string(),
        ))
        .expect("stored");
}

fn stored_session(data: &Path) -> Option<String> {
    PlatformSecretStore::rooted_at(SecretScope::User, data)
        .expect("store")
        .for_item(SecretItem::CoordinatorCliSession)
        .load()
        .expect("readable")
        .map(|value| value.expose_secret().to_string())
}

#[test]
fn coordinator_login_signs_this_account_in_through_a_browser_and_logout_forgets_it() {
    use std::io::{BufRead as _, BufReader};
    use std::process::Stdio;

    let coordinator = coordinator_with_dashboard();
    let data = tempfile::tempdir().expect("data root");
    let data = data.path();

    // Not joined and no --url: nothing to sign in to.
    let nowhere = command(data, &["coordinator", "login"]);
    assert_eq!(nowhere.code, 9, "{}", nowhere.both());
    assert!(nowhere.stderr.contains("--url"), "{}", nowhere.stderr);

    // The binary, its stdout read line by line while it waits.
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("runner-manager"))
        .env_remove("RUNNER_MANAGER_DATA_DIR")
        .env("NO_PROXY", "127.0.0.1,localhost,::1")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .arg("--data-dir")
        .arg(data)
        .args(["coordinator", "login", "--url", &coordinator.base])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("started");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut transcript = String::new();
    let code = loop {
        let line = lines.next().expect("a line").expect("readable");
        transcript.push_str(&line);
        transcript.push('\n');
        if let Some(rest) = line.strip_prefix("check that it shows the code ") {
            break rest.split(',').next().expect("code").to_owned();
        }
    };
    assert!(
        transcript.contains(&format!("{}/auth/cli?code={code}", coordinator.base)),
        "{transcript}"
    );

    // A person approves it in a browser signed in to the dashboard.
    let cookie = coordinator.session(SessionKind::Web);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let approved = runtime.block_on(async {
        reqwest::Client::new()
            .post(format!("{}/auth/cli/approve", coordinator.base))
            .header("cookie", format!("rm_session={cookie}"))
            .header("origin", coordinator.base.as_str())
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("code={code}&decision=approve"))
            .send()
            .await
            .expect("sent")
            .status()
    });
    assert_eq!(approved, 200);
    for line in lines {
        transcript.push_str(&line.expect("readable"));
        transcript.push('\n');
    }
    let status = child.wait().expect("finished");
    assert!(status.success(), "{transcript}");
    assert!(
        transcript.contains(&format!("Signed in to {} as ivanmurzak.", coordinator.base)),
        "{transcript}"
    );

    let stored: Value =
        serde_json::from_str(&stored_session(data).expect("a stored session")).expect("json");
    assert_eq!(stored["url"], coordinator.base.as_str());
    assert_eq!(stored["login"], "ivanmurzak");
    let token = stored["token"].as_str().expect("token").to_owned();
    assert_eq!(token.len(), 64);
    assert!(!transcript.contains(&token), "the token is never printed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file = data
            .join("secrets")
            .join("user")
            .join("coordinator-cli-session");
        let mode = std::fs::metadata(&file)
            .expect("the session file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }

    let hosts = command(data, &["coordinator", "hosts"]);
    assert_eq!(hosts.code, 0, "{}", hosts.both());
    assert!(
        hosts.stdout.contains("No hosts have joined it."),
        "{}",
        hosts.stdout
    );

    let out = command(data, &["coordinator", "logout"]);
    assert_eq!(out.code, 0, "{}", out.both());
    assert!(out.stdout.contains("signed out of"), "{}", out.stdout);
    assert!(!out.stdout.contains("could not be told"), "{}", out.stdout);
    assert_eq!(stored_session(data), None);
    // The coordinator ended the token as well.
    signed_in(data, &coordinator, &token);
    let refused = command(data, &["coordinator", "hosts"]);
    assert_eq!(refused.code, 3, "{}", refused.both());
    assert!(
        refused.stderr.contains("coordinator login"),
        "{}",
        refused.stderr
    );
    let again = command(data, &["coordinator", "logout"]);
    assert_eq!(again.code, 0);
    let again = command(data, &["coordinator", "logout"]);
    assert!(again.stdout.contains("not signed in"), "{}", again.stdout);
}

#[test]
fn the_signed_in_account_lists_hosts_and_runs_commands_on_them_remotely() {
    let coordinator = coordinator_with_dashboard();
    let data = tempfile::tempdir().expect("data root");
    let data = data.path();

    // Not signed in.
    let unsigned = command(data, &["--host", "remote:ivan-ms-a2", "repo", "list"]);
    assert_eq!(unsigned.code, 3, "{}", unsigned.both());
    assert!(
        unsigned.stderr.contains("runner-manager coordinator login"),
        "{}",
        unsigned.stderr
    );

    let asked = Arc::new(std::sync::Mutex::new(Vec::<(Vec<String>, String)>::new()));
    let seen = Arc::clone(&asked);
    coordinator.host("ivan-ms-a2", 61, Some(5), move |command| {
        seen.lock()
            .expect("lock")
            .push((command.argv.clone(), command.by.clone()));
        let change = command
            .argv
            .get(1)
            .is_some_and(|verb| verb == "set-capacity");
        CommandResult {
            request_id: command.request_id.clone(),
            exit_code: if change { 11 } else { 0 },
            stdout: if change {
                String::new()
            } else {
                "octo/app  autoscale  max 2\n".into()
            },
            stderr: if change {
                "error: this host does not take changes through the coordinator\n".into()
            } else {
                String::new()
            },
            truncated: false,
            access: Some(if change { "change" } else { "read" }.into()),
        }
    });
    coordinator.host("old-box", 62, Some(4), |_| unreachable!("never asked"));
    coordinator.host("offline-box", 63, None, |_| unreachable!("never asked"));
    let token = coordinator.session(SessionKind::Cli);
    signed_in(data, &coordinator, &token);

    let listed = command(data, &["coordinator", "hosts", "--json"]);
    assert_eq!(listed.code, 0, "{}", listed.both());
    let document: Value = serde_json::from_str(&listed.stdout).expect("json");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["login"], "ivanmurzak");
    let hosts = document["hosts"].as_array().expect("hosts");
    let names: Vec<&str> = hosts
        .iter()
        .filter_map(|host| host["name"].as_str())
        .collect();
    assert_eq!(names, ["ivan-ms-a2", "offline-box", "old-box"]);
    assert_eq!(hosts[0]["online"], true);
    assert_eq!(hosts[0]["manageable"], true);
    assert_eq!(hosts[1]["online"], false);
    assert_eq!(hosts[2]["manageable"], false);
    let text = command(data, &["coordinator", "hosts"]);
    assert_eq!(text.code, 0, "{}", text.both());
    assert!(text.stdout.contains("REMOTE CHANGES"), "{}", text.stdout);

    // A read: the host's output and exit code, as the host gave them.
    let read = command(data, &["--host", "remote:ivan-ms-a2", "repo", "list"]);
    assert_eq!(read.code, 0, "{}", read.both());
    assert_eq!(read.stdout, "octo/app  autoscale  max 2\n");
    // A change the host refused: its refusal and its exit code.
    let change = command(
        data,
        &[
            "repo",
            "set-capacity",
            "octo/app",
            "--max-capacity",
            "4",
            "--host=remote:ivan-ms-a2",
        ],
    );
    assert_eq!(change.code, 11, "{}", change.both());
    assert_eq!(change.stdout, "");
    assert!(
        change.stderr.contains("does not take changes"),
        "{}",
        change.stderr
    );
    assert_eq!(
        asked.lock().expect("lock").clone(),
        vec![
            (
                vec!["repo".to_owned(), "list".to_owned()],
                "ivanmurzak".to_owned()
            ),
            (
                ["repo", "set-capacity", "octo/app", "--max-capacity", "4"]
                    .map(String::from)
                    .to_vec(),
                "ivanmurzak".to_owned()
            ),
        ],
        "sent without --host or --data-dir, as the person who signed in"
    );

    let unknown = command(data, &["--host", "remote:nobody", "repo", "list"]);
    assert_eq!(unknown.code, 10, "{}", unknown.both());
    assert!(
        unknown
            .stderr
            .contains("its hosts are: ivan-ms-a2, offline-box, old-box"),
        "{}",
        unknown.stderr
    );
    let offline = command(data, &["--host", "remote:offline-box", "status"]);
    assert_eq!(offline.code, 26, "{}", offline.both());
    assert!(
        offline.stderr.contains("not connected"),
        "{}",
        offline.stderr
    );
    let old = command(data, &["--host", "remote:old-box", "status"]);
    assert_eq!(old.code, 15, "{}", old.both());
    assert!(old.stderr.contains("too old"), "{}", old.stderr);

    // The token never reaches any output.
    for outcome in [&listed, &text, &read, &change, &unknown, &offline, &old] {
        assert!(!outcome.both().contains(&token));
    }
}
