// owner: b3-acceptance-docs

//! The managed WSL host feature, exercised end to end over fake WSL, process
//! and Task Scheduler controls.
//!
//! # Why this file exists beside `wsl.rs`'s own tests
//!
//! The unit tests inside [`super`] are about *parts*: one stage's ordering, one
//! refusal, one rendered document. This file is about the **journeys**
//! `b3-acceptance-docs` names, each run against one scripted workstation from
//! beginning to end:
//!
//! | Journey | What it proves |
//! |---|---|
//! | Fresh provisioning | An unmanaged distribution becomes a healthy runner host, is listed as managed, and existing commands reach it |
//! | Adoption | A distribution that already runs runner-manager keeps its binary, credential, capacity and unit |
//! | Two distributions | Two hosts on one workstation stay independent in task, record and credential |
//! | Rerun convergence | The *same* workstation, provisioned twice, changes nothing the second time |
//! | Injected failures | Every mutating stage can fail and a later rerun still converges |
//! | Detach | The Windows half is removed and the Linux half is not |
//! | Credential canaries | Nothing that crossed the pipe is in stdout, stderr, logs, records, task XML, argv or the environment |
//!
//! The `chains` module at the end of this file (owned by
//! `c1-wsl-chain-corpus`) chains the same commands into at least 32 named,
//! replayable `wsl-NNNN` transition cases over one stateful fake workstation.
//! Its own documentation says what every case checks.
//!
//! # Unprivileged, and on every platform
//!
//! Nothing here starts `wsl.exe`, writes a scheduled task, or needs Windows:
//! the whole adapter is driven through
//! [`runner_manager_platform::wsl::exec::ScriptedRunner`], so the Linux and
//! macOS CI legs test this feature as thoroughly as the Windows one does. The
//! one thing a fake cannot answer, whether Task Scheduler really accepts the
//! document this renders, is the subject of the `#[ignore]`d Windows smoke test
//! in `crates/platform/tests/privileged_wsl_lifecycle.rs`.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use runner_manager_platform::wsl::exec::{
    CommandOutput, CommandRequest, CommandRunner, RecordedRequest, ScriptedRunner,
};

// ---------------------------------------------------------------------------
// The workstation these journeys run on
// ---------------------------------------------------------------------------

/// The version this build provisions, which is the only one it accepts.
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const UBUNTU: &str = "Ubuntu";
const DEBIAN: &str = "Debian";
const UNIT: &str = "runner-manager.service";
const TRIPLE: &str = "x86_64-unknown-linux-gnu";
const PRINCIPAL: &str = "FIXTURE\\operator";
const LINUX_BINARY: &str = DEFAULT_LINUX_DESTINATION;

/// A stored credential document's three secrets, for one distribution, shaped
/// like the real ones and unmistakably not real.
///
/// Assembled at run time from fragments so that no source file and no compiled
/// artifact carries the literal: the canary scan below looks for these values
/// everywhere, and a copy inside the test binary would make a leak into this
/// process's own output indistinguishable from the fixture itself.
///
/// `tag` is the distribution, which is what makes
/// [`two_distributions_never_share_a_credential_a_task_or_a_record`] an
/// assertion about independence rather than a count.
fn canaries_for(tag: &str) -> [String; 3] {
    [
        format!("{}b3{tag}AccessNotARealToken", "ghu_"),
        format!("{}b3{tag}RefreshNotARealToken", "ghr_"),
        format!("{}b3{tag}JitConfigNotARealOne=", "eyJ"),
    ]
}

/// The document the broker hands to `auth receive`.
fn credential_document(tag: &str) -> String {
    let [access, refresh, jit] = canaries_for(tag);
    format!(
        "{{\"schema\":1,\"access_token\":\"{access}\",\"refresh_token\":\"{refresh}\",\
         \"jit_config\":\"{jit}\"}}"
    )
}

/// An ordered log of everything a journey did, across all three seams.
///
/// The scripted runner records commands and nothing else, so a download and a
/// device flow would be invisible to it. One journal shared by the runner, the
/// release assets and the credential issuer makes a whole journey one readable
/// sequence.
#[derive(Debug, Default, Clone)]
struct Journal(Arc<Mutex<Vec<String>>>);

impl Journal {
    fn note(&self, entry: impl Into<String>) {
        self.0
            .lock()
            .expect("the journal is not shared across a panic")
            .push(entry.into());
    }

    fn entries(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("the journal is not shared across a panic")
            .clone()
    }

    fn count(&self, needle: &str) -> usize {
        self.entries()
            .iter()
            .filter(|entry| entry.contains(needle))
            .count()
    }

    /// Where something happened, or a failure that prints the whole log.
    fn at(&self, needle: &str) -> usize {
        self.entries()
            .iter()
            .position(|entry| entry.contains(needle))
            .unwrap_or_else(|| {
                panic!(
                    "{needle:?} never happened. The journal was:\n{:#?}",
                    self.entries()
                )
            })
    }

    fn never(&self, needle: &str) {
        assert_eq!(
            self.count(needle),
            0,
            "{needle:?} must not have happened. The journal was:\n{:#?}",
            self.entries()
        );
    }

    /// Asserts the log reads in this order, naming the pair that did not.
    fn in_order(&self, steps: &[&str]) {
        for pair in steps.windows(2) {
            assert!(
                self.at(pair[0]) < self.at(pair[1]),
                "{:?} must happen before {:?}. The journal was:\n{:#?}",
                pair[0],
                pair[1],
                self.entries()
            );
        }
    }
}

/// A [`CommandRunner`] that answers from a script and journals on the way
/// through.
#[derive(Debug, Clone)]
struct FakeControls {
    inner: Arc<ScriptedRunner>,
    journal: Journal,
}

impl CommandRunner for FakeControls {
    fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError> {
        let mut line = request
            .program()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for argument in request.argument_strings() {
            line.push(' ');
            line.push_str(&argument);
        }
        self.journal.note(line);
        self.inner.run(request)
    }
}

/// A release whose `SHA256SUMS` really does describe the bytes it serves, and
/// which can be told to refuse a bounded number of times first.
#[derive(Debug)]
struct FakeAssets {
    journal: Journal,
    document: String,
    archive: Vec<u8>,
    refusals_left: AtomicUsize,
}

impl FakeAssets {
    fn publishing(journal: Journal) -> Self {
        let archive = b"a stand-in for a release archive".to_vec();
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&archive));
        Self {
            journal,
            document: format!("{digest}  runner-manager-{}-{TRIPLE}.tar.gz\n", version()),
            archive,
            refusals_left: AtomicUsize::new(0),
        }
    }

    /// Refuses the next `times` requests for the checksum document and serves
    /// it afterwards.
    ///
    /// The failure and its repair are one object on purpose: the rerun in
    /// [`every_injected_stage_failure_is_repaired_by_running_the_command_again`]
    /// is then the same transaction run twice, which is what the failure table
    /// promises, rather than a second fixture that could differ in some other
    /// way.
    fn refusing_the_next(self, times: usize) -> Self {
        self.refusals_left.store(times, Ordering::SeqCst);
        self
    }
}

/// Consumes one injected refusal, if any are left.
fn refuse_once(left: &AtomicUsize) -> bool {
    left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
        remaining.checked_sub(1)
    })
    .is_ok()
}

impl ReleaseAssets for FakeAssets {
    fn describe(&self) -> String {
        "a fixture release".to_string()
    }

    fn checksums(&self) -> Result<String, CliError> {
        self.journal.note("assets SHA256SUMS");
        if refuse_once(&self.refusals_left) {
            return Err(CliError::new(
                Failure::GithubUnavailable,
                "the fixture release is unreachable",
            ));
        }
        Ok(self.document.clone())
    }

    fn download(&self, asset: &str, into: &Path) -> Result<(), CliError> {
        self.journal.note(format!("assets download {asset}"));
        std::fs::write(into, &self.archive).map_err(|source| {
            CliError::new(
                Failure::LocalState,
                format!("cannot write the fixture archive: {source}"),
            )
        })
    }
}

/// A device flow with no browser, issuing one named distribution's credential.
#[derive(Debug)]
struct FakeIssuer {
    journal: Journal,
    tag: String,
    refusals_left: AtomicUsize,
}

impl FakeIssuer {
    fn issuing(journal: Journal, tag: &str) -> Self {
        Self {
            journal,
            tag: tag.to_string(),
            refusals_left: AtomicUsize::new(0),
        }
    }

    fn refusing_the_next(self, times: usize) -> Self {
        self.refusals_left.store(times, Ordering::SeqCst);
        self
    }
}

impl CredentialIssuer for FakeIssuer {
    fn issue(
        &self,
        _out: &mut dyn Write,
        sink: &mut dyn SecretSink,
    ) -> Result<BrokeredCredential, CliError> {
        self.journal.note(format!("device flow for {}", self.tag));
        if refuse_once(&self.refusals_left) {
            return Err(CliError::new(
                Failure::AuthenticationDeclined,
                "the fixture operator closed the browser",
            ));
        }
        sink.send(&SecretString::from(credential_document(&self.tag)))
            .map_err(|source| CliError::new(Failure::SecretStore, source.to_string()))?;
        Ok(BrokeredCredential {
            renewable: true,
            access_expires_at: None,
            refresh_expires_at: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Scripting one workstation
// ---------------------------------------------------------------------------

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput::exited(0, stdout, "")
}

fn refused(stderr: &str) -> CommandOutput {
    CommandOutput::exited(1, "", stderr)
}

/// What `schtasks` says about a name it does not hold.
fn absent() -> CommandOutput {
    refused("ERROR: The system cannot find the file specified.")
}

/// The command line one command inside a distribution produces, as a match
/// rule.
///
/// Everything the adapter runs in a distribution goes through
/// `wsl.exe --distribution NAME --user root --exec …`, so this is what makes a
/// rule apply to one host and not to the other host on the same workstation.
fn inside(distribution: &str, command: &str) -> String {
    format!("--distribution {distribution} --user root --exec {command}")
}

fn identity_of(distribution: &str) -> LifecycleTaskIdentity {
    LifecycleTaskIdentity::for_distribution(distribution).expect("a usable fixture name")
}

fn task_name(distribution: &str) -> String {
    identity_of(distribution).name().to_string()
}

/// The document Task Scheduler would export for this product's own task.
fn our_task_xml(distribution: &str) -> String {
    LifecycleTask::new(
        identity_of(distribution),
        TaskPrincipal::named(PRINCIPAL),
        &WslExecutable::at("wsl.exe"),
        LINUX_BINARY,
    )
    .xml()
}

/// `status --json` as the Linux binary answers it.
fn linux_status_json(credential: bool, capacity: u16, reported: &str) -> String {
    format!(
        "{{\"schema_version\":1,\"product\":{{\"name\":\"runner-manager\",\
         \"version\":\"{reported}\",\"service_binary_version\":\"{reported}\"}},\
         \"credential\":{{\"present\":{credential},\
         \"unreadable\":null,\"store_scope\":\"machine\"}},\
         \"host\":{{\"capacity\":{capacity}}}}}"
    )
}

/// `wsl --list --verbose`, with the first name as the default distribution.
fn distribution_table(names: &[&str]) -> String {
    let mut table = String::from("  NAME      STATE     VERSION\n");
    for (index, name) in names.iter().enumerate() {
        let marker = if index == 0 { '*' } else { ' ' };
        table.push_str(&format!("{marker} {name}   Running   2\n"));
    }
    table
}

/// The three preflight questions asked inside a distribution.
fn preflight_for(script: ScriptedRunner, distribution: &str) -> ScriptedRunner {
    script
        .always(&inside(distribution, "id -u"), ok("0\n"))
        .always(&inside(distribution, "uname -m"), ok("x86_64\n"))
        .always(
            &inside(distribution, "systemctl is-system-running"),
            ok("running\n"),
        )
}

/// A distribution that has never been provisioned, through one install, its
/// read-back, and every question a later `wsl status` asks.
///
/// The sequences are the interaction the transaction really has, in order:
/// `status --json` refuses before the binary lands, then reports a host with no
/// credential of its own, then reports the provisioned host. The unit is
/// inactive before installation and becomes active only after the installer
/// starts it. The task is absent when the preflight looks and absent again when
/// `register` looks, and this product's own from then on.
fn fresh_for(
    script: ScriptedRunner,
    distribution: &str,
    docker: CommandOutput,
    settled_capacity: u16,
) -> ScriptedRunner {
    let name = task_name(distribution);
    preflight_for(script, distribution)
        .sequence(
            &inside(distribution, &format!("systemctl is-enabled {UNIT}")),
            vec![ok("disabled\n"), ok("enabled\n")],
        )
        .sequence(
            &inside(distribution, &format!("systemctl is-active {UNIT}")),
            vec![ok("inactive\n"), ok("inactive\n"), ok("active\n")],
        )
        .always(&inside(distribution, "docker info"), docker)
        .sequence(
            &inside(distribution, &format!("{LINUX_BINARY} status --json")),
            vec![
                refused(&format!("{LINUX_BINARY}: not found")),
                ok(&linux_status_json(false, 1, version())),
                ok(&linux_status_json(true, settled_capacity, version())),
            ],
        )
        .sequence(
            &format!("/Query /TN {name} /XML ONE"),
            vec![absent(), absent(), ok(&our_task_xml(distribution))],
        )
        .sequence(
            &format!("/Query /TN {name} /FO CSV"),
            vec![absent(), ok("\"task\",\"N/A\",\"Running\"\n")],
        )
}

/// A distribution that is already a healthy managed runner host: the exact
/// binary, its own credential, an enabled unit and this product's task.
fn adopted_for(
    script: ScriptedRunner,
    distribution: &str,
    docker: CommandOutput,
    existing_capacity: u16,
) -> ScriptedRunner {
    let name = task_name(distribution);
    preflight_for(script, distribution)
        .always(
            &inside(distribution, &format!("systemctl is-enabled {UNIT}")),
            ok("enabled\n"),
        )
        .always(
            &inside(distribution, &format!("systemctl is-active {UNIT}")),
            ok("active\n"),
        )
        .always(&inside(distribution, "docker info"), docker)
        .always(
            &inside(distribution, &format!("{LINUX_BINARY} status --json")),
            ok(&linux_status_json(true, existing_capacity, version())),
        )
        .always(
            &format!("/Query /TN {name} /XML ONE"),
            ok(&our_task_xml(distribution)),
        )
        .always(
            &format!("/Query /TN {name} /FO CSV"),
            ok("\"task\",\"N/A\",\"Running\"\n"),
        )
}

/// The rules every workstation has, whatever its distributions answer, added
/// after whatever `script` already holds.
///
/// Taking a script rather than starting one is what lets a journey put an
/// injected refusal in front of these: a scripted runner answers from the first
/// rule that matches, so a failing rule appended after them would never be
/// reached.
///
/// The `--version` rule is global on purpose: the binary installer asks the
/// *staged* copy for its version, and that copy's path carries a per-run
/// staging token no distribution-scoped rule could spell.
fn workstation_rules(script: ScriptedRunner, names: &[&str]) -> ScriptedRunner {
    script
        .always("--list --verbose", ok(&distribution_table(names)))
        .always("--version", ok(&format!("runner-manager {}\n", version())))
}

/// Those rules and nothing else, for a journey that injects no failure.
fn workstation_script(names: &[&str]) -> ScriptedRunner {
    workstation_rules(ScriptedRunner::new(), names)
}

/// One Windows workstation, its scripted controls, and its config directory.
struct Workstation {
    journal: Journal,
    host: WslHost,
    runner: Arc<ScriptedRunner>,
    assets: FakeAssets,
    root: tempfile::TempDir,
    paths: AppPaths,
    out: Vec<u8>,
    err: Vec<u8>,
}

impl Workstation {
    fn over(script: ScriptedRunner) -> Self {
        let journal = Journal::default();
        let inner = Arc::new(script);
        let controls = FakeControls {
            inner: Arc::clone(&inner),
            journal: journal.clone(),
        };
        let root = tempfile::tempdir().expect("a temporary directory");
        let paths = AppPaths::rooted_at(root.path());
        paths.create_all().expect("the fixture directories");
        Self {
            assets: FakeAssets::publishing(journal.clone()),
            journal,
            host: WslHost::with_runner(Box::new(controls), WslExecutable::at("wsl.exe")),
            runner: inner,
            root,
            paths,
            out: Vec::new(),
            err: Vec::new(),
        }
    }

    /// `runner-manager wsl install`, including the report an operator reads and
    /// the read-back that decides its exit code.
    fn install(
        &mut self,
        distribution: &str,
        capacity: Option<u16>,
        issuer: &FakeIssuer,
    ) -> Result<(WslStatusDocument, InstallOutcome), CliError> {
        let provisioner = Provisioner {
            host: &self.host,
            assets: &self.assets,
            issuer,
            paths: &self.paths,
            principal: TaskPrincipal::named(PRINCIPAL),
            version: version().to_string(),
            linux_binary: LINUX_BINARY.to_string(),
            unit: UNIT.to_string(),
            now: DateTime::from_timestamp(1_800_000_000, 0).expect("a fixed instant"),
        };
        let args = WslInstallArgs {
            distribution: distribution.to_string(),
            capacity,
        };
        let outcome = provisioner.install(&args, &mut self.out);
        match &outcome {
            Ok((document, report)) => {
                write_install_report(document, report, &mut self.out)
                    .expect("a report can always be written to a buffer");
                // The command's own last act, and the one that decides its exit
                // code: a host provisioned only in part is a failure however
                // well the stages went.
                if let Err(partial) = refuse_a_partial_host(document) {
                    partial
                        .render(&mut self.err)
                        .expect("a buffer accepts a rendered failure");
                }
            }
            Err(failure) => failure
                .render(&mut self.err)
                .expect("a buffer accepts a rendered failure"),
        }
        outcome
    }

    /// `runner-manager wsl status`, as a document.
    fn status(&self, distribution: &str) -> WslStatusDocument {
        probe(
            &self.host,
            &self.paths,
            distribution,
            LINUX_BINARY,
            UNIT,
            version(),
            DateTime::from_timestamp(1_800_000_100, 0).expect("a fixed instant"),
        )
        .expect("a status document")
    }

    /// The text an operator reads and the JSON a script parses, both appended
    /// to this workstation's stdout so the canary scan covers them.
    fn status_output(&mut self, distribution: &str) -> String {
        let document = self.status(distribution);
        let mut rendered = Vec::new();
        write_status_text(&document, &mut rendered).expect("a text report");
        write_json(&mut rendered, &document).expect("a JSON document");
        let rendered = String::from_utf8(rendered).expect("the report is UTF-8");
        self.out.extend_from_slice(rendered.as_bytes());
        rendered
    }

    fn list(&mut self) -> String {
        let mut rendered = Vec::new();
        list_with(&self.host, &self.paths, &mut rendered).expect("a distribution list");
        let rendered = String::from_utf8(rendered).expect("the list is UTF-8");
        self.out.extend_from_slice(rendered.as_bytes());
        rendered
    }

    fn detach(&mut self, distribution: &str) -> Result<(), CliError> {
        detach_with(&self.host, &self.paths, distribution, &mut self.out)
    }

    fn output(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    fn errors(&self) -> String {
        String::from_utf8_lossy(&self.err).into_owned()
    }

    fn record(&self, distribution: &str) -> Option<WslProviderRecord> {
        WslProviderRecord::read(&self.paths, distribution).expect("a readable record directory")
    }

    /// The requests the scripted controls recorded.
    fn recorded(&self) -> Vec<RecordedRequest> {
        self.runner.recorded()
    }
}

/// A workstation with one never-provisioned distribution and a working Docker.
fn fresh_workstation(distribution: &str) -> Workstation {
    Workstation::over(fresh_for(
        workstation_script(&[distribution]),
        distribution,
        ok("27.1.1\n"),
        8,
    ))
}

fn issuer_for(workstation: &Workstation, distribution: &str) -> FakeIssuer {
    FakeIssuer::issuing(workstation.journal.clone(), distribution)
}

// ---------------------------------------------------------------------------
// Journey 1: a fresh workstation reaches a healthy second host
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_distribution_becomes_a_healthy_managed_runner_host() {
    let mut workstation = fresh_workstation(UBUNTU);

    // Before: WSL has it and this machine does not manage it.
    let before = workstation.list();
    assert!(
        before.contains(UBUNTU) && before.contains("not managed"),
        "an unprovisioned distribution is listed and is not claimed: {before}"
    );

    let issuer = issuer_for(&workstation, UBUNTU);
    let (document, outcome) = workstation
        .install(UBUNTU, Some(8), &issuer)
        .expect("a fresh install succeeds");

    assert!(document.healthy, "{document:#?}");
    assert!(
        refuse_a_partial_host(&document).is_ok(),
        "a healthy read-back is what makes `wsl install` exit zero"
    );
    assert_eq!(outcome.version, version());
    assert!(outcome.binary_replaced, "nothing was installed before");
    assert!(outcome.credential_issued, "the host had no credential");
    assert_eq!(outcome.capacity_set, Some(8));
    assert!(outcome.service_installed, "the unit was disabled");

    // Every part the design names is reported from the host, and the record it
    // wrote agrees with what happened.
    assert_eq!(document.binary.version.as_deref(), Some(version()));
    assert!(document.credential.present);
    assert!(document.service.healthy);
    assert!(document.lifecycle_task.registered);
    assert!(document.lifecycle_task.product_owned);
    assert_eq!(document.capacity, Some(8));
    assert!(
        document.drift.is_empty(),
        "a host this run just provisioned cannot be in drift: {:?}",
        document.drift
    );
    let record = workstation.record(UBUNTU).expect("a provider record");
    assert_eq!(record.distribution, UBUNTU);
    assert_eq!(record.installed_version, version());
    assert_eq!(record.task_name, task_name(UBUNTU));

    // After: the same command an operator would run next says it is managed.
    let after = workstation.list();
    assert!(
        after.contains(&format!("managed, runner-manager {}", version())),
        "the provisioned distribution is listed as managed: {after}"
    );

    // And the journey ran in the documented order, with the credential issued
    // only after the binary that will hold it is in place.
    workstation.journal.in_order(&[
        "--list --verbose",
        "id -u",
        "assets SHA256SUMS",
        "assets download",
        "mv -T",
        &format!("device flow for {UBUNTU}"),
        "auth receive",
        "host set-capacity 8",
        "service install --start-at boot",
        "/Create /TN",
        "/Run /TN",
    ]);
}

/// The point of a second host: the commands that already existed reach it.
#[test]
fn an_existing_command_is_carried_into_the_provisioned_host_unchanged() {
    let typed = [
        "runner-manager",
        "--host",
        "wsl:Ubuntu",
        "repo",
        "add",
        "acme/repo",
        "--host-label",
        "home",
        "--max-capacity",
        "4",
    ]
    .map(OsString::from);

    let plan = ProxyPlan::new(
        &WslExecutable::at("wsl.exe"),
        UBUNTU,
        LINUX_BINARY,
        forwarded_arguments(&typed),
    )
    .expect("a usable distribution name");

    let arguments: Vec<String> = plan
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        arguments,
        [
            "--distribution",
            UBUNTU,
            "--user",
            "root",
            "--exec",
            LINUX_BINARY,
            "repo",
            "add",
            "acme/repo",
            "--host-label",
            "home",
            "--max-capacity",
            "4",
        ],
        "policy is configured through the product rather than by hand, and the selector is \
         the only thing the proxy removes"
    );
}

// ---------------------------------------------------------------------------
// Journey 2: adoption
// ---------------------------------------------------------------------------

#[test]
fn a_distribution_that_already_runs_the_product_is_adopted_and_not_rebuilt() {
    let mut workstation = Workstation::over(adopted_for(
        workstation_script(&[UBUNTU]),
        UBUNTU,
        ok("27.1.1\n"),
        4,
    ));
    let issuer = issuer_for(&workstation, UBUNTU);

    let (document, outcome) = workstation
        .install(UBUNTU, None, &issuer)
        .expect("adoption succeeds");

    assert!(document.healthy, "{document:#?}");
    assert!(
        !outcome.binary_replaced,
        "the distribution already runs this exact version"
    );
    assert!(
        !outcome.credential_issued,
        "`03-security-and-lifecycle.md` guarantee 1: an authenticated Linux store is never \
         signed in over"
    );
    assert_eq!(outcome.capacity_set, None);
    assert!(
        !outcome.service_installed,
        "an enabled unit is adopted rather than reinstalled"
    );

    // The five things adoption must not do, asserted against what was really
    // run rather than against the flags that report it.
    workstation.journal.never("device flow");
    workstation.journal.never("auth receive");
    workstation.journal.never("host set-capacity");
    workstation.journal.never("service install");
    workstation.journal.never("mv -T");
    assert_eq!(
        document.capacity,
        Some(4),
        "the capacity the Linux host already had is what status reports"
    );

    // Adoption still writes the Windows-side record, because a managed host
    // with no record is one `detach` could not clean up.
    assert!(workstation.record(UBUNTU).is_some());
    assert!(
        workstation
            .output()
            .contains("already holds its own credential"),
        "the operator is told what was preserved: {}",
        workstation.output()
    );
}

// ---------------------------------------------------------------------------
// Journey 3: two distributions on one workstation
// ---------------------------------------------------------------------------

#[test]
fn two_distributions_never_share_a_credential_a_task_or_a_record() {
    let script = fresh_for(
        fresh_for(
            workstation_script(&[UBUNTU, DEBIAN]),
            UBUNTU,
            ok("27.1.1\n"),
            8,
        ),
        DEBIAN,
        refused("Cannot connect to the Docker daemon"),
        2,
    );
    let mut workstation = Workstation::over(script);

    let ubuntu_issuer = issuer_for(&workstation, UBUNTU);
    let debian_issuer = issuer_for(&workstation, DEBIAN);

    let (ubuntu, _) = workstation
        .install(UBUNTU, Some(8), &ubuntu_issuer)
        .expect("the first host provisions");
    let (debian, _) = workstation
        .install(DEBIAN, Some(2), &debian_issuer)
        .expect("the second host provisions independently");

    assert!(ubuntu.healthy && debian.healthy, "both hosts are healthy");
    assert_eq!(ubuntu.capacity, Some(8));
    assert_eq!(
        debian.capacity,
        Some(2),
        "each host keeps its own capacity, read back from itself"
    );

    // Two records, two task names, two device flows.
    assert_ne!(
        task_name(UBUNTU),
        task_name(DEBIAN),
        "the task name is derived per distribution"
    );
    assert_eq!(
        workstation.record(UBUNTU).expect("a record").task_name,
        task_name(UBUNTU)
    );
    assert_eq!(
        workstation.record(DEBIAN).expect("a record").task_name,
        task_name(DEBIAN)
    );
    assert_eq!(workstation.journal.count("device flow"), 2);

    // And each credential went into its own distribution and nowhere else.
    let handoffs = workstation.recorded();
    for (distribution, other) in [(UBUNTU, DEBIAN), (DEBIAN, UBUNTU)] {
        let [access, _, _] = canaries_for(distribution);
        let [foreign, _, _] = canaries_for(other);
        let delivered: Vec<String> = handoffs
            .iter()
            .filter(|request| {
                request
                    .arguments
                    .iter()
                    .any(|argument| argument == "receive")
                    && request
                        .arguments
                        .iter()
                        .any(|argument| argument == distribution)
            })
            .map(|request| String::from_utf8_lossy(&request.stdin).into_owned())
            .collect();
        assert_eq!(
            delivered.len(),
            1,
            "{distribution} receives exactly one credential"
        );
        assert!(
            delivered[0].contains(&access),
            "{distribution} must receive its own credential"
        );
        assert!(
            !delivered[0].contains(&foreign),
            "{distribution} must never receive {other}'s credential: sharing a refresh \
             token is exactly what `03-security-and-lifecycle.md` guarantee 6 rules out"
        );
    }

    // Docker is a diagnostic: the host whose Docker is down is still healthy.
    let debian_docker = debian
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.name == "docker")
        .expect("the docker diagnostic");
    assert!(!debian_docker.available);
    assert!(
        debian.healthy,
        "`02-target-architecture.md` lists Docker among workload prerequisite diagnostics, \
         and `03-security-and-lifecycle.md` never lists it among the things provisioning \
         depends on"
    );

    // Detaching one leaves the other exactly as it was.
    workstation.detach(UBUNTU).expect("detach succeeds");
    assert!(workstation.record(UBUNTU).is_none());
    assert!(
        workstation.record(DEBIAN).is_some(),
        "detaching one host must not touch the other's record"
    );
    let deletions: Vec<String> = workstation
        .journal
        .entries()
        .into_iter()
        .filter(|entry| entry.contains("/Delete /TN"))
        .collect();
    assert_eq!(deletions.len(), 1, "{deletions:?}");
    assert!(
        deletions[0].contains(&task_name(UBUNTU)) && !deletions[0].contains(&task_name(DEBIAN)),
        "only the named host's task is removed: {deletions:?}"
    );
}

// ---------------------------------------------------------------------------
// Journey 4: rerunning the same workstation
// ---------------------------------------------------------------------------

#[test]
fn a_second_run_over_the_same_workstation_converges_and_changes_nothing() {
    let mut workstation = fresh_workstation(UBUNTU);
    let issuer = issuer_for(&workstation, UBUNTU);

    let (first, _) = workstation
        .install(UBUNTU, Some(8), &issuer)
        .expect("the first run provisions");
    assert!(first.healthy);

    let installs_before = workstation.journal.count("service install --start-at boot");
    let flows_before = workstation.journal.count("device flow");
    let renames_before = workstation.journal.count("mv -T");

    let (second, outcome) = workstation
        .install(UBUNTU, None, &issuer)
        .expect("the second run converges");

    assert!(second.healthy, "{second:#?}");
    assert!(
        !outcome.binary_replaced,
        "the exact version is already there"
    );
    assert!(!outcome.credential_issued, "the credential is adopted");
    assert_eq!(outcome.capacity_set, None, "no capacity was supplied");
    assert!(!outcome.service_installed, "the unit is now enabled");

    assert_eq!(
        workstation.journal.count("service install --start-at boot"),
        installs_before,
        "a rerun must not reinstall an enabled unit"
    );
    assert_eq!(
        workstation.journal.count("device flow"),
        flows_before,
        "a rerun must never send its operator back to a browser"
    );
    assert_eq!(
        workstation.journal.count("mv -T"),
        renames_before,
        "a rerun must not replace a binary that is already the right one"
    );
    assert!(
        workstation.journal.count("/Create /TN") >= 2,
        "the lifecycle task is the one thing a rerun does re-register, in place"
    );
}

// ---------------------------------------------------------------------------
// Journey 5: every injected failure is recoverable by rerunning
// ---------------------------------------------------------------------------

/// One mutating stage, made to fail once.
struct Injection {
    stage: Stage,
    /// A rule that refuses the first matching command and succeeds afterwards.
    first_failure: Option<(&'static str, &'static str)>,
    /// How many times the release assets refuse before serving.
    asset_refusals: usize,
    /// How many times the device flow refuses before issuing.
    issuer_refusals: usize,
}

/// `03-security-and-lifecycle.md`'s failure table, as a journey rather than as
/// a message.
///
/// For each mutating stage: make it fail once, require the failure to name the
/// stage and to say whether a rerun is safe, then run the very same transaction
/// again against the very same workstation and require a healthy host. That
/// second half is what the table's "rerun behavior" column actually promises,
/// and asserting only the message would leave it unmeasured.
#[test]
fn every_injected_stage_failure_is_repaired_by_running_the_command_again() {
    let injections = [
        Injection {
            stage: Stage::Artifact,
            first_failure: None,
            asset_refusals: 1,
            issuer_refusals: 0,
        },
        Injection {
            stage: Stage::Binary,
            first_failure: Some(("mv -T", "mv: cannot move: Read-only file system")),
            asset_refusals: 0,
            issuer_refusals: 0,
        },
        Injection {
            stage: Stage::Credential,
            first_failure: None,
            asset_refusals: 0,
            issuer_refusals: 1,
        },
        Injection {
            stage: Stage::Capacity,
            first_failure: Some(("host set-capacity", "cannot open the policy database")),
            asset_refusals: 0,
            issuer_refusals: 0,
        },
        Injection {
            stage: Stage::Service,
            first_failure: Some((
                "service install --start-at boot",
                "Failed to connect to bus",
            )),
            asset_refusals: 0,
            issuer_refusals: 0,
        },
        Injection {
            stage: Stage::LifecycleTask,
            first_failure: Some(("/Create /TN", "ERROR: Access is denied.")),
            asset_refusals: 0,
            issuer_refusals: 0,
        },
    ];

    for injection in injections {
        // The failing rule is added FIRST, because a scripted runner answers
        // from the first rule that matches: appended after the workstation's
        // own rules it would never be reached.
        let mut script = ScriptedRunner::new();
        if let Some((matches, detail)) = injection.first_failure {
            script = script.sequence(matches, vec![refused(detail), ok("")]);
        }
        let script = workstation_rules(script, &[UBUNTU]);
        let mut workstation = Workstation::over(fresh_for(script, UBUNTU, ok("27.1.1\n"), 8));
        workstation.assets = FakeAssets::publishing(workstation.journal.clone())
            .refusing_the_next(injection.asset_refusals);
        let issuer = issuer_for(&workstation, UBUNTU).refusing_the_next(injection.issuer_refusals);

        let failure = workstation
            .install(UBUNTU, Some(8), &issuer)
            .expect_err("the injected stage was made to fail");
        let message = failure.to_string();
        assert!(
            message.contains(injection.stage.label()),
            "a failure must name the stage it happened in, so an operator knows whether \
             anything was changed. {:?} said: {message}",
            injection.stage
        );
        assert!(
            message.contains("safe to run"),
            "and it must say that rerunning is the remedy. {:?} said: {message}",
            injection.stage
        );
        assert!(
            workstation.record(UBUNTU).is_none(),
            "{:?} failed before the record was written, so nothing may claim this host is \
             managed",
            injection.stage
        );

        let (document, _) = workstation
            .install(UBUNTU, Some(8), &issuer)
            .unwrap_or_else(|error| {
                panic!(
                    "the documented remedy for a {:?} failure is to fix it and run the \
                     command again, and the rerun refused: {error}",
                    injection.stage
                )
            });
        assert!(
            document.healthy,
            "a rerun after a {:?} failure must converge on a healthy host: {document:#?}",
            injection.stage
        );
        assert!(
            workstation.record(UBUNTU).is_some(),
            "and it must leave a record `detach` can clean up"
        );
    }
}

/// The preflight half of the same table: a refusal there changes nothing at
/// all, which is a stronger promise than "safe to rerun".
#[test]
fn a_preflight_refusal_changes_nothing_and_issues_no_credential() {
    let script = ScriptedRunner::new()
        .always("--list --verbose", ok("* Legacy   Running   1\n"))
        .always("--version", ok(&format!("runner-manager {}\n", version())));
    let mut workstation = Workstation::over(script);
    let issuer = issuer_for(&workstation, "Legacy");

    let failure = workstation
        .install("Legacy", Some(8), &issuer)
        .expect_err("a WSL1 distribution is refused");
    assert_eq!(failure.class(), Failure::UnsupportedHost);
    assert!(
        failure.to_string().contains("nothing has been changed"),
        "{failure}"
    );

    workstation.journal.never("device flow");
    workstation.journal.never("assets SHA256SUMS");
    workstation.journal.never("mv -T");
    workstation.journal.never("/Create /TN");
    assert!(workstation.record("Legacy").is_none());
}

// ---------------------------------------------------------------------------
// Journey 6: detach
// ---------------------------------------------------------------------------

#[test]
fn detach_removes_the_windows_half_and_states_what_it_left_inside_linux() {
    let mut workstation = fresh_workstation(UBUNTU);
    let issuer = issuer_for(&workstation, UBUNTU);
    workstation
        .install(UBUNTU, Some(8), &issuer)
        .expect("provisioned");

    let before = workstation.journal.entries().len();
    workstation.detach(UBUNTU).expect("detach succeeds");
    let mut entries = workstation.journal.entries();
    let during = entries.split_off(before);

    assert!(!during.is_empty(), "detach ran nothing at all");
    assert!(
        during.iter().all(|entry| entry.starts_with("schtasks")),
        "`wsl detach` runs nothing inside the distribution, which is why it cannot delete \
         Linux data even by mistake: {during:?}"
    );
    assert!(
        workstation.record(UBUNTU).is_none(),
        "the record is removed"
    );

    let output = workstation.output();
    assert!(
        output.contains("Nothing inside Ubuntu was changed"),
        "detach states the promise it keeps: {output}"
    );
    for named in [
        "runner-manager service uninstall",
        "runner-manager auth logout",
    ] {
        assert!(
            output.contains(named),
            "and names the explicit Linux commands an operator may run separately: {output}"
        );
    }

    // Convergent: detaching twice is not an error.
    workstation
        .detach(UBUNTU)
        .expect("a second detach is convergent");
}

// ---------------------------------------------------------------------------
// Journey 7: the credential canary, over every observable output
// ---------------------------------------------------------------------------

/// A `tracing` writer that keeps everything, so "no secret in the logs" is a
/// statement about logs that were really produced.
#[derive(Debug, Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn text(&self) -> String {
        let buffer = self
            .0
            .lock()
            .expect("the log buffer is not shared across a panic");
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

impl io::Write for CapturedLogs {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer is not shared across a panic")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

/// Every file under a directory, so a scan cannot miss one by not knowing its
/// name.
fn every_file_under(root: &Path, found: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            every_file_under(&path, found);
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.push((
                path.display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
}

/// `03-security-and-lifecycle.md` item 3, over the whole command rather than
/// over one module.
///
/// `crates/platform/tests/no_wsl_credential_outside_child_stdin.rs` drives the
/// same kind of canary through the *adapter*. This drives one through the
/// **command**: the install an operator runs, its report, its failure message,
/// its diagnostics, the files it wrote and the process it runs in. Those are
/// the seven places `b3-acceptance-docs` names.
#[test]
fn no_credential_reaches_stdout_stderr_logs_records_task_xml_argv_or_the_environment() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();

    // A workstation whose lifecycle task cannot be created the first time: the
    // credential is delivered and the command then FAILS, so the scan covers a
    // failure message and a rendered stderr, and the rerun then succeeds so it
    // also covers a clean report and the provider record that run wrote.
    let script = workstation_rules(
        ScriptedRunner::new().sequence(
            "/Create /TN",
            vec![refused("ERROR: Access is denied."), ok("")],
        ),
        &[UBUNTU],
    );
    let mut workstation = Workstation::over(fresh_for(script, UBUNTU, ok("27.1.1\n"), 8));
    let issuer = issuer_for(&workstation, UBUNTU);

    let (refusal, files) = tracing::subscriber::with_default(subscriber, || {
        let refusal = workstation
            .install(UBUNTU, Some(8), &issuer)
            .expect_err("the lifecycle task was refused");
        workstation
            .install(UBUNTU, Some(8), &issuer)
            .expect("the rerun converges");
        // The whole read-only surface as well, so the scan covers everything an
        // operator or a script can see.
        workstation.status_output(UBUNTU);
        workstation.list();
        // Read before the detach, which is what removes the record: the files
        // this run wrote are exactly what item 3 says must not carry a secret.
        let mut files = Vec::new();
        every_file_under(workstation.root.path(), &mut files);
        let _ = workstation.detach(UBUNTU);
        (refusal, files)
    });

    let [access, refresh, jit] = canaries_for(UBUNTU);
    let needles = [
        ("the access token", access.as_str()),
        ("the refresh token", refresh.as_str()),
        ("the encoded JIT configuration", jit.as_str()),
    ];

    let mut corpus: Vec<(String, String)> = vec![
        ("stdout".to_string(), workstation.output()),
        ("stderr".to_string(), workstation.errors()),
        ("the failure message".to_string(), refusal.to_string()),
        (
            "the failure's Debug output".to_string(),
            format!("{refusal:?}"),
        ),
        ("the diagnostics".to_string(), logs.text()),
        (
            "the scheduled-task document".to_string(),
            our_task_xml(UBUNTU),
        ),
        (
            "the argument vectors".to_string(),
            workstation.runner.command_lines().join("\n"),
        ),
        (
            "the recorded requests' Debug output".to_string(),
            format!("{:?}", workstation.recorded()),
        ),
        (
            "this process's environment".to_string(),
            std::env::vars_os()
                .map(|(name, value)| {
                    format!("{}={}", name.to_string_lossy(), value.to_string_lossy())
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        (
            "the journal".to_string(),
            workstation.journal.entries().join("\n"),
        ),
    ];
    assert!(
        !files.is_empty(),
        "the file scan found nothing, so it would pass vacuously"
    );
    for (path, contents) in files {
        corpus.push((format!("the file {path}"), contents));
    }

    let mut found = Vec::new();
    for (name, needle) in needles {
        for (origin, text) in &corpus {
            if text.contains(needle) {
                found.push(format!("{name} appears in {origin}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "`03-security-and-lifecycle.md` item 3: the credential document is absent from \
         argv, environment, provider records, logs, errors, status JSON, temporary files \
         and scheduled-task XML. Found:\n  {}",
        found.join("\n  ")
    );

    // Two controls, because "nothing was found" and "nothing was looked at"
    // are otherwise the same result.
    let piped = String::from_utf8_lossy(&workstation.runner.piped_input()).into_owned();
    for (name, needle) in needles {
        assert!(
            piped.contains(needle),
            "{name} never reached the child's stdin at all, so the clean scan above is \
             about a credential that was never handed over"
        );
    }

    // The scanner itself, run over a corpus that DOES contain all three: a
    // needle that had stopped matching would otherwise report a clean result
    // for the wrong reason.
    let planted: Vec<(String, String)> = needles
        .iter()
        .map(|(name, needle)| ((*name).to_string(), format!("prefix {needle} suffix")))
        .collect();
    let planted_hits = needles
        .iter()
        .filter(|(_, needle)| planted.iter().any(|(_, text)| text.contains(needle)))
        .count();
    assert_eq!(
        planted_hits,
        needles.len(),
        "the scan must find every needle when it is planted, or the clean result above is \
         a scanner that stopped matching"
    );
    assert!(
        workstation.output().contains("runner-manager wsl install"),
        "and the corpus must hold output this run really produced"
    );
}

/// The one door the credential is allowed through, stated as an exact count.
#[test]
fn the_credential_crosses_exactly_one_boundary_and_it_is_a_child_stdin_pipe() {
    let mut workstation = fresh_workstation(UBUNTU);
    let issuer = issuer_for(&workstation, UBUNTU);
    workstation
        .install(UBUNTU, Some(8), &issuer)
        .expect("provisioned");

    let [access, _, _] = canaries_for(UBUNTU);
    let carrying: Vec<String> = workstation
        .recorded()
        .iter()
        .filter(|request| String::from_utf8_lossy(&request.stdin).contains(&access))
        .map(|request| request.arguments.join(" "))
        .collect();
    assert_eq!(
        carrying.len(),
        1,
        "exactly one child is ever given the credential: {carrying:?}"
    );
    assert!(
        carrying[0].contains("auth receive --start-at boot"),
        "and it is the distribution's own `auth receive`: {carrying:?}"
    );
}

// ---------------------------------------------------------------------------
// The status document an operator and a script both read
// ---------------------------------------------------------------------------

#[test]
fn status_states_the_login_availability_constraint_rather_than_leaving_it_to_a_reboot() {
    let mut workstation = fresh_workstation(UBUNTU);
    let issuer = issuer_for(&workstation, UBUNTU);
    workstation
        .install(UBUNTU, Some(8), &issuer)
        .expect("provisioned");

    let rendered = workstation.status_output(UBUNTU);
    assert!(
        rendered.contains("after the owning Windows account logs on"),
        "`02-target-architecture.md` requires status to state the per-user constraint \
         explicitly: {rendered}"
    );
    assert!(
        rendered.contains("\"schema_version\": 1"),
        "the JSON document carries its version, so a script can branch on it: {rendered}"
    );
    for part in [
        "provider record",
        "linux binary",
        "credential",
        "linux service",
        "lifecycle task",
        "capacity",
        "docker",
    ] {
        assert!(
            rendered.contains(part),
            "status distinguishes every part the design names, and {part} is missing:\n\
             {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// The transition corpus
// ---------------------------------------------------------------------------

// owner: c1-wsl-chain-corpus
mod chains {
    //! At least 32 named, deterministic WSL transition cases, all of which the
    //! default test binary runs on every OS.
    //!
    //! # Why a corpus beside the journeys
    //!
    //! Each journey above proves one promise from beginning to end. This corpus
    //! proves the promises still hold when the commands are *chained*: `wsl
    //! list`, repeated `wsl install`, `wsl status`, `wsl detach` and a `--host
    //! wsl:NAME` proxied command, in the orders an operator really types them,
    //! over fresh, adopted, healthy, drifted, partial, detached and re-attached
    //! workstations. Every case has a stable `wsl-NNNN` identifier, declares
    //! every expectation before its first command runs, and stops at the first
    //! observation that disagrees. The failure names the case, the corpus
    //! version, the initial workstation, the steps already run, the step that
    //! diverged, and everything that step did.
    //!
    //! # Who answers a request
    //!
    //! Every request still goes through a [`ScriptedRunner`]. The runner records
    //! it (argument vector, stdin bytes, deadline) and answers it when the case
    //! injected a rule for it. A request no rule claims is answered by
    //! [`HostModel`], a small, deterministic Windows workstation. Its
    //! distributions' binary, credential, capacity and systemd unit change when,
    //! and only when, the product runs the command that changes them, and its
    //! Task Scheduler stores the document `/Create` really wrote. That is what
    //! lets a later command in a chain see what an earlier one did, without a
    //! count-shaped script that would have to be rewritten for every chain.
    //!
    //! The model is the *environment*, not the oracle. Every expected value is
    //! written into the case before it runs; the model only decides what a
    //! distribution or Task Scheduler says back.
    //!
    //! # What is checked after every step
    //!
    //! - The exit class and the fragments the operator reads.
    //! - The ordered request and event history, and any literal argument
    //!   vectors.
    //! - The provider records, and the Linux and Task Scheduler state.
    //! - A ceiling on requests, deadlines and output.
    //! - That a credential crossed only on the stdin of its own distribution's
    //!   `auth receive`, exactly as many times as expected.
    //! - A canary scan over stdout, stderr, failures and their `Debug` text, the
    //!   status document, diagnostics, argument vectors, the environment, every
    //!   file under the config directory and every registered task document.
    //!
    //! Three invariants hold for every case without being written into it: a
    //! read changes nothing, `wsl detach` changes nothing inside Linux, and a
    //! preflight refusal changes nothing anywhere.
    //!
    //! Nothing here starts `wsl.exe`, writes a scheduled task, reaches GitHub or
    //! opens a network connection.
    //!
    //! # Replay
    //!
    //! The default test always runs the complete corpus, and nothing in the
    //! environment can narrow it. To look at one case on its own, with its full
    //! transcript printed:
    //!
    //! ```text
    //! RUNNER_MANAGER_WSL_CHAIN_CASE=wsl-0007 cargo test -p runner-manager \
    //!     --bin runner-manager replay_one_wsl_chain_case -- --ignored --nocapture
    //! ```

    use super::*;

    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Instant;

    use clap::Parser as _;
    use runner_manager_platform::wsl::discovery::decode_console_output;
    use runner_manager_platform::wsl::exec::DEFAULT_STDERR_LIMIT;

    /// The corpus's version, printed with every divergence. Moved whenever a
    /// case's meaning changes, so a replay always names the corpus it came from.
    const CORPUS: &str = "wsl-chains/v1";

    /// `02-target-architecture.md`: "at least 32 named WSL transition cases".
    const MINIMUM_CASES: usize = 32;

    /// Selects one case for [`replay_one_wsl_chain_case`], and nothing else.
    const REPLAY_VARIABLE: &str = "RUNNER_MANAGER_WSL_CHAIN_CASE";

    /// The soft budget `02-target-architecture.md` sets. Reported, never
    /// asserted: wall-clock time is not a correctness oracle.
    const SOFT_BUDGET: Duration = Duration::from_secs(60);

    /// The same letters as [`UBUNTU`], in another case. WSL allows both to be
    /// registered at once.
    const LOWER_UBUNTU: &str = "ubuntu";
    /// A name with spaces and a slash, both of which WSL allows.
    const SPACED: &str = "Debian GNU/Linux 12";
    const LEGACY: &str = "Legacy";

    /// Who holds the credential of a distribution that had one before this
    /// workstation ever looked at it.
    const PREEXISTING: &str = "a credential the distribution already had";
    /// A release that is not this build's, for a binary replaced by hand.
    const OLDER: &str = "0.3.0";
    /// A service copy recent enough to take the cooperative upgrade handover.
    const HANDOVER_CAPABLE: &str = "0.2.0";
    /// A service copy that predates the handover and must never be replaced.
    const LEGACY_SERVICE: &str = "0.1.0";

    /// The most one step may write to stdout and stderr together.
    const OUTPUT_CEILING: usize = 16 * 1024;
    /// The longest deadline the adapter gives any child: unpacking a release.
    const LONGEST_DEADLINE: Duration = Duration::from_secs(300);
    /// `docker info` is a diagnostic, and must not be able to make `status`
    /// hang.
    const DOCKER_DEADLINE: Duration = Duration::from_secs(15);
    const FIRST_MAIN_PID: u32 = 4100;

    // -----------------------------------------------------------------------
    // The workstation's other half: what the distributions hold
    // -----------------------------------------------------------------------

    /// One WSL distribution, as the host model holds it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Distro {
        name: String,
        wsl_version: u8,
        machine: &'static str,
        systemd: &'static str,
        root: bool,
        docker: bool,
        binary: Option<String>,
        service_copy: Option<String>,
        /// Whose credential the Linux store holds: the distribution whose
        /// canary arrived on `auth receive`, or [`PREEXISTING`].
        credential: Option<String>,
        credentials_received: usize,
        capacity: u16,
        unit_enabled: bool,
        unit_active: bool,
        unit_failed: bool,
        /// Whether `systemctl start` really brings the unit up.
        unit_stays_up: bool,
        main_pid: u32,
        staged: Option<String>,
        staging: Vec<String>,
        /// Observations left before an in-progress cooperative handover
        /// completes.
        handover_observations: u8,
    }

    impl Distro {
        /// Never provisioned: WSL2, root, systemd, Docker, and nothing of this
        /// product's.
        fn fresh(name: &str) -> Self {
            Self {
                name: name.to_string(),
                wsl_version: 2,
                machine: "x86_64",
                systemd: "running",
                root: true,
                docker: true,
                binary: None,
                service_copy: None,
                credential: None,
                credentials_received: 0,
                capacity: crate::cli::DEFAULT_HOST_CAPACITY,
                unit_enabled: false,
                unit_active: false,
                unit_failed: false,
                unit_stays_up: true,
                main_pid: FIRST_MAIN_PID,
                staged: None,
                staging: Vec::new(),
                handover_observations: 0,
            }
        }

        /// Already a working runner-manager host, set up without this
        /// workstation: the exact binary, its own credential, an enabled and
        /// active unit.
        fn adopted(name: &str, capacity: u16) -> Self {
            Self {
                binary: Some(version().to_string()),
                service_copy: Some(version().to_string()),
                credential: Some(PREEXISTING.to_string()),
                capacity,
                unit_enabled: true,
                unit_active: true,
                ..Self::fresh(name)
            }
        }

        fn wsl1(mut self) -> Self {
            self.wsl_version = 1;
            self
        }

        fn systemd(mut self, word: &'static str) -> Self {
            self.systemd = word;
            self
        }

        fn machine(mut self, machine: &'static str) -> Self {
            self.machine = machine;
            self
        }

        fn not_root(mut self) -> Self {
            self.root = false;
            self
        }

        fn without_docker(mut self) -> Self {
            self.docker = false;
            self
        }

        fn unit(mut self, enabled: bool, active: bool) -> Self {
            self.unit_enabled = enabled;
            self.unit_active = active;
            self
        }

        /// The source binary and the service's private copy are this release.
        fn running(mut self, binary: &str, service_copy: &str) -> Self {
            self.binary = Some(binary.to_string());
            self.service_copy = Some(service_copy.to_string());
            self
        }

        /// A unit whose daemon exits as soon as systemd starts it.
        fn never_stays_up(mut self) -> Self {
            self.unit_stays_up = false;
            self
        }

        /// One command, run inside this distribution as root.
        fn run(
            &mut self,
            program: &str,
            arguments: &[&str],
            stdin: &[u8],
            names: &[String],
        ) -> CommandOutput {
            match (program, arguments) {
                ("id", ["-u"]) => ok(if self.root { "0\n" } else { "1000\n" }),
                ("uname", ["-m"]) => ok(&format!("{}\n", self.machine)),
                ("systemctl", ["is-system-running"]) => CommandOutput::exited(
                    i32::from(self.systemd != "running"),
                    format!("{}\n", self.systemd),
                    "",
                ),
                ("systemctl", ["is-enabled", UNIT]) => {
                    if self.unit_enabled {
                        ok("enabled\n")
                    } else {
                        CommandOutput::exited(1, "disabled\n", "")
                    }
                }
                ("systemctl", ["is-active", UNIT]) => {
                    if self.unit_active {
                        ok("active\n")
                    } else if self.unit_failed {
                        CommandOutput::exited(3, "failed\n", "")
                    } else {
                        CommandOutput::exited(3, "inactive\n", "")
                    }
                }
                ("systemctl", ["show", "--property=MainPID", "--value", UNIT]) => {
                    let pid = if self.unit_active { self.main_pid } else { 0 };
                    ok(&format!("{pid}\n"))
                }
                ("systemctl", ["enable", UNIT]) => {
                    self.unit_enabled = true;
                    ok("")
                }
                ("systemctl", ["start", UNIT]) => {
                    if self.unit_stays_up {
                        self.unit_active = true;
                        self.unit_failed = false;
                        if self.service_copy.is_none() {
                            self.service_copy = self.binary.clone();
                        }
                        self.main_pid += 1;
                    } else {
                        self.unit_failed = true;
                    }
                    ok("")
                }
                ("systemctl", ["stop", UNIT]) => {
                    self.unit_active = false;
                    ok("")
                }
                ("docker", ["info", "--format", "{{.ServerVersion}}"]) => {
                    if self.docker {
                        ok("27.1.1\n")
                    } else {
                        refused(
                            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.",
                        )
                    }
                }
                ("mkdir", ["-m", "0700", directory]) => {
                    if self
                        .staging
                        .iter()
                        .any(|existing| existing.as_str() == *directory)
                    {
                        refused("mkdir: cannot create directory: File exists")
                    } else {
                        self.staging.push((*directory).to_string());
                        ok("")
                    }
                }
                ("tar", ["-xzf", "-", "-C", directory, "--no-same-owner", _member]) => {
                    if self
                        .staging
                        .iter()
                        .any(|existing| existing.as_str() == *directory)
                    {
                        // The fixture archive is this release's, whatever its bytes.
                        self.staged = Some(version().to_string());
                        ok("")
                    } else {
                        CommandOutput::exited(2, "", "tar: cannot change to the directory")
                    }
                }
                ("chmod", ["0755", _staged]) => ok(""),
                ("mv", ["-T", _staged, LINUX_BINARY]) => match self.staged.take() {
                    Some(installed) => {
                        // A daemon recent enough watches its source binary and
                        // hands itself over when the source changes under it.
                        if self.unit_active
                            && self.service_copy.as_deref() != Some(installed.as_str())
                            && self.service_copy.as_deref() != Some(LEGACY_SERVICE)
                        {
                            self.handover_observations = 2;
                        }
                        self.binary = Some(installed);
                        ok("")
                    }
                    None => refused("mv: cannot stat the staged binary: No such file or directory"),
                },
                ("rm", ["-rf", directory]) => {
                    self.staging
                        .retain(|existing| existing.as_str() != *directory);
                    self.staged = None;
                    ok("")
                }
                (staged, ["--version"]) if staged.contains(".runner-manager-install-") => {
                    match &self.staged {
                        Some(staged) => ok(&format!("runner-manager {staged}\n")),
                        None => refused("No such file or directory"),
                    }
                }
                (executable, ["--version"]) if executable.starts_with("/proc/") => {
                    let pid = executable
                        .trim_start_matches("/proc/")
                        .trim_end_matches("/exe");
                    match &self.service_copy {
                        Some(copy) if self.unit_active && pid == self.main_pid.to_string() => {
                            ok(&format!("runner-manager {copy}\n"))
                        }
                        _ => refused("No such file or directory"),
                    }
                }
                (LINUX_BINARY, rest) => self.product(rest, stdin, names),
                _ => unmodelled(program, arguments),
            }
        }

        /// The runner-manager installed in this distribution, answering.
        fn product(&mut self, arguments: &[&str], stdin: &[u8], names: &[String]) -> CommandOutput {
            let Some(installed) = self.binary.clone() else {
                return refused(&format!(
                    "execvpe({LINUX_BINARY}) failed: No such file or directory"
                ));
            };
            match arguments {
                ["status", "--json"] => {
                    if self.handover_observations > 0 {
                        self.handover_observations -= 1;
                        if self.handover_observations == 0 {
                            self.service_copy = self.binary.clone();
                            self.main_pid += 1;
                        }
                    }
                    ok(&self.status_json(&installed))
                }
                ["auth", "receive", "--start-at", "boot"] => {
                    self.credentials_received += 1;
                    let document = String::from_utf8_lossy(stdin);
                    let owner = names
                        .iter()
                        .find(|name| {
                            let [access, _, _] = canaries_for(name);
                            document.contains(&access)
                        })
                        .cloned()
                        .unwrap_or_else(|| "a document with no known owner".to_string());
                    self.credential = Some(owner);
                    ok("Credential received.\n")
                }
                ["host", "set-capacity", value] => match value.parse::<u16>() {
                    Ok(0) => CommandOutput::exited(
                        9,
                        "",
                        "a host capacity of 0 is not a configured host, it is a disabled one. \
                         Set at least 1.",
                    ),
                    Ok(capacity) => {
                        self.capacity = capacity;
                        ok(&format!("Host capacity set to {capacity}.\n"))
                    }
                    Err(_) => CommandOutput::exited(2, "", "error: invalid value for <N>"),
                },
                ["service", "install", "--start-at", "boot"] => {
                    self.unit_enabled = true;
                    self.service_copy = Some(installed);
                    ok("Service installed.\n")
                }
                other => ok(&format!(
                    "runner-manager {installed} in {} ran `{}`\n",
                    self.name,
                    other.join(" ")
                )),
            }
        }

        /// `status --json`, in the fields `wsl status` reads.
        fn status_json(&self, installed: &str) -> String {
            let service = match &self.service_copy {
                Some(copy) => format!("\"{copy}\""),
                None => "null".to_string(),
            };
            format!(
                "{{\"schema_version\":1,\"product\":{{\"name\":\"runner-manager\",\
                 \"version\":\"{installed}\",\"service_binary_version\":{service}}},\
                 \"credential\":{{\"present\":{},\"unreadable\":null,\
                 \"store_scope\":\"machine\"}},\"host\":{{\"capacity\":{}}}}}",
                self.credential.is_some(),
                self.capacity
            )
        }
    }

    /// A request the model has no answer for. It fails, so that a command the
    /// product starts running is a divergence rather than a silent success.
    fn unmodelled(program: &str, arguments: &[&str]) -> CommandOutput {
        CommandOutput::exited(
            127,
            "",
            format!(
                "fixture: `{program} {}` is not modelled by the WSL chain corpus",
                arguments.join(" ")
            ),
        )
    }

    /// One registered scheduled task.
    #[derive(Clone, PartialEq, Eq)]
    struct ModelTask {
        document: String,
        running: bool,
    }

    impl fmt::Debug for ModelTask {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ModelTask")
                .field("owned", &self.document.contains(PRODUCT_MARKER))
                .field("running", &self.running)
                .finish_non_exhaustive()
        }
    }

    /// Everything the scripted workstation holds, on both sides of the
    /// Windows/Linux boundary.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct HostModel {
        distros: Vec<Distro>,
        tasks: BTreeMap<String, ModelTask>,
    }

    impl HostModel {
        fn distro(&self, name: &str) -> Option<&Distro> {
            self.distros.iter().find(|distro| distro.name == name)
        }

        fn distro_mut(&mut self, name: &str) -> Option<&mut Distro> {
            self.distros.iter_mut().find(|distro| distro.name == name)
        }

        fn answer(&mut self, program: &str, arguments: &[String], stdin: &[u8]) -> CommandOutput {
            let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
            match program {
                "wsl.exe" => self.wsl(&arguments, stdin),
                "schtasks.exe" => self.schtasks(&arguments),
                _ => unmodelled(program, &arguments),
            }
        }

        /// `wsl --list --verbose`, with the first distribution as the default.
        fn table(&self) -> String {
            let mut table = String::from("  NAME      STATE     VERSION\n");
            for (index, distro) in self.distros.iter().enumerate() {
                let marker = if index == 0 { '*' } else { ' ' };
                table.push_str(&format!(
                    "{marker} {}   Running   {}\n",
                    distro.name, distro.wsl_version
                ));
            }
            table
        }

        fn wsl(&mut self, arguments: &[&str], stdin: &[u8]) -> CommandOutput {
            if arguments == ["--list", "--verbose"] {
                return ok(&self.table());
            }
            let [
                "--distribution",
                name,
                "--user",
                "root",
                "--exec",
                program,
                rest @ ..,
            ] = arguments
            else {
                return unmodelled("wsl.exe", arguments);
            };
            let names: Vec<String> = self
                .distros
                .iter()
                .map(|distro| distro.name.clone())
                .collect();
            match self.distro_mut(name) {
                Some(distro) => distro.run(program, rest, stdin, &names),
                // WSL's own answer. Matched exactly, as `wsl.exe` matches.
                None => refused("There is no distribution with the supplied name."),
            }
        }

        fn schtasks(&mut self, arguments: &[&str]) -> CommandOutput {
            match arguments {
                ["/Query", "/TN", name, "/XML", "ONE"] => match self.tasks.get(*name) {
                    Some(task) => ok(&task.document),
                    None => absent(),
                },
                ["/Query", "/TN", name, "/FO", "CSV", "/NH"] => match self.tasks.get(*name) {
                    Some(task) => ok(&format!(
                        "\"\\{name}\",\"N/A\",\"{}\"\n",
                        if task.running { "Running" } else { "Ready" }
                    )),
                    None => absent(),
                },
                ["/Create", "/TN", name, "/XML", document, "/F"] => match std::fs::read(document) {
                    Ok(bytes) => {
                        let running = self.tasks.get(*name).is_some_and(|task| task.running);
                        self.tasks.insert(
                            (*name).to_string(),
                            ModelTask {
                                document: decode_console_output(&bytes).into_text(),
                                running,
                            },
                        );
                        ok("SUCCESS: The scheduled task has successfully been created.\n")
                    }
                    Err(error) => refused(&format!("ERROR: {error}")),
                },
                ["/Run", "/TN", name] => match self.tasks.get_mut(*name) {
                    Some(task) => {
                        task.running = true;
                        ok("SUCCESS: Attempted to run the scheduled task.\n")
                    }
                    None => absent(),
                },
                ["/End", "/TN", name] => match self.tasks.get_mut(*name) {
                    Some(task) => {
                        task.running = false;
                        ok("SUCCESS: The scheduled task was terminated.\n")
                    }
                    None => absent(),
                },
                ["/Delete", "/TN", name, "/F"] => match self.tasks.remove(*name) {
                    Some(_) => ok("SUCCESS: The scheduled task was successfully deleted.\n"),
                    None => absent(),
                },
                _ => unmodelled("schtasks.exe", arguments),
            }
        }
    }

    /// The answer a [`ScriptedRunner`] gives when no rule claimed a request,
    /// which hands the request to the host model.
    fn the_model_answers() -> CommandOutput {
        CommandOutput::exited(i32::MIN, "<answered by the WSL chain host model>", "")
    }

    /// The [`CommandRunner`] a chain's workstation runs on: recorded and
    /// injected by the script, answered by the model, journaled either way.
    #[derive(Debug, Clone)]
    struct ModelledControls {
        script: Arc<ScriptedRunner>,
        model: Arc<Mutex<HostModel>>,
        journal: Journal,
    }

    impl ModelledControls {
        fn model(&self) -> std::sync::MutexGuard<'_, HostModel> {
            self.model
                .lock()
                .expect("the host model is not shared across a panic")
        }
    }

    impl CommandRunner for ModelledControls {
        fn run(&self, request: &CommandRequest) -> Result<CommandOutput, WslError> {
            self.journal.note(normalised_line(request));
            let scripted = self.script.run(request)?;
            if scripted != the_model_answers() {
                return Ok(scripted);
            }
            // The script recorded this request a moment ago; its stdin is the
            // one door the model reads a credential through.
            let stdin = self
                .script
                .recorded()
                .last()
                .map(|recorded| recorded.stdin.clone())
                .unwrap_or_default();
            let program = request
                .program()
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(self
                .model()
                .answer(&program, &request.argument_strings(), &stdin))
        }
    }

    /// One journal line for a request: the program's file name and its
    /// arguments, with the two values that differ per run replaced by a
    /// placeholder, so that a history can be compared literally.
    fn normalised_line(request: &CommandRequest) -> String {
        let mut line = request
            .program()
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut previous = String::new();
        for argument in request.argument_strings() {
            line.push(' ');
            if previous == "/XML" && argument != "ONE" {
                line.push_str("<task-document>");
            } else {
                line.push_str(&without_staging_token(&argument));
            }
            previous = argument;
        }
        line
    }

    /// Replaces the random staging token the binary installer picks.
    fn without_staging_token(argument: &str) -> String {
        const MARK: &str = ".runner-manager-install-";
        let Some(at) = argument.find(MARK) else {
            return argument.to_string();
        };
        let start = at + MARK.len();
        let token = argument[start..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .count();
        format!(
            "{}<token>{}",
            &argument[..start],
            &argument[start + token..]
        )
    }

    // -----------------------------------------------------------------------
    // Cases
    // -----------------------------------------------------------------------

    /// What a case exists to cover. The inventory test requires every one of
    /// these to be covered by at least one case.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Covers {
        Fresh,
        Adopted,
        Healthy,
        Drifted,
        Partial,
        Detached,
        Reattached,
        ExactName,
        Capacity,
        Convergence,
        Failure(Stage),
        Bounded,
        Canary,
        Proxy,
    }

    /// Everything a case must cover between them.
    fn required_coverage() -> Vec<Covers> {
        let mut required = vec![
            Covers::Fresh,
            Covers::Adopted,
            Covers::Healthy,
            Covers::Drifted,
            Covers::Partial,
            Covers::Detached,
            Covers::Reattached,
            Covers::ExactName,
            Covers::Capacity,
            Covers::Convergence,
            Covers::Bounded,
            Covers::Canary,
            Covers::Proxy,
        ];
        required.extend(Stage::ALL.iter().copied().map(Covers::Failure));
        required
    }

    /// A rule injected in front of the host model.
    #[derive(Clone)]
    struct Injection {
        needle: String,
        responses: Vec<CommandOutput>,
    }

    /// A case's starting workstation.
    #[derive(Clone, Default)]
    struct World {
        host: HostModel,
        /// Provider records already on this machine: distribution, version.
        records: Vec<(String, String)>,
        injections: Vec<Injection>,
        asset_refusals: usize,
        issuer_refusals: usize,
        tampered_archive: bool,
    }

    /// Written by hand so a divergence report does not print a 64 KiB
    /// injected stderr as a list of bytes.
    impl fmt::Debug for World {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let injections: Vec<String> = self
                .injections
                .iter()
                .map(|injection| {
                    format!(
                        "{:?} answered by {} scripted response(s), then the host model",
                        injection.needle,
                        injection.responses.len().saturating_sub(1)
                    )
                })
                .collect();
            f.debug_struct("World")
                .field("host", &self.host)
                .field("records", &self.records)
                .field("injections", &injections)
                .field("asset_refusals", &self.asset_refusals)
                .field("issuer_refusals", &self.issuer_refusals)
                .field("tampered_archive", &self.tampered_archive)
                .finish()
        }
    }

    impl World {
        fn with(distros: impl IntoIterator<Item = Distro>) -> Self {
            Self {
                host: HostModel {
                    distros: distros.into_iter().collect(),
                    tasks: BTreeMap::new(),
                },
                ..Self::default()
            }
        }

        /// A task already registered under `distribution`'s derived name.
        fn task(mut self, distribution: &str, document: String) -> Self {
            self.host.tasks.insert(
                task_name(distribution),
                ModelTask {
                    document,
                    running: false,
                },
            );
            self
        }

        /// A provider record already on this machine, naming `installed`.
        fn record(mut self, distribution: &str, installed: &str) -> Self {
            self.records
                .push((distribution.to_string(), installed.to_string()));
            self
        }

        /// Answers the first matching requests with `failures`, then hands
        /// every later match back to the host model.
        fn inject(mut self, needle: &str, mut failures: Vec<CommandOutput>) -> Self {
            failures.push(the_model_answers());
            self.injections.push(Injection {
                needle: needle.to_string(),
                responses: failures,
            });
            self
        }

        /// Answers every matching request with `response`.
        fn inject_always(mut self, needle: &str, response: CommandOutput) -> Self {
            self.injections.push(Injection {
                needle: needle.to_string(),
                responses: vec![response],
            });
            self
        }

        fn release_refusing(mut self, times: usize) -> Self {
            self.asset_refusals = times;
            self
        }

        fn sign_in_refusing(mut self, times: usize) -> Self {
            self.issuer_refusals = times;
            self
        }

        fn tampered_archive(mut self) -> Self {
            self.tampered_archive = true;
            self
        }
    }

    /// Something done outside runner-manager, between two of its commands.
    #[derive(Debug, Clone)]
    enum Change {
        ReplaceBinary(&'static str, &'static str),
        LogOut(&'static str),
        DeleteTask(&'static str),
        HoldExits(&'static str),
        CorruptRecord(&'static str),
    }

    /// One step of a chain.
    #[derive(Debug, Clone)]
    enum Action {
        List,
        Install {
            distribution: String,
            capacity: Option<u16>,
        },
        Status {
            distribution: String,
        },
        Detach {
            distribution: String,
        },
        Proxy {
            argv: Vec<String>,
        },
        ByHand(Change),
    }

    impl fmt::Display for Action {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::List => f.write_str("runner-manager wsl list"),
                Self::Install {
                    distribution,
                    capacity,
                } => {
                    write!(
                        f,
                        "runner-manager wsl install --distribution {distribution:?}"
                    )?;
                    match capacity {
                        Some(capacity) => write!(f, " --capacity {capacity}"),
                        None => Ok(()),
                    }
                }
                Self::Status { distribution } => {
                    write!(
                        f,
                        "runner-manager wsl status --distribution {distribution:?}"
                    )
                }
                Self::Detach { distribution } => {
                    write!(
                        f,
                        "runner-manager wsl detach --distribution {distribution:?}"
                    )
                }
                Self::Proxy { argv } => f.write_str(&argv.join(" ")),
                Self::ByHand(change) => write!(f, "(by hand, outside runner-manager) {change:?}"),
            }
        }
    }

    fn list() -> Action {
        Action::List
    }

    fn install(distribution: &str, capacity: Option<u16>) -> Action {
        Action::Install {
            distribution: distribution.to_string(),
            capacity,
        }
    }

    fn status(distribution: &str) -> Action {
        Action::Status {
            distribution: distribution.to_string(),
        }
    }

    fn detach(distribution: &str) -> Action {
        Action::Detach {
            distribution: distribution.to_string(),
        }
    }

    fn proxy(argv: &[&str]) -> Action {
        Action::Proxy {
            argv: argv.iter().map(ToString::to_string).collect(),
        }
    }

    fn by_hand(change: Change) -> Action {
        Action::ByHand(change)
    }

    /// How a command ended.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Outcome {
        Succeeded,
        Failed(Failure),
        /// A proxied child's own exit code.
        Exited(i32),
    }

    impl fmt::Display for Outcome {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Succeeded => f.write_str("exit 0"),
                Self::Failed(class) => {
                    write!(f, "failure `{}` (exit {})", class.as_str(), class.code())
                }
                Self::Exited(code) => write!(f, "the proxied child's exit {code}"),
            }
        }
    }

    /// A fact about the host model after a step.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Fact {
        Binary(Option<String>),
        Credential(Option<String>),
        Received(usize),
        Capacity(u16),
        Unit { enabled: bool, active: bool },
        ServiceCopy(Option<String>),
        Task(Option<TaskFact>),
        Staging(usize),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TaskFact {
        owned: bool,
        running: bool,
    }

    fn binary(installed: &str) -> Fact {
        Fact::Binary(Some(installed.to_string()))
    }

    fn no_binary() -> Fact {
        Fact::Binary(None)
    }

    fn credential_of(owner: &str) -> Fact {
        Fact::Credential(Some(owner.to_string()))
    }

    fn no_credential() -> Fact {
        Fact::Credential(None)
    }

    fn our_task(running: bool) -> Fact {
        Fact::Task(Some(TaskFact {
            owned: true,
            running,
        }))
    }

    fn no_task() -> Fact {
        Fact::Task(None)
    }

    fn foreign_task() -> Fact {
        Fact::Task(Some(TaskFact {
            owned: false,
            running: false,
        }))
    }

    /// Everything one step must show. Built before the step runs.
    #[derive(Debug, Clone)]
    struct Expect {
        outcome: Outcome,
        healthy: Option<bool>,
        drift: Option<bool>,
        capacity: Option<Option<u16>>,
        says: Vec<String>,
        complains: Vec<String>,
        runs: Vec<String>,
        never: Vec<String>,
        exactly: Option<Vec<String>>,
        argv: Vec<Vec<String>>,
        records: Vec<(String, bool)>,
        linux: Vec<(String, Fact)>,
        /// Requests whose stdin carried a credential.
        credentials: usize,
        output_ceiling: usize,
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    impl Expect {
        fn ending(outcome: Outcome) -> Self {
            Self {
                outcome,
                healthy: None,
                drift: None,
                capacity: None,
                says: Vec::new(),
                complains: Vec::new(),
                runs: Vec::new(),
                never: Vec::new(),
                exactly: None,
                argv: Vec::new(),
                records: Vec::new(),
                linux: Vec::new(),
                credentials: 0,
                output_ceiling: OUTPUT_CEILING,
            }
        }

        fn succeeds() -> Self {
            Self::ending(Outcome::Succeeded)
        }

        fn fails(class: Failure) -> Self {
            Self::ending(Outcome::Failed(class))
        }

        fn exits(code: i32) -> Self {
            Self::ending(Outcome::Exited(code))
        }

        fn healthy(mut self, healthy: bool) -> Self {
            self.healthy = Some(healthy);
            self
        }

        fn drift(mut self, drift: bool) -> Self {
            self.drift = Some(drift);
            self
        }

        fn capacity(mut self, capacity: u16) -> Self {
            self.capacity = Some(Some(capacity));
            self
        }

        fn says(mut self, fragments: &[&str]) -> Self {
            self.says.extend(strings(fragments));
            self
        }

        fn complains(mut self, fragments: &[&str]) -> Self {
            self.complains.extend(strings(fragments));
            self
        }

        fn runs(mut self, needles: &[&str]) -> Self {
            self.runs.extend(strings(needles));
            self
        }

        fn never(mut self, needles: &[&str]) -> Self {
            self.never.extend(strings(needles));
            self
        }

        fn exactly(mut self, lines: Vec<String>) -> Self {
            self.exactly = Some(lines);
            self
        }

        fn nothing_runs(self) -> Self {
            self.exactly(Vec::new())
        }

        fn argv(mut self, argv: &[&str]) -> Self {
            self.argv.push(strings(argv));
            self
        }

        fn record(mut self, distribution: &str, present: bool) -> Self {
            self.records.push((distribution.to_string(), present));
            self
        }

        fn linux(mut self, distribution: &str, fact: Fact) -> Self {
            self.linux.push((distribution.to_string(), fact));
            self
        }

        fn credentials(mut self, crossings: usize) -> Self {
            self.credentials = crossings;
            self
        }

        fn output_ceiling(mut self, bytes: usize) -> Self {
            self.output_ceiling = bytes;
            self
        }
    }

    /// One named, replayable chain.
    #[derive(Debug, Clone)]
    struct Case {
        id: &'static str,
        title: &'static str,
        covers: &'static [Covers],
        world: World,
        steps: Vec<(Action, Expect)>,
    }

    // -----------------------------------------------------------------------
    // Expectation vocabulary shared by many cases
    // -----------------------------------------------------------------------

    fn product(command: &str) -> String {
        format!("{LINUX_BINARY} {command}")
    }

    fn wsl_line(distribution: &str, command: &str) -> String {
        format!("wsl.exe {}", inside(distribution, command))
    }

    fn schtasks_line(arguments: &str) -> String {
        format!("schtasks.exe {arguments}")
    }

    /// The exact history of `wsl status` over a distribution that is ready.
    fn status_history(distribution: &str, task_registered: bool) -> Vec<String> {
        let name = task_name(distribution);
        let mut lines = vec![
            "wsl.exe --list --verbose".to_string(),
            wsl_line(distribution, "id -u"),
            wsl_line(distribution, "uname -m"),
            wsl_line(distribution, "systemctl is-system-running"),
            wsl_line(distribution, &product("status --json")),
            wsl_line(distribution, &format!("systemctl is-enabled {UNIT}")),
            wsl_line(distribution, &format!("systemctl is-active {UNIT}")),
            wsl_line(distribution, "docker info --format {{.ServerVersion}}"),
            schtasks_line(&format!("/Query /TN {name} /XML ONE")),
        ];
        if task_registered {
            lines.push(schtasks_line(&format!("/Query /TN {name} /FO CSV /NH")));
        }
        lines
    }

    /// The exact history of `wsl status` over a distribution the preflight
    /// refuses: nothing inside it is asked.
    fn refused_status_history(distribution: &str, asked_inside: &[&str]) -> Vec<String> {
        let mut lines = vec!["wsl.exe --list --verbose".to_string()];
        lines.extend(
            asked_inside
                .iter()
                .map(|command| wsl_line(distribution, command)),
        );
        lines.push("wsl.exe --list --verbose".to_string());
        lines.push(schtasks_line(&format!(
            "/Query /TN {} /XML ONE",
            task_name(distribution)
        )));
        lines
    }

    /// The exact history of `wsl detach` over a registered task.
    fn detach_history(distribution: &str, running: bool) -> Vec<String> {
        let name = task_name(distribution);
        let mut lines = vec![
            schtasks_line(&format!("/Query /TN {name} /XML ONE")),
            schtasks_line(&format!("/Query /TN {name} /FO CSV /NH")),
        ];
        if running {
            lines.push(schtasks_line(&format!("/End /TN {name}")));
        }
        lines.extend([
            schtasks_line(&format!("/Query /TN {name} /XML ONE")),
            schtasks_line(&format!("/Query /TN {name} /FO CSV /NH")),
            schtasks_line(&format!("/Delete /TN {name} /F")),
        ]);
        lines
    }

    /// `wsl detach` over a distribution with no task at all.
    fn detach_nothing_history(distribution: &str) -> Vec<String> {
        let line = schtasks_line(&format!("/Query /TN {} /XML ONE", task_name(distribution)));
        vec![line.clone(), line]
    }

    /// Every stage of a first install, in the order `02-target-architecture.md`
    /// fixes, as the history shows it.
    fn fresh_order(distribution: &str, capacity: Option<u16>) -> Vec<String> {
        let name = task_name(distribution);
        let mut order = vec![
            "wsl.exe --list --verbose".to_string(),
            inside(distribution, "id -u"),
            inside(distribution, "uname -m"),
            inside(distribution, "systemctl is-system-running"),
            schtasks_line(&format!("/Query /TN {name} /XML ONE")),
            "assets SHA256SUMS".to_string(),
            "assets download".to_string(),
            inside(distribution, &product("status --json")),
            inside(distribution, "mkdir -m 0700"),
            inside(distribution, "tar -xzf -"),
            inside(distribution, "chmod 0755"),
            format!("{TRIPLE}/runner-manager --version"),
            inside(distribution, "mv -T"),
            inside(distribution, "rm -rf"),
            format!("device flow for {distribution}"),
            inside(distribution, &product("auth receive --start-at boot")),
        ];
        if let Some(capacity) = capacity {
            order.push(inside(
                distribution,
                &product(&format!("host set-capacity {capacity}")),
            ));
        }
        order.extend([
            inside(distribution, &product("service install --start-at boot")),
            inside(distribution, &format!("systemctl start {UNIT}")),
            schtasks_line(&format!("/Create /TN {name}")),
            schtasks_line(&format!("/Run /TN {name}")),
            inside(distribution, "docker info"),
        ]);
        order
    }

    fn runs_all(mut expect: Expect, needles: &[String]) -> Expect {
        expect.runs.extend(needles.iter().cloned());
        expect
    }

    /// A first install that provisions a healthy host.
    fn provisioned(distribution: &str, capacity: Option<u16>) -> Expect {
        let settled = capacity.unwrap_or(crate::cli::DEFAULT_HOST_CAPACITY);
        let report_capacity = match capacity {
            Some(capacity) => format!("set to {capacity}"),
            None => "unchanged (none was supplied)".to_string(),
        };
        runs_all(
            Expect::succeeds()
                .healthy(true)
                .drift(false)
                .capacity(settled)
                .credentials(1)
                .record(distribution, true)
                .says(&[
                    &format!("Installing runner-manager-{}-{TRIPLE}.tar.gz", version()),
                    &format!("installed {}", version()),
                    "issued independently and delivered on a pipe",
                    &report_capacity,
                    "Linux service installed and started at boot.",
                    &format!("{distribution} is a healthy managed runner host."),
                ])
                .linux(distribution, binary(version()))
                .linux(distribution, credential_of(distribution))
                .linux(distribution, Fact::Received(1))
                .linux(distribution, Fact::Capacity(settled))
                .linux(
                    distribution,
                    Fact::Unit {
                        enabled: true,
                        active: true,
                    },
                )
                .linux(distribution, Fact::ServiceCopy(Some(version().to_string())))
                .linux(distribution, our_task(true))
                .linux(distribution, Fact::Staging(0)),
            &fresh_order(distribution, capacity),
        )
    }

    /// A rerun over a host that is already what it should be.
    fn converged(distribution: &str) -> Expect {
        Expect::succeeds()
            .healthy(true)
            .drift(false)
            .record(distribution, true)
            .says(&[
                &format!(
                    "{distribution} already runs runner-manager {}; the binary is left alone.",
                    version()
                ),
                "already holds its own credential; it is left untouched.",
                "the distribution's existing one was preserved",
                "it is adopted rather than reinstalled",
            ])
            .never(&[
                "device flow",
                "auth receive",
                "mkdir",
                "mv -T",
                "service install",
                "host set-capacity",
                "systemctl start",
                "systemctl stop",
                "systemctl enable",
            ])
            .runs(&["/Create /TN", "/Run /TN"])
    }

    /// A failure after the preflight: what landed stands, and a rerun is safe.
    fn stage_failed(class: Failure, stage: Stage) -> Expect {
        Expect::fails(class).complains(&[
            &format!("the {} stage failed", stage.label()),
            "`wsl install` is safe to run again once this is fixed",
        ])
    }

    /// A preflight refusal: nothing changed and nobody was sent to a browser.
    fn preflight_refused(class: Failure) -> Expect {
        Expect::fails(class)
            .complains(&[
                "preflight failed, so nothing has been changed and no credential was issued",
            ])
            .never(&[
                "assets",
                "device flow",
                "mkdir",
                "auth receive",
                "/Create",
                "/Delete",
            ])
    }

    /// A lifecycle task somebody made by hand under the derived name.
    fn hand_made_task_xml(distribution: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
             <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n  \
             <RegistrationInfo>\n    <Description>Keeps {distribution} awake. Made by hand.</Description>\n  \
             </RegistrationInfo>\n  <Actions Context=\"Author\">\n    <Exec>\n      \
             <Command>wsl.exe</Command>\n      <Arguments>-d {distribution} -- sleep infinity</Arguments>\n    \
             </Exec>\n  </Actions>\n</Task>\n"
        )
    }

    // -----------------------------------------------------------------------
    // The corpus
    // -----------------------------------------------------------------------

    /// Every case, in identifier order. Append; never renumber.
    #[allow(
        clippy::too_many_lines,
        reason = "the corpus is data, one case per block"
    )]
    fn corpus() -> Vec<Case> {
        let v = version();
        vec![
            Case {
                id: "wsl-0001",
                title: "list names an unmanaged distribution and claims nothing",
                covers: &[Covers::Fresh, Covers::Bounded],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![(
                    list(),
                    Expect::succeeds()
                        .says(&[
                            "Ubuntu  WSL2, Running, default (not managed)",
                            "Names are matched exactly.",
                        ])
                        .exactly(strings(&["wsl.exe --list --verbose"]))
                        .record(UBUNTU, false),
                )],
            },
            Case {
                id: "wsl-0002",
                title: "list on a machine with no distributions says so plainly",
                covers: &[Covers::Fresh, Covers::Bounded],
                world: World::with([]),
                steps: vec![(
                    list(),
                    Expect::succeeds()
                        .says(&["This machine has no WSL distributions installed."])
                        .exactly(strings(&["wsl.exe --list --verbose"])),
                )],
            },
            Case {
                id: "wsl-0003",
                title: "a fresh install with a capacity provisions a healthy host in the documented order",
                covers: &[
                    Covers::Fresh,
                    Covers::Healthy,
                    Covers::Capacity,
                    Covers::Canary,
                ],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        list(),
                        Expect::succeeds()
                            .says(&[&format!(
                                "Ubuntu  WSL2, Running, default (managed, runner-manager {v})"
                            )])
                            .exactly(strings(&["wsl.exe --list --verbose"])),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(true)
                            .drift(false)
                            .capacity(8)
                            .says(&[
                                "\"schema_version\": 1",
                                "after the owning Windows account logs on",
                                "Ubuntu is a healthy managed runner host.",
                            ])
                            .exactly(status_history(UBUNTU, true)),
                    ),
                ],
            },
            Case {
                id: "wsl-0004",
                title: "a fresh install without a capacity leaves the Linux default alone",
                covers: &[Covers::Fresh, Covers::Capacity],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![(
                    install(UBUNTU, None),
                    provisioned(UBUNTU, None).never(&["host set-capacity"]),
                )],
            },
            Case {
                id: "wsl-0005",
                title: "a second install over a healthy host converges and changes nothing",
                covers: &[Covers::Healthy, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        install(UBUNTU, None),
                        converged(UBUNTU)
                            .capacity(8)
                            .linux(UBUNTU, Fact::Received(1))
                            .linux(UBUNTU, Fact::Capacity(8)),
                    ),
                ],
            },
            Case {
                id: "wsl-0006",
                title: "three installs change the capacity only when one is supplied",
                covers: &[Covers::Capacity, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        install(UBUNTU, Some(2)),
                        Expect::succeeds()
                            .healthy(true)
                            .capacity(2)
                            .runs(&[&inside(UBUNTU, &product("host set-capacity 2"))])
                            .never(&["device flow", "mv -T", "service install"])
                            .says(&["Capacity set to 2.", "set to 2"])
                            .linux(UBUNTU, Fact::Capacity(2)),
                    ),
                    (
                        install(UBUNTU, None),
                        converged(UBUNTU)
                            .capacity(2)
                            .linux(UBUNTU, Fact::Capacity(2)),
                    ),
                    (status(UBUNTU), Expect::succeeds().healthy(true).capacity(2)),
                ],
            },
            Case {
                id: "wsl-0007",
                title: "the largest capacity a u16 holds reaches the Linux host verbatim",
                covers: &[Covers::Capacity, Covers::Fresh],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (
                        install(UBUNTU, Some(u16::MAX)),
                        provisioned(UBUNTU, Some(u16::MAX)),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(true)
                            .capacity(u16::MAX)
                            .says(&["capacity                  65535"]),
                    ),
                ],
            },
            Case {
                id: "wsl-0008",
                title: "a zero capacity is refused by the Linux host and a corrected rerun converges",
                covers: &[
                    Covers::Capacity,
                    Covers::Failure(Stage::Capacity),
                    Covers::Partial,
                    Covers::Convergence,
                ],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (
                        install(UBUNTU, Some(0)),
                        stage_failed(Failure::WslProvisioning, Stage::Capacity)
                            .complains(&["a host capacity of 0 is not a configured host"])
                            .credentials(1)
                            .record(UBUNTU, false)
                            .never(&["service install", "/Create"])
                            .linux(UBUNTU, Fact::Capacity(1))
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, binary(v))
                            .linux(
                                UBUNTU,
                                Fact::Unit {
                                    enabled: false,
                                    active: false,
                                },
                            )
                            .linux(UBUNTU, no_task()),
                    ),
                    (
                        install(UBUNTU, Some(4)),
                        Expect::succeeds()
                            .healthy(true)
                            .capacity(4)
                            .record(UBUNTU, true)
                            .never(&["device flow", "auth receive", "mv -T"])
                            .runs(&[
                                &inside(UBUNTU, &product("host set-capacity 4")),
                                &inside(UBUNTU, &product("service install --start-at boot")),
                                "/Create /TN",
                            ])
                            .linux(UBUNTU, Fact::Received(1)),
                    ),
                ],
            },
            Case {
                id: "wsl-0009",
                title: "adoption keeps the binary, credential, capacity and unit a distribution already has",
                covers: &[Covers::Adopted, Covers::Healthy],
                world: World::with([Distro::adopted(UBUNTU, 4)]),
                steps: vec![(
                    install(UBUNTU, None),
                    converged(UBUNTU)
                        .capacity(4)
                        .linux(UBUNTU, credential_of(PREEXISTING))
                        .linux(UBUNTU, Fact::Received(0))
                        .linux(UBUNTU, Fact::Capacity(4))
                        .linux(UBUNTU, our_task(true))
                        .says(&[
                            "is already enabled and active; it is adopted rather than reinstalled",
                        ]),
                )],
            },
            Case {
                id: "wsl-0010",
                title: "an adopted unit that is enabled but inactive is started, not reinstalled",
                covers: &[Covers::Adopted],
                world: World::with([Distro::adopted(UBUNTU, 4).unit(true, false)]),
                steps: vec![(
                    install(UBUNTU, None),
                    Expect::succeeds()
                        .healthy(true)
                        .runs(&[&inside(UBUNTU, &format!("systemctl start {UNIT}"))])
                        .never(&[
                            "service install",
                            "systemctl enable",
                            "device flow",
                            "mv -T",
                        ])
                        .says(&["was already enabled but not active; it was adopted and started"])
                        .linux(
                            UBUNTU,
                            Fact::Unit {
                                enabled: true,
                                active: true,
                            },
                        ),
                )],
            },
            Case {
                id: "wsl-0011",
                title: "an adopted unit that is active but disabled is enabled in place and never stopped",
                covers: &[Covers::Adopted],
                world: World::with([Distro::adopted(UBUNTU, 4).unit(false, true)]),
                steps: vec![(
                    install(UBUNTU, None),
                    Expect::succeeds()
                        .healthy(true)
                        .runs(&[&inside(UBUNTU, &format!("systemctl enable {UNIT}"))])
                        .never(&[
                            "systemctl stop",
                            "service install",
                            "systemctl start",
                            "device flow",
                        ])
                        .says(&["was adopted and enabled at boot"])
                        .linux(
                            UBUNTU,
                            Fact::Unit {
                                enabled: true,
                                active: true,
                            },
                        ),
                )],
            },
            Case {
                id: "wsl-0012",
                title: "a name that differs only in case is not found and changes nothing",
                covers: &[
                    Covers::ExactName,
                    Covers::Failure(Stage::Preflight),
                    Covers::Bounded,
                ],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (
                        install(LOWER_UBUNTU, Some(8)),
                        preflight_refused(Failure::NotFound)
                            .exactly(strings(&["wsl.exe --list --verbose"]))
                            .record(LOWER_UBUNTU, false)
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_binary()),
                    ),
                    (
                        status(LOWER_UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .says(&["ubuntu is not ready to accept jobs"])
                            .exactly(refused_status_history(LOWER_UBUNTU, &[])),
                    ),
                ],
            },
            Case {
                id: "wsl-0013",
                title: "two names that differ only in case are two independent hosts",
                covers: &[Covers::ExactName, Covers::Healthy, Covers::Canary],
                world: World::with([Distro::fresh(UBUNTU), Distro::fresh(LOWER_UBUNTU)]),
                steps: vec![
                    (
                        install(LOWER_UBUNTU, Some(2)),
                        provisioned(LOWER_UBUNTU, Some(2))
                            .never(&["--distribution Ubuntu "])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_binary())
                            .linux(UBUNTU, no_credential()),
                    ),
                    (
                        list(),
                        Expect::succeeds().says(&[
                            &format!("ubuntu  WSL2, Running (managed, runner-manager {v})"),
                            "Ubuntu  WSL2, Running, default (not managed)",
                        ]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .never(&["--distribution ubuntu "])
                            .exactly(status_history(UBUNTU, false)),
                    ),
                ],
            },
            Case {
                id: "wsl-0014",
                title: "a name with spaces and a slash stays one literal argument from install to detach",
                covers: &[Covers::ExactName, Covers::Healthy, Covers::Detached],
                world: World::with([Distro::fresh(SPACED)]),
                steps: vec![
                    (
                        install(SPACED, Some(3)),
                        provisioned(SPACED, Some(3))
                            .argv(&[
                                "--distribution",
                                SPACED,
                                "--user",
                                "root",
                                "--exec",
                                "id",
                                "-u",
                            ])
                            .argv(&[
                                "--distribution",
                                SPACED,
                                "--user",
                                "root",
                                "--exec",
                                LINUX_BINARY,
                                "auth",
                                "receive",
                                "--start-at",
                                "boot",
                            ]),
                    ),
                    (
                        status(SPACED),
                        Expect::succeeds()
                            .healthy(true)
                            .drift(false)
                            .capacity(3)
                            .exactly(status_history(SPACED, true)),
                    ),
                    (
                        detach(SPACED),
                        Expect::succeeds()
                            .record(SPACED, false)
                            .says(&["Nothing inside Debian GNU/Linux 12 was changed"])
                            .exactly(detach_history(SPACED, true))
                            .linux(SPACED, no_task())
                            .linux(SPACED, binary(v)),
                    ),
                ],
            },
            Case {
                id: "wsl-0015",
                title: "a name that reads as an option or carries whitespace is refused before anything starts",
                covers: &[
                    Covers::ExactName,
                    Covers::Failure(Stage::Preflight),
                    Covers::Bounded,
                ],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (
                        install("--shutdown", Some(8)),
                        preflight_refused(Failure::InvalidArgument)
                            .complains(&["starts with `-`"])
                            .nothing_runs(),
                    ),
                    (
                        install(" Ubuntu", None),
                        preflight_refused(Failure::InvalidArgument)
                            .complains(&["starts or ends with whitespace"])
                            .nothing_runs(),
                    ),
                    (
                        status("--shutdown"),
                        Expect::fails(Failure::InvalidArgument).nothing_runs(),
                    ),
                    (
                        detach("--shutdown"),
                        Expect::fails(Failure::InvalidArgument).nothing_runs(),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl:--shutdown", "repo", "list"]),
                        Expect::fails(Failure::InvalidArgument)
                            .complains(&["starts with `-`"])
                            .nothing_runs(),
                    ),
                ],
            },
            Case {
                id: "wsl-0016",
                title: "a WSL1 distribution is listed, refused at the preflight, and reported by status",
                covers: &[Covers::Failure(Stage::Preflight), Covers::Bounded],
                world: World::with([Distro::fresh(LEGACY).wsl1()]),
                steps: vec![
                    (
                        list(),
                        Expect::succeeds().says(&["Legacy  WSL1, Running, default (not managed)"]),
                    ),
                    (
                        install(LEGACY, Some(8)),
                        preflight_refused(Failure::UnsupportedHost)
                            .exactly(strings(&["wsl.exe --list --verbose"]))
                            .record(LEGACY, false),
                    ),
                    (
                        status(LEGACY),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .says(&["Legacy is not ready to accept jobs"])
                            .exactly(refused_status_history(LEGACY, &[])),
                    ),
                ],
            },
            Case {
                id: "wsl-0017",
                title: "a distribution without systemd is refused before anything is downloaded",
                covers: &[Covers::Failure(Stage::Preflight)],
                world: World::with([Distro::fresh(UBUNTU).systemd("offline")]),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        preflight_refused(Failure::UnsupportedHost)
                            .runs(&["systemctl is-system-running"])
                            .never(&["/XML ONE"]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .exactly(refused_status_history(
                                UBUNTU,
                                &["id -u", "uname -m", "systemctl is-system-running"],
                            )),
                    ),
                ],
            },
            Case {
                id: "wsl-0018",
                title: "an architecture the release does not publish is refused before systemd is asked",
                covers: &[Covers::Failure(Stage::Preflight)],
                world: World::with([Distro::fresh(UBUNTU).machine("armv7l")]),
                steps: vec![(
                    install(UBUNTU, Some(8)),
                    preflight_refused(Failure::UnsupportedHost)
                        .runs(&["uname -m"])
                        .never(&["is-system-running"])
                        .complains(&["armv7l"]),
                )],
            },
            Case {
                id: "wsl-0019",
                title: "a distribution that will not run commands as root is refused at the first question",
                covers: &[Covers::Failure(Stage::Preflight)],
                world: World::with([Distro::fresh(UBUNTU).not_root()]),
                steps: vec![(
                    install(UBUNTU, Some(8)),
                    preflight_refused(Failure::UnsupportedHost)
                        .runs(&["id -u"])
                        .never(&["uname -m"]),
                )],
            },
            Case {
                id: "wsl-0020",
                title: "a hand-made task under the derived name stops install and detach and is never touched",
                covers: &[Covers::Failure(Stage::Preflight), Covers::Fresh],
                world: World::with([Distro::fresh(UBUNTU)])
                    .task(UBUNTU, hand_made_task_xml(UBUNTU)),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        preflight_refused(Failure::Conflict)
                            .complains(&["does not identify it as this product's"])
                            .runs(&["/XML ONE"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, foreign_task())
                            .linux(UBUNTU, no_binary()),
                    ),
                    (
                        detach(UBUNTU),
                        Expect::fails(Failure::Conflict)
                            .never(&["/End", "/Delete"])
                            .linux(UBUNTU, foreign_task()),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .says(&["is NOT this product's"]),
                    ),
                ],
            },
            Case {
                id: "wsl-0021",
                title: "an unreachable release fails the artifact stage before anything lands and a rerun converges",
                covers: &[Covers::Failure(Stage::Artifact), Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]).release_refusing(1),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::GithubUnavailable, Stage::Artifact)
                            .complains(&["the fixture release is unreachable"])
                            .runs(&["assets SHA256SUMS"])
                            .never(&["assets download", "mkdir", "device flow", "/Create"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_binary()),
                    ),
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                ],
            },
            Case {
                id: "wsl-0022",
                title: "an archive its checksum does not describe never crosses into the distribution",
                covers: &[Covers::Failure(Stage::Binary)],
                world: World::with([Distro::fresh(UBUNTU)]).tampered_archive(),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::UnusableResponse, Stage::Binary)
                            .runs(&["assets download"])
                            .never(&["mkdir", "tar -xzf", "mv -T", "device flow"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_binary()),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::UnusableResponse, Stage::Binary)
                            .never(&["mkdir", "tar -xzf", "mv -T", "device flow"])
                            .linux(UBUNTU, no_binary()),
                    ),
                ],
            },
            Case {
                id: "wsl-0023",
                title: "a failed rename leaves no binary and no staging, and a rerun converges",
                covers: &[Covers::Failure(Stage::Binary), Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]).inject(
                    "mv -T",
                    vec![refused("mv: cannot move: Read-only file system")],
                ),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::WslProvisioning, Stage::Binary)
                            .complains(&["Read-only file system"])
                            .runs(&["tar -xzf -", "mv -T", "rm -rf"])
                            .never(&["device flow", "auth receive"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_binary())
                            .linux(UBUNTU, Fact::Staging(0)),
                    ),
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                ],
            },
            Case {
                id: "wsl-0024",
                title: "a staged binary that reports another version is never moved into place",
                covers: &[Covers::Failure(Stage::Binary)],
                world: World::with([Distro::fresh(UBUNTU)]).inject_always(
                    &format!("{TRIPLE}/runner-manager --version"),
                    ok(&format!("runner-manager {OLDER}\n")),
                ),
                steps: vec![(
                    install(UBUNTU, Some(8)),
                    stage_failed(Failure::UnusableResponse, Stage::Binary)
                        .runs(&["chmod 0755", "--version", "rm -rf"])
                        .never(&["mv -T", "device flow"])
                        .linux(UBUNTU, no_binary())
                        .linux(UBUNTU, Fact::Staging(0)),
                )],
            },
            Case {
                id: "wsl-0025",
                title: "a declined sign-in leaves the landed binary and a rerun issues exactly one credential",
                covers: &[
                    Covers::Failure(Stage::Credential),
                    Covers::Partial,
                    Covers::Convergence,
                    Covers::Canary,
                ],
                world: World::with([Distro::fresh(UBUNTU)]).sign_in_refusing(1),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::AuthenticationDeclined, Stage::Credential)
                            .complains(&["closed the browser"])
                            .runs(&["mv -T", "device flow for Ubuntu"])
                            .never(&[
                                "auth receive",
                                "host set-capacity",
                                "service install",
                                "/Create",
                            ])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, binary(v))
                            .linux(UBUNTU, no_credential()),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .says(&["none: this host has not been signed in"]),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        Expect::succeeds()
                            .healthy(true)
                            .credentials(1)
                            .record(UBUNTU, true)
                            .never(&["mv -T"])
                            .runs(&["device flow for Ubuntu", "auth receive --start-at boot"])
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, Fact::Received(1)),
                    ),
                ],
            },
            Case {
                id: "wsl-0026",
                title: "a refused credential handoff names no secret and a rerun delivers it once",
                covers: &[
                    Covers::Failure(Stage::Credential),
                    Covers::Canary,
                    Covers::Convergence,
                ],
                world: World::with([Distro::fresh(UBUNTU)]).inject(
                    "auth receive",
                    vec![refused("auth receive: the machine store is locked")],
                ),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::SecretStore, Stage::Credential)
                            .complains(&["the machine store is locked"])
                            .credentials(1)
                            .never(&["host set-capacity", "service install"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_credential())
                            .linux(UBUNTU, Fact::Received(0)),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        Expect::succeeds()
                            .healthy(true)
                            .credentials(1)
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, Fact::Received(1)),
                    ),
                ],
            },
            Case {
                id: "wsl-0027",
                title: "a capacity stage failure keeps the delivered credential and a rerun signs in no more",
                covers: &[Covers::Failure(Stage::Capacity), Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]).inject(
                    "host set-capacity",
                    vec![refused("cannot open the policy database")],
                ),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::WslProvisioning, Stage::Capacity)
                            .complains(&["cannot open the policy database"])
                            .credentials(1)
                            .never(&["service install"])
                            .linux(UBUNTU, Fact::Capacity(1))
                            .linux(UBUNTU, credential_of(UBUNTU)),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        Expect::succeeds()
                            .healthy(true)
                            .capacity(8)
                            .never(&["device flow", "auth receive"])
                            .runs(&["host set-capacity 8"])
                            .linux(UBUNTU, Fact::Capacity(8)),
                    ),
                ],
            },
            Case {
                id: "wsl-0028",
                title: "a Linux service stage failure is repaired by the rerun without a second credential",
                covers: &[Covers::Failure(Stage::Service), Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]).inject(
                    "service install --start-at boot",
                    vec![refused("Failed to connect to bus")],
                ),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::WslProvisioning, Stage::Service)
                            .complains(&["Failed to connect to bus"])
                            .credentials(1)
                            .never(&["/Create", "systemctl start"])
                            .record(UBUNTU, false)
                            .linux(
                                UBUNTU,
                                Fact::Unit {
                                    enabled: false,
                                    active: false,
                                },
                            ),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        Expect::succeeds()
                            .healthy(true)
                            .never(&["device flow", "auth receive", "mv -T"])
                            .runs(&[
                                "service install --start-at boot",
                                "systemctl start",
                                "/Create /TN",
                            ])
                            .record(UBUNTU, true),
                    ),
                ],
            },
            Case {
                id: "wsl-0029",
                title: "a refused lifecycle task leaves no record and the rerun registers it",
                covers: &[Covers::Failure(Stage::LifecycleTask), Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)])
                    .inject("/Create /TN", vec![refused("ERROR: Access is denied.")]),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::WslProvisioning, Stage::LifecycleTask)
                            .credentials(1)
                            .never(&["/Run /TN"])
                            .record(UBUNTU, false)
                            .linux(UBUNTU, no_task()),
                    ),
                    (
                        install(UBUNTU, Some(8)),
                        Expect::succeeds()
                            .healthy(true)
                            .record(UBUNTU, true)
                            .never(&["device flow", "mv -T", "service install"])
                            .runs(&["/Create /TN", "/Run /TN"])
                            .linux(UBUNTU, our_task(true)),
                    ),
                ],
            },
            Case {
                id: "wsl-0030",
                title: "a unit that never stays up is a partial host whose record still lets detach clean up",
                covers: &[
                    Covers::Failure(Stage::Verification),
                    Covers::Partial,
                    Covers::Detached,
                ],
                world: World::with([Distro::fresh(UBUNTU).never_stays_up()]),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        Expect::fails(Failure::WslProvisioning)
                            .healthy(false)
                            .credentials(1)
                            .record(UBUNTU, true)
                            .complains(&[
                                "Ubuntu is provisioned only in part",
                                &format!("the systemd unit {UNIT} is failed"),
                            ])
                            .runs(&["systemctl start", "/Create /TN", "/Run /TN", "docker info"]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds().healthy(false).drift(false),
                    ),
                    (
                        detach(UBUNTU),
                        Expect::succeeds()
                            .record(UBUNTU, false)
                            .linux(UBUNTU, binary(v))
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, no_task()),
                    ),
                ],
            },
            Case {
                id: "wsl-0031",
                title: "a child diagnostic at the runner's capture ceiling is reported once and not amplified",
                covers: &[
                    Covers::Bounded,
                    Covers::Failure(Stage::Service),
                    Covers::Convergence,
                ],
                world: World::with([Distro::fresh(UBUNTU)]).inject(
                    "service install --start-at boot",
                    vec![
                        CommandOutput::exited(1, "", "x".repeat(DEFAULT_STDERR_LIMIT))
                            .with_truncation(false, true),
                    ],
                ),
                steps: vec![
                    (
                        install(UBUNTU, Some(8)),
                        stage_failed(Failure::WslProvisioning, Stage::Service)
                            .credentials(1)
                            .output_ceiling(DEFAULT_STDERR_LIMIT + 4096),
                    ),
                    (install(UBUNTU, Some(8)), Expect::succeeds().healthy(true)),
                ],
            },
            Case {
                id: "wsl-0032",
                title: "a Linux binary replaced by hand is drift, and the next install replaces it",
                covers: &[Covers::Drifted, Covers::Healthy, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        by_hand(Change::ReplaceBinary(UBUNTU, OLDER)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(true)
                            .says(&[&format!(
                                "the record says runner-manager {v} was installed and the \
                                 distribution reports {OLDER}"
                            )]),
                    ),
                    (
                        install(UBUNTU, None),
                        Expect::succeeds()
                            .healthy(true)
                            .drift(false)
                            .runs(&["mv -T"])
                            .never(&["device flow", "service install", "systemctl stop"])
                            .linux(UBUNTU, binary(v)),
                    ),
                ],
            },
            Case {
                id: "wsl-0033",
                title: "a lifecycle task deleted by hand is drift, and install puts it back",
                covers: &[Covers::Drifted, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        by_hand(Change::DeleteTask(UBUNTU)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(true)
                            .says(&["no task named"])
                            .exactly(status_history(UBUNTU, false)),
                    ),
                    (
                        list(),
                        Expect::succeeds().says(&[&format!("(managed, runner-manager {v})")]),
                    ),
                    (
                        install(UBUNTU, None),
                        Expect::succeeds()
                            .healthy(true)
                            .drift(false)
                            .runs(&["/Create /TN", "/Run /TN"])
                            .never(&["mv -T", "device flow", "service install"])
                            .linux(UBUNTU, our_task(true)),
                    ),
                ],
            },
            Case {
                id: "wsl-0034",
                title: "a credential removed inside Linux is re-issued once, to that distribution",
                covers: &[Covers::Partial, Covers::Canary, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        by_hand(Change::LogOut(UBUNTU)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .says(&["none: this host has not been signed in"]),
                    ),
                    (
                        install(UBUNTU, None),
                        Expect::succeeds()
                            .healthy(true)
                            .credentials(1)
                            .runs(&["device flow for Ubuntu", "auth receive --start-at boot"])
                            .never(&["mv -T", "service install"])
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, Fact::Received(2)),
                    ),
                ],
            },
            Case {
                id: "wsl-0035",
                title: "an unreadable record is reported by list, refused by status, and rewritten by install",
                covers: &[Covers::Drifted, Covers::Convergence, Covers::Bounded],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        by_hand(Change::CorruptRecord(UBUNTU)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        list(),
                        Expect::succeeds()
                            .says(&["Ubuntu  WSL2, Running, default (record unreadable"]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::fails(Failure::LocalState).nothing_runs(),
                    ),
                    (
                        install(UBUNTU, None),
                        Expect::succeeds()
                            .healthy(true)
                            .record(UBUNTU, true)
                            .never(&["device flow", "mv -T"]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds().healthy(true).drift(false),
                    ),
                ],
            },
            Case {
                id: "wsl-0036",
                title: "an older service copy hands itself over and is never stopped",
                covers: &[Covers::Adopted, Covers::Drifted, Covers::Convergence],
                world: World::with([
                    Distro::adopted(UBUNTU, 4).running(HANDOVER_CAPABLE, HANDOVER_CAPABLE)
                ]),
                steps: vec![(
                    install(UBUNTU, None),
                    Expect::succeeds()
                        .healthy(true)
                        .runs(&[
                            "mv -T",
                            "systemctl show --property=MainPID --value",
                            "/proc/",
                            "/Create /TN",
                        ])
                        .never(&["systemctl stop", "service install", "device flow"])
                        .says(&["cooperative upgrade handover", "systemd restarted it"])
                        .linux(UBUNTU, binary(v))
                        .linux(UBUNTU, Fact::ServiceCopy(Some(v.to_string()))),
                )],
            },
            Case {
                id: "wsl-0037",
                title: "an active service too old to hand over is left running and nothing is replaced",
                covers: &[Covers::Adopted],
                world: World::with([
                    Distro::adopted(UBUNTU, 4).running(LEGACY_SERVICE, LEGACY_SERVICE)
                ]),
                steps: vec![(
                    install(UBUNTU, None),
                    Expect::fails(Failure::WslProvisioning)
                        .complains(&["predates the cooperative upgrade handover"])
                        .never(&["mkdir", "mv -T", "systemctl stop", "device flow", "/Create"])
                        .record(UBUNTU, false)
                        .linux(UBUNTU, binary(LEGACY_SERVICE))
                        .linux(
                            UBUNTU,
                            Fact::Unit {
                                enabled: true,
                                active: true,
                            },
                        ),
                )],
            },
            Case {
                id: "wsl-0038",
                title: "Docker being down is a diagnostic and never decides health",
                covers: &[Covers::Healthy, Covers::Bounded],
                world: World::with([Distro::fresh(UBUNTU).without_docker()]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        status(UBUNTU),
                        Expect::succeeds().healthy(true).says(&[
                            "not usable here, so container jobs would fail while ordinary jobs run",
                        ]),
                    ),
                ],
            },
            Case {
                id: "wsl-0039",
                title: "detach removes only the Windows half and states what it left inside Linux",
                covers: &[Covers::Detached, Covers::Healthy],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        detach(UBUNTU),
                        Expect::succeeds()
                            .record(UBUNTU, false)
                            .exactly(detach_history(UBUNTU, true))
                            .says(&[
                                "stopped and removed",
                                "Nothing inside Ubuntu was changed",
                                "runner-manager service uninstall",
                                "runner-manager auth logout",
                            ])
                            .linux(UBUNTU, binary(v))
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, Fact::Capacity(8))
                            .linux(
                                UBUNTU,
                                Fact::Unit {
                                    enabled: true,
                                    active: true,
                                },
                            )
                            .linux(UBUNTU, no_task()),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(false)
                            .says(&["is not registered"]),
                    ),
                    (
                        list(),
                        Expect::succeeds().says(&["Ubuntu  WSL2, Running, default (not managed)"]),
                    ),
                ],
            },
            Case {
                id: "wsl-0040",
                title: "a second detach is convergent and removes nothing twice",
                covers: &[Covers::Detached, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (detach(UBUNTU), Expect::succeeds().record(UBUNTU, false)),
                    (
                        detach(UBUNTU),
                        Expect::succeeds()
                            .says(&["was not registered", "was not there"])
                            .exactly(detach_nothing_history(UBUNTU)),
                    ),
                ],
            },
            Case {
                id: "wsl-0041",
                title: "detach over a distribution this machine never managed is convergent",
                covers: &[Covers::Detached, Covers::Fresh],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![(
                    detach(UBUNTU),
                    Expect::succeeds()
                        .says(&["was not registered", "was not there"])
                        .exactly(detach_nothing_history(UBUNTU))
                        .record(UBUNTU, false),
                )],
            },
            Case {
                id: "wsl-0042",
                title: "re-attaching a detached host adopts everything it kept",
                covers: &[Covers::Reattached, Covers::Detached, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (detach(UBUNTU), Expect::succeeds().record(UBUNTU, false)),
                    (
                        install(UBUNTU, None),
                        converged(UBUNTU)
                            .capacity(8)
                            .linux(UBUNTU, Fact::Received(1))
                            .linux(UBUNTU, our_task(true)),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds().healthy(true).drift(false).capacity(8),
                    ),
                ],
            },
            Case {
                id: "wsl-0043",
                title: "detaching one of two hosts leaves the other's task, record and Linux state alone",
                covers: &[Covers::Detached, Covers::Healthy, Covers::Canary],
                world: World::with([
                    Distro::fresh(UBUNTU),
                    Distro::fresh(DEBIAN).without_docker(),
                ]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        install(DEBIAN, Some(2)),
                        provisioned(DEBIAN, Some(2))
                            .never(&["--distribution Ubuntu "])
                            .linux(UBUNTU, Fact::Received(1)),
                    ),
                    (
                        detach(UBUNTU),
                        Expect::succeeds()
                            .record(UBUNTU, false)
                            .record(DEBIAN, true)
                            .never(&[&task_name(DEBIAN), "--exec"])
                            .linux(UBUNTU, no_task())
                            .linux(DEBIAN, our_task(true)),
                    ),
                    (status(DEBIAN), Expect::succeeds().healthy(true).capacity(2)),
                ],
            },
            Case {
                id: "wsl-0044",
                title: "a lifecycle task whose hold has exited is removed without an /End",
                covers: &[Covers::Detached],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        by_hand(Change::HoldExits(UBUNTU)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        detach(UBUNTU),
                        Expect::succeeds()
                            .says(&["(removed)"])
                            .exactly(detach_history(UBUNTU, false))
                            .record(UBUNTU, false),
                    ),
                ],
            },
            Case {
                id: "wsl-0045",
                title: "a proxied command reaches the Linux binary with only the selector removed",
                covers: &[Covers::Proxy, Covers::Healthy],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        proxy(&[
                            "runner-manager",
                            "--host",
                            "wsl:Ubuntu",
                            "repo",
                            "add",
                            "acme/repo",
                            "--host-label",
                            "home",
                            "--max-capacity",
                            "4",
                        ]),
                        Expect::exits(0)
                            .exactly(vec![wsl_line(
                                UBUNTU,
                                &product("repo add acme/repo --host-label home --max-capacity 4"),
                            )])
                            .says(&["ran `repo add acme/repo --host-label home --max-capacity 4`"]),
                    ),
                    (
                        proxy(&["runner-manager", "status", "--json", "--host=wsl:Ubuntu"]),
                        Expect::exits(0)
                            .exactly(vec![wsl_line(UBUNTU, &product("status --json"))])
                            .says(&["\"schema_version\":1"]),
                    ),
                    (
                        proxy(&[
                            "runner-manager",
                            "--data-dir",
                            "/srv/runner-manager",
                            "--host",
                            "wsl:Ubuntu",
                            "host",
                            "show",
                        ]),
                        Expect::exits(0)
                            .argv(&[
                                "--distribution",
                                UBUNTU,
                                "--user",
                                "root",
                                "--exec",
                                LINUX_BINARY,
                                "--data-dir",
                                "/srv/runner-manager",
                                "host",
                                "show",
                            ])
                            .never(&["--host"]),
                    ),
                ],
            },
            Case {
                id: "wsl-0046",
                title: "a proxied command keeps the child's own exit code, success or not",
                covers: &[Covers::Proxy],
                world: World::with([Distro::fresh(UBUNTU), Distro::fresh(DEBIAN)]).inject_always(
                    "runner-manager repo remove",
                    CommandOutput::exited(10, "", "no policy for acme/missing"),
                ),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        proxy(&[
                            "runner-manager",
                            "--host",
                            "wsl:Ubuntu",
                            "repo",
                            "remove",
                            "acme/missing",
                        ]),
                        Expect::exits(10).complains(&["no policy for acme/missing"]),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl:Debian", "status"]),
                        Expect::exits(1)
                            .complains(&["No such file or directory"])
                            .exactly(vec![wsl_line(DEBIAN, &product("status"))]),
                    ),
                ],
            },
            Case {
                id: "wsl-0047",
                title: "commands that address this machine cannot be proxied and start nothing",
                covers: &[Covers::Proxy, Covers::Bounded],
                world: World::with([Distro::fresh(UBUNTU)]),
                steps: vec![
                    (
                        proxy(&[
                            "runner-manager",
                            "--host",
                            "wsl:Ubuntu",
                            "wsl",
                            "status",
                            "--distribution",
                            "Ubuntu",
                        ]),
                        Expect::fails(Failure::InvalidArgument)
                            .complains(&["cannot carry it"])
                            .nothing_runs(),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl:Ubuntu", "wsl-host", "hold"]),
                        Expect::fails(Failure::InvalidArgument)
                            .complains(&["cannot carry it"])
                            .nothing_runs(),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl: Ubuntu", "status"]),
                        Expect::fails(Failure::InvalidArgument)
                            .complains(&["starts or ends with whitespace"])
                            .nothing_runs(),
                    ),
                ],
            },
            Case {
                id: "wsl-0048",
                title: "the proxy carries a case-sensitive name verbatim to the host it names",
                covers: &[Covers::Proxy, Covers::ExactName],
                world: World::with([Distro::fresh(UBUNTU), Distro::fresh(LOWER_UBUNTU)]),
                steps: vec![
                    (
                        install(LOWER_UBUNTU, Some(1)),
                        provisioned(LOWER_UBUNTU, Some(1)).never(&["--distribution Ubuntu "]),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl:ubuntu", "host", "show"]),
                        Expect::exits(0)
                            .exactly(vec![wsl_line(LOWER_UBUNTU, &product("host show"))]),
                    ),
                    (
                        proxy(&["runner-manager", "--host", "wsl:Ubuntu", "host", "show"]),
                        Expect::exits(1).exactly(vec![wsl_line(UBUNTU, &product("host show"))]),
                    ),
                ],
            },
            Case {
                id: "wsl-0049",
                title: "two hosts never share a credential, and a re-issue reaches only its own",
                covers: &[Covers::Canary, Covers::Healthy, Covers::Partial],
                world: World::with([Distro::fresh(UBUNTU), Distro::fresh(DEBIAN)]),
                steps: vec![
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (install(DEBIAN, Some(2)), provisioned(DEBIAN, Some(2))),
                    (
                        by_hand(Change::LogOut(UBUNTU)),
                        Expect::succeeds().nothing_runs(),
                    ),
                    (
                        install(UBUNTU, None),
                        Expect::succeeds()
                            .healthy(true)
                            .credentials(1)
                            .never(&["--distribution Debian "])
                            .linux(UBUNTU, credential_of(UBUNTU))
                            .linux(UBUNTU, Fact::Received(2))
                            .linux(DEBIAN, credential_of(DEBIAN))
                            .linux(DEBIAN, Fact::Received(1)),
                    ),
                ],
            },
            Case {
                id: "wsl-0050",
                title: "a stale record never makes an unprovisioned host look healthy, and install replaces it",
                covers: &[Covers::Drifted, Covers::Fresh, Covers::Convergence],
                world: World::with([Distro::fresh(UBUNTU)]).record(UBUNTU, OLDER),
                steps: vec![
                    (
                        list(),
                        Expect::succeeds().says(&[&format!(
                            "Ubuntu  WSL2, Running, default (managed, runner-manager {OLDER})"
                        )]),
                    ),
                    (
                        status(UBUNTU),
                        Expect::succeeds()
                            .healthy(false)
                            .drift(true)
                            .says(&[
                                "the record says this host is managed and no task named",
                                &format!(
                                    "the record says runner-manager {OLDER} was installed and the \
                                     distribution has no readable binary"
                                ),
                            ])
                            .exactly(status_history(UBUNTU, false)),
                    ),
                    (install(UBUNTU, Some(8)), provisioned(UBUNTU, Some(8))),
                    (
                        status(UBUNTU),
                        Expect::succeeds().healthy(true).drift(false),
                    ),
                ],
            },
        ]
    }

    // -----------------------------------------------------------------------
    // Running a case
    // -----------------------------------------------------------------------

    /// Everything one step left behind, sliced out of the workstation's
    /// cumulative buffers.
    struct Observed {
        outcome: Outcome,
        failure: Option<CliError>,
        document: Option<WslStatusDocument>,
        install: Option<InstallOutcome>,
        stdout: String,
        stderr: String,
        history: Vec<String>,
        requests: Vec<RecordedRequest>,
        logs: String,
        before: Snapshot,
        after: Snapshot,
    }

    /// The state a step may or may not change.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Snapshot {
        distros: Vec<Distro>,
        tasks: BTreeMap<String, ModelTask>,
        files: Vec<(String, String)>,
    }

    /// One case, running.
    struct Chain<'case> {
        case: &'case Case,
        station: Workstation,
        controls: ModelledControls,
        issuers: BTreeMap<String, FakeIssuer>,
        logs: CapturedLogs,
        tags: Vec<String>,
        transcript: Vec<String>,
    }

    fn recorded_instant() -> DateTime<Utc> {
        DateTime::from_timestamp(1_799_990_000, 0).expect("a fixed instant")
    }

    fn status_instant() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_100, 0).expect("a fixed instant")
    }

    impl<'case> Chain<'case> {
        fn new(case: &'case Case, logs: CapturedLogs) -> Self {
            let world = &case.world;
            let journal = Journal::default();
            let mut script = ScriptedRunner::new();
            for injection in &world.injections {
                script = script.sequence(&injection.needle, injection.responses.clone());
            }
            let script = Arc::new(script.otherwise(the_model_answers()));
            let controls = ModelledControls {
                script: Arc::clone(&script),
                model: Arc::new(Mutex::new(world.host.clone())),
                journal: journal.clone(),
            };

            let root = tempfile::tempdir().expect("a temporary directory");
            let paths = AppPaths::rooted_at(root.path());
            paths.create_all().expect("the fixture directories");
            for (distribution, installed) in &world.records {
                WslProviderRecord::new(
                    distribution.clone(),
                    task_name(distribution),
                    installed.clone(),
                    recorded_instant(),
                )
                .write(&paths)
                .expect("a seeded provider record");
            }

            let mut assets =
                FakeAssets::publishing(journal.clone()).refusing_the_next(world.asset_refusals);
            if world.tampered_archive {
                assets.archive = b"bytes that SHA256SUMS does not describe".to_vec();
            }

            let mut tags: Vec<String> = world
                .host
                .distros
                .iter()
                .map(|distro| distro.name.clone())
                .collect();
            for (action, _) in &case.steps {
                if let Action::Install { distribution, .. } = action
                    && !tags.contains(distribution)
                    && validate_distribution_name(distribution).is_ok()
                {
                    tags.push(distribution.clone());
                }
            }

            Self {
                case,
                station: Workstation {
                    journal,
                    host: WslHost::with_runner(
                        Box::new(controls.clone()),
                        WslExecutable::at("wsl.exe"),
                    ),
                    runner: script,
                    assets,
                    root,
                    paths,
                    out: Vec::new(),
                    err: Vec::new(),
                },
                controls,
                issuers: BTreeMap::new(),
                logs,
                tags,
                transcript: Vec::new(),
            }
        }

        fn snapshot(&self) -> Snapshot {
            let model = self.controls.model().clone();
            let mut files = Vec::new();
            every_file_under(self.station.root.path(), &mut files);
            files.sort();
            Snapshot {
                distros: model.distros,
                tasks: model.tasks,
                files,
            }
        }

        /// Runs one step and slices out everything it did.
        fn perform(&mut self, action: &Action) -> Observed {
            let before = self.snapshot();
            let out_mark = self.station.out.len();
            let err_mark = self.station.err.len();
            let journal_mark = self.station.journal.entries().len();
            let request_mark = self.station.recorded().len();
            let log_mark = self.logs.text().len();

            let mut document = None;
            let mut install = None;
            let result = match action {
                Action::List => list_with(
                    &self.station.host,
                    &self.station.paths,
                    &mut self.station.out,
                )
                .map(|()| Outcome::Succeeded),
                Action::Install {
                    distribution,
                    capacity,
                } => {
                    let journal = self.station.journal.clone();
                    let refusals = self.case.world.issuer_refusals;
                    let issuer = self.issuers.entry(distribution.clone()).or_insert_with(|| {
                        FakeIssuer::issuing(journal, distribution).refusing_the_next(refusals)
                    });
                    // `Workstation::install` renders its own failures, the
                    // partial-host one included, exactly as the command does.
                    match self.station.install(distribution, *capacity, issuer) {
                        Ok((read_back, outcome)) => {
                            let partial = refuse_a_partial_host(&read_back).err();
                            document = Some(read_back);
                            install = Some(outcome);
                            partial.map_or(Ok(Outcome::Succeeded), Err)
                        }
                        Err(failure) => Err(failure),
                    }
                }
                Action::Status { distribution } => match probe(
                    &self.station.host,
                    &self.station.paths,
                    distribution,
                    LINUX_BINARY,
                    UNIT,
                    version(),
                    status_instant(),
                ) {
                    Ok(read) => {
                        write_status_text(&read, &mut self.station.out).expect("a text report");
                        write_json(&mut self.station.out, &read).expect("a JSON document");
                        document = Some(read);
                        Ok(Outcome::Succeeded)
                    }
                    Err(failure) => Err(failure),
                },
                Action::Detach { distribution } => detach_with(
                    &self.station.host,
                    &self.station.paths,
                    distribution,
                    &mut self.station.out,
                )
                .map(|()| Outcome::Succeeded),
                Action::Proxy { argv } => self.proxy(argv).map(Outcome::Exited),
                Action::ByHand(change) => {
                    self.apply(change);
                    Ok(Outcome::Succeeded)
                }
            };
            let (outcome, failure) = match result {
                Ok(outcome) => (outcome, None),
                Err(failure) => {
                    if !matches!(action, Action::Install { .. }) {
                        failure
                            .render(&mut self.station.err)
                            .expect("a buffer accepts a rendered failure");
                    }
                    (Outcome::Failed(failure.class()), Some(failure))
                }
            };

            let journal = self.station.journal.entries();
            let requests = self.station.recorded();
            let logs = self.logs.text();
            Observed {
                outcome,
                failure,
                document,
                install,
                stdout: String::from_utf8_lossy(&self.station.out[out_mark..]).into_owned(),
                stderr: String::from_utf8_lossy(&self.station.err[err_mark..]).into_owned(),
                history: journal[journal_mark..].to_vec(),
                requests: requests[request_mark..].to_vec(),
                logs: logs.get(log_mark..).unwrap_or_default().to_string(),
                before,
                after: self.snapshot(),
            }
        }

        /// `--host wsl:NAME …`, through the production parser, refusal, argument
        /// forwarding and plan.
        ///
        /// The one thing simulated is [`HostProxyRunner`]'s spawn, which hands
        /// the child this process's own three streams: here the plan is run
        /// through the workstation's controls and the child's streams are
        /// appended to the workstation's, which is what the scan reads.
        fn proxy(&mut self, argv: &[String]) -> Result<i32, CliError> {
            let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
            let cli = Cli::try_parse_from(&argv)
                .map_err(|error| CliError::new(Failure::InvalidArgument, error.to_string()))?;
            let Some(distribution) = cli.host.distribution() else {
                return Err(CliError::new(
                    Failure::InvalidArgument,
                    "the corpus proxies `--host wsl:NAME` invocations only",
                ));
            };
            refuse_a_command_that_cannot_be_proxied(&cli.command)?;
            let plan = ProxyPlan::new(
                self.station.host.executable(),
                distribution,
                LINUX_BINARY,
                forwarded_arguments(&argv),
            )?;
            let request =
                CommandRequest::new(plan.program()).args(plan.arguments().iter().cloned());
            let output = self
                .controls
                .run(&request)
                .map_err(|source| wsl_failure(&source))?;
            self.station.out.extend_from_slice(output.stdout());
            self.station.err.extend_from_slice(output.stderr());
            Ok(output
                .exit_code()
                .unwrap_or_else(|| i32::from(Failure::WslProvisioning.code())))
        }

        fn apply(&mut self, change: &Change) {
            if let Change::CorruptRecord(distribution) = change {
                let path = WslProviderRecord::path(&self.station.paths, distribution)
                    .expect("a record path");
                std::fs::create_dir_all(WslProviderRecord::directory(&self.station.paths))
                    .expect("the record directory");
                std::fs::write(path, "this is not a provider record").expect("a damaged record");
                return;
            }
            let mut model = self.controls.model();
            match change {
                Change::ReplaceBinary(distribution, replacement) => {
                    model
                        .distro_mut(distribution)
                        .expect("a distribution the case declared")
                        .binary = Some((*replacement).to_string());
                }
                Change::LogOut(distribution) => {
                    model
                        .distro_mut(distribution)
                        .expect("a distribution the case declared")
                        .credential = None;
                }
                Change::DeleteTask(distribution) => {
                    model.tasks.remove(&task_name(distribution));
                }
                Change::HoldExits(distribution) => {
                    if let Some(task) = model.tasks.get_mut(&task_name(distribution)) {
                        task.running = false;
                    }
                }
                Change::CorruptRecord(_) => {}
            }
        }

        /// The first disagreement between a step and its expectation, if any.
        fn judge(
            &self,
            action: &Action,
            expect: &Expect,
            observed: &Observed,
        ) -> Result<(), String> {
            if observed.outcome != expect.outcome {
                return Err(format!(
                    "the command was expected to end with {} and ended with {}",
                    expect.outcome, observed.outcome
                ));
            }
            judge_document(expect, observed)?;
            for fragment in &expect.says {
                if !observed.stdout.contains(fragment.as_str()) {
                    return Err(format!("stdout does not say {fragment:?}"));
                }
            }
            let complaint = format!(
                "{}\n{}",
                observed
                    .failure
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                observed.stderr
            );
            for fragment in &expect.complains {
                if !complaint.contains(fragment.as_str()) {
                    return Err(format!("neither the failure nor stderr says {fragment:?}"));
                }
            }
            check_order(&observed.history, &expect.runs)?;
            check_never(&observed.history, &expect.never)?;
            if let Some(exact) = &expect.exactly
                && observed.history != *exact
            {
                return Err(format!(
                    "the request history was expected to be exactly\n{}\n    and was\n{}",
                    indented(exact),
                    indented(&observed.history)
                ));
            }
            for argv in &expect.argv {
                if !observed
                    .requests
                    .iter()
                    .any(|request| request.arguments == *argv)
                {
                    return Err(format!(
                        "no request carried exactly the argument vector {argv:?}"
                    ));
                }
            }
            for (distribution, present) in &expect.records {
                let found = WslProviderRecord::read(&self.station.paths, distribution)
                    .map_err(|error| {
                        format!("the provider record for {distribution:?} cannot be read: {error}")
                    })?
                    .is_some();
                if found != *present {
                    return Err(format!(
                        "a provider record for {distribution:?} was expected to be {} and is {}",
                        presence(*present),
                        presence(found)
                    ));
                }
            }
            {
                let model = self.controls.model();
                for (distribution, fact) in &expect.linux {
                    check_fact(&model, distribution, fact)?;
                }
            }
            check_invariants(action, observed)?;
            check_bounds(action, expect, observed)?;
            check_crossings(&observed.requests, &self.tags, expect.credentials)?;
            let findings = scan_for_canaries(&self.channels(observed), &needles_for(&self.tags));
            if !findings.is_empty() {
                return Err(format!(
                    "a credential canary escaped the stdin pipe:\n      {}",
                    findings.join("\n      ")
                ));
            }
            Ok(())
        }

        /// Every place a secret must not be, as this step left it.
        fn channels(&self, observed: &Observed) -> Vec<(String, String)> {
            let mut channels = vec![
                ("stdout".to_string(), observed.stdout.clone()),
                ("stderr".to_string(), observed.stderr.clone()),
                (
                    "the failure message".to_string(),
                    observed
                        .failure
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "the failure's Debug output".to_string(),
                    format!("{:?}", observed.failure),
                ),
                (
                    "the status document's Debug output".to_string(),
                    format!("{:?}", observed.document),
                ),
                (
                    "the status document as JSON".to_string(),
                    observed
                        .document
                        .as_ref()
                        .map(|document| {
                            serde_json::to_string(document).expect("a status document serialises")
                        })
                        .unwrap_or_default(),
                ),
                (
                    "the install outcome's Debug output".to_string(),
                    format!("{:?}", observed.install),
                ),
                ("the diagnostics".to_string(), observed.logs.clone()),
                (
                    "the argument vectors".to_string(),
                    observed
                        .requests
                        .iter()
                        .map(RecordedRequest::command_line)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "the request and event history".to_string(),
                    observed.history.join("\n"),
                ),
                (
                    "the WSL adapter's Debug output".to_string(),
                    format!("{:?}", self.station.host),
                ),
                ("this process's environment".to_string(), environment()),
            ];
            for (name, task) in &observed.after.tasks {
                channels.push((
                    format!("the scheduled-task document {name}"),
                    task.document.clone(),
                ));
            }
            for (path, contents) in &observed.after.files {
                channels.push((format!("the file {path}"), contents.clone()));
            }
            channels
        }

        /// The first-divergence report.
        fn report(
            &self,
            index: usize,
            action: &Action,
            expect: &Expect,
            observed: &Observed,
            divergence: &str,
        ) -> String {
            let mut report = format!(
                "{} {:?}\n  corpus {CORPUS}; fixed order, no random input; replay with \
                 {REPLAY_VARIABLE}={}\n  initial workstation: {:#?}\n  actions already run:\n",
                self.case.id, self.case.title, self.case.id, self.case.world
            );
            if self.transcript.is_empty() {
                report.push_str("    (none)\n");
            }
            for line in &self.transcript {
                report.push_str(&format!("    {line}\n"));
            }
            report.push_str(&format!(
                "  diverged at step {}: {action}\n    divergence: {divergence}\n    \
                 expected: {expect:#?}\n    observed: {}\n    failure: {}\n    stdout:\n{}\n    \
                 stderr:\n{}\n    requests and events:\n{}\n    host model after the step: \
                 {:#?}\n",
                index + 1,
                observed.outcome,
                observed
                    .failure
                    .as_ref()
                    .map_or_else(|| "none".to_string(), ToString::to_string),
                indented_text(&observed.stdout),
                indented_text(&observed.stderr),
                indented(&observed.history),
                self.controls.model()
            ));
            report
        }
    }

    fn presence(present: bool) -> &'static str {
        if present { "present" } else { "absent" }
    }

    fn indented(lines: &[String]) -> String {
        if lines.is_empty() {
            return "      (none)".to_string();
        }
        lines
            .iter()
            .map(|line| format!("      {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn indented_text(text: &str) -> String {
        let lines: Vec<String> = text.lines().map(ToString::to_string).collect();
        indented(&lines)
    }

    fn environment() -> String {
        std::env::vars_os()
            .map(|(name, value)| format!("{}={}", name.to_string_lossy(), value.to_string_lossy()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The status document half of an expectation.
    fn judge_document(expect: &Expect, observed: &Observed) -> Result<(), String> {
        if expect.healthy.is_none() && expect.drift.is_none() && expect.capacity.is_none() {
            return Ok(());
        }
        let Some(document) = &observed.document else {
            return Err("a status document was expected and the command produced none".to_string());
        };
        if let Some(healthy) = expect.healthy
            && document.healthy != healthy
        {
            return Err(format!(
                "the read-back was expected to be {} and is {}; unhealthy parts: {:?}",
                if healthy { "healthy" } else { "unhealthy" },
                if document.healthy {
                    "healthy"
                } else {
                    "unhealthy"
                },
                document.unhealthy_parts()
            ));
        }
        if let Some(drift) = expect.drift
            && document.drift.is_empty() == drift
        {
            return Err(format!(
                "drift was expected to be {} and is {:?}",
                if drift { "reported" } else { "empty" },
                document.drift
            ));
        }
        if let Some(capacity) = expect.capacity
            && document.capacity != capacity
        {
            return Err(format!(
                "the reported capacity was expected to be {capacity:?} and is {:?}",
                document.capacity
            ));
        }
        Ok(())
    }

    /// Every needle appears, each after the one before it.
    fn check_order(history: &[String], needles: &[String]) -> Result<(), String> {
        let mut from = 0;
        for (position, needle) in needles.iter().enumerate() {
            match history[from..]
                .iter()
                .position(|line| line.contains(needle.as_str()))
            {
                Some(found) => from += found + 1,
                None if history.iter().any(|line| line.contains(needle.as_str())) => {
                    return Err(format!(
                        "the required request {needle:?} happened, but not after {:?}",
                        needles[position - 1]
                    ));
                }
                None => return Err(format!("the required request {needle:?} never happened")),
            }
        }
        Ok(())
    }

    fn check_never(history: &[String], needles: &[String]) -> Result<(), String> {
        for needle in needles {
            if let Some(line) = history.iter().find(|line| line.contains(needle.as_str())) {
                return Err(format!("{needle:?} must not happen, and did: {line}"));
            }
        }
        Ok(())
    }

    fn check_fact(model: &HostModel, distribution: &str, fact: &Fact) -> Result<(), String> {
        let actual = if let Fact::Task(_) = fact {
            Fact::Task(
                model
                    .tasks
                    .get(&task_name(distribution))
                    .map(|task| TaskFact {
                        owned: task.document.contains(PRODUCT_MARKER),
                        running: task.running,
                    }),
            )
        } else {
            let Some(distro) = model.distro(distribution) else {
                return Err(format!(
                    "the host model has no distribution {distribution:?}"
                ));
            };
            match fact {
                Fact::Binary(_) => Fact::Binary(distro.binary.clone()),
                Fact::Credential(_) => Fact::Credential(distro.credential.clone()),
                Fact::Received(_) => Fact::Received(distro.credentials_received),
                Fact::Capacity(_) => Fact::Capacity(distro.capacity),
                Fact::Unit { .. } => Fact::Unit {
                    enabled: distro.unit_enabled,
                    active: distro.unit_active,
                },
                Fact::ServiceCopy(_) => Fact::ServiceCopy(distro.service_copy.clone()),
                Fact::Staging(_) => Fact::Staging(distro.staging.len()),
                Fact::Task(_) => unreachable!("answered above"),
            }
        };
        if actual == *fact {
            Ok(())
        } else {
            Err(format!(
                "{distribution:?} was expected to hold {fact:?} and holds {actual:?}"
            ))
        }
    }

    /// What every step must leave alone, whatever its case says.
    fn check_invariants(action: &Action, observed: &Observed) -> Result<(), String> {
        let (before, after) = (&observed.before, &observed.after);
        let changed = |what: &str| {
            Err(format!(
                "{what}\n      before: {before:#?}\n      after: {after:#?}"
            ))
        };
        match action {
            Action::List | Action::Status { .. } if before != after => {
                changed("a read changed the workstation")
            }
            Action::Detach { .. } if before.distros != after.distros => {
                changed("`wsl detach` changed something inside Linux")
            }
            Action::Proxy { .. } if before.tasks != after.tasks || before.files != after.files => {
                changed("a proxied command changed this machine's task or records")
            }
            Action::Install { .. }
                if observed.failure.as_ref().is_some_and(|failure| {
                    failure.to_string().starts_with(Stage::Preflight.label())
                }) && before != after =>
            {
                changed("a preflight refusal changed the workstation")
            }
            _ => Ok(()),
        }
    }

    /// The most requests one command of each kind may make.
    fn request_ceiling(action: &Action) -> usize {
        match action {
            Action::List | Action::Proxy { .. } => 1,
            Action::Status { .. } => 12,
            Action::Detach { .. } => 8,
            Action::Install { .. } => 48,
            Action::ByHand(_) => 0,
        }
    }

    fn check_bounds(action: &Action, expect: &Expect, observed: &Observed) -> Result<(), String> {
        let ceiling = request_ceiling(action);
        if observed.requests.len() > ceiling {
            return Err(format!(
                "{} requests were made and this command may make at most {ceiling}",
                observed.requests.len()
            ));
        }
        for request in &observed.requests {
            let line = request.command_line();
            let limit = if line.contains("docker info") {
                DOCKER_DEADLINE
            } else {
                LONGEST_DEADLINE
            };
            if request.timeout.is_zero() || request.timeout > limit {
                return Err(format!(
                    "`{line}` ran under a {:?} deadline, outside (0, {limit:?}]",
                    request.timeout
                ));
            }
        }
        let written = observed.stdout.len() + observed.stderr.len();
        if written > expect.output_ceiling {
            return Err(format!(
                "the step wrote {written} bytes and may write at most {}",
                expect.output_ceiling
            ));
        }
        Ok(())
    }

    /// The argument vector of one distribution's own `auth receive`.
    fn receive_argv(distribution: &str) -> Vec<String> {
        strings(&[
            "--distribution",
            distribution,
            "--user",
            "root",
            "--exec",
            LINUX_BINARY,
            "auth",
            "receive",
            "--start-at",
            "boot",
        ])
    }

    /// A credential crossed exactly `expected` times, and every time on the
    /// stdin of its own distribution's `auth receive`.
    fn check_crossings(
        requests: &[RecordedRequest],
        tags: &[String],
        expected: usize,
    ) -> Result<(), String> {
        let mut crossings = 0;
        for request in requests {
            let stdin = String::from_utf8_lossy(&request.stdin);
            let carried: Vec<&String> = tags
                .iter()
                .filter(|tag| {
                    canaries_for(tag)
                        .iter()
                        .any(|canary| stdin.contains(canary.as_str()))
                })
                .collect();
            if carried.is_empty() {
                continue;
            }
            crossings += 1;
            for tag in carried {
                if request.arguments != receive_argv(tag) {
                    return Err(format!(
                        "{tag}'s credential crossed on the stdin of `{}`, which is not {tag}'s own \
                         `auth receive`",
                        request.command_line()
                    ));
                }
            }
        }
        if crossings == expected {
            Ok(())
        } else {
            Err(format!(
                "a credential crossed the stdin pipe {crossings} time(s) and was expected to \
                 cross {expected} time(s)"
            ))
        }
    }

    /// Every canary of every distribution a case names.
    fn needles_for(tags: &[String]) -> Vec<(String, String)> {
        let mut needles = Vec::new();
        for tag in tags {
            let [access, refresh, jit] = canaries_for(tag);
            needles.push((format!("{tag}'s access token"), access));
            needles.push((format!("{tag}'s refresh token"), refresh));
            needles.push((format!("{tag}'s encoded JIT configuration"), jit));
        }
        needles
    }

    fn scan_for_canaries(
        channels: &[(String, String)],
        needles: &[(String, String)],
    ) -> Vec<String> {
        let mut found = Vec::new();
        for (name, needle) in needles {
            for (origin, text) in channels {
                if text.contains(needle.as_str()) {
                    found.push(format!("{name} appears in {origin}"));
                }
            }
        }
        found
    }

    /// What running a case proved.
    #[derive(Debug)]
    struct Ran {
        elapsed: Duration,
        steps: usize,
    }

    /// Runs one case to its end or to its first divergence.
    fn run_case(case: &Case) -> Result<Ran, String> {
        let started = Instant::now();
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let steps = tracing::subscriber::with_default(subscriber, || {
            let mut chain = Chain::new(case, logs.clone());
            for (index, (action, expect)) in case.steps.iter().enumerate() {
                let observed = chain.perform(action);
                if let Err(divergence) = chain.judge(action, expect, &observed) {
                    return Err(chain.report(index, action, expect, &observed, &divergence));
                }
                chain
                    .transcript
                    .push(format!("{}. {action}  =>  {}", index + 1, observed.outcome));
            }
            Ok(chain.transcript.len())
        })?;
        Ok(Ran {
            elapsed: started.elapsed(),
            steps,
        })
    }

    fn case_named(id: &str) -> Case {
        corpus()
            .into_iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("{id} is not in the corpus"))
    }

    // -----------------------------------------------------------------------
    // The inventory and the corpus run
    // -----------------------------------------------------------------------

    /// Whether a step is one invocation of a given command.
    type Selects = fn(&Action) -> bool;

    /// One deliberate mistake in a case's expectation.
    type Corruption = fn(&mut Expect);

    #[test]
    fn the_inventory_holds_at_least_32_distinct_named_cases_covering_every_state() {
        let cases = corpus();
        assert!(
            cases.len() >= MINIMUM_CASES,
            "`02-target-architecture.md` requires at least {MINIMUM_CASES} named WSL transition \
             cases and the corpus holds {}",
            cases.len()
        );

        let mut titles = BTreeSet::new();
        for (index, case) in cases.iter().enumerate() {
            assert_eq!(
                case.id,
                format!("wsl-{:04}", index + 1),
                "identifiers are stable, contiguous and in corpus order: append, never renumber"
            );
            assert!(titles.insert(case.title), "{} repeats a title", case.id);
            assert!(!case.steps.is_empty(), "{} runs nothing", case.id);
            assert!(!case.covers.is_empty(), "{} names no contribution", case.id);
            assert!(
                case.steps
                    .iter()
                    .any(|(action, _)| !matches!(action, Action::ByHand(_))),
                "{} runs none of the product's commands",
                case.id
            );
        }

        let covered: BTreeSet<Covers> = cases
            .iter()
            .flat_map(|case| case.covers.iter().copied())
            .collect();
        for required in required_coverage() {
            assert!(covered.contains(&required), "no case covers {required:?}");
        }

        let commands: [(&str, Selects); 5] = [
            ("wsl list", |action| matches!(action, Action::List)),
            ("wsl install", |action| {
                matches!(action, Action::Install { .. })
            }),
            ("wsl status", |action| {
                matches!(action, Action::Status { .. })
            }),
            ("wsl detach", |action| {
                matches!(action, Action::Detach { .. })
            }),
            ("--host wsl:NAME", |action| {
                matches!(action, Action::Proxy { .. })
            }),
        ];
        for (command, runs) in commands {
            assert!(
                cases
                    .iter()
                    .any(|case| case.steps.iter().any(|(action, _)| runs(action))),
                "no case runs `{command}`"
            );
        }

        // Repeated installation, which is how `wsl install` also updates.
        let most_installs = cases
            .iter()
            .map(|case| {
                let mut per_distribution = BTreeMap::<&str, usize>::new();
                for (action, _) in &case.steps {
                    if let Action::Install { distribution, .. } = action {
                        *per_distribution.entry(distribution.as_str()).or_default() += 1;
                    }
                }
                per_distribution.into_values().max().unwrap_or(0)
            })
            .max()
            .unwrap_or(0);
        assert!(
            most_installs >= 3,
            "some case must install the same distribution at least three times"
        );
    }

    #[test]
    fn every_case_in_the_inventory_runs_exactly_once_and_matches_its_transitions() {
        let cases = corpus();
        let started = Instant::now();
        let mut executed = Vec::new();
        let mut divergences = Vec::new();
        let mut timings = Vec::new();
        for case in &cases {
            executed.push(case.id);
            match run_case(case) {
                Ok(ran) => {
                    assert_eq!(
                        ran.steps,
                        case.steps.len(),
                        "{} stopped before its last step without diverging",
                        case.id
                    );
                    timings.push((ran.elapsed, case.id));
                }
                Err(report) => divergences.push(report),
            }
        }
        let total = started.elapsed();

        let inventory: Vec<&str> = cases.iter().map(|case| case.id).collect();
        assert_eq!(
            executed, inventory,
            "every case in the inventory runs exactly once, in corpus order"
        );

        timings.sort_by(|left, right| right.0.cmp(&left.0));
        let slowest: Vec<String> = timings
            .iter()
            .take(3)
            .map(|(elapsed, id)| format!("{id} {elapsed:?}"))
            .collect();
        eprintln!(
            "{CORPUS}: {} cases, {} steps, {total:?}; slowest: {}",
            cases.len(),
            cases.iter().map(|case| case.steps.len()).sum::<usize>(),
            slowest.join(", ")
        );
        if total > SOFT_BUDGET {
            eprintln!(
                "{CORPUS} exceeded its soft budget of {SOFT_BUDGET:?}; slowest: {}",
                slowest.join(", ")
            );
        }

        assert!(
            divergences.is_empty(),
            "{} of {} WSL chain cases diverged:\n\n{}",
            divergences.len(),
            cases.len(),
            divergences.join("\n\n")
        );
    }

    /// Local diagnosis only. Ignored, so the default run always executes the
    /// complete corpus and no environment can narrow it.
    #[test]
    #[ignore = "replays one case named by RUNNER_MANAGER_WSL_CHAIN_CASE"]
    fn replay_one_wsl_chain_case() {
        let Ok(id) = std::env::var(REPLAY_VARIABLE) else {
            panic!(
                "set {REPLAY_VARIABLE} to one of: {}",
                corpus()
                    .iter()
                    .map(|case| case.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        let case = case_named(&id);
        let logs = CapturedLogs::default();
        let mut chain = Chain::new(&case, logs);
        eprintln!(
            "{} {:?}\n  corpus {CORPUS}\n  initial workstation: {:#?}",
            case.id, case.title, case.world
        );
        for (index, (action, expect)) in case.steps.iter().enumerate() {
            let observed = chain.perform(action);
            eprintln!(
                "\nstep {}: {action}\n  observed: {}\n  stdout:\n{}\n  stderr:\n{}\n  requests and events:\n{}",
                index + 1,
                observed.outcome,
                indented_text(&observed.stdout),
                indented_text(&observed.stderr),
                indented(&observed.history)
            );
            if let Err(divergence) = chain.judge(action, expect, &observed) {
                panic!(
                    "{}",
                    chain.report(index, action, expect, &observed, &divergence)
                );
            }
            chain
                .transcript
                .push(format!("{}. {action}  =>  {}", index + 1, observed.outcome));
        }
    }

    // -----------------------------------------------------------------------
    // Acceptance controls: the oracle itself must be able to fail
    // -----------------------------------------------------------------------

    /// The fresh install of `wsl-0003`, observed and accepted.
    fn an_accepted_fresh_install() -> (Chain<'static>, Observed, Expect) {
        let case: &'static Case = Box::leak(Box::new(case_named("wsl-0003")));
        let mut chain = Chain::new(case, CapturedLogs::default());
        let (action, expect) = &case.steps[0];
        let observed = chain.perform(action);
        chain
            .judge(action, expect, &observed)
            .expect("the untampered observation satisfies its own expectation");
        (chain, observed, expect.clone())
    }

    #[test]
    fn removing_any_required_stage_from_the_history_makes_the_oracle_fail() {
        let (_chain, observed, expect) = an_accepted_fresh_install();
        assert!(
            expect.runs.len() >= 20,
            "the fresh install names every stage"
        );
        check_order(&observed.history, &expect.runs).expect("the real history is in order");
        for needle in &expect.runs {
            let without: Vec<String> = observed
                .history
                .iter()
                .filter(|line| !line.contains(needle.as_str()))
                .cloned()
                .collect();
            assert!(
                check_order(&without, &expect.runs).is_err(),
                "a history without {needle:?} still satisfied the stage order"
            );
        }
    }

    #[test]
    fn reordering_any_two_required_requests_makes_the_oracle_fail() {
        let (_chain, observed, expect) = an_accepted_fresh_install();
        let happens_once = |needle: &String| {
            observed
                .history
                .iter()
                .filter(|line| line.contains(needle.as_str()))
                .count()
                == 1
        };
        let unique: Vec<String> = expect
            .runs
            .iter()
            .filter(|&needle| happens_once(needle))
            .cloned()
            .collect();
        assert!(
            unique.len() >= 12,
            "every mutating stage happens exactly once in a fresh install: {unique:#?}"
        );
        for pair in unique.windows(2) {
            let at = |needle: &String| {
                observed
                    .history
                    .iter()
                    .position(|line| line.contains(needle.as_str()))
                    .expect("a stage the history holds")
            };
            let (earlier, later) = (at(&pair[0]), at(&pair[1]));
            let mut swapped = observed.history.clone();
            let moved = swapped.remove(later);
            swapped.insert(earlier, moved);
            assert!(
                check_order(&swapped, &unique).is_err(),
                "moving {:?} in front of {:?} still satisfied the stage order",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn a_leaked_canary_is_found_in_every_channel_and_a_misdirected_one_is_refused() {
        let (chain, observed, _) = an_accepted_fresh_install();
        let needles = needles_for(&chain.tags);
        let channels = chain.channels(&observed);
        assert!(
            scan_for_canaries(&channels, &needles).is_empty(),
            "the untampered channels are clean"
        );
        assert!(
            channels
                .iter()
                .any(|(name, _)| name.starts_with("the file ")),
            "the scan covers the files the install wrote"
        );
        assert!(
            channels
                .iter()
                .any(|(name, _)| name.starts_with("the scheduled-task document ")),
            "and the task document it registered"
        );

        for (planted_in, _) in &channels {
            for (name, needle) in &needles {
                let mut leaked = channels.clone();
                for (origin, text) in &mut leaked {
                    if *origin == *planted_in {
                        text.push_str(&format!(" prefix {needle} suffix "));
                    }
                }
                let found = scan_for_canaries(&leaked, &needles);
                assert_eq!(
                    found,
                    vec![format!("{name} appears in {planted_in}")],
                    "a canary planted in {planted_in} must be found there and only there"
                );
            }
        }

        // The stdin door: the real crossing passes, and every way of moving it
        // is refused.
        check_crossings(&observed.requests, &chain.tags, 1).expect("the real crossing");
        assert!(check_crossings(&observed.requests, &chain.tags, 0).is_err());
        let receive = observed
            .requests
            .iter()
            .position(|request| request.arguments == receive_argv(UBUNTU))
            .expect("the install delivered a credential");
        let tar = observed
            .requests
            .iter()
            .position(|request| request.arguments.iter().any(|argument| argument == "tar"))
            .expect("the install unpacked an archive");

        let mut to_another_program = observed.requests.clone();
        to_another_program[tar].stdin = to_another_program[receive].stdin.clone();
        to_another_program[receive].stdin.clear();
        assert!(check_crossings(&to_another_program, &chain.tags, 1).is_err());

        let mut to_another_distribution = observed.requests.clone();
        to_another_distribution[receive].arguments = receive_argv(DEBIAN);
        let tags = vec![UBUNTU.to_string(), DEBIAN.to_string()];
        assert!(check_crossings(&to_another_distribution, &tags, 1).is_err());
    }

    #[test]
    fn a_corrupted_expectation_makes_its_case_diverge_at_that_step() {
        let pristine = case_named("wsl-0003");
        run_case(&pristine).unwrap_or_else(|report| panic!("the pristine case passes:\n{report}"));

        let corruptions: [(&str, Corruption); 10] = [
            ("the outcome", |expect| {
                expect.outcome = Outcome::Failed(Failure::Conflict);
            }),
            ("the health", |expect| expect.healthy = Some(false)),
            ("the credential count", |expect| expect.credentials = 0),
            ("the record", |expect| {
                expect.records = vec![(UBUNTU.to_string(), false)];
            }),
            ("a Linux fact", |expect| {
                expect.linux.push((UBUNTU.to_string(), Fact::Capacity(9)));
            }),
            ("a report fragment", |expect| {
                expect
                    .says
                    .push("a sentence the install never says".to_string());
            }),
            ("a stage that never ran", |expect| {
                expect.runs.push("systemctl stop".to_string());
            }),
            ("a forbidden request", |expect| {
                expect.never.push("auth receive".to_string());
            }),
            ("the literal history", |expect| {
                expect.exactly = Some(Vec::new())
            }),
            ("the output ceiling", |expect| expect.output_ceiling = 16),
        ];
        for (what, corrupt) in corruptions {
            let mut case = pristine.clone();
            corrupt(&mut case.steps[0].1);
            let report = run_case(&case)
                .err()
                .unwrap_or_else(|| panic!("a corrupted expectation ({what}) still passed"));
            assert!(
                report.starts_with("wsl-0003 ") && report.contains("diverged at step 1:"),
                "a corrupted expectation ({what}) must be reported at its own case and step:\n\
                 {report}"
            );
        }

        // And a later step, to prove the transcript names what already ran.
        let mut case = pristine.clone();
        case.steps[2].1.healthy = Some(false);
        let report = run_case(&case).expect_err("a corrupted status expectation");
        assert!(report.contains("diverged at step 3:"), "{report}");
        assert!(
            report.contains(
                "1. runner-manager wsl install --distribution \"Ubuntu\" --capacity 8  =>  exit 0"
            ),
            "the report lists the steps already run:\n{report}"
        );
    }
}
