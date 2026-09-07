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
         \"version\":\"{reported}\"}},\"credential\":{{\"present\":{credential},\
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
/// credential of its own, then reports the provisioned host; the task is absent
/// when the preflight looks and absent again when `register` looks, and this
/// product's own from then on.
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
        .always(
            &inside(distribution, &format!("systemctl is-active {UNIT}")),
            ok("active\n"),
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

/// The rules every workstation has, whatever its distributions answer.
///
/// The `--version` rule is global on purpose: the binary installer asks the
/// *staged* copy for its version, and that copy's path carries a per-run
/// staging token no distribution-scoped rule could spell.
fn workstation_script(names: &[&str]) -> ScriptedRunner {
    ScriptedRunner::new()
        .always("--list --verbose", ok(&distribution_table(names)))
        .always("--version", ok(&format!("runner-manager {}\n", version())))
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
        let script = script
            .always("--list --verbose", ok(&distribution_table(&[UBUNTU])))
            .always("--version", ok(&format!("runner-manager {}\n", version())));
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
    let script = ScriptedRunner::new()
        .sequence(
            "/Create /TN",
            vec![refused("ERROR: Access is denied."), ok("")],
        )
        .always("--list --verbose", ok(&distribution_table(&[UBUNTU])))
        .always("--version", ok(&format!("runner-manager {}\n", version())));
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
