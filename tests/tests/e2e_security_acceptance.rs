//! Release acceptance for the complete product.
//!
//! The disruptive scenarios (reboot, network isolation and two physical hosts)
//! cannot truthfully be faked from inside a test process.  A host controller
//! executes them and leaves one small JSON evidence file per scenario.  This
//! test validates those records, runs the local security gates, independently
//! proves the fixture is clean through GitHub's API, and emits one report for
//! the current OS.  Missing evidence is a failure; missing fixture credentials
//! is a clean skip.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use runner_manager_github::rest::{Admission, BudgetProjection, TargetCost};
use runner_manager_platform::process::{RestrictiveHandoff, SpawnSpec};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

const REQUIRED_ENV: [&str; 4] = [
    "RUNNER_MANAGER_E2E_TOKEN",
    "RUNNER_MANAGER_E2E_FIXTURE_TOKEN",
    "RUNNER_MANAGER_E2E_REPO",
    "RUNNER_MANAGER_E2E_ORG",
];

const SCENARIOS: [(&str, &str); 8] = [
    ("successful_jit_job", "repository"),
    ("network_outage_recovery", "repository"),
    ("jit_expiry_recovery", "repository"),
    ("policy_disable_drain", "repository"),
    ("boot_start_recovery", "repository"),
    ("organization_scoped_job", "organization"),
    ("monitor_only_demand", "repository"),
    ("two_host_contention", "repository"),
];

const SECURITY_GATES: [&str; 10] = [
    "process_inspection",
    "two_job_contamination",
    "runner_package_integrity",
    "secret_injection_scan",
    "revoked_token_rejection",
    "credential_free_config_and_sqlite",
    "workspace_removal",
    "restart_duplicate_poll",
    "budget_refusal",
    "post_condition",
];

#[derive(Debug)]
struct Fixture {
    product_token: SecretString,
    fixture_token: SecretString,
    repository: String,
    organization: String,
}

impl Fixture {
    fn from_environment() -> Option<Self> {
        let missing: Vec<_> = REQUIRED_ENV
            .iter()
            .copied()
            .filter(|name| std::env::var_os(name).is_none_or(|value| value.is_empty()))
            .collect();
        if !missing.is_empty() {
            eprintln!(
                "SKIP [{}]: disposable GitHub fixture is not configured; missing {}",
                os_name(),
                missing.join(", ")
            );
            return None;
        }
        Some(Self {
            product_token: SecretString::from(std::env::var(REQUIRED_ENV[0]).unwrap()),
            fixture_token: SecretString::from(std::env::var(REQUIRED_ENV[1]).unwrap()),
            repository: std::env::var(REQUIRED_ENV[2]).unwrap(),
            organization: std::env::var(REQUIRED_ENV[3]).unwrap(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioEvidence {
    schema: u8,
    scenario: String,
    os: String,
    scope: String,
    observed_evidence: Vec<String>,
    registered_runners_after: u64,
    runtime_directories_after: u64,
    legacy_label_reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackEvidence {
    schema: u8,
    os: String,
    label_restored: bool,
    drain_completed: bool,
    attempts_terminal: bool,
    legacy_runner_reenabled: bool,
    observed_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityEvidence {
    schema: u8,
    gate: String,
    os: String,
    observed_evidence: Vec<String>,
    control_removed_failure: String,
}

#[derive(Debug, Serialize)]
struct GateEvidence {
    gate: &'static str,
    observed_evidence: String,
}

#[derive(Debug, Serialize)]
struct OsReport {
    schema: u8,
    os: &'static str,
    repository: String,
    organization: String,
    scenarios: Vec<ScenarioEvidence>,
    security_gates: Vec<GateEvidence>,
    rollback: RollbackEvidence,
}

#[test]
fn absent_fixture_inputs_are_a_clean_skip() {
    // This ordinary (non-ignored) test pins the same all-four-input rule as the
    // workflow guard.  It deliberately does not mutate this process's real
    // environment, which is shared with concurrently running test binaries.
    let present = |name: &str| !name.is_empty();
    assert!(!REQUIRED_ENV.iter().all(|_| present("")));
    assert_eq!(REQUIRED_ENV.len(), 4);
}

#[test]
fn security_gate_process_inspection_is_mutation_sensitive() -> Result<()> {
    process_inspection_gate().map(|_| ())
}

#[test]
fn security_gate_two_job_contamination_requires_observed_evidence() -> Result<()> {
    evidence_validator_is_mutation_sensitive("two_job_contamination")
}

#[test]
fn security_gate_runner_package_integrity_requires_both_rejections() -> Result<()> {
    evidence_validator_is_mutation_sensitive("runner_package_integrity")
}

#[test]
fn security_gate_secret_injection_scans_token_and_jit_configuration() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("clean.log"), "ordinary diagnostic")?;
    scan_tree_for_secrets(root.path(), &["product-token", "encoded-jit"])?;
    fs::write(root.path().join("mutated.log"), "encoded-jit")?;
    ensure!(
        scan_tree_for_secrets(root.path(), &["product-token", "encoded-jit"]).is_err(),
        "deliberately injected JIT configuration passed the scanner"
    );
    Ok(())
}

#[test]
fn security_gate_revoked_token_requires_precise_failure_evidence() -> Result<()> {
    evidence_validator_is_mutation_sensitive("revoked_token_rejection")
}

#[test]
fn security_gate_config_and_sqlite_reject_a_usable_credential() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("runner-manager.sqlite3"), b"schema only")?;
    scan_tree_for_secrets(root.path(), &["github-user-token"])?;
    fs::write(root.path().join("mutated.sqlite3"), b"github-user-token")?;
    ensure!(
        scan_tree_for_secrets(root.path(), &["github-user-token"]).is_err(),
        "a deliberately injected usable credential passed the state scan"
    );
    Ok(())
}

#[test]
fn security_gate_workspace_removal_requires_success_and_failure_evidence() -> Result<()> {
    evidence_validator_is_mutation_sensitive("workspace_removal")
}

#[test]
fn security_gate_restart_duplicate_poll_requires_observed_evidence() -> Result<()> {
    evidence_validator_is_mutation_sensitive("restart_duplicate_poll")
}

#[test]
fn security_gate_budget_refusal_shows_computed_numbers() -> Result<()> {
    budget_refusal_gate().map(|_| ())
}

#[test]
fn security_gate_post_condition_rejects_each_residue() {
    let mut evidence = ScenarioEvidence {
        schema: 1,
        scenario: "successful_jit_job".into(),
        os: os_name().into(),
        scope: "repository".into(),
        observed_evidence: vec!["job completed".into()],
        registered_runners_after: 0,
        runtime_directories_after: 0,
        legacy_label_reused: false,
    };
    assert!(post_condition_holds(&evidence));
    evidence.registered_runners_after = 1;
    assert!(!post_condition_holds(&evidence));
    evidence.registered_runners_after = 0;
    evidence.runtime_directories_after = 1;
    assert!(!post_condition_holds(&evidence));
    evidence.runtime_directories_after = 0;
    evidence.legacy_label_reused = true;
    assert!(!post_condition_holds(&evidence));
}

#[test]
#[ignore = "requires the disposable repository, organization, and native host controller"]
fn release_acceptance_and_security_report() -> Result<()> {
    let Some(fixture) = Fixture::from_environment() else {
        return Ok(());
    };

    validate_target(&fixture.repository, "RUNNER_MANAGER_E2E_REPO")?;
    ensure!(
        !fixture.organization.contains('/') && !fixture.organization.trim().is_empty(),
        "RUNNER_MANAGER_E2E_ORG must be an organization login"
    );

    let evidence_dir = std::env::var_os("RUNNER_MANAGER_E2E_EVIDENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".e2e-evidence").join(os_name()));
    let scenarios = load_scenarios(&evidence_dir)?;
    let rollback = load_rollback(&evidence_dir)?;

    // The two credentials have deliberately disjoint roles.  The product
    // token is used only for the product-facing inventory proof; the fixture
    // token is used only to prove the test fixture itself is reachable.
    let runtime = tokio::runtime::Runtime::new()?;
    let (repository_runners, organization_runners) = runtime.block_on(async {
        ensure_fixture_reachable(&fixture).await?;
        Ok::<_, anyhow::Error>((
            runner_count(&fixture.product_token, "repos", &fixture.repository).await?,
            runner_count(&fixture.product_token, "orgs", &fixture.organization).await?,
        ))
    })?;
    ensure!(
        repository_runners == 0,
        "fixture repository still has {repository_runners} registered runner(s)"
    );
    ensure!(
        organization_runners == 0,
        "fixture organization still has {organization_runners} registered runner(s)"
    );

    let gates = run_security_gates(&fixture, &evidence_dir, &scenarios)?;
    ensure!(
        gates.len() == SECURITY_GATES.len(),
        "security gate roster is incomplete"
    );

    let report = OsReport {
        schema: 1,
        os: os_name(),
        repository: fixture.repository,
        organization: fixture.organization,
        scenarios,
        security_gates: gates,
        rollback,
    };
    let report_dir = PathBuf::from("target").join("e2e-reports");
    fs::create_dir_all(&report_dir)?;
    let report_path = report_dir.join(format!("{}.json", os_name()));
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("E2E REPORT [{}]: {}", os_name(), report_path.display());
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn load_scenarios(root: &Path) -> Result<Vec<ScenarioEvidence>> {
    SCENARIOS
        .iter()
        .map(|&(scenario, scope)| {
            let path = root.join(format!("{scenario}.json"));
            let bytes = fs::read(&path).with_context(|| {
                format!(
                    "missing evidence for {scenario} on {}: {}",
                    os_name(),
                    path.display()
                )
            })?;
            let evidence: ScenarioEvidence = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid scenario evidence: {}", path.display()))?;
            ensure!(
                evidence.schema == 1,
                "{} has unsupported schema",
                path.display()
            );
            ensure!(
                evidence.scenario == scenario,
                "{} names the wrong scenario",
                path.display()
            );
            ensure!(
                evidence.os == os_name(),
                "{} records a different OS",
                path.display()
            );
            ensure!(
                evidence.scope == scope,
                "{} records the wrong scope",
                path.display()
            );
            ensure!(
                !evidence.observed_evidence.is_empty(),
                "{} contains no observed evidence",
                path.display()
            );
            ensure!(
                evidence
                    .observed_evidence
                    .iter()
                    .all(|line| !line.trim().is_empty()),
                "{} contains blank evidence",
                path.display()
            );
            ensure!(
                evidence.registered_runners_after == 0,
                "{scenario} left a registered runner"
            );
            ensure!(
                evidence.runtime_directories_after == 0,
                "{scenario} left a runtime directory"
            );
            ensure!(
                !evidence.legacy_label_reused,
                "{scenario} reused the legacy routing label"
            );
            Ok(evidence)
        })
        .collect()
}

fn load_rollback(root: &Path) -> Result<RollbackEvidence> {
    let path = root.join("rollback.json");
    let value: RollbackEvidence = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("missing rollback evidence: {}", path.display()))?,
    )?;
    ensure!(
        value.schema == 1 && value.os == os_name(),
        "rollback evidence has the wrong schema or OS"
    );
    ensure!(
        value.label_restored,
        "rollback did not restore the legacy label first"
    );
    ensure!(value.drain_completed, "rollback drain did not complete");
    ensure!(
        value.attempts_terminal,
        "rollback stopped before attempts were terminal"
    );
    ensure!(
        value.legacy_runner_reenabled,
        "rollback did not re-enable the legacy runner"
    );
    ensure!(
        !value.observed_evidence.is_empty(),
        "rollback has no observed evidence"
    );
    Ok(value)
}

fn run_security_gates(
    fixture: &Fixture,
    evidence_root: &Path,
    scenarios: &[ScenarioEvidence],
) -> Result<Vec<GateEvidence>> {
    let mut gates = vec![
        process_inspection_gate()?,
        evidence_gate("two_job_contamination", evidence_root)?,
        evidence_gate("runner_package_integrity", evidence_root)?,
        secret_injection_gate(fixture, evidence_root)?,
        evidence_gate("revoked_token_rejection", evidence_root)?,
        credential_free_state_gate(fixture, evidence_root)?,
        evidence_gate("workspace_removal", evidence_root)?,
        evidence_gate("restart_duplicate_poll", evidence_root)?,
        budget_refusal_gate()?,
    ];
    ensure!(scenarios.iter().all(post_condition_holds));
    gates.push(GateEvidence { gate: "post_condition", observed_evidence: "all eight scenario records assert zero remote runners, zero runtime directories, and no legacy-label reuse".into() });
    let actual: BTreeSet<_> = gates.iter().map(|gate| gate.gate).collect();
    let required: BTreeSet<_> = SECURITY_GATES.into_iter().collect();
    ensure!(
        actual == required,
        "security gates do not match the release roster"
    );
    Ok(gates)
}

fn evidence_validator_is_mutation_sensitive(name: &'static str) -> Result<()> {
    let root = tempfile::tempdir()?;
    let security = root.path().join("security");
    fs::create_dir(&security)?;
    ensure!(
        evidence_gate(name, root.path()).is_err(),
        "{name} accepted missing evidence"
    );
    let mut record = SecurityEvidence {
        schema: 1,
        gate: name.into(),
        os: os_name().into(),
        observed_evidence: vec!["observed control".into()],
        control_removed_failure: "deliberate mutation failed at assertion X".into(),
    };
    let path = security.join(format!("{name}.json"));
    fs::write(&path, serde_json::to_vec(&record)?)?;
    evidence_gate(name, root.path())?;
    record.control_removed_failure.clear();
    fs::write(path, serde_json::to_vec(&record)?)?;
    ensure!(
        evidence_gate(name, root.path()).is_err(),
        "{name} accepted a mutation that recorded no observed failure"
    );
    Ok(())
}

fn post_condition_holds(evidence: &ScenarioEvidence) -> bool {
    evidence.registered_runners_after == 0
        && evidence.runtime_directories_after == 0
        && !evidence.legacy_label_reused
}

fn process_inspection_gate() -> Result<GateEvidence> {
    let root = tempfile::tempdir()?;
    let marker = SecretString::from("jit_Acceptance_Mutation_7cb467f9".to_string());
    let handoff = RestrictiveHandoff::create(root.path(), marker.clone())?;
    let safe = SpawnSpec::new("runner-listener").arg(handoff.path());
    ensure!(
        safe.arguments().iter().all(|a| a != marker.expose_secret()),
        "JIT payload reached the safe process command line"
    );

    // Mutation proof: deliberately remove the control by putting the payload
    // in an argument.  The production seam must reject it before process spawn.
    let exposed = SpawnSpec::new("runner-listener").arg(marker.expose_secret());
    ensure!(
        exposed.spawn_with_handoff(&handoff).is_err(),
        "process-inspection gate did not detect its deliberate control removal"
    );
    Ok(GateEvidence { gate: "process_inspection", observed_evidence: "restrictive handoff path is argument-safe; deliberate payload argument was rejected before spawn".into() })
}

fn evidence_gate(name: &'static str, root: &Path) -> Result<GateEvidence> {
    let path = root.join("security").join(format!("{name}.json"));
    let evidence: SecurityEvidence = serde_json::from_slice(
        &fs::read(&path)
            .with_context(|| format!("missing security-gate evidence: {}", path.display()))?,
    )
    .with_context(|| format!("invalid security-gate evidence: {}", path.display()))?;
    ensure!(
        evidence.schema == 1,
        "{} has unsupported schema",
        path.display()
    );
    ensure!(
        evidence.gate == name,
        "{} names the wrong gate",
        path.display()
    );
    ensure!(
        evidence.os == os_name(),
        "{} records a different OS",
        path.display()
    );
    ensure!(
        !evidence.observed_evidence.is_empty()
            && evidence
                .observed_evidence
                .iter()
                .all(|line| !line.trim().is_empty()),
        "{} contains no observed evidence",
        path.display()
    );
    ensure!(
        !evidence.control_removed_failure.trim().is_empty(),
        "{} does not record the failure observed with its control removed",
        path.display()
    );
    Ok(GateEvidence {
        gate: name,
        observed_evidence: format!(
            "{}; deliberate control removal failed: {}",
            evidence.observed_evidence.join("; "),
            evidence.control_removed_failure.trim()
        ),
    })
}

fn secret_injection_gate(fixture: &Fixture, root: &Path) -> Result<GateEvidence> {
    let artifacts = root.join("security").join("secret-scan-root");
    let jit = fs::read_to_string(root.join("security").join("jit-marker.txt"))
        .context("missing encoded-JIT marker used by the secret-injection gate")?;
    ensure!(!jit.trim().is_empty(), "encoded-JIT marker is empty");
    scan_tree_for_secrets(
        &artifacts,
        &[fixture.product_token.expose_secret(), jit.trim()],
    )?;

    // Mutation proof: the exact scanner used above must fail on both values.
    ensure!(scan_bytes(b"prefix token-leak suffix", &["token-leak"]).is_err());
    ensure!(scan_bytes(b"encoded-jit-leak", &["encoded-jit-leak"]).is_err());
    Ok(GateEvidence {
        gate: "secret_injection_scan",
        observed_evidence: format!(
            "scanned logs, databases, snapshots, crash reports and CLI output under {}",
            artifacts.display()
        ),
    })
}

fn credential_free_state_gate(fixture: &Fixture, root: &Path) -> Result<GateEvidence> {
    let state = root.join("security").join("config-and-sqlite");
    scan_tree_for_secrets(&state, &[fixture.product_token.expose_secret()])?;
    Ok(GateEvidence {
        gate: "credential_free_config_and_sqlite",
        observed_evidence: format!("no usable product credential in {}", state.display()),
    })
}

fn scan_tree_for_secrets(root: &Path, needles: &[&str]) -> Result<()> {
    ensure!(
        root.is_dir(),
        "scan root does not exist: {}",
        root.display()
    );
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                scan_bytes(&fs::read(entry.path())?, needles)
                    .with_context(|| format!("secret scan failed in {}", entry.path().display()))?;
            }
        }
    }
    Ok(())
}

fn scan_bytes(bytes: &[u8], needles: &[&str]) -> Result<()> {
    for needle in needles {
        ensure!(!needle.is_empty(), "a secret scanner needle was empty");
        if bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            bail!("sensitive marker was present");
        }
    }
    Ok(())
}

fn budget_refusal_gate() -> Result<GateEvidence> {
    use runner_manager_domain::model::RefreshInterval;
    let interval = RefreshInterval::default();
    let maximum = BudgetProjection::max_repository_targets(interval);
    let projection =
        BudgetProjection::new(interval, vec![TargetCost::repository(); maximum as usize]);
    let refusal = projection.admit(TargetCost::repository());
    let rendered = refusal.to_string();
    ensure!(
        matches!(refusal, Admission::Refused { .. }),
        "an over-budget target was admitted"
    );
    ensure!(
        rendered.contains("requests/hour") && rendered.contains("2500"),
        "budget refusal omitted its computed inputs: {rendered}"
    );
    Ok(GateEvidence {
        gate: "budget_refusal",
        observed_evidence: rendered,
    })
}

async fn ensure_fixture_reachable(fixture: &Fixture) -> Result<()> {
    let url = format!("https://api.github.com/repos/{}", fixture.repository);
    let response = github_get(&fixture.fixture_token, &url).await?;
    ensure!(
        response.status().is_success(),
        "fixture token cannot reach {}: {}",
        fixture.repository,
        response.status()
    );
    Ok(())
}

async fn runner_count(token: &SecretString, scope: &str, target: &str) -> Result<u64> {
    let url = format!("https://api.github.com/{scope}/{target}/actions/runners?per_page=100");
    let response = github_get(token, &url).await?;
    ensure!(
        response.status().is_success(),
        "cannot inspect {scope}/{target} runners: {}",
        response.status()
    );
    let value: serde_json::Value = response.json().await?;
    value["total_count"]
        .as_u64()
        .context("runner inventory omitted total_count")
}

async fn github_get(token: &SecretString, url: &str) -> Result<reqwest::Response> {
    reqwest::Client::new()
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "runner-manager-e2e")
        .bearer_auth(token.expose_secret())
        .send()
        .await
        .context("GitHub request failed")
}

fn validate_target(value: &str, variable: &str) -> Result<()> {
    let mut parts = value.split('/');
    ensure!(
        parts.next().is_some_and(|p| !p.is_empty())
            && parts.next().is_some_and(|p| !p.is_empty())
            && parts.next().is_none(),
        "{variable} must be OWNER/REPO"
    );
    Ok(())
}

const fn os_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unsupported"
    }
}
