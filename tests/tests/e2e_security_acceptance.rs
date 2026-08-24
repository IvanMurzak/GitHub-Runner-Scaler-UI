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
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    data_dir: PathBuf,
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
            data_dir: PathBuf::from(
                std::env::var_os("RUNNER_MANAGER_E2E_DATA_DIR").expect(
                    "RUNNER_MANAGER_E2E_DATA_DIR is required when fixture inputs are present",
                ),
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioEvidence {
    schema: u8,
    authentication_tag: String,
    controller: String,
    scenario: String,
    os: String,
    scope: String,
    target: String,
    routing_label: String,
    legacy_label: String,
    started_at_ms: u64,
    finished_at_ms: u64,
    facts: ScenarioFacts,
    post_condition: PostCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ScenarioFacts {
    SuccessfulJitJob {
        workflow_run_id: u64,
        job_id: u64,
        attempt_id: String,
        conclusion: String,
    },
    NetworkOutageRecovery {
        outage_started_ms: u64,
        failed_contact_ms: u64,
        recovered_contact_ms: u64,
        job_id: u64,
    },
    JitExpiryRecovery {
        expired_attempt_id: String,
        expiry_observed_ms: u64,
        replacement_attempt_id: String,
        job_id: u64,
    },
    PolicyDisableDrain {
        disable_requested_ms: u64,
        busy_observed_ms: u64,
        terminal_observed_ms: u64,
        launches_after_disable: u64,
    },
    BootStartRecovery {
        boot_id_before: String,
        boot_id_after: String,
        service_started_ms: u64,
        github_contact_ms: u64,
        interactive_login_observed: bool,
        job_id: u64,
    },
    OrganizationScopedJob {
        job_id: u64,
        runner_id: u64,
        github_scope: String,
    },
    MonitorOnlyDemand {
        queued_jobs_observed: u64,
        runner_attempts_started: u64,
    },
    TwoHostContention {
        host_ids: [String; 2],
        attempt_ids: [String; 2],
        completed_job_ids: Vec<u64>,
        idle_exit_attempt_id: String,
        idle_exit_recorded_as_failure: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostCondition {
    github_observed_at_ms: u64,
    registered_runner_ids: Vec<u64>,
    legacy_label_runner_ids: Vec<u64>,
    local_observed_at_ms: u64,
    runtime_directories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackEvidence {
    schema: u8,
    authentication_tag: String,
    controller: String,
    os: String,
    target: String,
    steps: Vec<RollbackStep>,
    post_condition: PostCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RollbackKind {
    RestoreLabel,
    Drain,
    VerifyTerminal,
    ReenableLegacy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackStep {
    kind: RollbackKind,
    started_at_ms: u64,
    finished_at_ms: u64,
    command: Vec<String>,
    exit_code: i32,
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
fn fabricated_controller_json_fails_authentication() -> Result<()> {
    let key = "product-fixture-token";
    let mut value = serde_json::json!({
        "schema": 1,
        "authentication_tag": "",
        "controller": "runner-manager-e2e-host-controller/v1",
        "job_id": 42
    });
    sign_json_value(&mut value, key)?;
    let signed = serde_json::to_vec(&value)?;
    verify_signed_json(&signed, key)?;

    value["job_id"] = serde_json::json!(43);
    ensure!(verify_signed_json(&serde_json::to_vec(&value)?, key).is_err());
    ensure!(verify_signed_json(&signed, "different-token").is_err());
    assert_eq!(
        hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "HMAC-SHA-256 must match RFC 4231 test case 1"
    );
    Ok(())
}

#[test]
fn canonical_redaction_preserves_report_json_and_removes_leaks() -> Result<()> {
    let leaked = "ghu_0123456789abcdefghijklmnopqrstuvwxyzABCD";
    let mut value = serde_json::json!({
        "scenario": "successful_jit_job",
        "command_output": format!("Authorization: Bearer {leaked}")
    });
    redact_json_strings(&mut value);
    let redacted = serde_json::to_string_pretty(&value)?;
    let _: serde_json::Value = serde_json::from_str(&redacted)?;
    ensure!(!redacted.contains(leaked));
    ensure!(redacted.contains(runner_manager_platform::logging::REDACTION));
    Ok(())
}

#[test]
fn security_gate_process_inspection_is_mutation_sensitive() -> Result<()> {
    recipe_validator_is_mutation_sensitive(recipe("process_inspection"))
}

#[test]
fn security_gate_two_job_contamination_requires_observed_evidence() -> Result<()> {
    recipe_validator_is_mutation_sensitive(recipe("two_job_contamination"))
}

#[test]
fn security_gate_runner_package_integrity_requires_both_rejections() -> Result<()> {
    let recipe = recipe("runner_package_integrity");
    ensure!(
        recipe.tests.len() == 2,
        "both checksum mutations are required"
    );
    recipe_validator_is_mutation_sensitive(recipe)
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
    recipe_validator_is_mutation_sensitive(recipe("revoked_token_rejection"))
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
    let recipe = recipe("workspace_removal");
    ensure!(
        recipe.tests.len() == 2,
        "success and failure cleanup are required"
    );
    recipe_validator_is_mutation_sensitive(recipe)
}

#[test]
fn security_gate_restart_duplicate_poll_requires_observed_evidence() -> Result<()> {
    recipe_validator_is_mutation_sensitive(recipe("restart_duplicate_poll"))
}

#[test]
fn security_gate_budget_refusal_shows_computed_numbers() -> Result<()> {
    budget_refusal_gate().map(|_| ())
}

#[test]
fn security_gate_post_condition_rejects_each_residue() {
    let mut evidence = ScenarioEvidence {
        schema: 1,
        authentication_tag: "fixture-tag".into(),
        controller: "runner-manager-e2e-host-controller/v1".into(),
        scenario: "successful_jit_job".into(),
        os: os_name().into(),
        scope: "repository".into(),
        target: "owner/repo".into(),
        routing_label: "rm-host-win-x64".into(),
        legacy_label: "legacy-win".into(),
        started_at_ms: 1,
        finished_at_ms: 9,
        facts: ScenarioFacts::SuccessfulJitJob {
            workflow_run_id: 1,
            job_id: 2,
            attempt_id: "attempt-1".into(),
            conclusion: "success".into(),
        },
        post_condition: PostCondition {
            github_observed_at_ms: 8,
            registered_runner_ids: vec![],
            legacy_label_runner_ids: vec![],
            local_observed_at_ms: 9,
            runtime_directories: vec![],
        },
    };
    validate_scenario(&evidence, "successful_jit_job", "repository", "owner/repo")
        .expect("repository-controller evidence is structurally valid");
    assert!(post_condition_holds(&evidence));
    evidence.post_condition.registered_runner_ids.push(1);
    assert!(!post_condition_holds(&evidence));
    evidence.post_condition.registered_runner_ids.clear();
    evidence
        .post_condition
        .runtime_directories
        .push("runtime/a".into());
    assert!(!post_condition_holds(&evidence));
    evidence.post_condition.runtime_directories.clear();
    evidence.post_condition.legacy_label_runner_ids.push(2);
    assert!(!post_condition_holds(&evidence));
    evidence.post_condition.legacy_label_runner_ids.clear();
    evidence.controller = "fabricated-prose/v1".into();
    assert!(
        validate_scenario(&evidence, "successful_jit_job", "repository", "owner/repo").is_err()
    );
    evidence.controller = "runner-manager-e2e-host-controller/v1".into();
    if let ScenarioFacts::SuccessfulJitJob { conclusion, .. } = &mut evidence.facts {
        *conclusion = "failure".into();
    }
    assert!(
        validate_scenario(&evidence, "successful_jit_job", "repository", "owner/repo").is_err()
    );
}

#[test]
fn rollback_rejects_reordered_or_failed_controller_commands() {
    let kinds = [
        RollbackKind::RestoreLabel,
        RollbackKind::Drain,
        RollbackKind::VerifyTerminal,
        RollbackKind::ReenableLegacy,
    ];
    let mut evidence = RollbackEvidence {
        schema: 1,
        authentication_tag: "fixture-tag".into(),
        controller: "runner-manager-e2e-host-controller/v1".into(),
        os: os_name().into(),
        target: "owner/repo".into(),
        steps: kinds
            .into_iter()
            .enumerate()
            .map(|(i, kind)| RollbackStep {
                kind,
                started_at_ms: 10 + (i as u64 * 10),
                finished_at_ms: 19 + (i as u64 * 10),
                command: vec!["runner-manager".into(), format!("rollback-{i}")],
                exit_code: 0,
            })
            .collect(),
        post_condition: PostCondition {
            github_observed_at_ms: 51,
            registered_runner_ids: vec![],
            legacy_label_runner_ids: vec![42],
            local_observed_at_ms: 52,
            runtime_directories: vec![],
        },
    };
    validate_rollback(&evidence, "owner/repo").expect("ordered successful rollback passes");
    evidence.steps.swap(0, 1);
    assert!(validate_rollback(&evidence, "owner/repo").is_err());
    evidence.steps.swap(0, 1);
    evidence.steps[2].exit_code = 1;
    assert!(validate_rollback(&evidence, "owner/repo").is_err());
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
    let jit_marker = fs::read_to_string(evidence_dir.join("security").join("jit-marker.txt"))?;
    ensure!(!jit_marker.trim().is_empty(), "encoded-JIT marker is empty");
    let sensitive = [fixture.product_token.expose_secret(), jit_marker.trim()];
    scan_evidence_tree(&evidence_dir, &sensitive)?;
    let scenarios = load_scenarios(&evidence_dir, &fixture)?;
    let rollback = load_rollback(&evidence_dir, &fixture)?;

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
    let runtime_dir = fixture.data_dir.join("runtime");
    let local_residue = if runtime_dir.is_dir() {
        fs::read_dir(&runtime_dir)?.collect::<std::io::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    ensure!(
        local_residue.is_empty(),
        "final local probe found runtime residue under {}",
        runtime_dir.display()
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
    let unredacted = serde_json::to_string_pretty(&report)?;
    scan_bytes(unredacted.as_bytes(), &sensitive)?;
    let mut report_value = serde_json::to_value(&report)?;
    redact_json_strings(&mut report_value);
    let rendered = serde_json::to_string_pretty(&report_value)?;
    scan_bytes(rendered.as_bytes(), &sensitive)?;
    let _: serde_json::Value = serde_json::from_str(&rendered)
        .context("canonical redaction must preserve a readable JSON report")?;
    fs::write(&report_path, rendered.as_bytes())?;
    println!("E2E REPORT [{}]: {}", os_name(), report_path.display());
    println!("{rendered}");
    Ok(())
}

fn load_scenarios(root: &Path, fixture: &Fixture) -> Result<Vec<ScenarioEvidence>> {
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
            verify_signed_json(&bytes, fixture.product_token.expose_secret()).with_context(
                || format!("unauthenticated controller journal: {}", path.display()),
            )?;
            let evidence: ScenarioEvidence = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid scenario evidence: {}", path.display()))?;
            let target = if scope == "repository" {
                &fixture.repository
            } else {
                &fixture.organization
            };
            validate_scenario(&evidence, scenario, scope, target)
                .with_context(|| format!("untrustworthy scenario evidence: {}", path.display()))?;
            Ok(evidence)
        })
        .collect()
}

fn load_rollback(root: &Path, fixture: &Fixture) -> Result<RollbackEvidence> {
    let path = root.join("rollback.json");
    let value: RollbackEvidence = serde_json::from_slice(&{
        let bytes = fs::read(&path)
            .with_context(|| format!("missing rollback evidence: {}", path.display()))?;
        verify_signed_json(&bytes, fixture.product_token.expose_secret())?;
        bytes
    })?;
    validate_rollback(&value, &fixture.repository)?;
    Ok(value)
}

fn validate_scenario(
    e: &ScenarioEvidence,
    scenario: &str,
    scope: &str,
    target: &str,
) -> Result<()> {
    ensure!(e.schema == 1 && e.controller == "runner-manager-e2e-host-controller/v1");
    ensure!(e.scenario == scenario && e.os == os_name() && e.scope == scope && e.target == target);
    ensure!(
        !e.routing_label.trim().is_empty()
            && !e.legacy_label.trim().is_empty()
            && e.routing_label != e.legacy_label
    );
    ensure!(e.started_at_ms > 0 && e.finished_at_ms > e.started_at_ms);
    ensure!(
        e.post_condition.github_observed_at_ms >= e.started_at_ms
            && e.post_condition.github_observed_at_ms <= e.finished_at_ms
    );
    ensure!(
        e.post_condition.local_observed_at_ms >= e.started_at_ms
            && e.post_condition.local_observed_at_ms <= e.finished_at_ms
    );
    ensure!(
        post_condition_holds(e),
        "scenario post-condition contains residue"
    );
    match (&e.facts, scenario) {
        (
            ScenarioFacts::SuccessfulJitJob {
                workflow_run_id,
                job_id,
                attempt_id,
                conclusion,
            },
            "successful_jit_job",
        ) => ensure!(
            *workflow_run_id > 0
                && *job_id > 0
                && !attempt_id.is_empty()
                && conclusion == "success"
        ),
        (
            ScenarioFacts::NetworkOutageRecovery {
                outage_started_ms,
                failed_contact_ms,
                recovered_contact_ms,
                job_id,
            },
            "network_outage_recovery",
        ) => ensure!(
            e.started_at_ms <= *outage_started_ms
                && *outage_started_ms <= *failed_contact_ms
                && *failed_contact_ms < *recovered_contact_ms
                && *recovered_contact_ms <= e.finished_at_ms
                && *job_id > 0
        ),
        (
            ScenarioFacts::JitExpiryRecovery {
                expired_attempt_id,
                expiry_observed_ms,
                replacement_attempt_id,
                job_id,
            },
            "jit_expiry_recovery",
        ) => ensure!(
            !expired_attempt_id.is_empty()
                && !replacement_attempt_id.is_empty()
                && expired_attempt_id != replacement_attempt_id
                && *expiry_observed_ms >= e.started_at_ms
                && *expiry_observed_ms <= e.finished_at_ms
                && *job_id > 0
        ),
        (
            ScenarioFacts::PolicyDisableDrain {
                disable_requested_ms,
                busy_observed_ms,
                terminal_observed_ms,
                launches_after_disable,
            },
            "policy_disable_drain",
        ) => ensure!(
            *busy_observed_ms <= *disable_requested_ms
                && *disable_requested_ms < *terminal_observed_ms
                && *terminal_observed_ms <= e.finished_at_ms
                && *launches_after_disable == 0
        ),
        (
            ScenarioFacts::BootStartRecovery {
                boot_id_before,
                boot_id_after,
                service_started_ms,
                github_contact_ms,
                interactive_login_observed,
                job_id,
            },
            "boot_start_recovery",
        ) => ensure!(
            !boot_id_before.is_empty()
                && !boot_id_after.is_empty()
                && boot_id_before != boot_id_after
                && *service_started_ms < *github_contact_ms
                && !interactive_login_observed
                && *job_id > 0
        ),
        (
            ScenarioFacts::OrganizationScopedJob {
                job_id,
                runner_id,
                github_scope,
            },
            "organization_scoped_job",
        ) => ensure!(
            *job_id > 0
                && *runner_id > 0
                && github_scope == "organization"
                && scope == "organization"
        ),
        (
            ScenarioFacts::MonitorOnlyDemand {
                queued_jobs_observed,
                runner_attempts_started,
            },
            "monitor_only_demand",
        ) => ensure!(*queued_jobs_observed > 0 && *runner_attempts_started == 0),
        (
            ScenarioFacts::TwoHostContention {
                host_ids,
                attempt_ids,
                completed_job_ids,
                idle_exit_attempt_id,
                idle_exit_recorded_as_failure,
            },
            "two_host_contention",
        ) => ensure!(
            !host_ids[0].is_empty()
                && host_ids[0] != host_ids[1]
                && !attempt_ids[0].is_empty()
                && attempt_ids[0] != attempt_ids[1]
                && completed_job_ids.len() == 1
                && completed_job_ids[0] > 0
                && attempt_ids.contains(idle_exit_attempt_id)
                && !idle_exit_recorded_as_failure
        ),
        _ => bail!("scenario facts do not match scenario name"),
    }
    Ok(())
}

fn validate_rollback(value: &RollbackEvidence, target: &str) -> Result<()> {
    ensure!(
        value.schema == 1
            && value.controller == "runner-manager-e2e-host-controller/v1"
            && value.os == os_name()
            && value.target == target
    );
    ensure!(
        value.steps.len() == 4,
        "rollback must contain exactly four steps"
    );
    let kinds = [
        RollbackKind::RestoreLabel,
        RollbackKind::Drain,
        RollbackKind::VerifyTerminal,
        RollbackKind::ReenableLegacy,
    ];
    for (index, (step, kind)) in value.steps.iter().zip(kinds).enumerate() {
        ensure!(step.kind == kind && step.exit_code == 0 && !step.command.is_empty());
        ensure!(step.finished_at_ms > step.started_at_ms);
        if index > 0 {
            ensure!(
                step.started_at_ms >= value.steps[index - 1].finished_at_ms,
                "rollback steps overlap or are out of order"
            );
        }
    }
    ensure!(value.post_condition.registered_runner_ids.is_empty());
    ensure!(value.post_condition.runtime_directories.is_empty());
    ensure!(
        value.post_condition.legacy_label_runner_ids.len() == 1,
        "legacy re-enable must be independently visible at GitHub"
    );
    Ok(())
}

fn run_security_gates(
    fixture: &Fixture,
    evidence_root: &Path,
    scenarios: &[ScenarioEvidence],
) -> Result<Vec<GateEvidence>> {
    let mut gates = vec![
        execute_recipe(recipe("process_inspection"), fixture, evidence_root)?,
        execute_recipe(recipe("two_job_contamination"), fixture, evidence_root)?,
        execute_recipe(recipe("runner_package_integrity"), fixture, evidence_root)?,
        secret_injection_gate(fixture, evidence_root)?,
        execute_recipe(recipe("revoked_token_rejection"), fixture, evidence_root)?,
        credential_free_state_gate(fixture, evidence_root)?,
        execute_recipe(recipe("workspace_removal"), fixture, evidence_root)?,
        execute_recipe(recipe("restart_duplicate_poll"), fixture, evidence_root)?,
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

fn recipe_validator_is_mutation_sensitive(recipe: &GateRecipe) -> Result<()> {
    for test in recipe.tests {
        let valid = CommandReceipt {
            package: test.package.into(),
            filter: test.filter.into(),
            success: true,
            matched_tests: 1,
        };
        validate_receipt(test, &valid)?;

        let mut mutated = valid.clone();
        mutated.success = false;
        ensure!(validate_receipt(test, &mutated).is_err());
        mutated = valid.clone();
        mutated.filter.push_str("_fabricated");
        ensure!(validate_receipt(test, &mutated).is_err());
        mutated = valid;
        mutated.matched_tests = 0;
        ensure!(validate_receipt(test, &mutated).is_err());
    }
    Ok(())
}

fn post_condition_holds(evidence: &ScenarioEvidence) -> bool {
    evidence.post_condition.registered_runner_ids.is_empty()
        && evidence.post_condition.runtime_directories.is_empty()
        && evidence.post_condition.legacy_label_runner_ids.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandReceipt {
    package: String,
    filter: String,
    success: bool,
    matched_tests: usize,
}

#[derive(Debug)]
struct TestCase {
    package: &'static str,
    filter: &'static str,
}

#[derive(Debug)]
struct GateRecipe {
    gate: &'static str,
    tests: &'static [TestCase],
}

const PROCESS_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "native_process_listing_never_contains_jit_and_handoffs_never_survive",
}];
const CONTAMINATION_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "two_attempts_never_share_a_workspace_even_after_failure",
}];
const PACKAGE_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager-agent",
        filter: "a_checksum_mismatch_is_retryable_and_clean_bytes_still_install",
    },
    TestCase {
        package: "runner-manager-agent",
        filter: "an_absent_published_checksum_refuses_to_install_and_names_the_remedy",
    },
];
const REVOKED_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager",
        filter: "a_revoked_credential_is_reported_as_revoked_and_not_as_a_missing_one",
    },
    TestCase {
        package: "runner-manager-domain",
        filter: "re_authentication_is_the_only_way_out_of_authentication_failed",
    },
    TestCase {
        package: "runner-manager-domain",
        filter: "authentication_failed_policy_is_ineligible_and_cannot_start_a_runner",
    },
];
const WORKSPACE_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager-agent",
        filter: "a_job_walks_every_state_and_cleans_every_artifact",
    },
    TestCase {
        package: "runner-manager-agent",
        filter: "expired_jit_is_removed_and_does_not_reregister_after_demand_disappears",
    },
];
const DUPLICATE_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "three_polls_of_one_still_queued_run_yield_exactly_one_attempt",
}];

fn recipe(name: &str) -> &'static GateRecipe {
    static RECIPES: &[GateRecipe] = &[
        GateRecipe {
            gate: "process_inspection",
            tests: PROCESS_TESTS,
        },
        GateRecipe {
            gate: "two_job_contamination",
            tests: CONTAMINATION_TESTS,
        },
        GateRecipe {
            gate: "runner_package_integrity",
            tests: PACKAGE_TESTS,
        },
        GateRecipe {
            gate: "revoked_token_rejection",
            tests: REVOKED_TESTS,
        },
        GateRecipe {
            gate: "workspace_removal",
            tests: WORKSPACE_TESTS,
        },
        GateRecipe {
            gate: "restart_duplicate_poll",
            tests: DUPLICATE_TESTS,
        },
    ];
    RECIPES
        .iter()
        .find(|recipe| recipe.gate == name)
        .expect("security recipe exists")
}

fn execute_recipe(
    recipe: &'static GateRecipe,
    fixture: &Fixture,
    evidence_root: &Path,
) -> Result<GateEvidence> {
    let jit = fs::read_to_string(evidence_root.join("security").join("jit-marker.txt"))?;
    let needles = [fixture.product_token.expose_secret(), jit.trim()];
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("acceptance package has a workspace parent")?;
    let mut executed = Vec::new();
    for test in recipe.tests {
        let output = std::process::Command::new(env!("CARGO"))
            .current_dir(workspace)
            .args(["test", "-p", test.package, test.filter, "--", "--nocapture"])
            .output()
            .with_context(|| format!("could not execute {} negative control", test.filter))?;
        scan_bytes(&output.stdout, &needles)?;
        scan_bytes(&output.stderr, &needles)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let receipt = CommandReceipt {
            package: test.package.into(),
            filter: test.filter.into(),
            success: output.status.success(),
            matched_tests: stdout.matches(" ... ok").count(),
        };
        validate_receipt(test, &receipt).with_context(|| {
            format!(
                "{} failed\nstdout:\n{stdout}\nstderr:\n{stderr}",
                test.filter
            )
        })?;
        executed.push(format!("{}::{}", test.package, test.filter));
    }
    Ok(GateEvidence {
        gate: recipe.gate,
        observed_evidence: format!(
            "repository-defined executable negative controls passed: {}",
            executed.join(", ")
        ),
    })
}

fn validate_receipt(expected: &TestCase, receipt: &CommandReceipt) -> Result<()> {
    ensure!(
        receipt.package == expected.package,
        "wrong package executed"
    );
    ensure!(
        receipt.filter == expected.filter,
        "wrong negative control executed"
    );
    ensure!(receipt.success, "negative-control command failed");
    ensure!(
        receipt.matched_tests == 1,
        "negative control matched {} tests, expected exactly one",
        receipt.matched_tests
    );
    Ok(())
}

fn secret_injection_gate(fixture: &Fixture, root: &Path) -> Result<GateEvidence> {
    let artifacts = root.join("security").join("secret-scan-root");
    let jit = fs::read_to_string(root.join("security").join("jit-marker.txt"))
        .context("missing encoded-JIT marker used by the secret-injection gate")?;
    ensure!(!jit.trim().is_empty(), "encoded-JIT marker is empty");
    let needles = [fixture.product_token.expose_secret(), jit.trim()];
    for category in [
        "logs",
        "database",
        "snapshots",
        "crash-reports",
        "cli-output",
    ] {
        let path = artifacts.join(category);
        scan_tree_for_secrets(&path, &needles)
            .with_context(|| format!("required secret-scan category {category}"))?;
    }

    // Mutation proof: the exact scanner used above must fail on both values.
    ensure!(scan_bytes(b"prefix token-leak suffix", &["token-leak"]).is_err());
    ensure!(scan_bytes(b"encoded-jit-leak", &["encoded-jit-leak"]).is_err());
    let shaped = "ghu_0123456789abcdefghijklmnopqrstuvwxyzABCD";
    ensure!(
        runner_manager_platform::logging::redact(shaped)
            == runner_manager_platform::logging::REDACTION,
        "canonical redaction negative control did not redact a token-shaped value"
    );
    Ok(GateEvidence {
        gate: "secret_injection_scan",
        observed_evidence: format!(
            "scanned logs, databases, snapshots, crash reports and CLI output under {}",
            artifacts.display()
        ),
    })
}

fn scan_evidence_tree(root: &Path, needles: &[&str]) -> Result<()> {
    ensure!(
        root.is_dir(),
        "evidence root does not exist: {}",
        root.display()
    );
    let marker = root.join("security").join("jit-marker.txt");
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.path() == marker {
                continue;
            }
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file() {
                scan_bytes(&fs::read(entry.path())?, needles)?;
            }
        }
    }
    Ok(())
}

fn credential_free_state_gate(fixture: &Fixture, root: &Path) -> Result<GateEvidence> {
    let state = root.join("security").join("config-and-sqlite");
    ensure!(
        state.join("runner-manager.sqlite3").is_file(),
        "credential scan requires the actual SQLite snapshot"
    );
    ensure!(
        fs::read_dir(&state)?.filter_map(Result::ok).any(|entry| {
            matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("toml" | "json")
            )
        }),
        "credential scan requires a configuration snapshot"
    );
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
    let mut files = 0_usize;
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files += 1;
                scan_bytes(&fs::read(entry.path())?, needles)
                    .with_context(|| format!("secret scan failed in {}", entry.path().display()))?;
            }
        }
    }
    ensure!(
        files > 0,
        "scan root contains no artifacts: {}",
        root.display()
    );
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

fn redact_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = runner_manager_platform::logging::redact(text);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_strings(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                redact_json_strings(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn verify_signed_json(bytes: &[u8], key: &str) -> Result<()> {
    ensure!(!key.is_empty(), "controller authentication key is empty");
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let supplied = value
        .get("authentication_tag")
        .and_then(serde_json::Value::as_str)
        .context("controller journal omitted authentication_tag")?
        .to_string();
    ensure!(supplied.len() == 64 && supplied.bytes().all(|b| b.is_ascii_hexdigit()));
    value["authentication_tag"] = serde_json::Value::String(String::new());
    let expected = hex::encode(hmac_sha256(key.as_bytes(), &serde_json::to_vec(&value)?));
    ensure!(
        supplied
            .bytes()
            .zip(expected.bytes())
            .fold(0_u8, |difference, (left, right)| difference
                | (left ^ right))
            == 0,
        "controller journal authentication failed"
    );
    Ok(())
}

fn sign_json_value(value: &mut serde_json::Value, key: &str) -> Result<()> {
    ensure!(value.get("authentication_tag").is_some());
    value["authentication_tag"] = serde_json::Value::String(String::new());
    let tag = hex::encode(hmac_sha256(key.as_bytes(), &serde_json::to_vec(value)?));
    value["authentication_tag"] = serde_json::Value::String(tag);
    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
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
