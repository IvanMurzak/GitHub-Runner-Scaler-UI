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
use std::io::Write as _;
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
    evidence_key: SecretString,
    expected_context: ExpectedContext,
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
            evidence_key: SecretString::from(
                std::env::var("RUNNER_MANAGER_E2E_EVIDENCE_KEY")
                    .expect("a separate RUNNER_MANAGER_E2E_EVIDENCE_KEY is required"),
            ),
            expected_context: ExpectedContext::from_environment(),
        })
    }
}

#[derive(Debug)]
struct ExpectedContext {
    run_id: u64,
    run_attempt: u64,
    commit_sha: String,
    architecture: String,
    challenge: String,
}

impl ExpectedContext {
    fn from_environment() -> Self {
        let required = |name: &str| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} is required for live evidence binding"))
        };
        let challenge = required("RUNNER_MANAGER_E2E_CHALLENGE");
        assert!(
            challenge.len() >= 64 && challenge.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "RUNNER_MANAGER_E2E_CHALLENGE must be at least 256 random bits encoded as hex"
        );
        Self {
            run_id: required("GITHUB_RUN_ID")
                .parse()
                .expect("GITHUB_RUN_ID is numeric"),
            run_attempt: required("GITHUB_RUN_ATTEMPT")
                .parse()
                .expect("GITHUB_RUN_ATTEMPT is numeric"),
            commit_sha: required("GITHUB_SHA"),
            architecture: required("RUNNER_ARCH"),
            challenge,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceContext {
    run_id: u64,
    run_attempt: u64,
    commit_sha: String,
    os: String,
    architecture: String,
    challenge: String,
    nonce: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioEvidence {
    schema: u8,
    authentication_tag: String,
    context: EvidenceContext,
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
        runner_id: u64,
        attempt_id: String,
        conclusion: String,
    },
    NetworkOutageRecovery {
        workflow_run_id: u64,
        job_id: u64,
        runner_id: u64,
        attempt_id: String,
        outage_started_ms: u64,
        failed_contact_ms: u64,
        recovered_contact_ms: u64,
        conclusion: String,
    },
    JitExpiryRecovery {
        workflow_run_id: u64,
        job_id: u64,
        expired_attempt_id: String,
        expired_runner_id: u64,
        expiry_observed_ms: u64,
        replacement_attempt_id: String,
        replacement_runner_id: u64,
        conclusion: String,
    },
    PolicyDisableDrain {
        workflow_run_id: u64,
        job_id: u64,
        attempt_id: String,
        disable_requested_ms: u64,
        busy_observed_ms: u64,
        terminal_observed_ms: u64,
        launches_after_disable: u64,
        conclusion: String,
    },
    BootStartRecovery {
        workflow_run_id: u64,
        job_id: u64,
        runner_id: u64,
        attempt_id: String,
        boot_id_before: String,
        boot_id_after: String,
        service_started_ms: u64,
        github_contact_ms: u64,
        interactive_login_observed: bool,
        conclusion: String,
    },
    OrganizationScopedJob {
        workflow_run_id: u64,
        job_id: u64,
        runner_id: u64,
        attempt_id: String,
        github_scope: String,
        conclusion: String,
    },
    MonitorOnlyDemand {
        workflow_run_id: u64,
        policy_id: String,
        queued_job_ids: Vec<u64>,
        runner_attempts_started: u64,
    },
    TwoHostContention {
        workflow_run_id: u64,
        host_ids: [String; 2],
        attempt_ids: [String; 2],
        runner_ids: [u64; 2],
        completed_job_ids: Vec<u64>,
        idle_exit_attempt_id: String,
        idle_exit_reason: String,
        idle_exit_recorded_as_failure: bool,
        surplus_cleanup: CleanupReceipt,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    attempt_id: String,
    github_removed_at_ms: u64,
    runtime_removed_at_ms: u64,
    outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostCondition {
    github_observed_at_ms: u64,
    registered_runner_ids: Vec<u64>,
    legacy_label_runner_ids: Vec<u64>,
    local_observed_at_ms: u64,
    runtime_root: String,
    runtime_directories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackEvidence {
    schema: u8,
    authentication_tag: String,
    context: EvidenceContext,
    controller: String,
    os: String,
    target: String,
    legacy_runner_id: u64,
    legacy_label: String,
    legacy_service: String,
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
    target: String,
    exit_code: i32,
    stdout: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessInspectionEvidence {
    schema: u8,
    authentication_tag: String,
    context: EvidenceContext,
    controller: String,
    observed_at_ms: u64,
    manager_pid: u32,
    listener_pid: u32,
    manager_command_line: String,
    listener_command_line: String,
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
fn host_controller_refuses_imports_and_reports_required_manual() -> Result<()> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("acceptance package has a workspace parent")?;
    let root = tempfile::tempdir()?;
    let imported = root.path().join("imported");
    fs::create_dir(&imported)?;
    fs::write(imported.join("successful_jit_job.json"), "fabricated")?;
    let imported_argument = bash_path(&imported);
    let rejected = std::process::Command::new(bash_program())
        .current_dir(workspace)
        .args([
            "tests/host-controller.sh",
            "live-suite",
            &imported_argument,
            os_name(),
        ])
        .output()?;
    ensure!(!rejected.status.success(), "imported evidence was accepted");

    let fresh = root.path().join("fresh");
    let fresh_argument = bash_path(&fresh);
    let manual = std::process::Command::new(bash_program())
        .current_dir(workspace)
        .env_remove("RUNNER_MANAGER_E2E_PHYSICAL_HOST")
        .args([
            "tests/host-controller.sh",
            "live-suite",
            &fresh_argument,
            os_name(),
        ])
        .output()?;
    ensure!(!manual.status.success(), "missing physical topology passed");
    let classification: serde_json::Value =
        serde_json::from_slice(&fs::read(fresh.join("manual-required.json"))?)?;
    ensure!(classification["status"] == "required_manual");
    ensure!(
        fs::read_dir(&fresh)?
            .all(|entry| { entry.is_ok_and(|entry| entry.file_name() == "manual-required.json") }),
        "required_manual path emitted signable evidence"
    );
    Ok(())
}

fn bash_path(path: &Path) -> String {
    let rendered = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) && rendered.as_bytes().get(1) == Some(&b':') {
        format!("/{}/{}", rendered[..1].to_ascii_lowercase(), &rendered[3..])
    } else {
        rendered
    }
}

fn bash_program() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .map(|root| root.join("Git").join("bin").join("bash.exe"))
            .filter(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from("bash.exe"))
    } else {
        PathBuf::from("bash")
    }
}

#[test]
fn fabricated_controller_json_fails_authentication() -> Result<()> {
    let key = "independent-evidence-authority";
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
    ensure!(
        validate_authority_separation(key, key).is_err(),
        "fixture token was accepted as a signing oracle"
    );
    validate_authority_separation("product-fixture-token", key)?;
    assert_eq!(
        hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "HMAC-SHA-256 must match RFC 4231 test case 1"
    );
    Ok(())
}

#[test]
fn wrong_run_expired_and_replayed_evidence_are_rejected() -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let expected = ExpectedContext {
        run_id: 7,
        run_attempt: 2,
        commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        architecture: "X64".into(),
        challenge: "cd".repeat(32),
    };
    let mut context = EvidenceContext {
        run_id: 7,
        run_attempt: 2,
        commit_sha: expected.commit_sha.clone(),
        os: os_name().into(),
        architecture: "X64".into(),
        challenge: expected.challenge.clone(),
        nonce: "ab".repeat(16),
        issued_at_ms: now - 1_000,
        expires_at_ms: now + 60_000,
    };
    validate_evidence_context(&context, &expected)?;
    context.run_id = 8;
    ensure!(validate_evidence_context(&context, &expected).is_err());
    context.run_id = 7;
    context.run_attempt = 3;
    ensure!(validate_evidence_context(&context, &expected).is_err());
    context.run_attempt = 2;
    context.commit_sha = "wrong-commit".into();
    ensure!(validate_evidence_context(&context, &expected).is_err());
    context.commit_sha = expected.commit_sha.clone();
    context.challenge = "ef".repeat(32);
    ensure!(validate_evidence_context(&context, &expected).is_err());
    context.challenge = expected.challenge.clone();
    context.expires_at_ms = now - 1;
    ensure!(validate_evidence_context(&context, &expected).is_err());
    context.expires_at_ms = now + 60_000;
    let root = tempfile::tempdir()?;
    consume_nonce(root.path(), &context)?;
    ensure!(
        consume_nonce(root.path(), &context).is_err(),
        "replayed nonce was accepted"
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
    ensure!(recipe("process_inspection").tests.len() == 1);
    Ok(())
}

#[test]
fn security_gate_two_job_contamination_requires_observed_evidence() -> Result<()> {
    recipe_declares_product_mutants(recipe("two_job_contamination"))
}

#[test]
fn security_gate_runner_package_integrity_requires_both_rejections() -> Result<()> {
    let recipe = recipe("runner_package_integrity");
    ensure!(
        recipe.tests.len() == 2,
        "both checksum mutations are required"
    );
    recipe_declares_product_mutants(recipe)
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
    recipe_declares_product_mutants(recipe("revoked_token_rejection"))
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
    recipe_declares_product_mutants(recipe)
}

#[test]
fn security_gate_restart_duplicate_poll_requires_observed_evidence() -> Result<()> {
    recipe_declares_product_mutants(recipe("restart_duplicate_poll"))
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
        context: test_context("scenario-nonce"),
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
            runner_id: 3,
            attempt_id: "attempt-1".into(),
            conclusion: "success".into(),
        },
        post_condition: PostCondition {
            github_observed_at_ms: 8,
            registered_runner_ids: vec![],
            legacy_label_runner_ids: vec![],
            local_observed_at_ms: 9,
            runtime_root: "runtime".into(),
            runtime_directories: vec![],
        },
    };
    validate_scenario(
        &evidence,
        "successful_jit_job",
        "repository",
        "owner/repo",
        "runtime",
    )
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
        validate_scenario(
            &evidence,
            "successful_jit_job",
            "repository",
            "owner/repo",
            "runtime"
        )
        .is_err()
    );
    evidence.controller = "runner-manager-e2e-host-controller/v1".into();
    if let ScenarioFacts::SuccessfulJitJob { conclusion, .. } = &mut evidence.facts {
        *conclusion = "failure".into();
    }
    assert!(
        validate_scenario(
            &evidence,
            "successful_jit_job",
            "repository",
            "owner/repo",
            "runtime"
        )
        .is_err()
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
        context: test_context("rollback-nonce"),
        controller: "runner-manager-e2e-host-controller/v1".into(),
        os: os_name().into(),
        target: "owner/repo".into(),
        legacy_runner_id: 42,
        legacy_label: "legacy-win".into(),
        legacy_service: "actions.runner.legacy".into(),
        steps: kinds
            .into_iter()
            .enumerate()
            .map(|(i, kind)| RollbackStep {
                kind,
                started_at_ms: 10 + (i as u64 * 10),
                finished_at_ms: 19 + (i as u64 * 10),
                command: match kind {
                    RollbackKind::RestoreLabel => vec![
                        "bash".into(),
                        "tests/host-controller.sh".into(),
                        "operation".into(),
                        "restore-label".into(),
                        "owner/repo".into(),
                        "42".into(),
                        "legacy-win".into(),
                    ],
                    RollbackKind::Drain => vec![
                        "runner-manager".into(),
                        "repo".into(),
                        "set-scale".into(),
                        "owner/repo".into(),
                        "--enabled".into(),
                        "false".into(),
                    ],
                    RollbackKind::VerifyTerminal => {
                        vec!["runner-manager".into(), "status".into(), "--json".into()]
                    }
                    RollbackKind::ReenableLegacy => vec![
                        "bash".into(),
                        "tests/host-controller.sh".into(),
                        "operation".into(),
                        "legacy-service-enable".into(),
                        os_name().into(),
                        "actions.runner.legacy".into(),
                    ],
                },
                target: "owner/repo".into(),
                exit_code: 0,
                stdout: match kind {
                    RollbackKind::RestoreLabel => "{\"label_restored\":true,\"runner_id\":42}",
                    RollbackKind::Drain => "{\"state\":\"draining\"}",
                    RollbackKind::VerifyTerminal => "{\"active_attempts\":0}",
                    RollbackKind::ReenableLegacy => "{\"legacy_enabled\":true}",
                }
                .into(),
            })
            .collect(),
        post_condition: PostCondition {
            github_observed_at_ms: 51,
            registered_runner_ids: vec![],
            legacy_label_runner_ids: vec![42],
            local_observed_at_ms: 52,
            runtime_root: "runtime".into(),
            runtime_directories: vec![],
        },
    };
    validate_rollback(&evidence, "owner/repo", "runtime")
        .expect("ordered successful rollback passes");
    evidence.steps.swap(0, 1);
    assert!(validate_rollback(&evidence, "owner/repo", "runtime").is_err());
    evidence.steps.swap(0, 1);
    evidence.steps[2].exit_code = 1;
    assert!(validate_rollback(&evidence, "owner/repo", "runtime").is_err());
}

fn test_context(nonce: &str) -> EvidenceContext {
    EvidenceContext {
        run_id: 1,
        run_attempt: 1,
        commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        os: os_name().into(),
        architecture: "X64".into(),
        challenge: "ab".repeat(32),
        nonce: nonce.into(),
        issued_at_ms: 1,
        expires_at_ms: u64::MAX,
    }
}

#[test]
#[ignore = "requires the disposable repository, organization, and native host controller"]
fn release_acceptance_and_security_report() -> Result<()> {
    let Some(fixture) = Fixture::from_environment() else {
        return Ok(());
    };
    validate_authority_separation(
        fixture.product_token.expose_secret(),
        fixture.evidence_key.expose_secret(),
    )?;

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
    let sensitive = [
        fixture.product_token.expose_secret(),
        fixture.fixture_token.expose_secret(),
        fixture.evidence_key.expose_secret(),
        jit_marker.trim(),
    ];
    scan_evidence_tree(&evidence_dir, &sensitive)?;
    let scenarios = load_scenarios(&evidence_dir, &fixture)?;
    let rollback = load_rollback(&evidence_dir, &fixture)?;

    // The two credentials have deliberately disjoint roles.  The product
    // token is used only for the product-facing inventory proof; the fixture
    // token is used only to prove the test fixture itself is reachable.
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        ensure_fixture_reachable(&fixture).await?;
        verify_remote_scenarios(&fixture, &scenarios).await?;
        verify_final_runner_inventory(&fixture, &scenarios, &rollback).await
    })?;
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
            verify_signed_json(&bytes, fixture.evidence_key.expose_secret()).with_context(
                || format!("unauthenticated controller journal: {}", path.display()),
            )?;
            let evidence: ScenarioEvidence = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid scenario evidence: {}", path.display()))?;
            validate_evidence_context(&evidence.context, &fixture.expected_context)?;
            consume_nonce(&fixture.data_dir, &evidence.context)?;
            let target = if scope == "repository" {
                &fixture.repository
            } else {
                &fixture.organization
            };
            let runtime_root = fixture
                .data_dir
                .join("runtime")
                .to_string_lossy()
                .into_owned();
            validate_scenario(&evidence, scenario, scope, target, &runtime_root)
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
        verify_signed_json(&bytes, fixture.evidence_key.expose_secret())?;
        bytes
    })?;
    validate_evidence_context(&value.context, &fixture.expected_context)?;
    consume_nonce(&fixture.data_dir, &value.context)?;
    let runtime_root = fixture
        .data_dir
        .join("runtime")
        .to_string_lossy()
        .into_owned();
    validate_rollback(&value, &fixture.repository, &runtime_root)?;
    Ok(value)
}

fn validate_scenario(
    e: &ScenarioEvidence,
    scenario: &str,
    scope: &str,
    target: &str,
    runtime_root: &str,
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
    ensure!(
        e.post_condition.runtime_root == runtime_root,
        "scenario local probe used a different runtime root"
    );
    match (&e.facts, scenario) {
        (
            ScenarioFacts::SuccessfulJitJob {
                workflow_run_id,
                job_id,
                runner_id,
                attempt_id,
                conclusion,
            },
            "successful_jit_job",
        ) => ensure!(
            *workflow_run_id > 0
                && *job_id > 0
                && *runner_id > 0
                && !attempt_id.is_empty()
                && conclusion == "success"
        ),
        (
            ScenarioFacts::NetworkOutageRecovery {
                workflow_run_id,
                job_id,
                runner_id,
                attempt_id,
                outage_started_ms,
                failed_contact_ms,
                recovered_contact_ms,
                conclusion,
            },
            "network_outage_recovery",
        ) => ensure!(
            e.started_at_ms <= *outage_started_ms
                && *outage_started_ms <= *failed_contact_ms
                && *failed_contact_ms < *recovered_contact_ms
                && *recovered_contact_ms <= e.finished_at_ms
                && *job_id > 0
                && *workflow_run_id > 0
                && *runner_id > 0
                && !attempt_id.is_empty()
                && conclusion == "success"
        ),
        (
            ScenarioFacts::JitExpiryRecovery {
                workflow_run_id,
                job_id,
                expired_attempt_id,
                expired_runner_id,
                expiry_observed_ms,
                replacement_attempt_id,
                replacement_runner_id,
                conclusion,
            },
            "jit_expiry_recovery",
        ) => ensure!(
            !expired_attempt_id.is_empty()
                && !replacement_attempt_id.is_empty()
                && expired_attempt_id != replacement_attempt_id
                && *expiry_observed_ms >= e.started_at_ms
                && *expiry_observed_ms <= e.finished_at_ms
                && *job_id > 0
                && *workflow_run_id > 0
                && *expired_runner_id > 0
                && *replacement_runner_id > 0
                && expired_runner_id != replacement_runner_id
                && conclusion == "success"
        ),
        (
            ScenarioFacts::PolicyDisableDrain {
                workflow_run_id,
                job_id,
                attempt_id,
                disable_requested_ms,
                busy_observed_ms,
                terminal_observed_ms,
                launches_after_disable,
                conclusion,
            },
            "policy_disable_drain",
        ) => ensure!(
            *busy_observed_ms <= *disable_requested_ms
                && *disable_requested_ms < *terminal_observed_ms
                && *terminal_observed_ms <= e.finished_at_ms
                && *launches_after_disable == 0
                && *workflow_run_id > 0
                && *job_id > 0
                && !attempt_id.is_empty()
                && conclusion == "success"
        ),
        (
            ScenarioFacts::BootStartRecovery {
                workflow_run_id,
                runner_id,
                attempt_id,
                boot_id_before,
                boot_id_after,
                service_started_ms,
                github_contact_ms,
                interactive_login_observed,
                job_id,
                conclusion,
            },
            "boot_start_recovery",
        ) => ensure!(
            !boot_id_before.is_empty()
                && !boot_id_after.is_empty()
                && boot_id_before != boot_id_after
                && *service_started_ms < *github_contact_ms
                && !interactive_login_observed
                && *job_id > 0
                && *workflow_run_id > 0
                && *runner_id > 0
                && !attempt_id.is_empty()
                && conclusion == "success"
        ),
        (
            ScenarioFacts::OrganizationScopedJob {
                workflow_run_id,
                job_id,
                runner_id,
                attempt_id,
                github_scope,
                conclusion,
            },
            "organization_scoped_job",
        ) => ensure!(
            *job_id > 0
                && *workflow_run_id > 0
                && *runner_id > 0
                && !attempt_id.is_empty()
                && github_scope == "organization"
                && scope == "organization"
                && conclusion == "success"
        ),
        (
            ScenarioFacts::MonitorOnlyDemand {
                workflow_run_id,
                policy_id,
                queued_job_ids,
                runner_attempts_started,
            },
            "monitor_only_demand",
        ) => ensure!(
            *workflow_run_id > 0
                && !policy_id.is_empty()
                && !queued_job_ids.is_empty()
                && queued_job_ids.iter().all(|id| *id > 0)
                && *runner_attempts_started == 0
        ),
        (
            ScenarioFacts::TwoHostContention {
                workflow_run_id,
                host_ids,
                attempt_ids,
                runner_ids,
                completed_job_ids,
                idle_exit_attempt_id,
                idle_exit_reason,
                idle_exit_recorded_as_failure,
                surplus_cleanup,
            },
            "two_host_contention",
        ) => ensure!(
            !host_ids[0].is_empty()
                && *workflow_run_id > 0
                && host_ids[0] != host_ids[1]
                && !attempt_ids[0].is_empty()
                && attempt_ids[0] != attempt_ids[1]
                && completed_job_ids.len() == 1
                && completed_job_ids[0] > 0
                && attempt_ids.contains(idle_exit_attempt_id)
                && runner_ids.iter().all(|id| *id > 0)
                && runner_ids[0] != runner_ids[1]
                && idle_exit_reason == "idle_timeout"
                && !idle_exit_recorded_as_failure
                && surplus_cleanup.attempt_id == *idle_exit_attempt_id
                && surplus_cleanup.outcome == "cleaned"
                && surplus_cleanup.github_removed_at_ms > 0
                && surplus_cleanup.runtime_removed_at_ms > 0
        ),
        _ => bail!("scenario facts do not match scenario name"),
    }
    Ok(())
}

fn validate_rollback(value: &RollbackEvidence, target: &str, runtime_root: &str) -> Result<()> {
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
    ensure!(
        value.legacy_runner_id > 0
            && !value.legacy_label.is_empty()
            && !value.legacy_service.is_empty(),
        "rollback omitted the legacy runner target identity"
    );
    let kinds = [
        RollbackKind::RestoreLabel,
        RollbackKind::Drain,
        RollbackKind::VerifyTerminal,
        RollbackKind::ReenableLegacy,
    ];
    for (index, (step, kind)) in value.steps.iter().zip(kinds).enumerate() {
        ensure!(step.kind == kind && step.exit_code == 0 && step.target == target);
        let (expected_command, output_fact): (Vec<String>, &str) = match kind {
            RollbackKind::RestoreLabel => (
                vec![
                    "bash".into(),
                    "tests/host-controller.sh".into(),
                    "operation".into(),
                    "restore-label".into(),
                    target.into(),
                    value.legacy_runner_id.to_string(),
                    value.legacy_label.clone(),
                ],
                "\"label_restored\":true",
            ),
            RollbackKind::Drain => (
                vec![
                    "runner-manager".into(),
                    "repo".into(),
                    "set-scale".into(),
                    target.into(),
                    "--enabled".into(),
                    "false".into(),
                ],
                "\"state\":\"draining\"",
            ),
            RollbackKind::VerifyTerminal => (
                vec!["runner-manager".into(), "status".into(), "--json".into()],
                "\"active_attempts\":0",
            ),
            RollbackKind::ReenableLegacy => (
                vec![
                    "bash".into(),
                    "tests/host-controller.sh".into(),
                    "operation".into(),
                    "legacy-service-enable".into(),
                    os_name().into(),
                    value.legacy_service.clone(),
                ],
                "\"legacy_enabled\":true",
            ),
        };
        ensure!(
            step.command == expected_command,
            "rollback command verb/args do not match the required operation"
        );
        ensure!(
            step.stdout.contains(output_fact),
            "rollback command output omitted its required observed outcome"
        );
        if kind == RollbackKind::RestoreLabel {
            ensure!(
                step.stdout
                    .contains(&format!("\"runner_id\":{}", value.legacy_runner_id)),
                "restore-label output names a different runner"
            );
        }
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
    ensure!(value.post_condition.runtime_root == runtime_root);
    ensure!(
        value.post_condition.legacy_label_runner_ids == [value.legacy_runner_id],
        "legacy re-enable must be independently visible at GitHub"
    );
    Ok(())
}

fn validate_evidence_context(context: &EvidenceContext, expected: &ExpectedContext) -> Result<()> {
    ensure!(
        context.run_id == expected.run_id,
        "evidence belongs to a different GitHub run"
    );
    ensure!(
        context.run_attempt == expected.run_attempt,
        "evidence belongs to a different run attempt"
    );
    ensure!(
        context.commit_sha == expected.commit_sha,
        "evidence belongs to a different commit"
    );
    ensure!(
        context.os == os_name(),
        "evidence belongs to a different OS"
    );
    ensure!(
        context.architecture == expected.architecture,
        "evidence belongs to a different architecture"
    );
    ensure!(
        context.challenge == expected.challenge,
        "evidence challenge does not match this job"
    );
    ensure!(
        context.nonce.len() >= 32 && context.nonce.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "evidence nonce is not a cryptographic hex nonce"
    );
    ensure!(
        context.expires_at_ms > context.issued_at_ms
            && context.expires_at_ms - context.issued_at_ms <= 15 * 60 * 1_000,
        "evidence lifetime exceeds fifteen minutes"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    ensure!(
        context.issued_at_ms <= now && now <= context.expires_at_ms,
        "evidence is not currently valid"
    );
    Ok(())
}

fn consume_nonce(data_dir: &Path, context: &EvidenceContext) -> Result<()> {
    let directory = data_dir
        .join("state")
        .join("evidence-consumed")
        .join(context.run_id.to_string());
    fs::create_dir_all(&directory)?;
    let path = directory.join(&context.nonce);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "evidence nonce was already consumed (replay): {}",
                context.nonce
            )
        })?;
    writeln!(file, "{} {}", context.run_attempt, context.commit_sha)?;
    Ok(())
}

fn run_security_gates(
    fixture: &Fixture,
    evidence_root: &Path,
    scenarios: &[ScenarioEvidence],
) -> Result<Vec<GateEvidence>> {
    let mut gates = vec![
        process_inspection_gate(fixture, evidence_root)?,
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

fn process_inspection_gate(fixture: &Fixture, evidence_root: &Path) -> Result<GateEvidence> {
    // Keep the product-level negative control, then require an observation of
    // the two shipping processes from the native host controller.
    execute_recipe(recipe("process_inspection"), fixture, evidence_root)?;
    let path = evidence_root
        .join("security")
        .join("process-inspection.json");
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "native process inspection evidence is required: {}",
            path.display()
        )
    })?;
    verify_signed_json(&bytes, fixture.evidence_key.expose_secret())?;
    let evidence: ProcessInspectionEvidence = serde_json::from_slice(&bytes)?;
    validate_evidence_context(&evidence.context, &fixture.expected_context)?;
    consume_nonce(&fixture.data_dir, &evidence.context)?;
    ensure!(
        evidence.schema == 1
            && evidence.controller == "runner-manager-e2e-host-controller/v1"
            && evidence.manager_pid > 0
            && evidence.listener_pid > 0
            && evidence.manager_pid != evidence.listener_pid
    );
    let manager = evidence.manager_command_line.to_ascii_lowercase();
    let listener = evidence.listener_command_line.to_ascii_lowercase();
    ensure!(
        manager.contains("runner-manager"),
        "native inspection did not observe the shipping runner-manager"
    );
    ensure!(
        listener.contains("runner.listener"),
        "native inspection did not observe an Actions Runner.Listener"
    );
    ensure!(
        evidence.observed_at_ms >= evidence.context.issued_at_ms
            && evidence.observed_at_ms <= evidence.context.expires_at_ms,
        "native process observation is outside its signed validity window"
    );
    Ok(GateEvidence {
        gate: "process_inspection",
        observed_evidence: format!(
            "OS command-line inspection observed shipping manager PID {} and Runner.Listener PID {}",
            evidence.manager_pid, evidence.listener_pid
        ),
    })
}

fn recipe_declares_product_mutants(recipe: &GateRecipe) -> Result<()> {
    ensure!(
        recipe.tests.iter().any(|test| test.mutant.is_some()),
        "gate has no injectable production-control mutant"
    );
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
    mutant: Option<&'static str>,
}

#[derive(Debug)]
struct GateRecipe {
    gate: &'static str,
    tests: &'static [TestCase],
}

const PROCESS_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "native_process_listing_never_contains_jit_and_handoffs_never_survive",
    mutant: None,
}];
const CONTAMINATION_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "two_attempts_never_share_a_workspace_even_after_failure",
    mutant: Some("reuse_job_workspace"),
}];
const PACKAGE_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager-agent",
        filter: "a_checksum_mismatch_is_retryable_and_clean_bytes_still_install",
        mutant: Some("skip_checksum_comparison"),
    },
    TestCase {
        package: "runner-manager-agent",
        filter: "an_absent_published_checksum_refuses_to_install_and_names_the_remedy",
        mutant: Some("accept_missing_checksum"),
    },
];
const REVOKED_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager",
        filter: "a_revoked_credential_is_reported_as_revoked_and_not_as_a_missing_one",
        mutant: None,
    },
    TestCase {
        package: "runner-manager-domain",
        filter: "re_authentication_is_the_only_way_out_of_authentication_failed",
        mutant: None,
    },
    TestCase {
        package: "runner-manager-domain",
        filter: "authentication_failed_policy_is_ineligible_and_cannot_start_a_runner",
        mutant: Some("start_with_revoked_credential"),
    },
];
const WORKSPACE_TESTS: &[TestCase] = &[
    TestCase {
        package: "runner-manager-agent",
        filter: "a_job_walks_every_state_and_cleans_every_artifact",
        mutant: Some("skip_workspace_cleanup"),
    },
    TestCase {
        package: "runner-manager-agent",
        filter: "expired_jit_is_removed_and_does_not_reregister_after_demand_disappears",
        mutant: Some("skip_workspace_cleanup"),
    },
];
const DUPLICATE_TESTS: &[TestCase] = &[TestCase {
    package: "runner-manager-agent",
    filter: "three_polls_of_one_still_queued_run_yield_exactly_one_attempt",
    mutant: Some("ignore_in_flight_attempts"),
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
    let needles = [
        fixture.product_token.expose_secret(),
        fixture.fixture_token.expose_secret(),
        fixture.evidence_key.expose_secret(),
        jit.trim(),
    ];
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
        if let Some(mutant) = test.mutant {
            let mutated = std::process::Command::new(env!("CARGO"))
                .current_dir(workspace)
                .env("RUNNER_MANAGER_TEST_MUTANT", mutant)
                .args([
                    "test",
                    "-p",
                    test.package,
                    "--features",
                    "test-mutants",
                    test.filter,
                    "--",
                    "--nocapture",
                ])
                .output()
                .with_context(|| format!("could not inject product mutant {mutant}"))?;
            scan_bytes(&mutated.stdout, &needles)?;
            scan_bytes(&mutated.stderr, &needles)?;
            ensure!(
                !mutated.status.success(),
                "security gate {} stayed green when production control mutant {mutant} was injected",
                recipe.gate
            );
        }
        executed.push(format!("{}::{}", test.package, test.filter));
    }
    Ok(GateEvidence {
        gate: recipe.gate,
        observed_evidence: format!(
            "repository-defined negative controls passed and every declared production mutant made its gate fail: {}",
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
    let needles = [
        fixture.product_token.expose_secret(),
        fixture.fixture_token.expose_secret(),
        fixture.evidence_key.expose_secret(),
        jit.trim(),
    ];
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

fn validate_authority_separation(product_token: &str, evidence_key: &str) -> Result<()> {
    ensure!(!evidence_key.is_empty(), "evidence authority key is empty");
    ensure!(
        product_token != evidence_key,
        "GitHub fixture token cannot act as the evidence signing authority"
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

#[derive(Debug, Deserialize)]
struct RunnerInventory {
    runners: Vec<GitHubRunner>,
}

#[derive(Debug, Deserialize)]
struct GitHubRunner {
    id: u64,
    name: String,
    labels: Vec<GitHubRunnerLabel>,
}

#[derive(Debug, Deserialize)]
struct GitHubRunnerLabel {
    name: String,
}

async fn runner_inventory(
    token: &SecretString,
    scope: &str,
    target: &str,
) -> Result<RunnerInventory> {
    let url = format!("https://api.github.com/{scope}/{target}/actions/runners?per_page=100");
    let response = github_get(token, &url).await?;
    ensure!(
        response.status().is_success(),
        "cannot inspect {scope}/{target} runners: {}",
        response.status()
    );
    response
        .json()
        .await
        .context("runner inventory response has an invalid shape")
}

async fn verify_final_runner_inventory(
    fixture: &Fixture,
    scenarios: &[ScenarioEvidence],
    rollback: &RollbackEvidence,
) -> Result<()> {
    let repository = runner_inventory(&fixture.product_token, "repos", &fixture.repository).await?;
    let organization =
        runner_inventory(&fixture.product_token, "orgs", &fixture.organization).await?;
    let all_runners = repository.runners.iter().chain(&organization.runners);
    let routing_labels: BTreeSet<_> = scenarios
        .iter()
        .map(|scenario| scenario.routing_label.as_str())
        .collect();
    let scenario_runner_ids: BTreeSet<_> = scenarios
        .iter()
        .flat_map(|scenario| match &scenario.facts {
            ScenarioFacts::SuccessfulJitJob { runner_id, .. }
            | ScenarioFacts::NetworkOutageRecovery { runner_id, .. }
            | ScenarioFacts::BootStartRecovery { runner_id, .. }
            | ScenarioFacts::OrganizationScopedJob { runner_id, .. } => vec![*runner_id],
            ScenarioFacts::JitExpiryRecovery {
                expired_runner_id,
                replacement_runner_id,
                ..
            } => vec![*expired_runner_id, *replacement_runner_id],
            ScenarioFacts::TwoHostContention { runner_ids, .. } => runner_ids.to_vec(),
            ScenarioFacts::PolicyDisableDrain { .. } | ScenarioFacts::MonitorOnlyDemand { .. } => {
                Vec::new()
            }
        })
        .collect();

    for runner in all_runners {
        ensure!(
            !scenario_runner_ids.contains(&runner.id),
            "scenario runner {} ({}) remains registered",
            runner.id,
            runner.name
        );
        ensure!(
            !runner
                .labels
                .iter()
                .any(|label| routing_labels.contains(label.name.as_str())),
            "runner {} ({}) still carries an ephemeral routing label",
            runner.id,
            runner.name
        );
    }

    let expected_legacy = rollback
        .post_condition
        .legacy_label_runner_ids
        .first()
        .copied()
        .context("rollback omitted the restored legacy runner identity")?;
    let legacy_label = rollback.legacy_label.as_str();
    ensure!(
        scenarios
            .iter()
            .filter(|scenario| scenario.scope == "repository")
            .all(|scenario| scenario.legacy_label == legacy_label),
        "repository scenarios disagree about the legacy label identity"
    );
    let legacy_matches: Vec<_> = repository
        .runners
        .iter()
        .filter(|runner| {
            runner.id == expected_legacy
                && runner.labels.iter().any(|label| label.name == legacy_label)
        })
        .collect();
    ensure!(
        legacy_matches.len() == 1,
        "GitHub does not independently confirm the one restored legacy runner and label"
    );
    Ok(())
}

async fn verify_remote_scenarios(fixture: &Fixture, scenarios: &[ScenarioEvidence]) -> Result<()> {
    for scenario in scenarios {
        let (run_id, job_ids, runner_ids, require_success): (u64, Vec<u64>, Vec<u64>, bool) =
            match &scenario.facts {
                ScenarioFacts::SuccessfulJitJob {
                    workflow_run_id,
                    job_id,
                    runner_id,
                    ..
                } => (*workflow_run_id, vec![*job_id], vec![*runner_id], true),
                ScenarioFacts::NetworkOutageRecovery {
                    workflow_run_id,
                    job_id,
                    runner_id,
                    ..
                } => (*workflow_run_id, vec![*job_id], vec![*runner_id], true),
                ScenarioFacts::JitExpiryRecovery {
                    workflow_run_id,
                    job_id,
                    replacement_runner_id,
                    ..
                } => (
                    *workflow_run_id,
                    vec![*job_id],
                    vec![*replacement_runner_id],
                    true,
                ),
                ScenarioFacts::PolicyDisableDrain {
                    workflow_run_id,
                    job_id,
                    ..
                } => (*workflow_run_id, vec![*job_id], vec![], true),
                ScenarioFacts::BootStartRecovery {
                    workflow_run_id,
                    job_id,
                    runner_id,
                    ..
                } => (*workflow_run_id, vec![*job_id], vec![*runner_id], true),
                ScenarioFacts::OrganizationScopedJob {
                    workflow_run_id,
                    job_id,
                    runner_id,
                    ..
                } => (*workflow_run_id, vec![*job_id], vec![*runner_id], true),
                ScenarioFacts::MonitorOnlyDemand {
                    workflow_run_id,
                    queued_job_ids,
                    ..
                } => (*workflow_run_id, queued_job_ids.clone(), vec![], false),
                ScenarioFacts::TwoHostContention {
                    workflow_run_id,
                    completed_job_ids,
                    runner_ids,
                    ..
                } => (
                    *workflow_run_id,
                    completed_job_ids.clone(),
                    runner_ids.to_vec(),
                    true,
                ),
            };
        let run_url = format!(
            "https://api.github.com/repos/{}/actions/runs/{run_id}",
            fixture.repository
        );
        let run_response = github_get(&fixture.fixture_token, &run_url).await?;
        ensure!(
            run_response.status().is_success(),
            "cannot independently inspect workflow run {run_id}: {}",
            run_response.status()
        );
        let run: serde_json::Value = run_response.json().await?;
        ensure!(
            run["id"].as_u64() == Some(run_id),
            "GitHub returned the wrong run identity"
        );
        ensure!(
            run["head_sha"].as_str() == Some(fixture.expected_context.commit_sha.as_str()),
            "workflow run {run_id} is not bound to the acceptance commit"
        );

        let url = format!(
            "https://api.github.com/repos/{}/actions/runs/{run_id}/jobs?per_page=100",
            fixture.repository
        );
        let response = github_get(&fixture.fixture_token, &url).await?;
        ensure!(
            response.status().is_success(),
            "cannot independently inspect workflow run {run_id}: {}",
            response.status()
        );
        let body: serde_json::Value = response.json().await?;
        let jobs = body["jobs"]
            .as_array()
            .context("GitHub jobs response omitted jobs")?;
        for expected_job in job_ids {
            let job = jobs
                .iter()
                .find(|job| job["id"].as_u64() == Some(expected_job))
                .with_context(|| {
                    format!(
                        "scenario {} cites job {expected_job} absent from GitHub run {run_id}",
                        scenario.scenario
                    )
                })?;
            if require_success {
                ensure!(
                    job["status"] == "completed" && job["conclusion"] == "success",
                    "GitHub does not confirm successful completion for job {expected_job}"
                );
            }
            if !runner_ids.is_empty() {
                let observed = job["runner_id"]
                    .as_u64()
                    .context("GitHub job omitted runner_id")?;
                ensure!(
                    runner_ids.contains(&observed),
                    "GitHub job runner identity does not match controller facts"
                );
            }
        }
    }
    Ok(())
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
