//! Native host-controller journal signer.
//!
//! Disruptive scenario commands write typed JSON with an empty
//! `authentication_tag`. This repository command authenticates the completed
//! journals with a separate evidence-authority key before CI validates them.

use std::fs;
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

use anyhow::{Context, Result, ensure};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const FILES: [&str; 9] = [
    "successful_jit_job.json",
    "network_outage_recovery.json",
    "jit_expiry_recovery.json",
    "policy_disable_drain.json",
    "boot_start_recovery.json",
    "organization_scoped_job.json",
    "monitor_only_demand.json",
    "two_host_contention.json",
    "rollback.json",
];

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    ensure!(
        arguments.next().as_deref() == Some(std::ffi::OsStr::new("seal-live-run")),
        "usage: cargo run -p runner-manager-e2e --example e2e-host-controller -- seal-live-run EVIDENCE_DIR"
    );
    ensure!(
        std::env::var("RUNNER_MANAGER_E2E_PHYSICAL_HOST").as_deref() == Ok("true"),
        "REQUIRED MANUAL GATE: disruptive acceptance needs a provisioned physical host; hosted runners cannot produce live evidence"
    );
    let root = PathBuf::from(arguments.next().context("missing EVIDENCE_DIR")?);
    ensure!(arguments.next().is_none(), "unexpected extra argument");
    let authority = SecretString::from(
        std::env::var("RUNNER_MANAGER_E2E_EVIDENCE_KEY")
            .context("RUNNER_MANAGER_E2E_EVIDENCE_KEY is required and must be distinct from the GitHub fixture token")?,
    );
    let product_token = SecretString::from(
        std::env::var("RUNNER_MANAGER_E2E_TOKEN")
            .context("RUNNER_MANAGER_E2E_TOKEN is required")?,
    );
    let fixture_token = SecretString::from(
        std::env::var("RUNNER_MANAGER_E2E_FIXTURE_TOKEN")
            .context("RUNNER_MANAGER_E2E_FIXTURE_TOKEN is required")?,
    );
    ensure!(
        product_token.expose_secret() != authority.expose_secret()
            && fixture_token.expose_secret() != authority.expose_secret(),
        "evidence authority must be separate from the GitHub fixture credential"
    );
    let required = |name: &str| std::env::var(name).with_context(|| format!("{name} is required"));
    let run_id: u64 = required("GITHUB_RUN_ID")?.parse()?;
    let run_attempt: u64 = required("GITHUB_RUN_ATTEMPT")?.parse()?;
    let commit_sha = required("GITHUB_SHA")?;
    let architecture = required("RUNNER_ARCH")?;
    let challenge = required("RUNNER_MANAGER_E2E_CHALLENGE")?;
    let repository = required("RUNNER_MANAGER_E2E_REPO")?;
    let organization = required("RUNNER_MANAGER_E2E_ORG")?;
    let data_dir = PathBuf::from(required("RUNNER_MANAGER_E2E_DATA_DIR")?);
    ensure!(
        challenge.len() >= 64 && challenge.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "challenge must contain at least 256 random bits as hex"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let runtime_root = data_dir.join("runtime");
    let runtime_directories: Vec<String> = if runtime_root.is_dir() {
        fs::read_dir(&runtime_root)?
            .map(|entry| entry.map(|entry| entry.path().to_string_lossy().into_owned()))
            .collect::<std::io::Result<_>>()?
    } else {
        Vec::new()
    };
    ensure!(
        runtime_directories.is_empty(),
        "independent local probe found runtime residue"
    );
    let jit = fs::read_to_string(root.join("security").join("jit-marker.txt"))?;
    for name in FILES {
        let path = root.join(name);
        let mut value: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("missing {}", path.display()))?,
        )?;
        let scenario = name.strip_suffix(".json").unwrap_or(name);
        if name == "rollback.json" {
            ensure!(
                value["target"].as_str() == Some(repository.as_str()),
                "rollback target was not independently bound to the fixture repository"
            );
            let finished = value["steps"]
                .as_array()
                .and_then(|steps| steps.last())
                .and_then(|step| step["finished_at_ms"].as_u64())
                .context("rollback omitted its final command timestamp")?;
            ensure!(
                finished <= now && now - finished <= 3 * 60 * 60 * 1_000,
                "rollback journal is stale and cannot be re-signed"
            );
        } else {
            ensure!(
                value["scenario"].as_str() == Some(scenario),
                "{name} names another scenario"
            );
            ensure!(
                value["os"].as_str() == Some(os),
                "{name} belongs to another OS"
            );
            let scope = value["scope"].as_str().context("scenario omitted scope")?;
            let target = if scope == "organization" {
                &organization
            } else {
                &repository
            };
            ensure!(
                value["target"].as_str() == Some(target.as_str()),
                "{name} target was not independently bound to the fixture"
            );
            let finished = value["finished_at_ms"]
                .as_u64()
                .context("scenario omitted completion timestamp")?;
            ensure!(
                finished <= now && now - finished <= 3 * 60 * 60 * 1_000,
                "{name} is stale and cannot be re-signed"
            );
            value["finished_at_ms"] = serde_json::json!(now);
        }
        ensure!(
            value.get("authentication_tag").is_some(),
            "{name} omitted authentication_tag"
        );
        ensure!(
            value.get("facts").is_some() || name == "rollback.json",
            "{name} is not controller-observed typed evidence"
        );
        value["post_condition"]["local_observed_at_ms"] = serde_json::json!(now);
        value["post_condition"]["runtime_root"] =
            serde_json::Value::String(runtime_root.to_string_lossy().into_owned());
        value["post_condition"]["runtime_directories"] = serde_json::json!([]);
        value["controller"] =
            serde_json::Value::String("runner-manager-e2e-host-controller/v1".into());
        value["context"] = serde_json::json!({
            "run_id": run_id,
            "run_attempt": run_attempt,
            "commit_sha": commit_sha.clone(),
            "os": os,
            "architecture": architecture,
            "challenge": challenge.clone(),
            "nonce": uuid::Uuid::new_v4().simple().to_string(),
            "issued_at_ms": now,
            "expires_at_ms": now + 5 * 60 * 1_000
        });
        value["authentication_tag"] = serde_json::Value::String(String::new());
        reject_secrets(
            &serde_json::to_vec(&value)?,
            &[
                product_token.expose_secret(),
                fixture_token.expose_secret(),
                authority.expose_secret(),
                jit.trim(),
            ],
        )?;
        let tag = hex::encode(hmac_sha256(
            authority.expose_secret().as_bytes(),
            &serde_json::to_vec(&value)?,
        ));
        value["authentication_tag"] = serde_json::Value::String(tag);
        fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    }
    seal_process_inspection(
        &root,
        authority.expose_secret(),
        product_token.expose_secret(),
        &challenge,
        run_id,
        run_attempt,
        &commit_sha,
        &architecture,
        os,
        now,
    )?;
    fs::write(
        root.join("controller.json"),
        format!("{{\"controller\":\"runner-manager-e2e-host-controller/v1\",\"os\":\"{os}\"}}"),
    )?;
    Ok(())
}

fn reject_secrets(bytes: &[u8], secrets: &[&str]) -> Result<()> {
    for secret in secrets {
        ensure!(
            !secret.is_empty(),
            "secret scanning requires non-empty markers"
        );
        ensure!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "controller journal contains a secret marker"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn seal_process_inspection(
    root: &std::path::Path,
    authority: &str,
    product_token: &str,
    challenge: &str,
    run_id: u64,
    run_attempt: u64,
    commit_sha: &str,
    architecture: &str,
    os: &str,
    now: u64,
) -> Result<()> {
    let path = root.join("security").join("process-inspection.json");
    let supplied: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("missing {}", path.display()))?,
    )?;
    let manager_pid = supplied["manager_pid"]
        .as_u64()
        .context("process journal omitted manager_pid")? as u32;
    let listener_pid = supplied["listener_pid"]
        .as_u64()
        .context("process journal omitted listener_pid")? as u32;
    ensure!(manager_pid > 0 && listener_pid > 0 && manager_pid != listener_pid);
    let manager_command_line = native_command_line(manager_pid)?;
    let listener_command_line = native_command_line(listener_pid)?;
    ensure!(
        manager_command_line
            .to_ascii_lowercase()
            .contains("runner-manager"),
        "manager_pid does not identify the shipping runner-manager"
    );
    ensure!(
        listener_command_line
            .to_ascii_lowercase()
            .contains("runner.listener"),
        "listener_pid does not identify Runner.Listener"
    );
    let jit = fs::read_to_string(root.join("security").join("jit-marker.txt"))?;
    for command_line in [&manager_command_line, &listener_command_line] {
        ensure!(
            !command_line.contains(jit.trim())
                && (product_token.is_empty() || !command_line.contains(product_token))
                && !command_line.contains(authority),
            "native process command line exposed a secret"
        );
    }
    let mut value = serde_json::json!({
        "schema": 1,
        "authentication_tag": "",
        "context": {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "commit_sha": commit_sha,
            "os": os,
            "architecture": architecture,
            "challenge": challenge,
            "nonce": uuid::Uuid::new_v4().simple().to_string(),
            "issued_at_ms": now,
            "expires_at_ms": now + 5 * 60 * 1_000
        },
        "controller": "runner-manager-e2e-host-controller/v1",
        "observed_at_ms": now,
        "manager_pid": manager_pid,
        "listener_pid": listener_pid,
        "manager_command_line": manager_command_line,
        "listener_command_line": listener_command_line
    });
    let tag = hex::encode(hmac_sha256(
        authority.as_bytes(),
        &serde_json::to_vec(&value)?,
    ));
    value["authentication_tag"] = serde_json::Value::String(tag);
    fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn native_command_line(pid: u32) -> Result<String> {
    #[cfg(target_os = "linux")]
    let output = fs::read(format!("/proc/{pid}/cmdline"))?
        .into_iter()
        .map(|byte| if byte == 0 { b' ' } else { byte })
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let command_line = String::from_utf8(output)?;

    #[cfg(target_os = "macos")]
    let command_line = String::from_utf8(
        Command::new("ps")
            .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
            .output()?
            .stdout,
    )?;

    #[cfg(target_os = "windows")]
    let command_line = String::from_utf8(
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine"),
            ])
            .output()?
            .stdout,
    )?;

    ensure!(!command_line.trim().is_empty(), "PID {pid} is not running");
    Ok(command_line)
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
