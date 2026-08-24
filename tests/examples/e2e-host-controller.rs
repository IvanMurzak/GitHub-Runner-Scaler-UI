//! Native host-controller journal signer.
//!
//! Disruptive scenario commands write typed JSON with an empty
//! `authentication_tag`. This repository command authenticates the completed
//! journals with the product fixture credential before CI imports them.

use std::fs;
use std::path::PathBuf;

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
        arguments.next().as_deref() == Some(std::ffi::OsStr::new("sign")),
        "usage: cargo run -p runner-manager-e2e --example e2e-host-controller -- sign EVIDENCE_DIR"
    );
    let root = PathBuf::from(arguments.next().context("missing EVIDENCE_DIR")?);
    ensure!(arguments.next().is_none(), "unexpected extra argument");
    let token = SecretString::from(
        std::env::var("RUNNER_MANAGER_E2E_TOKEN")
            .context("RUNNER_MANAGER_E2E_TOKEN is required to authenticate journals")?,
    );
    for name in FILES {
        let path = root.join(name);
        let mut value: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("missing {}", path.display()))?,
        )?;
        ensure!(
            value.get("authentication_tag").is_some(),
            "{name} omitted authentication_tag"
        );
        value["authentication_tag"] = serde_json::Value::String(String::new());
        let tag = hex::encode(hmac_sha256(
            token.expose_secret().as_bytes(),
            &serde_json::to_vec(&value)?,
        ));
        value["authentication_tag"] = serde_json::Value::String(tag);
        fs::write(path, serde_json::to_vec_pretty(&value)?)?;
    }
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    fs::write(
        root.join("controller.json"),
        format!("{{\"controller\":\"runner-manager-e2e-host-controller/v1\",\"os\":\"{os}\"}}"),
    )?;
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
