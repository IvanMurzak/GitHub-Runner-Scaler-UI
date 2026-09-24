use std::{path::Path, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=RUNNER_MANAGER_RELEASE_BUILD");
    watch_source_identity_inputs();

    let package = std::env::var("CARGO_PKG_VERSION").expect("Cargo sets CARGO_PKG_VERSION");
    let release = std::env::var_os("RUNNER_MANAGER_RELEASE_BUILD").is_some();
    let identity = if release {
        package
    } else {
        source_identity(&package)
    };
    println!("cargo:rustc-env=RUNNER_MANAGER_BUILD_VERSION={identity}");
}

fn watch_source_identity_inputs() {
    let Some(root) = git_stdout(&["rev-parse", "--show-toplevel"]) else {
        return;
    };
    let root = Path::new(&root);

    // Cargo otherwise caches the build-script output across both commits and
    // tracked-file edits. Linked worktrees make watching `../../.git` especially
    // ineffective because it is a stable text file, not the worktree's git dir.
    for git_path in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = git_stdout(&["rev-parse", "--git-path", git_path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git_stdout(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_stdout(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }

    if let Ok(output) = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "-z"])
        .output()
        && output.status.success()
    {
        for relative in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
        {
            let relative = String::from_utf8_lossy(relative);
            println!(
                "cargo:rerun-if-changed={}",
                root.join(relative.as_ref()).display()
            );
        }
    }
}

fn git_stdout(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn source_identity(package: &str) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let dirty = Command::new("git")
                .args(["status", "--porcelain", "--untracked-files=no"])
                .output()
                .is_ok_and(|status| status.status.success() && !status.stdout.is_empty());
            let suffix = if dirty { ".dirty" } else { "" };
            format!("{package}+git.{sha}{suffix}")
        }
        // A crates.io package has no .git directory. It is published source,
        // so a `cargo install` build keeps the package's released identity.
        _ => package.to_string(),
    }
}
