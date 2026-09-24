use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUNNER_MANAGER_RELEASE_BUILD");
    println!("cargo:rerun-if-changed=../../.git");

    let package = std::env::var("CARGO_PKG_VERSION").expect("Cargo sets CARGO_PKG_VERSION");
    let release = std::env::var_os("RUNNER_MANAGER_RELEASE_BUILD").is_some();
    let identity = if release {
        package
    } else {
        source_identity(&package)
    };
    println!("cargo:rustc-env=RUNNER_MANAGER_BUILD_VERSION={identity}");
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
