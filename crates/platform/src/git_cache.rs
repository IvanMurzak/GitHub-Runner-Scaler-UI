//! Independent local Git snapshots for native repository runners. The manager
//! never fetches from GitHub: checkout keeps its own authentication and ref
//! selection. Only Git objects and generated Git metadata cross job boundaries.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use runner_manager_domain::model::ScaleTarget;
use serde::{Deserialize, Serialize};

use crate::lock::{HostLock, LockKind};
use crate::process::{OutputMode, SpawnSpec};

pub const ENVIRONMENT: &str = "RUNNER_MANAGER_GIT_CACHE_DIR";
const PLAN: &str = "runner-manager-git-cache.json";
const POINTER: &str = "current.json";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SHALLOW_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Cold,
    Seeded,
    Existing,
    Updated,
    Skipped,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    target: String,
    origin: String,
    workspace_name: String,
    generation: uuid::Uuid,
}

fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}

fn plain(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    !metadata.file_type().is_symlink()
}

fn real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && plain(&metadata) {
        Ok(())
    } else {
        Err(failure("Git cache path is not a regular directory"))
    }
}

/// Every component below a known root must be a real directory. In particular,
/// a workflow's symlinked _work must never redirect manager writes elsewhere.
fn directories(root: &Path, path: &Path) -> io::Result<()> {
    real_directory(root)?;
    let suffix = path
        .strip_prefix(root)
        .map_err(|_| failure("Git cache path escaped its root"))?;
    let mut current = root.to_path_buf();
    for component in suffix.components() {
        let Component::Normal(name) = component else {
            return Err(failure("invalid Git cache path component"));
        };
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        real_directory(&current)?;
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || !plain(&metadata) || metadata.len() > 8192 {
        return Err(failure("invalid Git cache metadata file"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(failure("Git cache metadata grew beyond its limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| failure("invalid Git cache metadata"))
}

fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| failure("cannot encode Git cache metadata"))?;
    crate::host_fitness::write_atomically(path, &bytes)
}

fn repository(target: &ScaleTarget) -> io::Result<&runner_manager_domain::model::OwnerRepo> {
    match target {
        ScaleTarget::Repository(repository) => Ok(repository),
        ScaleTarget::Organization(_) => Err(failure("Git cache requires repository scope")),
    }
}

#[cfg(test)]
fn checkout_path(runtime: &Path, target: &ScaleTarget) -> io::Result<PathBuf> {
    let name = repository(target)?.repo();
    checkout_named(runtime, name)
}

fn checkout_named(runtime: &Path, name: &str) -> io::Result<PathBuf> {
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(failure("invalid checkout directory name"));
    }
    Ok(runtime.join("_work").join(name).join(name))
}

fn existing_checkout(runtime: &Path, target: &ScaleTarget) -> io::Result<Option<PathBuf>> {
    real_directory(runtime)?;
    let work = runtime.join("_work");
    match real_directory(&work) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    }
    let expected = repository(target)?.repo();
    let mut found = None;
    for entry in fs::read_dir(&work)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name
            .to_str()
            .filter(|name| name.eq_ignore_ascii_case(expected))
        else {
            continue;
        };
        real_directory(&entry.path())?;
        let candidate = checkout_named(runtime, name)?;
        match real_directory(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            other => other?,
        }
        if found.replace(candidate).is_some() {
            return Err(failure("ambiguous checkout directory casing"));
        }
    }
    Ok(found)
}

fn cache_box(git_dir: &Path, target: &ScaleTarget) -> io::Result<PathBuf> {
    use sha2::Digest as _;
    repository(target)?;
    // A deliberately shared dependency namespace still has distinct Git stores
    // for distinct repositories. Casing stays in the checkout metadata.
    // Bound the Windows path budget and avoid reserved Windows directory names.
    // Metadata checks the full target too, so a digest collision is a cache
    // miss rather than permission to reuse another repository's objects.
    let digest = hex::encode(sha2::Sha256::digest(target.slug().to_ascii_lowercase()));
    Ok(git_dir.join(&digest[..16]))
}

fn origin_matches(origin: &str, target: &ScaleTarget) -> bool {
    origin
        .strip_prefix("https://github.com/")
        .is_some_and(|path| {
            path.eq_ignore_ascii_case(&target.slug())
                || path
                    .strip_suffix(".git")
                    .unwrap_or(path)
                    .eq_ignore_ascii_case(&target.slug())
        })
}

fn snapshot(box_dir: &Path, target: &ScaleTarget) -> io::Result<Option<Snapshot>> {
    let value: Snapshot = match read_json(&box_dir.join(POINTER)) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if value.schema != 1
        || value.target != target.slug().to_ascii_lowercase()
        || !origin_matches(&value.origin, target)
        || !value
            .workspace_name
            .eq_ignore_ascii_case(repository(target)?.repo())
        || checkout_named(Path::new(""), &value.workspace_name).is_err()
    {
        return Err(failure("Git cache repository identity mismatch"));
    }
    real_directory(&box_dir.join(value.generation.to_string()))?;
    Ok(Some(value))
}

fn lock(box_dir: &Path) -> io::Result<HostLock> {
    // The caller's namespace lease excludes LRU pruning. Serialize only this
    // repository, so a large copy never blocks unrelated dependency-cache
    // launches or Git operations for other repositories.
    HostLock::acquire_at(
        &box_dir.join(LockKind::GitCache.file_name()),
        LockKind::GitCache,
        Duration::from_secs(2),
    )
    .map_err(|_| failure("Git cache is busy"))
}

fn git(arguments: &[OsString]) -> io::Result<Vec<u8>> {
    let mut spec = SpawnSpec::new("git")
        .args(arguments)
        .output(OutputMode::Capture);
    // Inherited Git variables must not redirect a command to another repository,
    // object store, credentials file, SSH helper or per-command config.
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            spec = spec.without_env(key);
        }
    }
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    spec = spec
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CONFIG_COUNT", "3")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", null)
        .env("GIT_CONFIG_KEY_1", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_1", "false")
        .env("GIT_CONFIG_KEY_2", "core.longpaths")
        .env("GIT_CONFIG_VALUE_2", "true");
    let mut child = spec
        .spawn()
        .map_err(|_| failure("Git cache command could not start"))?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| failure("Git cache stdout unavailable"))?;
    let mut stderr = child
        .take_stderr()
        .ok_or_else(|| failure("Git cache stderr unavailable"))?;
    let output = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(8193).read_to_end(&mut bytes).map(|_| bytes)
    });
    let errors = std::thread::spawn(move || {
        let _ = io::copy(&mut stderr, &mut io::sink());
    });
    let waited = child.wait_for(COMMAND_TIMEOUT);
    let status = match waited {
        Ok(Some(status)) => Ok(status),
        _ => {
            let _ = child.stop(Duration::ZERO);
            Err(failure(
                "Git cache command timed out or could not be observed",
            ))
        }
    };
    let bytes = output
        .join()
        .map_err(|_| failure("Git cache output unavailable"))??;
    let _ = errors.join();
    if !status?.success() || bytes.len() > 8192 {
        return Err(failure("Git cache command failed"));
    }
    Ok(bytes)
}

fn command(path: &Path, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let mut args = vec![OsString::from("-C"), path.as_os_str().to_owned()];
    args.extend(arguments.iter().map(OsString::from));
    git(&args)
}

fn clone(source: &Path, destination: &Path, bare: bool, template: &Path) -> io::Result<()> {
    let mut args: Vec<OsString> = ["clone", "--local", "--no-hardlinks", "--no-checkout"]
        .into_iter()
        .map(OsString::from)
        .collect();
    if bare {
        args.push("--bare".into());
    }
    args.push(format!("--template={}", template.display()).into());
    args.push("--".into());
    args.push(source.as_os_str().to_owned());
    args.push(destination.as_os_str().to_owned());
    git(&args).map(|_| ())
}

fn independent(git_dir: &Path) -> io::Result<()> {
    real_directory(git_dir)?;
    real_directory(&git_dir.join("objects"))?;
    for path in [
        git_dir.join("commondir"),
        git_dir.join("objects/info/alternates"),
        git_dir.join("objects/info/http-alternates"),
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(failure("Git repository uses an external object store")),
        }
    }
    Ok(())
}

/// Record the repository, and seed only an empty standard checkout. A first
/// attempt is cold; normal checkout authenticates and downloads as before.
/// The caller must hold the namespace's normal runner lease during this call.
pub fn prepare(
    root: &Path,
    git_dir: &Path,
    target: &ScaleTarget,
    runtime: &Path,
) -> io::Result<Outcome> {
    repository(target)?;
    directories(runtime, &runtime.join("_diag"))?;
    write_json(&runtime.join("_diag").join(PLAN), target)?;
    let box_dir = cache_box(git_dir, target)?;
    directories(root, &box_dir)?;
    let _lock = lock(&box_dir)?;
    let Some(cached) = snapshot(&box_dir, target)? else {
        return Ok(Outcome::Cold);
    };
    let checkout = checkout_named(runtime, &cached.workspace_name)?;
    // Check all ancestors before examining or writing the work directory.
    directories(runtime, checkout.parent().expect("checkout parent"))?;
    match fs::symlink_metadata(&checkout) {
        Ok(metadata) if !metadata.is_dir() || !plain(&metadata) => {
            return Err(failure("checkout path is not a regular directory"));
        }
        Ok(_) if fs::read_dir(&checkout)?.next().is_some() => return Ok(Outcome::Existing),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let source = box_dir.join(cached.generation.to_string());
    independent(&source)?;
    // Keep staging outside retained _work: after a manager crash, ordinary
    // native cleanup removes it even for a persistent slot. The runtime and
    // its work directory normally share the filesystem needed for rename.
    let stage = tempfile::Builder::new()
        .prefix("git-seed-")
        .tempdir_in(runtime)?;
    let template = stage.path().join("template");
    fs::create_dir(&template)?;
    let format = command(&source, &["rev-parse", "--show-object-format"])?;
    let format = std::str::from_utf8(&format)
        .map_err(|_| failure("invalid Git object format"))?
        .trim();
    if !matches!(format, "sha1" | "sha256") {
        return Err(failure("unsupported Git object format"));
    }
    let head = command(&source, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let head = std::str::from_utf8(&head)
        .map_err(|_| failure("invalid cached HEAD"))?
        .trim();
    if !hex_name(OsStr::new(head), &[40, 64]) {
        return Err(failure("invalid cached HEAD"));
    }
    // Fresh metadata prevents stale tags, remote refs and branch settings from
    // leaking into commands such as git describe in the next job.
    let fresh = stage.path().join("fresh");
    git(&[
        "init".into(),
        format!("--object-format={format}").into(),
        format!("--template={}", template.display()).into(),
        fresh.as_os_str().to_owned(),
    ])?;
    let fresh_git = fresh.join(".git");
    // A shallow local clone can fall back to upload-pack and omit objects
    // unreachable from its current refs. Copy immutable objects directly so
    // other cached PR tips remain useful without carrying their refs forward.
    merge_objects(&source.join("objects"), &fresh_git.join("objects"))?;
    merge_shallow(&source, &fresh_git)?;
    command(&fresh, &["remote", "add", "origin", &cached.origin])?;
    command(
        &fresh,
        &[
            "-c",
            "user.name=Runner Manager cache",
            "-c",
            "user.email=runner-manager@localhost",
            "update-ref",
            "--no-deref",
            "HEAD",
            head,
        ],
    )?;
    command(&fresh, &["fsck", "--full", "--no-dangling"])?;
    // No checkout files were copied. Even cancellation leaves at most our Git
    // metadata in the disposable workspace, with no reference to the cache.
    if !checkout.exists() {
        fs::create_dir(&checkout)?;
    }
    fs::rename(fresh_git, checkout.join(".git"))?;
    Ok(Outcome::Seeded)
}

/// Read the bounded launch plan; it contains no credentials or cache paths.
pub fn target_for_runtime(runtime: &Path) -> io::Result<Option<ScaleTarget>> {
    match fs::symlink_metadata(runtime.join("_diag")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.is_dir() || !plain(&metadata) => {
            return Err(failure("invalid diagnostic directory"));
        }
        Ok(_) => {}
    }
    match read_json(&runtime.join("_diag").join(PLAN)) {
        Ok(target) => Ok(Some(target)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn hex_name(value: &OsStr, lengths: &[usize]) -> bool {
    value.to_str().is_some_and(|value| {
        lengths.contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Merge only immutable loose objects and pack files, never configuration,
/// alternates, hooks, refs or working files from a previous generation.
fn merge_objects(source: &Path, destination: &Path) -> io::Result<()> {
    real_directory(source)?;
    for directory in fs::read_dir(source)? {
        let directory = directory?;
        let name = directory.file_name();
        if name != OsStr::new("pack") && !hex_name(&name, &[2]) {
            continue;
        }
        real_directory(&directory.path())?;
        let target = destination.join(&name);
        fs::create_dir_all(&target)?;
        real_directory(&target)?;
        for file in fs::read_dir(directory.path())? {
            let file = file?;
            let filename = file.file_name();
            let valid_pack = filename.to_str().is_some_and(|name| {
                let Some((stem, extension)) = name.rsplit_once('.') else {
                    return false;
                };
                stem.strip_prefix("pack-")
                    .is_some_and(|hash| hex_name(OsStr::new(hash), &[40, 64]))
                    && matches!(extension, "pack" | "idx" | "rev")
            });
            if !(if name == OsStr::new("pack") {
                valid_pack
            } else {
                hex_name(&filename, &[38, 62])
            }) {
                continue;
            }
            let metadata = fs::symlink_metadata(file.path())?;
            if !metadata.is_file() || !plain(&metadata) {
                return Err(failure("invalid Git object file"));
            }
            let target = target.join(filename);
            if !target.exists() {
                fs::copy(file.path(), target)?;
            }
        }
    }
    Ok(())
}

fn merge_shallow(source: &Path, destination: &Path) -> io::Result<()> {
    let mut boundaries = BTreeSet::new();
    for path in [source.join("shallow"), destination.join("shallow")] {
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            other => other?,
        };
        if !metadata.is_file() || !plain(&metadata) || metadata.len() > MAX_SHALLOW_BYTES {
            return Err(failure("invalid shallow boundary file"));
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)?
            .take(MAX_SHALLOW_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SHALLOW_BYTES {
            return Err(failure("shallow boundary file is too large"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| failure("invalid shallow boundaries"))?;
        for boundary in text.lines() {
            if !hex_name(OsStr::new(boundary), &[40, 64]) {
                return Err(failure("invalid shallow boundary"));
            }
            boundaries.insert(boundary.to_owned());
        }
    }
    if !boundaries.is_empty() {
        let text = boundaries.into_iter().collect::<Vec<_>>().join("\n") + "\n";
        // Two individually bounded inputs can have an oversized union. Never
        // publish a shallow file that our next launch would refuse to read.
        if text.len() as u64 > MAX_SHALLOW_BYTES {
            return Err(failure("merged shallow boundaries are too large"));
        }
        crate::host_fitness::write_atomically(&destination.join("shallow"), text.as_bytes())?;
    }
    Ok(())
}

/// Called only after the runner has stopped and before the workspace is removed.
/// The caller must hold the namespace's normal runner lease during this call.
/// Publish through an atomic pointer, retaining the previous good generation on
/// every failure. Snapshots borrow no objects from the attempt or other caches.
pub fn capture(
    root: &Path,
    git_dir: &Path,
    target: &ScaleTarget,
    runtime: &Path,
) -> io::Result<Outcome> {
    let Some(source) = existing_checkout(runtime, target)? else {
        return Ok(Outcome::Skipped);
    };
    if !source.join(".git").exists() {
        return Ok(Outcome::Skipped);
    }
    independent(&source.join(".git"))?;
    let origin = command(&source, &["remote", "get-url", "origin"])?;
    let origin = std::str::from_utf8(&origin)
        .map_err(|_| failure("invalid Git origin"))?
        .trim();
    if !origin_matches(origin, target) {
        return Ok(Outcome::Skipped);
    }
    // actions/checkout's standard HTTPS remote has no .git suffix. Normalize
    // ordinary `git clone https://.../Repo.git` checkouts to that spelling.
    let origin = origin
        .strip_suffix(".git")
        .filter(|without_suffix| origin_matches(without_suffix, target))
        .unwrap_or(origin);
    let box_dir = cache_box(git_dir, target)?;
    directories(root, &box_dir)?;
    let _lock = lock(&box_dir)?;
    let previous = snapshot(&box_dir, target).ok().flatten();
    let stage = tempfile::Builder::new()
        .prefix("git-stage-")
        .tempdir_in(&box_dir)?;
    let template = stage.path().join("template");
    fs::create_dir(&template)?;
    let copy = stage.path().join("copy");
    clone(&source, &copy, true, &template)?;
    independent(&copy)?;
    command(&copy, &["remote", "set-url", "origin", origin])?;
    if let Some(previous) = &previous {
        let objects = box_dir
            .join(previous.generation.to_string())
            .join("objects");
        merge_objects(&objects, &copy.join("objects"))?;
        // Objects from another shallow attempt need their own boundary markers;
        // otherwise fsck treats their intentionally absent parents as corruption.
        merge_shallow(&box_dir.join(previous.generation.to_string()), &copy)?;
    }
    command(&copy, &["fsck", "--full", "--no-dangling"])?;
    let generation = uuid::Uuid::new_v4();
    let published = box_dir.join(generation.to_string());
    fs::rename(&copy, &published)?;
    let value = Snapshot {
        schema: 1,
        target: target.slug().to_ascii_lowercase(),
        origin: origin.into(),
        workspace_name: source
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| failure("invalid workspace name"))?
            .into(),
        generation,
    };
    if let Err(error) = write_json(&box_dir.join(POINTER), &value) {
        let _ = remove_dir_all::remove_dir_all(&published);
        return Err(error);
    }
    if let Some(previous) = previous {
        // Exact UUID-owned generation, checked above; never scan for arbitrary
        // repositories or recursively delete a workflow-supplied path.
        let old = box_dir.join(previous.generation.to_string());
        if real_directory(&old).is_ok() {
            let _ = remove_dir_all::remove_dir_all(old);
        }
    }
    Ok(Outcome::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_union_limit_preserves_the_last_readable_destination() {
        use std::fmt::Write as _;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let count = MAX_SHALLOW_BYTES as usize / 41;
        let mut before = String::new();
        for index in 0..count {
            writeln!(before, "{index:040x}").unwrap();
        }
        fs::write(destination.join("shallow"), &before).unwrap();
        fs::write(source.join("shallow"), format!("{:040x}\n", count - 1)).unwrap();
        merge_shallow(&source, &destination).unwrap();
        assert_eq!(
            fs::read(destination.join("shallow")).unwrap(),
            before.as_bytes()
        );
        fs::write(source.join("shallow"), format!("{count:040x}\n")).unwrap();
        assert!(merge_shallow(&source, &destination).is_err());
        assert_eq!(
            fs::read(destination.join("shallow")).unwrap(),
            before.as_bytes()
        );
    }

    struct Fixture {
        root: tempfile::TempDir,
        cache: PathBuf,
        git_dir: PathBuf,
        target: ScaleTarget,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let cache = root.path().join("cache");
            fs::create_dir(&cache).unwrap();
            Self {
                git_dir: cache.join("octo/repo/git"),
                cache,
                root,
                target: ScaleTarget::repository("Octo/Repo").unwrap(),
            }
        }

        fn runtime(&self, name: &str) -> PathBuf {
            let path = self.root.path().join(name);
            fs::create_dir(&path).unwrap();
            path
        }

        fn source(&self, runtime: &Path) -> PathBuf {
            let checkout = checkout_path(runtime, &self.target).unwrap();
            fs::create_dir_all(&checkout).unwrap();
            command(&checkout, &["init", "--initial-branch=main"]).unwrap();
            command(&checkout, &["config", "user.name", "Cache fixture"]).unwrap();
            command(
                &checkout,
                &["config", "user.email", "cache@example.invalid"],
            )
            .unwrap();
            command(&checkout, &["config", "commit.gpgsign", "false"]).unwrap();
            command(
                &checkout,
                &[
                    "remote",
                    "add",
                    "origin",
                    &format!("https://github.com/{}", self.target.slug()),
                ],
            )
            .unwrap();
            checkout
        }

        fn prepare(&self, runtime: &Path) -> io::Result<Outcome> {
            prepare(&self.cache, &self.git_dir, &self.target, runtime)
        }

        fn capture(&self, runtime: &Path) -> io::Result<Outcome> {
            capture(&self.cache, &self.git_dir, &self.target, runtime)
        }
    }

    fn commit(path: &Path, content: &str) -> String {
        fs::write(path.join("tracked.txt"), content).unwrap();
        command(path, &["add", "tracked.txt"]).unwrap();
        command(path, &["commit", "--quiet", "-m", content]).unwrap();
        String::from_utf8(command(path, &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .into()
    }

    #[test]
    fn cold_to_warm_checkout_is_independent_and_copies_no_credentials_or_working_files() {
        let fixture = Fixture::new();
        let first = fixture.runtime("first");
        assert_eq!(fixture.prepare(&first).unwrap(), Outcome::Cold);
        assert_eq!(
            target_for_runtime(&first).unwrap(),
            Some(fixture.target.clone())
        );
        let source = fixture.source(&first);
        let initial = commit(&source, "first version");
        command(&source, &["tag", "old-cache-tag"]).unwrap();
        command(&source, &["branch", "old-cache-branch"]).unwrap();
        fs::write(source.join("untracked-secret"), b"secret").unwrap();
        command(
            &source,
            &[
                "config",
                "http.https://github.com/.extraheader",
                "AUTHORIZATION: secret-fixture-token",
            ],
        )
        .unwrap();
        fs::write(
            source.join(".git/hooks/post-checkout"),
            b"#!/bin/sh\nexit 97\n",
        )
        .unwrap();
        assert_eq!(fixture.capture(&first).unwrap(), Outcome::Updated);

        let second = fixture.runtime("second");
        assert_eq!(fixture.prepare(&second).unwrap(), Outcome::Seeded);
        let checkout = checkout_path(&second, &fixture.target).unwrap();
        assert!(!checkout.join("tracked.txt").exists());
        assert!(!checkout.join("untracked-secret").exists());
        assert!(!checkout.join(".git/objects/info/alternates").exists());
        assert!(!checkout.join(".git/hooks/post-checkout").exists());
        let config = fs::read_to_string(checkout.join(".git/config")).unwrap();
        assert!(!config.contains("secret-fixture-token"));
        assert!(!config.contains("extraheader"));
        assert!(!config.contains("branch."));
        assert!(
            command(&checkout, &["for-each-ref", "--format=%(refname)"])
                .unwrap()
                .is_empty(),
            "old tags and branches must not affect the next job"
        );
        assert_eq!(
            command(&checkout, &["remote", "get-url", "origin"]).unwrap(),
            b"https://github.com/Octo/Repo\n"
        );
        // Delete the entire local cache. The seeded repository remains valid.
        remove_dir_all::remove_dir_all(&fixture.cache).unwrap();
        command(&checkout, &["fsck", "--full", "--no-dangling"]).unwrap();
        command(&checkout, &["checkout", "--detach", &initial]).unwrap();
        assert_eq!(
            fs::read_to_string(checkout.join("tracked.txt")).unwrap(),
            "first version"
        );

        let next = commit(&source, "new remote version");
        let source_path = source.to_str().unwrap();
        command(&checkout, &["fetch", "--no-tags", source_path, &next]).unwrap();
        command(&checkout, &["checkout", "--detach", "FETCH_HEAD"]).unwrap();
        assert_eq!(
            fs::read_to_string(checkout.join("tracked.txt")).unwrap(),
            "new remote version"
        );
    }

    #[test]
    fn publications_from_two_cold_attempts_keep_both_sets_of_objects() {
        let fixture = Fixture::new();
        let first = fixture.runtime("first");
        let second = fixture.runtime("second");
        let source_a = fixture.source(&first);
        let source_b = fixture.source(&second);
        let a = commit(&source_a, "branch A");
        let b = commit(&source_b, "branch B");
        fixture.capture(&first).unwrap();
        fixture.capture(&second).unwrap();
        let third = fixture.runtime("third");
        fixture.prepare(&third).unwrap();
        let checkout = checkout_path(&third, &fixture.target).unwrap();
        command(&checkout, &["cat-file", "-e", &a]).unwrap();
        command(&checkout, &["cat-file", "-e", &b]).unwrap();
        let box_dir = cache_box(&fixture.git_dir, &fixture.target).unwrap();
        assert_eq!(
            fs::read_dir(box_dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().unwrap().is_dir())
                .count(),
            1,
            "a publication retires its previous generation"
        );
    }

    #[test]
    fn repositories_stay_separate_inside_a_shared_dependency_namespace() {
        let mut fixture = Fixture::new();
        let first = fixture.runtime("first");
        let source = fixture.source(&first);
        let a = commit(&source, "repository A");
        fixture.capture(&first).unwrap();
        fixture.target = ScaleTarget::repository("Octo/Other").unwrap();
        let second = fixture.runtime("second");
        let source = fixture.source(&second);
        let b = commit(&source, "repository B");
        fixture.capture(&second).unwrap();
        fixture.target = ScaleTarget::repository("Octo/Repo").unwrap();
        let third = fixture.runtime("third");
        fixture.prepare(&third).unwrap();
        let checkout = checkout_path(&third, &fixture.target).unwrap();
        command(&checkout, &["cat-file", "-e", &a]).unwrap();
        assert!(command(&checkout, &["cat-file", "-e", &b]).is_err());
    }

    #[test]
    fn long_repository_names_use_a_bounded_cache_path() {
        let mut fixture = Fixture::new();
        fixture.target =
            ScaleTarget::repository(format!("Octo/{}", "repository".repeat(6))).unwrap();
        let first = fixture.runtime("first");
        let source = fixture.source(&first);
        let head = commit(&source, "long name");
        fixture.capture(&first).unwrap();
        assert_eq!(
            cache_box(&fixture.git_dir, &fixture.target)
                .unwrap()
                .file_name()
                .unwrap()
                .len(),
            16
        );
        let second = fixture.runtime("second");
        fixture.prepare(&second).unwrap();
        let checkout = checkout_path(&second, &fixture.target).unwrap();
        assert_eq!(
            command(&checkout, &["rev-parse", "HEAD"]).unwrap(),
            format!("{head}\n").as_bytes()
        );
    }

    #[test]
    fn a_repository_copy_does_not_hold_the_global_dependency_cache_lock() {
        let fixture = Fixture::new();
        let box_dir = cache_box(&fixture.git_dir, &fixture.target).unwrap();
        directories(&fixture.cache, &box_dir).unwrap();
        let _git = lock(&box_dir).unwrap();
        let _global = HostLock::acquire_at(
            &fixture.cache.join(LockKind::DependencyCache.file_name()),
            LockKind::DependencyCache,
            Duration::ZERO,
        )
        .unwrap();
        let other = cache_box(
            &fixture.git_dir,
            &ScaleTarget::repository("Octo/Other").unwrap(),
        )
        .unwrap();
        directories(&fixture.cache, &other).unwrap();
        let _other = lock(&other).unwrap();
        assert!(
            lock(&box_dir).is_err(),
            "only copies of the same repository serialize"
        );
    }

    #[test]
    fn shallow_detached_pr_checkout_round_trips_and_can_fetch_the_next_commit() {
        let fixture = Fixture::new();
        let remote_runtime = fixture.runtime("remote");
        let remote = fixture.source(&remote_runtime);
        commit(&remote, "base");
        let pr = commit(&remote, "PR merge commit");
        let first = fixture.runtime("first");
        let checkout = checkout_path(&first, &fixture.target).unwrap();
        fs::create_dir_all(checkout.parent().unwrap()).unwrap();
        let prefix = if cfg!(windows) { "file:///" } else { "file://" };
        let url = format!(
            "{prefix}{}",
            remote.display().to_string().replace('\\', "/")
        );
        git(&[
            "clone".into(),
            "--depth=1".into(),
            url.into(),
            checkout.as_os_str().to_owned(),
        ])
        .unwrap();
        command(&checkout, &["checkout", "--detach", &pr]).unwrap();
        command(
            &checkout,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/Octo/Repo",
            ],
        )
        .unwrap();
        fixture.capture(&first).unwrap();
        let second = fixture.runtime("second");
        assert_eq!(fixture.prepare(&second).unwrap(), Outcome::Seeded);
        let copy = checkout_path(&second, &fixture.target).unwrap();
        assert_eq!(
            command(&copy, &["rev-parse", "--is-shallow-repository"]).unwrap(),
            b"true\n"
        );
        let next = commit(&remote, "next PR merge");
        command(
            &copy,
            &["fetch", "--depth=1", remote.to_str().unwrap(), &next],
        )
        .unwrap();
        command(&copy, &["checkout", "--detach", "FETCH_HEAD"]).unwrap();
        assert_eq!(
            fs::read_to_string(copy.join("tracked.txt")).unwrap(),
            "next PR merge"
        );
    }

    #[test]
    fn two_cold_shallow_publications_preserve_both_boundary_sets() {
        let fixture = Fixture::new();
        let remote_runtime = fixture.runtime("remote");
        let remote = fixture.source(&remote_runtime);
        let base = commit(&remote, "base");
        let a = commit(&remote, "branch A");
        command(&remote, &["branch", "branch-a"]).unwrap();
        command(&remote, &["reset", "--hard", &base]).unwrap();
        let b = commit(&remote, "branch B");
        command(&remote, &["branch", "branch-b"]).unwrap();
        let prefix = if cfg!(windows) { "file:///" } else { "file://" };
        let url = format!(
            "{prefix}{}",
            remote.display().to_string().replace('\\', "/")
        );
        for (name, branch) in [("first", "branch-a"), ("second", "branch-b")] {
            let runtime = fixture.runtime(name);
            let checkout = checkout_path(&runtime, &fixture.target).unwrap();
            fs::create_dir_all(checkout.parent().unwrap()).unwrap();
            git(&[
                "clone".into(),
                "--depth=1".into(),
                format!("--branch={branch}").into(),
                url.clone().into(),
                checkout.as_os_str().to_owned(),
            ])
            .unwrap();
            command(
                &checkout,
                &[
                    "remote",
                    "set-url",
                    "origin",
                    "https://github.com/Octo/Repo",
                ],
            )
            .unwrap();
            fixture.capture(&runtime).unwrap();
        }
        let third = fixture.runtime("third");
        fixture.prepare(&third).unwrap();
        let checkout = checkout_path(&third, &fixture.target).unwrap();
        assert_eq!(
            command(&checkout, &["rev-parse", "HEAD"]).unwrap(),
            format!("{b}\n").as_bytes()
        );
        command(&checkout, &["cat-file", "-e", &a]).unwrap();
        command(&checkout, &["fsck", "--full", "--no-dangling"]).unwrap();
    }

    #[test]
    fn nonempty_workspaces_wrong_origins_and_external_object_stores_are_preserved() {
        let fixture = Fixture::new();
        let first = fixture.runtime("first");
        let source = fixture.source(&first);
        commit(&source, "base");
        command(
            &source,
            &[
                "remote",
                "set-url",
                "origin",
                "https://token@github.com/Octo/Repo",
            ],
        )
        .unwrap();
        assert_eq!(fixture.capture(&first).unwrap(), Outcome::Skipped);
        command(
            &source,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/Other/Repo",
            ],
        )
        .unwrap();
        assert_eq!(fixture.capture(&first).unwrap(), Outcome::Skipped);
        command(
            &source,
            &[
                "remote",
                "set-url",
                "origin",
                "https://github.com/Octo/Repo",
            ],
        )
        .unwrap();
        fixture.capture(&first).unwrap();
        fs::write(source.join("sentinel"), b"preserve").unwrap();
        assert_eq!(fixture.prepare(&first).unwrap(), Outcome::Existing);
        assert_eq!(fs::read(source.join("sentinel")).unwrap(), b"preserve");
        fs::write(
            source.join(".git/objects/info/alternates"),
            b"/another/store\n",
        )
        .unwrap();
        assert!(fixture.capture(&first).is_err());
        let second = fixture.runtime("second");
        assert_eq!(
            fixture.prepare(&second).unwrap(),
            Outcome::Seeded,
            "a refused publication leaves the last good snapshot intact"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_workspace_is_never_followed_for_seed_or_capture() {
        let fixture = Fixture::new();
        let first = fixture.runtime("first");
        let source = fixture.source(&first);
        commit(&source, "base");
        fixture.capture(&first).unwrap();
        let second = fixture.runtime("second");
        let victim = fixture.runtime("victim");
        fs::write(victim.join("sentinel"), b"preserve").unwrap();
        std::os::unix::fs::symlink(&victim, second.join("_work")).unwrap();
        assert!(fixture.prepare(&second).is_err());
        assert!(fixture.capture(&second).is_err());
        assert_eq!(fs::read_dir(&victim).unwrap().count(), 1);
    }
}
