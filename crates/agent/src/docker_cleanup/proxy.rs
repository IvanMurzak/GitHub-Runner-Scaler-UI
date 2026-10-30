//! Native Linux companion. Request bodies and credentials never enter the
//! journal. Streaming endpoints are relayed without buffering their payloads.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::http::{Head, MAX_JSON};
use super::*;

pub fn launch(
    cleanup: &DockerCleanup,
    attempt: AttemptId,
    repository: &str,
    socket: &Path,
) -> io::Result<Option<std::ffi::OsString>> {
    if !socket.exists() {
        return Ok(None);
    }
    if !fs::metadata(socket)?.file_type().is_socket() {
        return Err(invalid("Docker endpoint is not a socket"));
    }
    fs::create_dir_all(&cleanup.root)?;
    fs::set_permissions(&cleanup.root, fs::Permissions::from_mode(0o700))?;
    let directory = cleanup.root.join(attempt.to_string());
    // An attempt gets exactly one proxy; never truncate a surviving journal.
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let path = directory.join("journal.json");
    write_json(
        &path,
        &Journal::new(
            cleanup.host,
            attempt,
            repository.into(),
            socket.to_path_buf(),
            PENDING_ENGINE.into(),
        ),
    )?;
    let binary = cleanup
        .companion
        .clone()
        .map_or_else(std::env::current_exe, Ok)?;
    let mut child = std::process::Command::new(binary)
        .arg("--runner-manager-docker-proxy")
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !directory.join("ready").is_file() {
        if child.try_wait()?.is_some() {
            return Err(invalid("Docker proxy failed to start"));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("Docker proxy startup timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Reap the companion when it stops; its identity is durably recorded by
    // the companion before ready, so a daemon reload does not orphan ownership.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(Some(
        format!("unix://{}", directory.join("s").display()).into(),
    ))
}

pub fn sweep(
    cleanup: &DockerCleanup,
    lookup: &dyn Fn(AttemptId) -> io::Result<Option<runner_manager_domain::attempt::RunnerAttempt>>,
    dry_run: bool,
) -> io::Result<SweepReport> {
    use runner_manager_domain::attempt::AttemptState;
    use runner_manager_platform::process::Adoption;

    let configured = Config::load(&cleanup.config)?.mode;
    let mode = if dry_run { Mode::Report } else { configured };
    if !cleanup.root.exists() {
        return Ok(SweepReport::default());
    }
    let _lock = runner_manager_platform::lock::HostLock::acquire_at(
        &cleanup.root.join(".sweep.lock"),
        runner_manager_platform::lock::LockKind::DockerCleanup,
        Duration::from_secs(1),
    )
    .map_err(invalid)?;
    let entries = match fs::read_dir(&cleanup.root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(SweepReport::default()),
        Err(error) => return Err(error),
    };
    let mut total = SweepReport::default();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !valid_operation(name) {
            continue;
        }
        let outcome = (|| -> io::Result<()> {
            let path = entry.path().join("journal.json");
            let mut journal = Journal::load(&path)?;
            if journal.host != cleanup.host || journal.attempt.to_string() != name {
                return Err(invalid("Docker journal directory ownership mismatch"));
            }
            let Some(attempt) = lookup(journal.attempt)? else {
                return Ok(());
            };
            if attempt.state() != AttemptState::Cleaned || !attempt.execution().is_native() {
                return Ok(());
            }
            write_json(&entry.path().join("stop"), &true)?;
            if let Some(identity) = &journal.proxy {
                match identity.recheck().map_err(invalid)? {
                    Adoption::Live => {
                        total.pending += 1;
                        return Ok(());
                    }
                    Adoption::Gone | Adoption::PidRecycled { .. } => {}
                }
            }
            if mode == Mode::Off {
                return Ok(());
            }
            if journal.intents.is_empty() && journal.resources.is_empty() {
                remove_journal_files(&entry.path())?;
                return Ok(());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(invalid)?
                .as_secs();
            // Collect/report mode must not repeatedly inventory every historical
            // job's Docker resources. Explicit operator reports bypass this.
            if mode == Mode::Report
                && !dry_run
                && journal
                    .last_reported_secs
                    .and_then(|previous| now.checked_sub(previous))
                    .is_some_and(|elapsed| elapsed < 3600)
            {
                return Ok(());
            }
            let engine = UnixEngine(journal.upstream.clone());
            let info = engine.request("GET", "/info", None)?;
            if info.status != 200
                || info.body.get("ID").and_then(Value::as_str) != Some(journal.engine.as_str())
                || info.body.get("OSType").and_then(Value::as_str) != Some("linux")
            {
                return Err(invalid("Docker engine identity changed"));
            }
            recover_creations(&mut journal, &engine)?;
            // Persist recovery discoveries before trying any deletion.
            write_json(&path, &journal)?;
            let report = clean_resources(
                &mut journal,
                &engine,
                if dry_run { Mode::Report } else { mode },
            )?;
            if mode == Mode::Report {
                journal.last_reported_secs = Some(now);
            }
            write_json(&path, &journal)?;
            total.candidates += report.candidates;
            total.removed += report.removed;
            total.pending += report.pending;
            total.protected += report.protected;
            total.details_truncated |= report.details_truncated;
            total.append_details(report.details);
            let unresolved = journal
                .intents
                .iter()
                .filter(|intent| !intent.settled)
                .count();
            total.pending += unresolved;
            if journal.resources.is_empty() && unresolved == 0 {
                // Remove only the companion's exact files, never recursively walk
                // this directory. An unexpected entry keeps the directory present.
                remove_journal_files(&entry.path())?;
            }
            Ok(())
        })();
        if outcome.is_err() {
            total.pending += 1;
            tracing::warn!(event="docker_cleanup_journal_deferred",attempt_id=%name,"one Docker journal could not be reconciled; continuing with the others");
        }
    }
    Ok(total)
}

fn remove_journal_files(directory: &Path) -> io::Result<()> {
    let expected = ["journal.json", "runner.json", "ready", "stop", "s"];
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !expected
            .iter()
            .any(|name| entry.file_name() == std::ffi::OsStr::new(name))
        {
            return Err(invalid(
                "unexpected entry in Docker journal directory; metadata retained",
            ));
        }
    }
    for name in ["journal.json", "runner.json", "ready", "stop", "s"] {
        match fs::remove_file(directory.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    fs::remove_dir(directory)
}

#[derive(Debug, Clone)]
pub struct UnixEngine(pub PathBuf);

impl Engine for UnixEngine {
    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> io::Result<Reply> {
        if !path.starts_with('/')
            || path
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(invalid("invalid local Docker API path"));
        }
        let mut stream = UnixStream::connect(&self.0)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(invalid)?
            .unwrap_or_default();
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )?;
        stream.write_all(&body)?;
        let head = Head::read(&mut stream)?;
        let status = head
            .first
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| invalid("missing Docker status"))?
            .parse()
            .map_err(invalid)?;
        let bytes =
            if head.get("Content-Length").is_some() || head.get("Transfer-Encoding").is_some() {
                head.body(&mut stream)?
            } else {
                let mut bytes = Vec::new();
                stream.take((MAX_JSON + 1) as u64).read_to_end(&mut bytes)?;
                if bytes.len() > MAX_JSON {
                    return Err(invalid("Docker response too large"));
                }
                bytes
            };
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(invalid)?
        };
        Ok(Reply { status, body })
    }
}

pub fn serve(path: &Path) -> io::Result<()> {
    let mut journal = Journal::load(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| invalid("missing proxy directory"))?;
    let socket = directory.join("s");
    if socket.as_os_str().as_encoded_bytes().len() >= 108 {
        return Err(invalid("Docker proxy path too long"));
    }
    if !fs::symlink_metadata(&journal.upstream)?
        .file_type()
        .is_socket()
    {
        return Err(invalid("Docker upstream is not a Unix socket"));
    }
    let engine = UnixEngine(journal.upstream.clone());
    let info = engine.request("GET", "/info", None)?;
    let actual_engine = info
        .body
        .get("ID")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("Docker engine identity unavailable"))?;
    if info.status != 200
        || info.body.get("OSType").and_then(Value::as_str) != Some("linux")
        || (journal.engine != PENDING_ENGINE && actual_engine != journal.engine)
    {
        return Err(invalid("Docker upstream identity mismatch"));
    }
    journal.engine = actual_engine.into();
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    journal.proxy = Some(ProcessIdentity::of_current_process().map_err(invalid)?);
    write_json(path, &journal)?;
    let shared = Arc::new(Mutex::new(journal));
    write_json(&directory.join("ready"), &true)?;
    let stop = directory.join("stop");
    let started = std::time::Instant::now();
    let mut last_probe = started
        .checked_sub(Duration::from_secs(1))
        .unwrap_or(started);
    let mut runner = None::<ProcessIdentity>;
    loop {
        if stop.exists() {
            // This is the private companion, not the daemon. Exiting also
            // stops relay threads, so a late create cannot race the sweep.
            std::process::exit(0);
        }
        if last_probe.elapsed() >= Duration::from_secs(1) {
            last_probe = std::time::Instant::now();
            if runner.is_none() {
                match fs::read(directory.join("runner.json")) {
                    Ok(bytes) => runner = Some(serde_json::from_slice(&bytes).map_err(invalid)?),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // The parent may have died between proxy readiness and
                        // starting the runner. Do not leave a helper forever.
                        if started.elapsed() >= Duration::from_secs(30) {
                            std::process::exit(0);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            if let Some(identity) = &runner
                && !matches!(
                    identity.recheck().map_err(invalid)?,
                    runner_manager_platform::process::Adoption::Live
                )
            {
                std::process::exit(0);
            }
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let journal = Arc::clone(&shared);
                let path = path.to_path_buf();
                let engine = engine.clone();
                std::thread::spawn(move || {
                    if handle(&mut stream, &journal, &path, &engine).is_err() {
                        let _ = reply(
                            &mut stream,
                            503,
                            &serde_json::json!({"message":"runner-manager Docker accounting failed; request was not acknowledged"}),
                        );
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error),
        }
    }
}

fn handle(
    stream: &mut UnixStream,
    shared: &Mutex<Journal>,
    path: &Path,
    engine: &UnixEngine,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let head = Head::read(stream)?;
    let parts: Vec<_> = head.first.split_whitespace().collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" || !parts[1].starts_with('/') {
        return Err(invalid("invalid Docker request"));
    }
    let method = parts[0];
    let endpoint = parts[1].split('?').next().unwrap_or(parts[1]);
    let create = method == "POST"
        && ["/containers/create", "/volumes/create", "/networks/create"]
            .iter()
            .any(|suffix| endpoint.ends_with(suffix));
    if !create {
        return relay(stream, &head, &engine.0);
    }
    if head
        .get("Expect")
        .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
    {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let mut body: Value = serde_json::from_slice(&head.body(stream)?).map_err(invalid)?;
    let intent = {
        let mut journal = shared
            .lock()
            .map_err(|_| invalid("Docker journal lock poisoned"))?;
        let intent = creation_intent(&journal, parts[1], &mut body)?;
        if let Some(intent) = &intent {
            journal.intents.push(intent.clone());
            write_json(path, &*journal)?;
        }
        intent
    };
    let response = engine.request(method, parts[1], Some(&body))?;
    if (200..300).contains(&response.status)
        && let Some(intent) = intent
    {
        let id = match intent.kind {
            Kind::Volume => response.body.get("Name"),
            _ => response.body.get("Id").or_else(|| response.body.get("ID")),
        }
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Docker create returned no identity"))?;
        let mut journal = shared
            .lock()
            .map_err(|_| invalid("Docker journal lock poisoned"))?;
        capture_created(&mut journal, &intent, id, engine)?;
        journal
            .intents
            .iter_mut()
            .find(|stored| stored.id == intent.id)
            .ok_or_else(|| invalid("missing Docker creation intent"))?
            .settled = true;
        write_json(path, &*journal)?;
    }
    reply(stream, response.status, &response.body)
}

fn reply(stream: &mut impl Write, status: u16, body: &Value) -> io::Result<()> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).map_err(invalid)?
    };
    write!(
        stream,
        "HTTP/1.1 {status} Docker\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)
}

fn relay(client: &mut UnixStream, head: &Head, socket: &Path) -> io::Result<()> {
    let mut upstream = UnixStream::connect(socket)?;
    upstream.write_all(&head.encode_for_relay())?;
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let send = std::thread::spawn(move || {
        let result = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let result = io::copy(&mut upstream, client);
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = send.join();
    result.map(|_| ())
}

/// Recover an ambiguous create by all three ownership labels, never by age,
/// container names, or an unscoped before/after inventory difference.
pub fn recover_creations(journal: &mut Journal, engine: &dyn Engine) -> io::Result<()> {
    for intent in journal.intents.clone() {
        let labels: Vec<_> = journal
            .labels(&intent.id)
            .into_iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        let filter = percent_encode(
            &serde_json::to_string(&serde_json::json!({"label":labels})).map_err(invalid)?,
        );
        let path = match intent.kind {
            Kind::Container => format!("/containers/json?all=true&filters={filter}"),
            Kind::Volume => format!("/volumes?filters={filter}"),
            Kind::Network => format!("/networks?filters={filter}"),
        };
        let response = engine.request("GET", &path, None)?;
        if response.status != 200 {
            return Err(invalid("Docker recovery inventory failed"));
        }
        let entries = if intent.kind == Kind::Volume {
            response.body.get("Volumes")
        } else {
            Some(&response.body)
        };
        if !entries.is_some_and(|entries| {
            entries.is_array() || (intent.kind == Kind::Volume && entries.is_null())
        }) {
            return Err(invalid("invalid Docker recovery inventory"));
        }
        if let Some(entries) = entries.and_then(Value::as_array) {
            for entry in entries {
                let id = if intent.kind == Kind::Volume {
                    entry.get("Name")
                } else {
                    entry.get("Id").or_else(|| entry.get("ID"))
                };
                let id = id
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("Docker recovery inventory has no ID"))?;
                capture_created(journal, &intent, id, engine)?;
            }
        }
    }
    Ok(())
}

fn percent_encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(result, "%{byte:02X}");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unexpected_journal_entries_keep_the_ownership_metadata() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("journal.json"), b"ownership").unwrap();
        fs::write(directory.path().join("unexpected"), b"preserve").unwrap();
        assert!(remove_journal_files(directory.path()).is_err());
        assert_eq!(
            fs::read(directory.path().join("journal.json")).unwrap(),
            b"ownership"
        );
        fs::remove_file(directory.path().join("unexpected")).unwrap();
        remove_journal_files(directory.path()).unwrap();
        assert!(!directory.path().exists());
    }
}
