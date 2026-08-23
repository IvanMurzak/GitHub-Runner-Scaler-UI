// owner: f1-cli-auth-host-status
//
// ----------------------------------------------------------------------------
// WHY THIS EXISTS ALONGSIDE `tests/common/mod.rs` RATHER THAN INSIDE IT.
// ----------------------------------------------------------------------------
// `common/` belongs to a3 and builds synthetic GitHub *releases* for the
// install-script and release-channel suites. Nothing in it helps a CLI test:
// there is no disposable data directory, no `Command::cargo_bin` wrapper and no
// GitHub API fixture. Teaching a3's module those tricks would make its two
// files fail for reasons a3 does not own, which is the drift its own header
// warns about. So this is a second module, for f1's suites.
//
// ----------------------------------------------------------------------------
// WHY THIS SPEAKS HTTP INSTEAD OF USING A MOCKING CRATE.
// ----------------------------------------------------------------------------
// `crates/app` has no `wiremock` dev-dependency and cannot acquire one: `a1`
// owns every manifest in this workspace and adding a dependency is an A-group
// change. `crates/github` has `wiremock` and uses it for exactly this, so the
// alternative here was not "a nicer fixture" but "no end-to-end coverage of
// `auth login` at all" -- the device flow's only injection seam is
// `Endpoints::for_test_server`, and it wants something on a socket.
//
// What is served is small on purpose: the four endpoints `auth login` and
// `auth status` touch, with canned bodies. It is not an HTTP server, it is a
// fixture that answers in HTTP/1.1.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command;

// ---------------------------------------------------------------------------
// Fixtures that are unmistakably not real credentials
// ---------------------------------------------------------------------------

/// Shaped like a real user-to-server token and unmistakably not one.
///
/// Assembled at run time so the literal appears in no source file and in no
/// compiled artifact — the same reasoning `d2`'s
/// `secret_store_without_a_login_session.rs` gives, and the property
/// `no_secret_reaches_command_output.rs` depends on when it scans the binary's
/// own output for it.
#[must_use]
pub fn fixture_token() -> String {
    format!("{}{}", "ghu_", "f1CliFixtureTokenNotARealOne0000")
}

/// The device code, which `07-security.md` says must never be displayed.
#[must_use]
pub fn fixture_device_code() -> String {
    format!("{}{}", "fixture-device-code-", "9f14c0b7a2e34d81")
}

/// The user code, which `07-security.md` says *is* displayed by design.
pub const FIXTURE_USER_CODE: &str = "WDJB-MJHT";

/// The client id the fake App is driven with. Public by design, like the real
/// one (`07-security.md`, credential inventory).
pub const FIXTURE_CLIENT_ID: &str = "Iv23liF1TESTCLIENTID";

/// The App slug the installation URL is built from.
pub const FIXTURE_APP_SLUG: &str = "runner-manager-test";

// ---------------------------------------------------------------------------
// Driving the binary
// ---------------------------------------------------------------------------

/// A `runner-manager` invocation rooted at a disposable data directory.
///
/// Every `RUNNER_MANAGER_*` variable is removed first, so a developer who has
/// one exported does not silently change what the suite measures. `--data-dir`
/// is passed as a flag rather than through its environment variable for the
/// same reason: a flag cannot be overridden by the environment.
#[must_use]
pub fn runner_manager(data_dir: &Path) -> Command {
    let mut command = Command::cargo_bin("runner-manager").expect("the binary must be built");
    for variable in [
        "RUNNER_MANAGER_DATA_DIR",
        "RUNNER_MANAGER_GITHUB_BASE_URL",
        "RUNNER_MANAGER_GITHUB_CLIENT_ID",
        "RUNNER_MANAGER_GITHUB_APP_SLUG",
        "RUST_LOG",
        // `reqwest` is built with `system-proxy`, so an exported proxy on the
        // developer's machine or on a CI image would be applied to the loopback
        // fixture too. Cleared rather than trusted: `NO_PROXY` below is the
        // belt, and these are the braces.
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(variable);
    }
    command.env("NO_PROXY", "127.0.0.1,localhost,::1");
    command.arg("--data-dir").arg(data_dir);
    command
}

/// The same, pointed at a fake GitHub.
#[must_use]
pub fn runner_manager_against(data_dir: &Path, github: &FakeGithub) -> Command {
    let mut command = runner_manager(data_dir);
    command
        .env("RUNNER_MANAGER_GITHUB_BASE_URL", github.base_url())
        .env("RUNNER_MANAGER_GITHUB_CLIENT_ID", FIXTURE_CLIENT_ID)
        .env("RUNNER_MANAGER_GITHUB_APP_SLUG", FIXTURE_APP_SLUG);
    command
}

/// Everything a finished invocation produced.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    #[must_use]
    pub fn both(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Runs a command and captures both streams and the exit code.
///
/// `assert_cmd`'s own assertions panic on a non-zero exit, and most of this
/// suite is *about* non-zero exits, so the outcome is returned rather than
/// asserted.
#[must_use]
pub fn run(mut command: Command) -> Outcome {
    let output = command.output().expect("the binary must run");
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n"),
        stderr: String::from_utf8_lossy(&output.stderr).replace("\r\n", "\n"),
    }
}

// ---------------------------------------------------------------------------
// The fake GitHub
// ---------------------------------------------------------------------------

/// One canned answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    /// Extra response headers.
    ///
    /// `c2` tells GitHub's temporary authentication lockout from an ordinary
    /// permissions refusal by reading `retry-after` and the absence of a
    /// message body, so a fixture that could not set a header could not produce
    /// the fourth of the four states `f1` has to distinguish.
    pub headers: Vec<(String, String)>,
}

impl Reply {
    #[must_use]
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        Self::json(200, body)
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

#[derive(Debug)]
struct Route {
    method: String,
    path: String,
    /// Taken in order. The last one repeats once the queue is down to it, so a
    /// route that is polled an unknown number of times does not need its
    /// answers counted in advance.
    replies: VecDeque<Reply>,
}

#[derive(Debug, Default)]
struct Shared {
    routes: Vec<Route>,
    seen: Vec<String>,
}

/// A loopback stand-in for `api.github.com` and `github.com`.
pub struct FakeGithub {
    base_url: String,
    shared: Arc<Mutex<Shared>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl FakeGithub {
    /// Binds an ephemeral loopback port and starts answering.
    ///
    /// # Panics
    /// If the port cannot be bound, which makes every test that uses it
    /// meaningless rather than merely failing.
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port must be available");
        let port = listener.local_addr().expect("a bound listener").port();
        listener
            .set_nonblocking(true)
            .expect("the listener must be pollable");

        let shared = Arc::new(Mutex::new(Shared::default()));
        let stop = Arc::new(AtomicBool::new(false));

        let worker = {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // One thread per connection. Serving inline would
                            // wedge the whole fixture on a client that opened a
                            // socket and then stalled, and the failure would
                            // look like a flaky product rather than a flaky
                            // fixture.
                            let shared = Arc::clone(&shared);
                            std::thread::spawn(move || serve(stream, &shared));
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            base_url: format!("http://127.0.0.1:{port}/"),
            shared,
            stop,
            worker: Some(worker),
        }
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Adds a route. Later replies for the same route queue behind earlier ones.
    pub fn route(&self, method: &str, path: &str, reply: Reply) -> &Self {
        let mut shared = self.shared.lock().expect("not poisoned");
        if let Some(existing) = shared
            .routes
            .iter_mut()
            .find(|r| r.method == method && r.path == path)
        {
            existing.replies.push_back(reply);
        } else {
            shared.routes.push(Route {
                method: method.to_string(),
                path: path.to_string(),
                replies: VecDeque::from([reply]),
            });
        }
        self
    }

    /// Every `METHOD /path` this fixture answered, in order.
    #[must_use]
    pub fn seen(&self) -> Vec<String> {
        self.shared.lock().expect("not poisoned").seen.clone()
    }

    // -- the four endpoints the CLI touches ------------------------------

    /// A device-code response whose `verification_uri` is on this fixture's own
    /// origin, which is what `c2`'s phishing control requires.
    pub fn with_device_code(&self) -> &Self {
        self.route(
            "POST",
            "/login/device/code",
            Reply::ok(format!(
                r#"{{"device_code":"{}","user_code":"{FIXTURE_USER_CODE}",
                     "verification_uri":"{}login/device","expires_in":900,"interval":1}}"#,
                fixture_device_code(),
                self.base_url
            )),
        )
    }

    /// The access-token exchange approves immediately.
    pub fn with_approval(&self) -> &Self {
        self.route(
            "POST",
            "/login/oauth/access_token",
            Reply::ok(format!(
                r#"{{"access_token":"{}","token_type":"bearer","scope":""}}"#,
                fixture_token()
            )),
        )
    }

    /// The access-token exchange answers with a device-flow error code.
    pub fn with_token_error(&self, code: &str) -> &Self {
        self.route(
            "POST",
            "/login/oauth/access_token",
            Reply::ok(format!(r#"{{"error":"{code}"}}"#)),
        )
    }

    /// `GET /user/installations` answers with no installations at all, which is
    /// the clean-machine case that produces the third onboarding action.
    pub fn with_no_installations(&self) -> &Self {
        self.route(
            "GET",
            "/user/installations",
            Reply::ok(r#"{"total_count":0,"installations":[]}"#),
        )
    }

    /// One installation on `account`, reaching `repositories`.
    pub fn with_installation(
        &self,
        id: u64,
        account: &str,
        account_type: &str,
        selection: &str,
        repositories: &[&str],
    ) -> &Self {
        self.route(
            "GET",
            "/user/installations",
            Reply::ok(format!(
                r#"{{"total_count":1,"installations":[
                     {{"id":{id},"account":{{"login":"{account}","type":"{account_type}"}},
                       "repository_selection":"{selection}",
                       "permissions":{{"administration":"write","actions":"read"}}}}]}}"#
            )),
        );
        let entries: Vec<String> = repositories
            .iter()
            .map(|full_name| format!(r#"{{"full_name":"{full_name}"}}"#))
            .collect();
        self.route(
            "GET",
            &format!("/user/installations/{id}/repositories"),
            Reply::ok(format!(
                r#"{{"total_count":{},"repositories":[{}]}}"#,
                entries.len(),
                entries.join(",")
            )),
        )
    }

    /// GitHub's temporary authentication lockout, as `c2` recognises it: a
    /// `403` carrying `retry-after` and **no** parseable message body.
    ///
    /// A permissions refusal names what is not accessible, so it carries a
    /// message and does not latch. That difference is the whole reason the two
    /// are separate states, and it is why this fixture sets a header rather
    /// than only a status.
    pub fn with_authentication_lockout(&self, retry_after_secs: u64) -> &Self {
        self.route(
            "GET",
            "/user/installations",
            Reply {
                status: 403,
                body: String::new(),
                headers: vec![("retry-after".to_string(), retry_after_secs.to_string())],
            },
        )
    }

    /// Every API call answers `401`, which `c2` turns into
    /// `AuthenticationFailed` after one re-validation.
    pub fn with_revoked_credential(&self) -> &Self {
        for _ in 0..8 {
            self.route(
                "GET",
                "/user/installations",
                Reply::json(401, r#"{"message":"Bad credentials"}"#),
            );
        }
        self
    }
}

impl Drop for FakeGithub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Reads one HTTP/1.1 request and writes the canned answer.
///
/// Deliberately minimal: request line, headers to the blank line, then exactly
/// `Content-Length` bytes of body. Nothing here parses a body — the device
/// flow's form fields are `c2`'s business and are asserted in `c2`'s own tests
/// against a real mock server.
fn serve(stream: TcpStream, shared: &Arc<Mutex<Shared>>) {
    // -----------------------------------------------------------------------
    // THE ACCEPTED SOCKET IS PUT BACK INTO BLOCKING MODE, EXPLICITLY.
    // -----------------------------------------------------------------------
    // The listener is non-blocking so the accept loop can poll a stop flag. On
    // Windows an accepted socket INHERITS the listening socket's blocking mode,
    // so without this line the first `read_line` below returns `WouldBlock`
    // immediately, this function gives up without answering, and the client
    // sees a closed connection. The symptom was an `auth login` that failed
    // roughly one run in three, at whichever request happened to arrive before
    // its bytes did -- a flaky fixture wearing the costume of a flaky product.
    // Linux does not inherit the flag, which is exactly why this would have
    // passed CI on one leg and failed on another.
    let _ = stream.set_nonblocking(false);

    // Timeouts rather than blocking forever: a stalled connection must fail the
    // one request it belongs to, never the whole fixture.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_nodelay(true);

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let path = target
        .split('?')
        .next()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };

    let mut content_length = 0_usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() {
            return;
        }
        if header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 0 {
        let mut body = vec![0_u8; content_length];
        let _ = reader.read_exact(&mut body);
    }

    let reply = {
        let mut shared = shared.lock().expect("not poisoned");
        shared.seen.push(format!("{method} {path}"));
        shared
            .routes
            .iter_mut()
            .find(|route| route.method == method && route.path == path)
            .map(|route| {
                if route.replies.len() > 1 {
                    route.replies.pop_front().expect("non-empty")
                } else {
                    route.replies.front().expect("non-empty").clone()
                }
            })
    };

    let reply = reply.unwrap_or_else(|| {
        Reply::json(
            404,
            format!(r#"{{"message":"this fixture has no route for {method} {path}"}}"#),
        )
    });

    let extra: String = reply
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let mut stream = stream;
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {length}\r\n\
         {extra}\
         Connection: close\r\n\
         \r\n\
         {body}",
        status = reply.status,
        reason = reason_phrase(reply.status),
        length = reply.body.len(),
        body = reply.body,
    );
    if stream.write_all(response.as_bytes()).is_err() {
        return;
    }
    let _ = stream.flush();

    // -----------------------------------------------------------------------
    // GRACEFUL CLOSE, NOT A BARE DROP.
    // -----------------------------------------------------------------------
    // Dropping a socket that still has unread bytes in its receive queue makes
    // Windows send an RST, and an RST discards data the peer has not read yet,
    // including the response just written. Half-closing and then draining to
    // EOF lets the client finish reading before the socket goes away.
    let _ = stream.shutdown(Shutdown::Write);
    let mut drained = [0_u8; 512];
    while matches!(stream.read(&mut drained), Ok(read) if read > 0) {}
}

/// Enough reason phrases to keep the responses well-formed.
///
/// `reqwest` does not read the phrase, but a fixture that answered `403 OK`
/// is a confusing thing to find in a packet capture — and this file spent one
/// debugging round on exactly that, because the first attempt at this function
/// silently failed to apply.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Looking at what a run left on disk
// ---------------------------------------------------------------------------

/// Every file under `root`, recursively.
///
/// Two suites walk the data directory looking for a planted secret, and they
/// had a copy of this each -- under two names, with two spellings of the
/// substring check, over the same directory for the same needle. Both live here
/// now.
#[must_use]
pub fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// Whether a file's bytes contain `needle`, unreadable files counting as no.
///
/// # The two spellings are equivalent here, and this one is the direct one
///
/// This started life as a byte-window scan in one suite and a
/// `String::from_utf8_lossy(..).contains(..)` in the other, and the reason
/// first recorded for keeping the byte window was **wrong**: it claimed a lossy
/// conversion could eat the needle out of a DPAPI blob or a keychain database.
/// It cannot. UTF-8 is self-synchronising and no ASCII byte is ever a
/// continuation byte, so `from_utf8_lossy` never consumes an ASCII byte into a
/// replacement character -- and every needle these suites look for is ASCII.
/// Both spellings find an ASCII needle wrapped in arbitrary invalid UTF-8.
///
/// So the choice is not correctness, and saying it was would mislead whoever
/// reads this next -- the same failure mode as a comment that overstates its
/// test. The byte window is kept because it is the more direct of the two: it
/// allocates nothing, and it assumes nothing about the needle's encoding, which
/// leaves it right for a future needle that is not ASCII, where the equivalence
/// above stops holding.
///
/// `no_secret_reaches_command_output.rs` still builds its corpus through
/// `from_utf8_lossy`, deliberately: its fragments are text -- command stdout and
/// stderr arrive as `String` already -- and it scans them all together rather
/// than file by file. Converting that to bytes would buy nothing while the
/// needles are ASCII, and the note above is what a future non-ASCII needle
/// should send somebody back to.
#[must_use]
pub fn file_contains(path: &Path, needle: &str) -> bool {
    let Ok(haystack) = std::fs::read(path) else {
        return false;
    };
    let needle = needle.as_bytes();
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether a path is inside the machine-scoped secret store.
///
/// The store is the **one** place the token is allowed to be -- that is what it
/// is for -- and on Linux `d2` keeps it there as a `0600` file rather than as
/// ciphertext, so a scan that included it would fail on one platform for the
/// correct behaviour. `d2`'s own `no_token_outside_the_store.rs` draws the same
/// line, and this is the CLI-side half of it.
#[must_use]
pub fn is_the_secret_store(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "secrets")
}
