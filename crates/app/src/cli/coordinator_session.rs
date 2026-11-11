//! A person's sign-in to a coordinator, and the commands it carries to other
//! hosts: `coordinator login | logout | hosts`, and `--host remote:NAME`.
//!
//! The person signs in with GitHub through the coordinator's dashboard (the
//! same allowlist), never with this machine's enrollment key: the key proves
//! a *host*, and a command is a *person's*. `coordinator login` starts a
//! sign-in, the person approves its code in a browser signed in to the
//! dashboard, and the coordinator hands this CLI a session token. The token
//! is kept in the user-scoped secret store of whoever ran `login` (a `0600`
//! file on Linux, DPAPI on Windows, the login keychain on macOS), never in the
//! service's.
//!
//! `runner-manager --host remote:NAME repo list` sends the arguments, minus
//! `--host` and `--data-dir`, to the host the coordinator knows as `NAME`.
//! That host decides what it runs: reads always, changes only once its own
//! operator allowed them there (`coordinator remote-changes allow`).

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use runner_manager_domain::coordinator_protocol::CoordinatorUrl;
use runner_manager_platform::coordinator as records;
use runner_manager_platform::secrets::{
    PlatformSecretStore, SecretItem, SecretScope, SecretStore as _,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    Cli, CliError, Context, CoordinatorHostsArgs, CoordinatorLoginArgs, Failure, HOST_OPTION,
    Styling, write_failed,
};

/// The version of the stored session and of `coordinator hosts --json`.
const SCHEMA_VERSION: u32 = 1;
/// How long one request to the coordinator may take; a command waits on the
/// host for up to a minute there.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const DATA_DIR_OPTION: &str = "--data-dir";

/// What `coordinator login` keeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    schema_version: u32,
    /// The coordinator's origin.
    url: String,
    /// The GitHub login the session is for.
    login: String,
    token: String,
}

/// One host as the coordinator lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteHost {
    id: String,
    name: String,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    manageable: bool,
    #[serde(default)]
    remote_changes: bool,
}

/// How a relayed command ended on its host.
#[derive(Debug, Deserialize)]
struct RemoteResult {
    exit_code: u8,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    truncated: bool,
}

// ---------------------------------------------------------------------------
// The stored session
// ---------------------------------------------------------------------------

/// The user-scoped store the session lives in: under `--data-dir` when one
/// is given, else this account's own.
fn session_store(data_root: Option<&Path>) -> Result<PlatformSecretStore, CliError> {
    let scope = SecretScope::User;
    match data_root {
        Some(root) => PlatformSecretStore::rooted_at(scope, root),
        None => PlatformSecretStore::standard(scope),
    }
    .map(|store| store.for_item(SecretItem::CoordinatorCliSession))
    .map_err(|source| {
        CliError::new(
            Failure::SecretStore,
            format!("cannot reach this account's secret store: {source}"),
        )
    })
}

fn load_session(data_root: Option<&Path>) -> Result<Option<Session>, CliError> {
    let stored = session_store(data_root)?.load().map_err(|source| {
        CliError::new(
            Failure::SecretStore,
            format!("the coordinator sign-in cannot be read: {source}"),
        )
    })?;
    Ok(stored.and_then(|value| serde_json::from_str(value.expose_secret()).ok()))
}

fn signed_in(data_root: Option<&Path>) -> Result<Session, CliError> {
    load_session(data_root)?.ok_or_else(|| {
        CliError::with_remedy(
            Failure::NotAuthenticated,
            "this account is not signed in to a coordinator",
            "runner-manager coordinator login",
        )
    })
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn client(timeout: Duration) -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|_| unavailable("cannot prepare an HTTPS client"))
}

fn unavailable(detail: impl Into<String>) -> CliError {
    CliError::new(Failure::CoordinatorUnavailable, detail)
}

fn unreachable(url: &str) -> CliError {
    CliError::with_remedy(
        Failure::CoordinatorUnavailable,
        format!("{url} could not be reached"),
        "check this machine's network and the coordinator's URL",
    )
}

/// The coordinator's `{"error": ...}`, or the status when it said nothing.
async fn error_text(response: reqwest::Response) -> String {
    let status = response.status().as_u16();
    response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|body| body["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

/// What a `401` or `404` from `/api/*` means to the person.
fn api_refusal(session: &Session, status: u16) -> Option<CliError> {
    match status {
        401 => Some(CliError::with_remedy(
            Failure::NotAuthenticated,
            format!(
                "{} no longer accepts the sign-in of {}: it expired, was signed out, or the \
                 login is no longer allowed there",
                session.url, session.login
            ),
            "runner-manager coordinator login",
        )),
        404 => Some(CliError::new(
            Failure::UnsupportedHost,
            format!(
                "{} has no dashboard sign-in configured, or is older than remote management \
                 (0.4.61)",
                session.url
            ),
        )),
        _ => None,
    }
}

async fn fetch_hosts(session: &Session) -> Result<Vec<RemoteHost>, CliError> {
    #[derive(Deserialize)]
    struct Overview {
        #[serde(default)]
        hosts: Vec<RemoteHost>,
    }
    let response = client(REQUEST_TIMEOUT)?
        .get(format!("{}/api/overview", session.url))
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|_| unreachable(&session.url))?;
    let status = response.status().as_u16();
    if let Some(refusal) = api_refusal(session, status) {
        return Err(refusal);
    }
    if status != 200 {
        return Err(unavailable(format!(
            "{} could not list its hosts: {}",
            session.url,
            error_text(response).await
        )));
    }
    let mut hosts = response
        .json::<Overview>()
        .await
        .map_err(|_| unavailable(format!("{}'s host list was not understood", session.url)))?
        .hosts;
    hosts.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(hosts)
}

// ---------------------------------------------------------------------------
// coordinator login | logout | hosts
// ---------------------------------------------------------------------------

/// `coordinator login [--url URL]`.
///
/// # Errors
/// No coordinator to sign in to, the coordinator unreachable or without a
/// dashboard, the sign-in denied or expired, or the store not writable.
pub fn login(
    context: &Context,
    args: &CoordinatorLoginArgs,
    styling: Styling,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the sign-in");
    let raw = match &args.url {
        Some(url) => url.clone(),
        None => records::configured(context.paths())
            .ok()
            .flatten()
            .map(|config| config.url)
            .ok_or_else(|| {
                CliError::with_remedy(
                    Failure::InvalidArgument,
                    "this host has not joined a coordinator, so there is none to sign in to by \
                     default",
                    "runner-manager coordinator login --url https://runners.example.com",
                )
            })?,
    };
    let url = CoordinatorUrl::parse(&raw)
        .map_err(|error| {
            CliError::new(
                Failure::InvalidArgument,
                format!("`coordinator login` needs the coordinator's https URL: {error}"),
            )
        })?
        .origin();
    let store = session_store(context.data_root.as_deref())?;

    let (login, token) = super::runtime()?.block_on(async {
        #[derive(Deserialize)]
        struct Started {
            device_code: String,
            user_code: String,
            verification_url: String,
            interval_secs: u64,
            expires_in_secs: u64,
        }
        #[derive(Deserialize)]
        struct Granted {
            token: String,
            login: String,
        }
        let http = client(REQUEST_TIMEOUT)?;
        let response = http
            .post(format!("{url}/auth/cli/start"))
            .send()
            .await
            .map_err(|_| unreachable(&url))?;
        match response.status().as_u16() {
            200 => {}
            404 => {
                return Err(CliError::new(
                    Failure::UnsupportedHost,
                    format!(
                        "{url} has no dashboard sign-in configured, or is older than CLI \
                         sign-in (0.4.61)"
                    ),
                ));
            }
            429 => {
                return Err(unavailable(
                    "the coordinator is limiting sign-ins from this address; wait a minute",
                ));
            }
            status => return Err(unavailable(format!("{url} answered HTTP {status}"))),
        }
        let started: Started = response
            .json()
            .await
            .map_err(|_| unavailable(format!("{url}'s answer was not a sign-in")))?;
        // The page must be the coordinator's own: the code is approved there.
        if !started
            .verification_url
            .starts_with(&format!("{url}/auth/cli?code="))
        {
            return Err(CliError::new(
                Failure::UnusableResponse,
                format!("{url} sent the sign-in to a page that is not its own"),
            ));
        }
        writeln!(
            out,
            "Open {} in a browser signed in to the coordinator,",
            started.verification_url
        )
        .map_err(failed)?;
        writeln!(
            out,
            "check that it shows the code {}, and approve it.",
            started.user_code
        )
        .map_err(failed)?;
        out.flush().map_err(failed)?;
        if super::open_in_browser(&started.verification_url, styling) {
            writeln!(out, "(a browser was opened)").map_err(failed)?;
        }
        writeln!(out, "Waiting for the approval...").map_err(failed)?;
        out.flush().map_err(failed)?;

        let interval = Duration::from_secs(started.interval_secs.clamp(1, 30));
        let deadline = Instant::now() + Duration::from_secs(started.expires_in_secs.min(3600));
        loop {
            tokio::time::sleep(interval).await;
            if Instant::now() >= deadline {
                break Err(expired());
            }
            let Ok(response) = http
                .post(format!("{url}/auth/cli/poll"))
                .json(&serde_json::json!({ "device_code": started.device_code }))
                .send()
                .await
            else {
                // A dropped poll is retried until the sign-in expires.
                continue;
            };
            match response.status().as_u16() {
                200 => {
                    let granted: Granted = response
                        .json()
                        .await
                        .map_err(|_| unavailable(format!("{url}'s answer was not a session")))?;
                    break Ok((granted.login, granted.token));
                }
                428 | 429 | 502..=504 => {}
                403 => {
                    break Err(CliError::with_remedy(
                        Failure::AuthenticationDeclined,
                        "the sign-in was denied",
                        "runner-manager coordinator login",
                    ));
                }
                410 => break Err(expired()),
                status => break Err(unavailable(format!("{url} answered HTTP {status}"))),
            }
        }
    })?;

    let session = Session {
        schema_version: SCHEMA_VERSION,
        url: url.clone(),
        login: login.clone(),
        token,
    };
    let value = serde_json::to_string(&session)
        .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?;
    store.store(&SecretString::from(value)).map_err(|source| {
        CliError::new(
            Failure::SecretStore,
            format!("signed in, but the session could not be stored: {source}"),
        )
    })?;
    writeln!(out, "Signed in to {url} as {login}.").map_err(failed)?;
    writeln!(
        out,
        "List its hosts with `runner-manager coordinator hosts`; run a command on one with \
         `runner-manager --host remote:NAME repo list`."
    )
    .map_err(failed)?;
    Ok(())
}

fn expired() -> CliError {
    CliError::with_remedy(
        Failure::AuthenticationExpired,
        "the sign-in expired before it was approved",
        "runner-manager coordinator login",
    )
}

/// `coordinator logout`: ends the session at the coordinator, best effort,
/// and forgets it here.
///
/// # Errors
/// The store cannot be read or written.
pub fn logout(context: &Context, out: &mut dyn Write) -> Result<(), CliError> {
    let failed = write_failed("the sign-out");
    let data_root = context.data_root.as_deref();
    let Some(session) = load_session(data_root)? else {
        writeln!(out, "this account is not signed in to a coordinator").map_err(failed)?;
        return Ok(());
    };
    let ended = super::runtime()?.block_on(async {
        let Ok(http) = client(REQUEST_TIMEOUT) else {
            return false;
        };
        http.post(format!("{}/auth/cli/logout", session.url))
            .bearer_auth(&session.token)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    });
    session_store(data_root)?.delete().map_err(|source| {
        CliError::new(
            Failure::SecretStore,
            format!("the coordinator sign-in could not be removed: {source}"),
        )
    })?;
    writeln!(
        out,
        "signed out of {} ({}){}",
        session.url,
        session.login,
        if ended {
            ""
        } else {
            "; the coordinator could not be told, and its session ends on its own in 90 days"
        }
    )
    .map_err(failed)
}

/// `coordinator hosts [--json]`.
///
/// # Errors
/// Not signed in, or the coordinator unreachable or refusing the session.
pub fn hosts(
    context: &Context,
    args: &CoordinatorHostsArgs,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    let failed = write_failed("the host list");
    let session = signed_in(context.data_root.as_deref())?;
    let hosts = super::runtime()?.block_on(fetch_hosts(&session))?;
    if args.json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "coordinator": session.url,
                "login": session.login,
                "hosts": hosts,
            }),
        )
        .map_err(|error| CliError::new(Failure::LocalState, error.to_string()))?;
        return writeln!(out).map_err(failed);
    }
    writeln!(
        out,
        "Coordinator: {} (signed in as {})",
        session.url, session.login
    )
    .map_err(failed)?;
    if hosts.is_empty() {
        return writeln!(out, "No hosts have joined it.").map_err(failed);
    }
    let width = hosts
        .iter()
        .map(|host| host.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    writeln!(
        out,
        "{:width$}  {:7}  {:10}  {:14}  ID",
        "NAME", "ONLINE", "MANAGEABLE", "REMOTE CHANGES"
    )
    .map_err(failed)?;
    let yes_no = |value: bool| if value { "yes" } else { "no" };
    for host in &hosts {
        writeln!(
            out,
            "{:width$}  {:7}  {:10}  {:14}  {}",
            host.name,
            yes_no(host.online),
            yes_no(host.manageable),
            if host.remote_changes {
                "allowed"
            } else {
                "reads only"
            },
            host.id
        )
        .map_err(failed)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// --host remote:NAME
// ---------------------------------------------------------------------------

/// The arguments a remote host is sent: everything after the program name
/// but `--host` and `--data-dir`, which address this machine.
fn remote_arguments(argv: &[OsString]) -> Result<Vec<String>, CliError> {
    let mut arguments = Vec::new();
    let mut skip_a_value = false;
    for argument in argv.iter().skip(1) {
        if skip_a_value {
            skip_a_value = false;
            continue;
        }
        let Some(text) = argument.to_str() else {
            return Err(CliError::new(
                Failure::InvalidArgument,
                "a remote command's arguments must be valid UTF-8",
            ));
        };
        if text == HOST_OPTION || text == DATA_DIR_OPTION {
            skip_a_value = true;
            continue;
        }
        if text.starts_with(&format!("{HOST_OPTION}="))
            || text.starts_with(&format!("{DATA_DIR_OPTION}="))
        {
            continue;
        }
        arguments.push(text.to_owned());
    }
    Ok(arguments)
}

/// Everything `--host remote:NAME` does, including owning the exit code:
/// the remote command's own.
#[must_use]
pub fn dispatch_to_remote_host(cli: &Cli, name: &str, argv: &[OsString]) -> ExitCode {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    match run_on_remote_host(cli, name, argv, &mut out, &mut err) {
        Ok(code) => {
            let _ = out.flush();
            let _ = err.flush();
            ExitCode::from(code)
        }
        Err(failure) => {
            let _ = out.flush();
            let _ = failure.render(&mut err);
            let _ = err.flush();
            ExitCode::from(failure.class().code())
        }
    }
}

fn run_on_remote_host(
    cli: &Cli,
    name: &str,
    argv: &[OsString],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, CliError> {
    let arguments = remote_arguments(argv)?;
    let session = signed_in(cli.data_dir.as_deref())?;
    let result = super::runtime()?.block_on(async {
        let hosts = fetch_hosts(&session).await?;
        let Some(host) = hosts
            .iter()
            .find(|host| host.name == name || host.id == name)
            .or_else(|| {
                hosts
                    .iter()
                    .find(|host| host.name.eq_ignore_ascii_case(name))
            })
        else {
            let names: Vec<&str> = hosts.iter().map(|host| host.name.as_str()).collect();
            return Err(CliError::with_remedy(
                Failure::NotFound,
                format!(
                    "{} knows no host named {name:?}; its hosts are: {}",
                    session.url,
                    if names.is_empty() {
                        "none".to_owned()
                    } else {
                        names.join(", ")
                    }
                ),
                "runner-manager coordinator hosts",
            ));
        };
        if !host.online {
            return Err(CliError::with_remedy(
                Failure::CoordinatorUnavailable,
                format!("{} is not connected to the coordinator", host.name),
                "check that its service is running and online",
            ));
        }
        if !host.manageable {
            return Err(CliError::with_remedy(
                Failure::UnsupportedHost,
                format!(
                    "{} runs a runner-manager too old to take commands (before 0.4.61)",
                    host.name
                ),
                "run `runner-manager update` on that host",
            ));
        }
        let response = client(COMMAND_TIMEOUT)?
            .post(format!("{}/api/hosts/{}/command", session.url, host.id))
            .bearer_auth(&session.token)
            .json(&serde_json::json!({ "argv": arguments }))
            .send()
            .await
            .map_err(|_| unreachable(&session.url))?;
        let status = response.status().as_u16();
        if let Some(refusal) = api_refusal(&session, status) {
            return Err(refusal);
        }
        let failure = match status {
            200 => {
                return response.json::<RemoteResult>().await.map_err(|_| {
                    unavailable(format!("{}'s answer was not a command result", session.url))
                });
            }
            409 => Failure::UnsupportedHost,
            400 => Failure::InvalidArgument,
            _ => Failure::CoordinatorUnavailable,
        };
        Err(CliError::new(
            failure,
            format!("{}: {}", host.name, error_text(response).await),
        ))
    })?;
    // As received: the host's own output, its own refusal included.
    let _ = out.write_all(result.stdout.as_bytes());
    let _ = err.write_all(result.stderr.as_bytes());
    if result.truncated {
        let _ = writeln!(err, "(the host cut its output to fit one message)");
    }
    Ok(result.exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_machines_options_are_left_out_of_a_remote_command() {
        let argv: Vec<OsString> = [
            "runner-manager",
            "--host",
            "remote:box",
            "--data-dir",
            "/tmp/x",
            "repo",
            "set-capacity",
            "octo/app",
            "--max-capacity=4",
            "--host=remote:box",
            "--data-dir=/y",
        ]
        .map(OsString::from)
        .to_vec();
        assert_eq!(
            remote_arguments(&argv).expect("UTF-8"),
            ["repo", "set-capacity", "octo/app", "--max-capacity=4"]
        );
    }
}
